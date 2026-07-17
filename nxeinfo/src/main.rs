use std::env;
use std::fs;
use std::process;

const EI_MAG0: usize = 0;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EM_X86_64: u16 = 62;
const ET_DYN: u16 = 3;
const ET_EXEC: u16 = 2;
const PT_NOTE: u32 = 4;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: nxinfo <file.nxe> [--brief|--metadata|--sections|--headers|--json|--check]");
        process::exit(1);
    }

    let path = &args[1];
    let mut mode = "brief";
    for arg in &args[2..] {
        match arg.as_str() {
            "--brief" | "-b" => mode = "brief",
            "--metadata" | "-m" => mode = "metadata",
            "--sections" | "-s" => mode = "sections",
            "--headers" | "-H" => mode = "headers",
            "--json" | "-j" => mode = "json",
            "--check" | "-c" => mode = "check",
            _ => {
                eprintln!("Unknown option: {}", arg);
                process::exit(1);
            }
        }
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", path, e);
            process::exit(1);
        }
    };

    if data.len() < 64 {
        eprintln!("File too small ({} bytes) — not a valid ELF", data.len());
        process::exit(1);
    }

    if &data[..4] != b"\x7fELF" {
        eprintln!("Not an ELF file (bad magic)");
        process::exit(1);
    }

    let class = data[EI_CLASS];
    let encoding = data[EI_DATA];
    if class != ELFCLASS64 {
        eprintln!("Not a 64-bit ELF (class={})", class);
        process::exit(1);
    }
    if encoding != ELFDATA2LSB {
        eprintln!("Not little-endian (data={})", encoding);
        process::exit(1);
    }

    let e_type = read_u16(&data, 16);
    let e_machine = read_u16(&data, 18);
    let e_entry = read_u64(&data, 24);
    let e_phoff = read_u64(&data, 32);
    let e_shoff = read_u64(&data, 40);
    let e_flags = read_u32(&data, 48);
    let e_ehsize = read_u16(&data, 52);
    let e_phentsize = read_u16(&data, 54);
    let e_phnum = read_u16(&data, 56);
    let e_shentsize = read_u16(&data, 58);
    let e_shnum = read_u16(&data, 60);
    let e_shstrndx = read_u16(&data, 62);

    match mode {
        "check" => do_check(path, &data, e_type, e_machine),
        "json" => do_json(&data, e_type, e_machine, e_entry, e_phnum, e_shnum),
        "metadata" => {
            print_brief(&data, e_type, e_machine, e_entry, e_phnum, e_shnum);
            if let Some(note) = find_neodos_note(&data) {
                print_metadata(&note);
            } else {
                println!("\nNo NeoDOS metadata note found.");
            }
        }
        "sections" => {
            print_brief(&data, e_type, e_machine, e_entry, e_phnum, e_shnum);
            print_sections(&data, e_shoff, e_shentsize, e_shnum, e_shstrndx);
        }
        "headers" => {
            print_full_headers(&data, e_type, e_machine, e_entry, e_flags, e_ehsize,
                              e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
                              e_phoff, e_shoff);
            print_program_headers(&data, e_phoff, e_phentsize, e_phnum);
        }
        _ => {
            print_brief(&data, e_type, e_machine, e_entry, e_phnum, e_shnum);
        }
    }
}

fn print_brief(data: &[u8], e_type: u16, e_machine: u16, e_entry: u64, e_phnum: u16, e_shnum: u16) {
    let type_str = match e_type {
        ET_DYN => "DYN (PIE/NXE)",
        ET_EXEC => "EXEC",
        t => &format!("0x{t:x}"),
    };
    let machine_str = match e_machine {
        EM_X86_64 => "x86_64",
        m => &format!("0x{m:x}"),
    };
    let size_str = if data.len() < 1024 {
        format!("{} B", data.len())
    } else if data.len() < 1024 * 1024 {
        format!("{:.1} KB", data.len() as f64 / 1024.0)
    } else {
        format!("{:.1} MB", data.len() as f64 / (1024.0 * 1024.0))
    };

    println!("NXE: ELF64 {} {} | entry={:#x} | {} segs, {} sections | {}",
        type_str, machine_str, e_entry, e_phnum, e_shnum, size_str);

    if let Some(note) = find_neodos_note(data) {
        if let Some(name) = get_meta_string(&note, 0x0001) {
            println!("Product: {}", name);
        }
        if let Some(ver) = get_meta_string(&note, 0x0002) {
            println!("Version: {}", ver);
        }
        if let Some(desc) = get_meta_string(&note, 0x0004) {
            println!("Description: {}", desc);
        }
        if let Some(sub) = get_meta_u32(&note, 0x0008) {
            let sub_str = match sub {
                0 => "NATIVE",
                1 => "CONSOLE",
                2 => "GUI",
                _ => "UNKNOWN",
            };
            println!("Subsystem: {}", sub_str);
        }
        if let Some(min_k) = get_meta_string(&note, 0x000A) {
            println!("Min kernel: {}", min_k);
        }
        if let Some(deps) = get_meta_string(&note, 0x000B) {
            println!("Dependencies: {}", deps);
        }
    }
}

fn do_check(path: &str, data: &[u8], e_type: u16, e_machine: u16) {
    let mut errors: Vec<String> = Vec::new();

    if data.len() < 64 {
        errors.push("File too small for ELF64 header".to_string());
    }
    if &data[..4] != b"\x7fELF" {
        errors.push("Invalid ELF magic".to_string());
    }
    if data[EI_CLASS] != ELFCLASS64 {
        errors.push("Not 64-bit".to_string());
    }
    if data[EI_DATA] != ELFDATA2LSB {
        errors.push("Not little-endian".to_string());
    }
    if e_type != ET_DYN && e_type != ET_EXEC {
        errors.push(format!("Unsupported type: {:#x}", e_type));
    }
    if e_machine != EM_X86_64 {
        errors.push(format!("Unsupported machine: {:#x}", e_machine));
    }
    if data.len() as u64 > 64 * 1024 {
        errors.push(format!("File too large for NXE slot ({} > 65536)", data.len()));
    }

    if errors.is_empty() {
        println!("{}: VALID NXE", path);
    } else {
        println!("{}: INVALID", path);
        for e in &errors {
            println!("  - {}", e);
        }
    }
}

fn do_json(data: &[u8], e_type: u16, e_machine: u16, e_entry: u64, e_phnum: u16, e_shnum: u16) {
    let mut map = serde_json::Map::new();
    map.insert("format".into(), "ELF64".into());
    map.insert("type".into(), format!("{:#x}", e_type).into());
    map.insert("machine".into(), format!("{:#x}", e_machine).into());
    map.insert("entry".into(), format!("{:#x}", e_entry).into());
    map.insert("segments".into(), e_phnum.into());
    map.insert("sections".into(), e_shnum.into());
    map.insert("size".into(), data.len().into());

    if let Some(note) = find_neodos_note(data) {
        let mut meta = serde_json::Map::new();
        let tags = [
            (0x0001, "product_name"),
            (0x0002, "product_version"),
            (0x0003, "file_version"),
            (0x0004, "description"),
            (0x0005, "author"),
            (0x0006, "license"),
            (0x0007, "arch"),
            (0x000A, "min_kernel"),
            (0x000B, "dependencies"),
        ];
        for (tag, key) in &tags {
            if let Some(val) = get_meta_string(&note, *tag) {
                meta.insert(key.to_string(), val.into());
            }
        }
        if let Some(sub) = get_meta_u32(&note, 0x0008) {
            meta.insert("subsystem".into(), sub.into());
        }
        if let Some(flags) = get_meta_u32(&note, 0x000D) {
            meta.insert("manifest_flags".into(), flags.into());
        }
        map.insert("metadata".into(), serde_json::Value::Object(meta));
    }

    let output = serde_json::Value::Object(map);
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn print_full_headers(data: &[u8], e_type: u16, e_machine: u16, e_entry: u64, e_flags: u32,
                      e_ehsize: u16, e_phentsize: u16, e_phnum: u16, e_shentsize: u16, e_shnum: u16, e_shstrndx: u16,
                      e_phoff: u64, e_shoff: u64) {
    println!("ELF Header:");
    println!("  Magic:    {:02x?}", &data[..4]);
    println!("  Class:    ELF64 ({})", data[EI_CLASS]);
    println!("  Data:     {} ({})", if data[EI_DATA] == 1 { "2's complement, little-endian" } else { "big-endian" }, data[EI_DATA]);
    println!("  Version:  {}", data[6]);
    println!("  OS/ABI:   {:#x}", data[7]);
    println!("  Type:     {:#06x} ({})", e_type,
        if e_type == ET_DYN { "DYN (PIE)" } else if e_type == ET_EXEC { "EXEC" } else { "Unknown" });
    println!("  Machine:  {:#06x} ({})", e_machine,
        if e_machine == EM_X86_64 { "x86_64" } else { "Unknown" });
    println!("  Entry:    {:#018x}", e_entry);
    println!("  PhOff:    {:#018x}", e_phoff);
    println!("  ShOff:    {:#018x}", e_shoff);
    println!("  Flags:    {:#010x}", e_flags);
    println!("  EhSize:   {}", e_ehsize);
    println!("  PhEnt:    {} ({} entries)", e_phentsize, e_phnum);
    println!("  ShEnt:    {} ({} entries)", e_shentsize, e_shnum);
    println!("  ShStrIdx: {}", e_shstrndx);
}

fn print_program_headers(data: &[u8], e_phoff: u64, e_phentsize: u16, e_phnum: u16) {
    println!("\nProgram Headers:");
    for i in 0..e_phnum as u64 {
        let off = (e_phoff + i * e_phentsize as u64) as usize;
        if off + 56 > data.len() { break; }
        let p_type = read_u32(data, off);
        let p_flags = read_u32(data, off + 4);
        let p_offset = read_u64(data, off + 8);
        let p_vaddr = read_u64(data, off + 16);
        let p_filesz = read_u64(data, off + 32);
        let p_memsz = read_u64(data, off + 40);
        let p_align = read_u64(data, off + 48);

        let type_str = match p_type {
            1 => "LOAD",
            2 => "DYNAMIC",
            3 => "INTERP",
            4 => "NOTE",
            6 => "PHDR",
            0x6474e550 => "GNU_EH_FRAME",
            0x6474e551 => "GNU_STACK",
            0x6474e552 => "GNU_RELRO",
            t => &format!("{:#x}", t),
        };
        let flag_str = format!("{}{}{}",
            if p_flags & 4 != 0 { 'R' } else { '-' },
            if p_flags & 2 != 0 { 'W' } else { '-' },
            if p_flags & 1 != 0 { 'E' } else { '-' });

        println!("  [{:2}] {} {} off={:#x} vaddr={:#x} filesz={:#x} memsz={:#x} align={:#x}",
            i, type_str, flag_str, p_offset, p_vaddr, p_filesz, p_memsz, p_align);
    }
}

fn print_sections(data: &[u8], e_shoff: u64, e_shentsize: u16, e_shnum: u16, e_shstrndx: u16) {
    if e_shoff == 0 || e_shnum == 0 {
        println!("\nNo section headers.");
        return;
    }

    let strtab_off = (e_shoff + e_shstrndx as u64 * e_shentsize as u64) as usize;
    let sh_name_off = if strtab_off + 64 <= data.len() {
        read_u32(data, strtab_off + 24) as usize
    } else { 0 };

    println!("\nSection Headers:");
    for i in 0..e_shnum as u64 {
        let off = (e_shoff + i * e_shentsize as u64) as usize;
        if off + 64 > data.len() { break; }
        let sh_name = read_u32(data, off) as usize;
        let sh_type = read_u32(data, off + 4);
        let sh_addr = read_u64(data, off + 12);
        let sh_offset = read_u64(data, off + 24);
        let sh_size = read_u64(data, off + 32);

        let name = if sh_name_off > 0 && sh_name_off + sh_name < data.len() {
            get_cstr(data, sh_name_off + sh_name)
        } else {
            format!("[{}]", i)
        };

        let type_str = match sh_type {
            0 => "NULL", 1 => "PROGBITS", 2 => "SYMTAB", 3 => "STRTAB",
            4 => "RELA", 7 => "NOTE", 8 => "NOBITS", 9 => "REL",
            11 => "DYNSYM", 27 => "DYNAMIC", 0x6ffffff6 => "GNU_HASH",
            t => &format!("{:#x}", t),
        };

        println!("  [{:2}] {:<20} {:12} addr={:#x} off={:#x} size={:#x}",
            i, name, type_str, sh_addr, sh_offset, sh_size);
    }
}

fn find_neodos_note(data: &[u8]) -> Option<Vec<u8>> {
    let e_phoff = read_u64(data, 32);
    let e_phentsize = read_u16(data, 54);
    let e_phnum = read_u16(data, 56);

    for i in 0..e_phnum as u64 {
        let off = (e_phoff + i * e_phentsize as u64) as usize;
        if off + 56 > data.len() { break; }
        let p_type = read_u32(data, off);
        if p_type != PT_NOTE { continue; }
        let p_offset = read_u64(data, off + 8) as usize;
        let p_filesz = read_u64(data, off + 32) as usize;

        if p_offset + p_filesz > data.len() { continue; }
        if let Some(note) = scan_notes(&data[p_offset..p_offset + p_filesz], b"NeoDOS") {
            return Some(note);
        }
    }
    None
}

fn scan_notes(segment: &[u8], target_name: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + 12 <= segment.len() {
        let namesz = read_u32(segment, pos) as usize;
        let descsz = read_u32(segment, pos + 4) as usize;
        let name_start = pos + 12;
        let name_padded = align4(namesz);
        let desc_start = name_start + name_padded;

        if namesz == target_name.len() + 1
            && name_start + namesz <= segment.len()
            && &segment[name_start..name_start + target_name.len()] == target_name
        {
            if desc_start + descsz <= segment.len() {
                return Some(segment[desc_start..desc_start + descsz].to_vec());
            }
        }
        pos = desc_start + align4(descsz);
    }
    None
}

fn print_metadata(desc: &[u8]) {
    println!("\nNeoDOS Metadata Block:");
    let mut pos = 0;
    while pos + 4 <= desc.len() {
        let tag = read_u16(desc, pos);
        let length = read_u16(desc, pos + 2) as usize;
        pos += 4;
        if pos + length > desc.len() { break; }

        let tag_name = match tag {
            0x0001 => "Product Name",
            0x0002 => "Product Version",
            0x0003 => "File Version",
            0x0004 => "Description",
            0x0005 => "Author",
            0x0006 => "License",
            0x0007 => "Architecture",
            0x0008 => "Subsystem",
            0x0009 => "Language",
            0x000A => "Min Kernel",
            0x000B => "Dependencies",
            0x000C => "Resource Dir",
            0x000D => "Manifest Flags",
            0x000E => "Original Filename",
            0x000F => "Build Timestamp",
            0x0010 => "Git Hash",
            t => &format!("Unknown({:#x})", t),
        };

        let value_str = if tag == 0x0008 || tag == 0x000D {
            let val = read_u32(&desc[pos - 4..], 0);
            if tag == 0x0008 {
                match val { 0 => "NATIVE", 1 => "CONSOLE", 2 => "GUI", _ => "UNKNOWN" }.to_string()
            } else {
                let mut s = String::new();
                if val & 1 != 0 { s.push_str("CORE "); }
                if val & 2 != 0 { s.push_str("BOOT "); }
                if val & 4 != 0 { s.push_str("NOASLR "); }
                if val & 8 != 0 { s.push_str("SINGLETON "); }
                if s.is_empty() { s.push_str("(none)"); }
                s
            }
        } else {
            String::from_utf8_lossy(&desc[pos..pos + length]).to_string()
        };

        println!("  {:<20} = {}", tag_name, value_str);
        pos += length;
    }
}

fn get_meta_string(desc: &[u8], target_tag: u16) -> Option<String> {
    let mut pos = 0;
    while pos + 4 <= desc.len() {
        let tag = read_u16(desc, pos);
        let length = read_u16(desc, pos + 2) as usize;
        pos += 4;
        if pos + length > desc.len() { break; }
        if tag == target_tag {
            return Some(String::from_utf8_lossy(&desc[pos..pos + length]).to_string());
        }
        pos += length;
    }
    None
}

fn get_meta_u32(desc: &[u8], target_tag: u16) -> Option<u32> {
    let mut pos = 0;
    while pos + 4 <= desc.len() {
        let tag = read_u16(desc, pos);
        let length = read_u16(desc, pos + 2) as usize;
        pos += 4;
        if pos + length > desc.len() { break; }
        if tag == target_tag && length >= 4 {
            let val = read_u32(desc, pos);
            return Some(val);
        }
        pos += length;
    }
    None
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}

fn get_cstr(data: &[u8], offset: usize) -> String {
    let mut s = String::new();
    let mut i = offset;
    while i < data.len() && data[i] != 0 {
        if data[i].is_ascii_graphic() || data[i] == b' ' || data[i] == b'.' || data[i] == b'_' || data[i] == b'-' {
            s.push(data[i] as char);
        } else {
            s.push('.');
        }
        i += 1;
    }
    s
}

fn align4(x: usize) -> usize {
    (x + 3) & !3
}
