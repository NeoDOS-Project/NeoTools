use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: nxdump <file> [--hex|--elf|--relocs|--strings|--segments]");
        process::exit(1);
    }

    let path = &args[1];
    let mut mode = "segments";
    for arg in &args[2..] {
        match arg.as_str() {
            "--hex" | "-x" => mode = "hex",
            "--elf" | "-e" => mode = "elf",
            "--relocs" | "-r" => mode = "relocs",
            "--strings" | "-s" => mode = "strings",
            "--segments" | "-S" => mode = "segments",
            _ => { eprintln!("Unknown option: {}", arg); process::exit(1); }
        }
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => { eprintln!("Error: {}", e); process::exit(1); }
    };

    if data.len() < 4 || &data[..4] != b"\x7fELF" {
        eprintln!("Not an ELF file");
        process::exit(1);
    }

    match mode {
        "hex" => print_hex(&data),
        "elf" => print_elf(&data),
        "relocs" => print_relocs(&data),
        "strings" => print_strings(&data),
        "segments" => print_segments(&data),
        _ => print_segments(&data),
    }
}

fn print_hex(data: &[u8]) {
    let max = data.len().min(4096);
    for (i, chunk) in data[..max].chunks(16).enumerate() {
        print!("{:08x}  ", i * 16);
        for (j, b) in chunk.iter().enumerate() {
            print!("{:02x} ", b);
            if j == 7 { print!(" "); }
        }
        let pad = 16 - chunk.len();
        for _ in 0..pad { print!("   "); }
        if pad >= 8 { print!(" "); }
        print!(" |");
        for b in chunk {
            if b.is_ascii_graphic() || *b == b' ' { print!("{}", *b as char); }
            else { print!("."); }
        }
        println!("|");
    }
    if data.len() > max {
        println!("... ({} more bytes)", data.len() - max);
    }
}

fn print_elf(data: &[u8]) {
    let e_type = read_u16(data, 16);
    let e_machine = read_u16(data, 18);
    let e_entry = read_u64(data, 24);
    let e_phoff = read_u64(data, 32);
    let e_shoff = read_u64(data, 40);
    let e_phnum = read_u16(data, 56);
    let e_shnum = read_u16(data, 60);

    println!("ELF64 {} {} entry={:#x}",
        if e_type == 3 { "DYN" } else if e_type == 2 { "EXEC" } else { "?" },
        if e_machine == 62 { "x86_64" } else { "?" },
        e_entry);
    println!("  {} program headers, {} section headers", e_phnum, e_shnum);
    println!("  PH off: {:#x}, SH off: {:#x}", e_phoff, e_shoff);

    // Program headers
    println!("\nProgram Headers:");
    for i in 0..e_phnum as u64 {
        let off = (e_phoff + i * 56) as usize;
        if off + 56 > data.len() { break; }
        let p_type = read_u32(data, off);
        let p_flags = read_u32(data, off + 4);
        let p_offset = read_u64(data, off + 8);
        let p_vaddr = read_u64(data, off + 16);
        let p_filesz = read_u64(data, off + 32);
        let p_memsz = read_u64(data, off + 40);

        let t = match p_type { 1 => "LOAD", 2 => "DYNAMIC", 4 => "NOTE", _ => "OTHER" };
        let f = format!("{}{}{}",
            if p_flags & 4 != 0 { 'R' } else { '-' },
            if p_flags & 2 != 0 { 'W' } else { '-' },
            if p_flags & 1 != 0 { 'E' } else { '-' });
        println!("  [{:2}] {} {} vaddr={:#010x} filesz={:#06x} memsz={:#06x} off={:#x}",
            i, t, f, p_vaddr, p_filesz, p_memsz, p_offset);
    }

    // Sections
    println!("\nSections:");
    if e_shoff > 0 && e_shnum > 0 {
        let e_shentsize = read_u16(data, 58);
        let e_shstrndx = read_u16(data, 62);
        let strtab_off = (e_shoff + e_shstrndx as u64 * e_shentsize as u64) as usize;
        if strtab_off + 64 <= data.len() {
            let sh_name_off = read_u32(data, strtab_off + 24) as usize;
            for i in 0..e_shnum as u64 {
                let off = (e_shoff + i * e_shentsize as u64) as usize;
                if off + 64 > data.len() { break; }
                let sh_name = read_u32(data, off) as usize;
                let sh_type = read_u32(data, off + 4);
                let sh_addr = read_u64(data, off + 12);
                let sh_size = read_u64(data, off + 32);
                let name = if sh_name_off + sh_name < data.len() {
                    let mut s = String::new();
                    let mut j = sh_name_off + sh_name;
                    while j < data.len() && data[j] != 0 { s.push(data[j] as char); j += 1; }
                    s
                } else { format!("[{}]", i) };
                let t = match sh_type { 1 => "PROGBITS", 2 => "SYMTAB", 3 => "STRTAB",
                    4 => "RELA", 7 => "NOTE", 8 => "NOBITS", 11 => "DYNSYM",
                    27 => "DYNAMIC", _ => "OTHER" };
                println!("  [{:2}] {:<20} {:12} addr={:#x} size={:#x}", i, name, t, sh_addr, sh_size);
            }
        }
    }
}

fn print_relocs(data: &[u8]) {
    let e_phoff = read_u64(data, 32);
    let e_phentsize = read_u16(data, 54);
    let e_phnum = read_u16(data, 56);

    for i in 0..e_phnum as u64 {
        let off = (e_phoff + i * e_phentsize as u64) as usize;
        if off + 56 > data.len() { break; }
        let p_type = read_u32(data, off);
        if p_type != 2 { continue; } // PT_DYNAMIC
        let p_offset = read_u64(data, off + 8) as usize;
        let p_filesz = read_u64(data, off + 32) as usize;

        if p_offset + p_filesz > data.len() { break; }

        let mut dyn_pos = p_offset;
        let mut rela_addr = 0u64;
        let mut rela_size = 0u64;
        let mut rela_ent = 0u64;

        while dyn_pos + 16 <= p_offset + p_filesz {
            let d_tag = read_i64(data, dyn_pos);
            let d_val = read_u64(data, dyn_pos + 8);
            match d_tag {
                7 => rela_addr = d_val,  // DT_RELA
                8 => rela_size = d_val,  // DT_RELASZ
                9 => rela_ent = d_val,   // DT_RELAENT
                0 => break,
                _ => {}
            }
            dyn_pos += 16;
        }

        if rela_size > 0 && rela_ent > 0 {
            println!("RELATIVE relocations ({}) at {:#x}:", rela_size / rela_ent, rela_addr);
            let rela_count = (rela_size / rela_ent) as usize;
            let rela_start = rela_addr as usize;
            for j in 0..rela_count.min(64) {
                let off2 = rela_start + j * rela_ent as usize;
                if off2 + 24 > data.len() { break; }
                let r_offset = read_u64(data, off2);
                let r_info = read_u64(data, off2 + 8);
                let r_addend = read_i64(data, off2 + 16);
                let r_type = (r_info & 0xFFFFFFFF) as u32;
                if r_type == 8 {
                    println!("  [{:4}] offset={:#010x} addend={:#x}", j, r_offset, r_addend);
                }
            }
            if rela_count > 64 {
                println!("  ... ({} more)", rela_count - 64);
            }
        }
    }
}

fn print_strings(data: &[u8]) {
    let max = data.len().min(65536);
    println!("Strings (printable, min 4 chars):");
    let mut count = 0;
    let mut i = 0;
    while i < max && count < 100 {
        if data[i].is_ascii_graphic() || data[i] == b' ' || data[i] == b'.' || data[i] == b'_' || data[i] == b'-' || data[i] == b'/' || data[i] == b'(' || data[i] == b')' {
            let start = i;
            while i < max && (data[i].is_ascii_graphic() || data[i] == b' ' || data[i] == b'.' || data[i] == b'_' || data[i] == b'-' || data[i] == b'/' || data[i] == b'(' || data[i] == b')' || data[i] == b':' || data[i] == b'\\') {
                i += 1;
            }
            let len = i - start;
            if len >= 4 {
                println!("  {:#06x}: {}", start, String::from_utf8_lossy(&data[start..i]));
                count += 1;
            }
        } else {
            i += 1;
        }
    }
    if count == 100 { println!("  ... (truncated)"); }
}

fn print_segments(data: &[u8]) {
    let e_phoff = read_u64(data, 32);
    let e_phentsize = read_u16(data, 54);
    let e_phnum = read_u16(data, 56);

    let mut load_segments: Vec<(u64, u64, u64, u32)> = Vec::new();

    for i in 0..e_phnum as u64 {
        let off = (e_phoff + i * e_phentsize as u64) as usize;
        if off + 56 > data.len() { break; }
        let p_type = read_u32(data, off);
        if p_type != 1 { continue; }
        let p_offset = read_u64(data, off + 8);
        let p_vaddr = read_u64(data, off + 16);
        let p_filesz = read_u64(data, off + 32);
        let p_memsz = read_u64(data, off + 40);
        let p_flags = read_u32(data, off + 4);
        load_segments.push((p_offset, p_vaddr, p_filesz, p_flags));
    }

    println!("Memory Map:");
    for seg in &load_segments {
        let flags_str = format!("{}{}{}",
            if seg.3 & 4 != 0 { 'R' } else { '-' },
            if seg.3 & 2 != 0 { 'W' } else { '-' },
            if seg.3 & 1 != 0 { 'E' } else { '-' });
        println!("  {:#010x} - {:#010x}  {}  {} bytes",
            seg.1, seg.1 + seg.2, flags_str, seg.2);
    }

    let e_type = read_u16(data, 16);
    if e_type == 3 {
        println!("\nNXE is PIE (ET_DYN) — requires relocation");
    }
    println!("File size: {} (max NXE: 65536)", data.len());
    if data.len() > 65536 {
        println!("WARNING: exceeds 64KB NXE slot limit!");
    }
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

fn read_i64(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}
