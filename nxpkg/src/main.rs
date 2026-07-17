use std::env;
use std::fs;
use std::path::Path;
use std::process;

const MAGIC_NXP1: u32 = 0x3150584E;
static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = 0xEDB88320 ^ (crc >> 1);
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: nxpkg <command> [options]");
        eprintln!();
        eprintln!("Commands:");
        eprintln!("  create  <dir> <output.nxp>   Create NXP from directory");
        eprintln!("  extract <nxp> <output-dir>    Extract NXP to directory");
        eprintln!("  list    <nxp>                 List contents");
        eprintln!("  info    <nxp>                 Show package metadata");
        eprintln!("  verify  <nxp>                 Verify CRC32 integrity");
        process::exit(1);
    }

    match args[1].as_str() {
        "create" | "c" => {
            if args.len() < 4 { eprintln!("Usage: nxpkg create <dir> <output.nxp>"); process::exit(1); }
            cmd_create(&args[2], &args[3]);
        }
        "extract" | "x" => {
            if args.len() < 4 { eprintln!("Usage: nxpkg extract <nxp> <output-dir>"); process::exit(1); }
            cmd_extract(&args[2], &args[3]);
        }
        "list" | "ls" | "l" => {
            if args.len() < 3 { eprintln!("Usage: nxpkg list <nxp>"); process::exit(1); }
            cmd_list(&args[2]);
        }
        "info" | "i" => {
            if args.len() < 3 { eprintln!("Usage: nxpkg info <nxp>"); process::exit(1); }
            cmd_info(&args[2]);
        }
        "verify" | "v" => {
            if args.len() < 3 { eprintln!("Usage: nxpkg verify <nxp>"); process::exit(1); }
            cmd_verify(&args[2]);
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            process::exit(1);
        }
    }
}

fn crc32_calc(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc = CRC32_TABLE[((crc as u8) ^ byte) as usize] ^ (crc >> 8);
    }
    !crc
}

fn make_tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + value.len());
    let mut tag_padded = [0u8; 4];
    let copy_len = tag.len().min(4);
    tag_padded[..copy_len].copy_from_slice(&tag[..copy_len]);
    buf.extend_from_slice(&tag_padded);
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
    buf
}

// ── Create ─────────────────────────────────────────────────────────

fn cmd_create(dir: &str, output: &str) {
    let dir_path = Path::new(dir);
    if !dir_path.is_dir() {
        eprintln!("Error: {} is not a directory", dir);
        process::exit(1);
    }

    let mut entries = Vec::new();
    collect_entries(dir_path, dir_path, "", &mut entries);

    if entries.is_empty() {
        eprintln!("Error: no files found in {}", dir);
        process::exit(1);
    }

    let mut meta_name = String::new();
    let mut meta_ver = String::new();
    let mut meta_desc = String::new();

    let manifest_path = dir_path.join("neopkg.toml");
    if manifest_path.exists() {
        if let Ok(content) = fs::read_to_string(&manifest_path) {
            for line in content.lines() {
                if let Some(val) = line.trim().strip_prefix("name = \"") {
                    meta_name = val.trim_end_matches('"').to_string();
                } else if let Some(val) = line.trim().strip_prefix("version = \"") {
                    meta_ver = val.trim_end_matches('"').to_string();
                } else if let Some(val) = line.trim().strip_prefix("description = \"") {
                    meta_desc = val.trim_end_matches('"').to_string();
                }
            }
        }
    }

    if meta_name.is_empty() {
        meta_name = dir_path.file_name().unwrap().to_string_lossy().to_string();
    }
    if meta_ver.is_empty() {
        meta_ver = "1.0.0".to_string();
    }

    // Build manifest TLV
    let mut manifest = Vec::new();
    manifest.extend_from_slice(&make_tlv(b"NAME", meta_name.as_bytes()));
    manifest.extend_from_slice(&make_tlv(b"VER ", meta_ver.as_bytes()));
    if !meta_desc.is_empty() {
        manifest.extend_from_slice(&make_tlv(b"DESC", meta_desc.as_bytes()));
    }
    manifest.extend_from_slice(&make_tlv(b"ARCH", b"x86_64"));

    // Build string pool (null-terminated paths)
    let mut str_pool = Vec::new();
    let mut str_offsets = Vec::new();
    for entry in &entries {
        str_offsets.push(str_pool.len() as u32);
        str_pool.extend_from_slice(entry.relative_path.as_bytes());
        str_pool.push(0);
    }

    // Build file entry table (32 bytes per entry)
    let entry_count = entries.len() as u32;
    let mut file_table = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        file_table.extend_from_slice(&str_offsets[i].to_le_bytes()); // path_offset
        file_table.extend_from_slice(&0u32.to_le_bytes()); // data_offset (placeholder)
        file_table.extend_from_slice(&(entry.content.len() as u32).to_le_bytes()); // data_size
        file_table.extend_from_slice(&crc32_calc(&entry.content).to_le_bytes()); // crc32
        let flags = if entry.relative_path.ends_with(".nxe") || entry.relative_path.ends_with(".nxl") {
            1u32 // EXECUTABLE
        } else if entry.relative_path.contains("locale") {
            4u32 // LOCALE
        } else if entry.relative_path.contains("config") || entry.relative_path.contains(".ini") || entry.relative_path.contains(".toml") {
            2u32 // CONFIG
        } else { 0u32 };
        file_table.extend_from_slice(&flags.to_le_bytes());
        file_table.extend_from_slice(&0u32.to_le_bytes()); // mode (reserved)
        file_table.extend_from_slice(&0u32.to_le_bytes()); // reserved
        file_table.extend_from_slice(&0u32.to_le_bytes()); // reserved
    }

    // Calculate offsets
    let header_size = 32u32;
    let manifest_off = header_size;
    let manifest_sz = manifest.len() as u32;
    let file_table_off = manifest_off + manifest_sz;
    let file_table_sz = file_table.len() as u32;
    let str_pool_off = file_table_off + file_table_sz;
    let str_pool_sz = str_pool.len() as u32;
    let data_off = str_pool_off + str_pool_sz;

    // Fill data offsets in file table
    let mut current_data_off = data_off;
    for i in 0..entries.len() {
        let entry_offset = i * 32 + 4; // data_offset is at byte 4 of each 32-byte entry
        file_table[entry_offset..entry_offset + 4].copy_from_slice(&current_data_off.to_le_bytes());
        current_data_off += entries[i].content.len() as u32;
    }

    // Build header
    let mut header = Vec::with_capacity(32);
    header.extend_from_slice(&MAGIC_NXP1.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // header_crc32 (placeholder)
    header.extend_from_slice(&1u16.to_le_bytes()); // version_major
    header.extend_from_slice(&0u16.to_le_bytes()); // version_minor
    header.extend_from_slice(&0u32.to_le_bytes()); // flags
    header.extend_from_slice(&manifest_off.to_le_bytes());
    header.extend_from_slice(&manifest_sz.to_le_bytes());
    header.extend_from_slice(&entry_count.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // signature_offset

    let hdr_crc = crc32_calc(&header[8..]);
    header[4..8].copy_from_slice(&hdr_crc.to_le_bytes());

    // Write output file
    let mut out = Vec::new();
    out.extend_from_slice(&header);
    out.extend_from_slice(&manifest);
    out.extend_from_slice(&file_table);
    out.extend_from_slice(&str_pool);

    for entry in &entries {
        out.extend_from_slice(&entry.content);
    }

    if let Err(e) = fs::write(output, &out) {
        eprintln!("Error writing {}: {}", output, e);
        process::exit(1);
    }

    let size_str = if out.len() < 1024 {
        format!("{} B", out.len())
    } else if out.len() < 1024 * 1024 {
        format!("{:.1} KB", out.len() as f64 / 1024.0)
    } else {
        format!("{:.1} MB", out.len() as f64 / (1024.0 * 1024.0))
    };

    println!("Created {} ({} files, {})", output, entries.len(), size_str);
}

// ── Extract ────────────────────────────────────────────────────────

fn cmd_extract(input: &str, output_dir: &str) {
    let data = read_file(input);
    let parsed = parse_nxp(&data);
    fs::create_dir_all(output_dir).unwrap_or_else(|e| {
        eprintln!("Error creating dir {}: {}", output_dir, e);
        process::exit(1);
    });

    for entry in &parsed.entries {
        let path = Path::new(output_dir).join(&entry.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| {
                eprintln!("Error creating dir {}: {}", parent.display(), e);
                process::exit(1);
            });
        }
        if let Err(e) = fs::write(&path, &entry.data) {
            eprintln!("Error writing {}: {}", path.display(), e);
            process::exit(1);
        }
    }

    let manifest_path = Path::new(output_dir).join("neopkg.toml");
    let mut manifest_str = String::new();
    manifest_str.push_str(&format!("name = \"{}\"\n", parsed.name));
    manifest_str.push_str(&format!("version = \"{}\"\n", parsed.version));
    if !parsed.description.is_empty() {
        manifest_str.push_str(&format!("description = \"{}\"\n", parsed.description));
    }
    if let Err(e) = fs::write(&manifest_path, &manifest_str) {
        eprintln!("Warning: could not write manifest: {}", e);
    }

    println!("Extracted {} files to {}", parsed.entries.len(), output_dir);
}

// ── List ───────────────────────────────────────────────────────────

fn cmd_list(input: &str) {
    let data = read_file(input);
    let parsed = parse_nxp(&data);

    println!("Package: {} v{}", parsed.name, parsed.version);
    if !parsed.description.is_empty() {
        println!("Description: {}", parsed.description);
    }
    println!();
    println!("{:<40} {:>10} {}", "Path", "Size", "CRC32");
    println!("{}", "-".repeat(65));
    for entry in &parsed.entries {
        let size_str = if entry.data.len() < 1024 {
            format!("{} B", entry.data.len())
        } else if entry.data.len() < 1024 * 1024 {
            format!("{:.1} KB", entry.data.len() as f64 / 1024.0)
        } else {
            format!("{:.1} MB", entry.data.len() as f64 / (1024.0 * 1024.0))
        };
        println!("{:<40} {:>10} {:08x}", entry.path, size_str, entry.crc32);
    }
}

// ── Info ───────────────────────────────────────────────────────────

fn cmd_info(input: &str) {
    let data = read_file(input);
    let parsed = parse_nxp(&data);

    println!("NXE Package Info");
    println!("  Name:        {}", parsed.name);
    println!("  Version:     {}", parsed.version);
    if !parsed.description.is_empty() {
        println!("  Description: {}", parsed.description);
    }
    println!("  Entries:     {}", parsed.entries.len());
    println!("  Format:      NXP1 v{}.{}", parsed.ver_major, parsed.ver_minor);
    println!("  File size:   {} B", data.len());
    let total_data: usize = parsed.entries.iter().map(|e| e.data.len()).sum();
    println!("  Data size:   {} B ({} overhead)", total_data, data.len() - total_data);
    println!("  Header CRC:  {:08x}", parsed.header_crc);
    println!("  Signed:      {}", if parsed.flags & 1 != 0 { "yes" } else { "no" });
}

// ── Verify ─────────────────────────────────────────────────────────

fn cmd_verify(input: &str) {
    let data = read_file(input);
    let parsed = parse_nxp(&data);

    let hdr_crc = crc32_calc(&data[8..32]);
    if hdr_crc != parsed.header_crc {
        eprintln!("ERROR: Header CRC mismatch (expected {:08x}, got {:08x})", parsed.header_crc, hdr_crc);
        process::exit(1);
    }

    let mut all_ok = true;
    for entry in &parsed.entries {
        let actual_crc = crc32_calc(&entry.data);
        if actual_crc != entry.crc32 {
            eprintln!("ERROR: CRC32 mismatch for '{}' (expected {:08x}, got {:08x})",
                entry.path, entry.crc32, actual_crc);
            all_ok = false;
        }
    }

    if all_ok {
        println!("{}: VALID — {} entries, all CRC32 match", input, parsed.entries.len());
    } else {
        process::exit(1);
    }
}

// ── Shared structures ─────────────────────────────────────────────

struct FileEntry {
    relative_path: String,
    content: Vec<u8>,
}

struct ParsedEntry {
    path: String,
    data: Vec<u8>,
    crc32: u32,
}

struct ParsedNxp {
    name: String,
    version: String,
    description: String,
    ver_major: u16,
    ver_minor: u16,
    flags: u32,
    header_crc: u32,
    entries: Vec<ParsedEntry>,
}

// ── File walker ───────────────────────────────────────────────────

fn collect_entries(base: &Path, dir: &Path, prefix: &str, entries: &mut Vec<FileEntry>) {
    if let Ok(rd) = fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let rel = if prefix.is_empty() { name.clone() } else { format!("{}/{}", prefix, name) };

            if name.starts_with('.') || name == "neopkg.toml" { continue; }

            if path.is_dir() {
                collect_entries(base, &path, &rel, entries);
            } else if path.is_file() {
                if let Ok(content) = fs::read(&path) {
                    entries.push(FileEntry {
                        relative_path: rel,
                        content,
                    });
                }
            }
        }
    }
}

// ── NXP parser ───────────────────────────────────────────────────

fn parse_nxp(data: &[u8]) -> ParsedNxp {
    if data.len() < 32 {
        eprintln!("File too small for NXP header");
        process::exit(1);
    }

    let magic = read_u32(data, 0);
    if magic != MAGIC_NXP1 {
        eprintln!("Not a valid NXP file (bad magic: {:08x})", magic);
        process::exit(1);
    }

    let header_crc = read_u32(data, 4);
    let ver_major = read_u16(data, 8);
    let ver_minor = read_u16(data, 10);
    let flags = read_u32(data, 12);
    let manifest_off = read_u32(data, 16) as usize;
    let manifest_sz = read_u32(data, 20) as usize;
    let entry_count = read_u32(data, 24) as usize;

    if manifest_off + manifest_sz > data.len() {
        eprintln!("Manifest extends beyond file");
        process::exit(1);
    }

    let manifest = &data[manifest_off..manifest_off + manifest_sz];

    let mut name = String::new();
    let mut version = String::new();
    let mut description = String::new();

    let mut pos = 0;
    while pos + 8 <= manifest.len() {
        let tag = &manifest[pos..pos + 4];
        let length = read_u32(manifest, pos + 4) as usize;
        pos += 8;
        if pos + length > manifest.len() { break; }
        let value = String::from_utf8_lossy(&manifest[pos..pos + length]).to_string();
        if tag == b"NAME" {
            name = value;
        } else if tag == b"VER " {
            version = value;
        } else if tag == b"DESC" {
            description = value;
        }
        pos += length;
    }

    let file_table_off = manifest_off + manifest_sz;
    let entry_sz = 32;
    let file_table_end = file_table_off + entry_count * entry_sz;

    if file_table_end > data.len() {
        eprintln!("File table extends beyond file");
        process::exit(1);
    }

    let mut entries = Vec::new();

    for i in 0..entry_count {
        let entry_off = file_table_off + i * entry_sz;
        let path_off = read_u32(data, entry_off) as usize;
        let data_off = read_u32(data, entry_off + 4) as usize;
        let data_sz = read_u32(data, entry_off + 8) as usize;
        let entry_crc = read_u32(data, entry_off + 12);

        let str_pool_start = file_table_off + entry_count * entry_sz;
        let path = get_str_at(&data[str_pool_start..], path_off);

        if data_off + data_sz > data.len() {
            eprintln!("Entry '{}' data extends beyond file", path);
            process::exit(1);
        }

        entries.push(ParsedEntry {
            path,
            data: data[data_off..data_off + data_sz].to_vec(),
            crc32: entry_crc,
        });
    }

    ParsedNxp {
        name,
        version,
        description,
        ver_major,
        ver_minor,
        flags,
        header_crc,
        entries,
    }
}

// ── Utilities ─────────────────────────────────────────────────────

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_file(path: &str) -> Vec<u8> {
    match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", path, e);
            process::exit(1);
        }
    }
}

fn get_str_at(pool: &[u8], offset: usize) -> String {
    let mut s = String::new();
    let mut i = offset;
    while i < pool.len() && pool[i] != 0 {
        if pool[i].is_ascii() {
            s.push(pool[i] as char);
        } else {
            s.push('\u{FFFD}');
        }
        i += 1;
    }
    s
}
