# NeoTools

Host tools for NeoDOS binary analysis and package management.

## Tools

| Tool | Description | Dependencies |
|------|-------------|--------------|
| **nxeinfo** | NXE binary inspector — metadata, headers, sections, JSON output | `serde_json` |
| **nxpkg** | NXP package tool — create, extract, list, info, verify | none |
| **nxdump** | Technical ELF/NXE/NEM dump — hex, elf headers, relocs, strings, segments | none |

## Build

```bash
cargo build --release
```

Binaries at `target/release/{nxeinfo,nxpkg,nxdump}`.

## Usage

```bash
# Inspect an NXE binary
nxeinfo program.nxe
nxeinfo program.nxe --json
nxeinfo program.nxe --check

# Work with NXP packages
nxpkg create my-package/ output.nxp
nxpkg list package.nxp
nxpkg extract package.nxp output-dir/
nxpkg verify package.nxp

# Dump ELF/NXE/NEM files
nxdump binary.elf
nxdump binary.elf --segments
nxdump binary.elf --relocs
nxdump binary.elf --hex
```

## License

MIT — same as NeoDOS.
