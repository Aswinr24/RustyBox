#![allow(dead_code)]
#![allow(unused_imports)]


use goblin::{
    elf::{Elf,dynamic::*},
    mach::{Mach},
    pe::PE,
    Object,
};
use std::fs::File;
use std::io::Read;
use std::{fs, error::Error};
use std::path::Path;
use gimli::{
      DebugAbbrev, DebugInfo, DebugLine, DebugStr, EndianSlice, LittleEndian, 
      DwTag
};

use owo_colors::OwoColorize;
use prettytable::{Table, Row, Cell};




pub fn analyze_binary(path: &str) -> Result<(), Box<dyn Error>> {
    let buffer = fs::read(path)?;
    let file_size = buffer.len() as u64;

    match Object::parse(&buffer)? {
        Object::PE(pe) => analyze_pe(&pe, &buffer, file_size),
        Object::Elf(elf) => analyze_elf(&elf, &buffer),
        _ => println!("Unsupported or unrecognized binary format"),
    }

    Ok(())
}

fn analyze_pe(pe: &PE, buffer: &[u8], file_size: u64) {
    println!("\n\n\n\n{:^120}","+++++++++++++++🔍 Detected PE (Windows) format+++++++++++++++".green().bold());
    println!("\n\n{} 0x{:x}","🚀 Entry Point: ".red().bold(), pe.entry);

    analyze_sections(pe, buffer);
    analyze_imports(pe);
    analyze_exports(pe);
    analyze_tls(pe);
    analyze_debug(pe);
    analyze_cert_table(pe);
    detect_overlay(pe, file_size);
    check_anti_debug(pe, buffer);
    calculate_entropy(buffer);
    
    // Try parsing the same buffer as ELF
    if let Ok(elf) = Elf::parse(buffer) {
        println!("\n--- Trying ELF analysis ---");
        analyze_elf(&elf, &buffer);
    } else {
        println!("❌ Not a valid ELF file.");
    }
}

//these are PE Binary Parsing Techniques

fn analyze_sections(pe: &PE, buffer: &[u8]) {
    println!("{}","\n\n📦 Sections:".red().bold());
    
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Name"),
        Cell::new("Virtual Address"),
        Cell::new("Virtual Size"),
        Cell::new("Permissions"),
        Cell::new("Entropy"),
    ]));



    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name).trim().to_string();
        let va = section.virtual_address;
        let size = section.virtual_size;
        let perms = format!(
            "{}{}{}",
            if section.characteristics & 0x20000000 != 0 { "X" } else { "-" },
            if section.characteristics & 0x80000000 != 0 { "W" } else { "-" },
            if section.characteristics & 0x40000000 != 0 { "R" } else { "-" }
        );

        let start = section.pointer_to_raw_data as usize;
        let end = start + section.size_of_raw_data as usize;
        let data = if end <= buffer.len() { &buffer[start..end] } else { &[] };
        let entropy = calculate_entropy(data);

        table.add_row(Row::new(vec![
            Cell::new(&name),
            Cell::new(&format!("0x{:08x}", va)),
            Cell::new(&format!("0x{:08x}", size)),
            Cell::new(&perms),
            Cell::new(&format!("{:.2}", entropy)),
        ]));
    }
    table.printstd();
}

fn analyze_imports(pe: &PE) {
    println!("{}","\n\n🔗 Imported DLLs & Functions :".red().bold());
    
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("DLL"),
        Cell::new("Function"),
        Cell::new("Ordinal"),
    ]));


    for import in &pe.imports {
        table.add_row(Row::new(vec![
            Cell::new(&import.dll),
            Cell::new(&import.name),
            Cell::new(&format!("{}", import.ordinal)),
        ]));
    }
    table.printstd();
}

fn analyze_exports(pe: &PE) {
    println!("{}","\n\n📤 Exported Symbols :".red().bold());
    
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Function"),
        Cell::new("RVA"),
    ]));

    for export in &pe.exports {
        let name = export.name.unwrap_or("<none>");
        table.add_row(Row::new(vec![
            Cell::new(name),
            Cell::new(&format!("0x{:x}", export.rva)),
        ]));
    }
    table.printstd();
}



fn analyze_tls(pe: &PE) {
    println!("{}","\n\n🧵 TLS Callback RVA :".red().bold());

    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Virtual Address"),
        Cell::new("Size"),
        ]));

    if let Some(optional_header) = &pe.header.optional_header {
        if let Some(tls_dir) = optional_header.data_directories.get_tls_table() {
            table.add_row(Row::new(vec![
                Cell::new(&format!("0x{:x}", tls_dir.virtual_address)),
                Cell::new(&format!("{}", tls_dir.size)),
            ]));
        } else {
            println!(" - No TLS table.");
        }
    }
    table.printstd();
}



fn analyze_debug(pe: &PE) {
    println!("{}","\n\n🐞 Debug Directory :".red().bold());
    if let Some(debug_data) = &pe.debug_data {
        if let Some(pdb_info) = &debug_data.codeview_pdb70_debug_info {
            let mut table = Table::new();
            table.add_row(Row::new(vec![
                Cell::new("Field"),
                Cell::new("Value"),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("PDB Signature"),
                Cell::new(&format!("{:?}", pdb_info.signature)),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("PDB Age"),
                Cell::new(&pdb_info.age.to_string()),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("PDB Path"),
                Cell::new(&String::from_utf8_lossy(&pdb_info.filename)),
            ]));

            table.printstd();

        } else {
            println!(" - No CodeView PDB 7.0 debug info.");
        }
    } else {
        println!(" - No debug data found.");
    }
}

fn analyze_cert_table(pe: &PE) {
    println!("{}","\n\n📜 Certificate Table :".red().bold());
    if let Some(optional_header) = &pe.header.optional_header {
        if let Some(cert_dir) = optional_header.data_directories.get_certificate_table() {
            let mut table = Table::new();
            table.add_row(Row::new(vec![
                Cell::new("Field"),
                Cell::new("Value"),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("Virtual Address"),
                Cell::new(&format!("0x{:x}", cert_dir.virtual_address)),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("Size"),
                Cell::new(&cert_dir.size.to_string()),
            ]));

            table.printstd();
        } else {
            println!(" - No certificate table found.");
        }
    }
}



fn detect_overlay(pe: &PE, file_size: u64) {

    

    let last_section_end = pe.sections.iter()
        .map(|s| s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64)
        .max()
        .unwrap_or(0);

    if last_section_end < file_size {
        println!("{}", "\n\n⚠️ Overlay Detected :".red().bold());

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Field"),
            Cell::new("Value"),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Hidden Data Size"),
            Cell::new(&format!("{} bytes", file_size - last_section_end)),
        ]));

        table.printstd();
    }
}



fn check_anti_debug(_pe: &PE, buffer: &[u8]) {
    println!("{}","\n\n🕵️ Anti-Debugging Techniques :".red().bold());
    let suspicious_bytes: &[&[u8]] = &[
        &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00], // FS:[30h] — PEB access
        &[0xCC],                              // INT 3 (breakpoint)
    ];

    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Signature").style_spec("Fb"), // Fb = Bold font
        Cell::new("Detected").style_spec("Fb"),
    ]));

    let  flags = 0;

    let mut found_any = false;

    for sig in suspicious_bytes {
        let found = buffer.windows(sig.len()).any(|w| w == *sig);
        table.add_row(Row::new(vec![
            Cell::new(&format!("{:?}", sig)),
            Cell::new(if found {
                found_any = true;
                "✔️"
            } else {
                "❌"
            }),
        ]));
    }
    table.printstd();

    if flags == 0 {
        println!(" - No obvious anti-debugging signs.");
    }
}



fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count == 0 { continue; }
        let p = count as f64 / len;
        entropy += -p * p.log2();
    }
    entropy
}



fn analyze_elf(elf: &Elf, bytes: &[u8]) {
    println!("\n\n\n\n{:^120}","+++++++++++++++🔍 Analyzing ELF Binary +++++++++++++++".green().bold());
    // Entry point address
    println!("\n\n{} 0x{:x}","🚀 Entry Point: ".red().bold(), elf.entry);
    analyze_elf_imports(elf);
    analyze_elf_exports(elf);
    parse_elf_header(bytes);
    parse_program_headers(bytes);
    parse_section_headers(bytes);
    parse_symbol_tables(bytes);
    parse_string_tables(bytes);
    parse_relocations(bytes);
    parse_dynamic_section(bytes);
    parse_hash_tables(bytes);
    parse_notes(bytes);
    parse_versioning_sections(bytes);
    parse_and_print_dwarf_functions(bytes).unwrap_or_else(|_| {
        println!("Failed to parse DWARF functions.");
    });
}


//these are ELF Binary Parsing Techniques


type Endian = LittleEndian;
type ReaderType<'a> = EndianSlice<'a, Endian>;

// Helper to extract section contents
fn get_section<'a>(
    bytes: &'a [u8],
    elf: &Elf,
    section_name: &str,
) -> Result<&'a [u8], Box<dyn Error>> {
    for header in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
            if name == section_name {
                let start = header.sh_offset as usize;
                let end = start + header.sh_size as usize;
                return Ok(&bytes[start..end]);
            }
        }
    }
    Err(format!("Section {} not found", section_name).into())
}



fn analyze_elf_imports(elf: &Elf) {
    println!("{}","\n\n🔗 Imported Shared Libraries:".red().bold());

    if let Some(dynamic) = &elf.dynamic {
        for dyn_ in &dynamic.dyns {
            if dyn_.d_tag == goblin::elf::dynamic::DT_NEEDED {
                if let Some(name) = elf.dynstrtab.get_at(dyn_.d_val as usize)  {
                    println!("   - {}", name);
                }
            }
        }
    }
}




fn analyze_elf_exports(elf: &Elf) {
    println!("{}","\n\n📤 Exported Symbols:".red().bold());

    let mut table = Table::new();

    // Add the headers
    table.add_row(Row::new(vec![
        Cell::new("Name"),
        Cell::new("Address"),
        Cell::new("Type"),
        Cell::new("Bind"),
    ]));

    for sym in &elf.dynsyms {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("<unnamed>");
        let bind = sym.st_bind();
        let typ = sym.st_type();

        // Typically exported: global binding & function/object type
        if bind == goblin::elf::sym::STB_GLOBAL && (typ == goblin::elf::sym::STT_FUNC || typ == goblin::elf::sym::STT_OBJECT) {
            table.add_row(Row::new(vec![
                Cell::new(name),
                Cell::new(&format!("0x{:x}", sym.st_value)),
                Cell::new(&format!("{:?}", typ)),
                Cell::new(&format!("{:?}", bind)),
            ]));
        }
    }
    // Print the table
    table.printstd();
}



fn parse_elf_header(bytes: &[u8]) {


    let mut table = Table::new();

        // Add headers to the table
        table.add_row(Row::new(vec![
            Cell::new("Type"),
            Cell::new("Machine"),
            Cell::new("Entry point"),
            Cell::new("Program header offset"),
            Cell::new("Section header offset"),
        ]));


    if let Ok(elf) = Elf::parse(bytes) {
        table.add_row(Row::new(vec![
            Cell::new(&format!("{:?}", elf.header.e_type)),
            Cell::new(&format!("{:?}", elf.header.e_machine)),
            Cell::new(&format!("0x{:x}", elf.entry)),
            Cell::new(&format!("{}", elf.header.e_phoff)),
            Cell::new(&format!("{}", elf.header.e_shoff)),
        ]));
    }
    println!("{}","\n\n⚙️ ELF Header :".red().bold());
    // Print the table
    table.printstd();
}

fn parse_program_headers(bytes: &[u8]) {
    if let Ok(elf) = Elf::parse(bytes) {
        println!("{}","\n\n⚙️ Program Headers :".red().bold());

        let mut table = Table::new();

        // Add headers to the table
        table.add_row(Row::new(vec![
            Cell::new("Type"),
            Cell::new("Offset"),
            Cell::new("VAddr"),
            Cell::new("PAddr"),
            Cell::new("Filesz"),
            Cell::new("Memsz"),
            Cell::new("Flags"),
        ]));

        for ph in &elf.program_headers {
            
            table.add_row(Row::new(vec![
                Cell::new(&format!("{:?}", ph.p_type)),
                Cell::new(&format!("{}", ph.p_offset)),
                Cell::new(&format!("0x{:x}", ph.p_vaddr)),
                Cell::new(&format!("0x{:x}", ph.p_paddr)),
                Cell::new(&format!("{}", ph.p_filesz)),
                Cell::new(&format!("{}", ph.p_memsz)),
                Cell::new(&format!("{:?}", ph.p_flags)),
            ]));
        }

        // Print the table
        table.printstd();
    }
}

fn parse_section_headers(bytes: &[u8]) {
    if let Ok(elf) = Elf::parse(bytes) {
        println!("{}","\n\n📦 Sections :".red().bold());

        let mut table = Table::new();

        // Add headers
        table.add_row(Row::new(vec![
            Cell::new("Index"),
            Cell::new("Name"),
            Cell::new("Offset"),
            Cell::new("Size"),
            Cell::new("Flags"),
            Cell::new("Entropy"),
        ]));

        for (i, section) in elf.section_headers.iter().enumerate() {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;

                // Calculate entropy if section data is in bounds
                let entropy = if end <= bytes.len() {
                    calculate_entropy(&bytes[start..end])
                } else {
                    0.0
                };

                table.add_row(Row::new(vec![
                    Cell::new(&i.to_string()),
                    Cell::new(name),
                    Cell::new(&section.sh_offset.to_string()),
                    Cell::new(&section.sh_size.to_string()),
                    Cell::new(&format!("{:?}", section.sh_flags)),
                    Cell::new(&format!("{:.2}", entropy)),
                ]));
            }
        }

        table.printstd();
    }
}


fn parse_symbol_tables(bytes: &[u8]) {
    if let Ok(elf) = Elf::parse(bytes) {
        println!("{}","\n\n📚 Symbol Tables :".red().bold());


        let mut table = Table::new();

        // Add headers
        table.add_row(Row::new(vec![
            Cell::new("Symbol"),
            Cell::new("Address"),
            Cell::new("Size"),
            Cell::new("Bind"),
            Cell::new("Type"),
        ]));

        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                table.add_row(Row::new(vec![
                    Cell::new(name),
                    Cell::new(&format!("0x{:x}", sym.st_value)),
                    Cell::new(&sym.st_size.to_string()),
                    Cell::new(&format!("{:?}", sym.st_bind())),
                    Cell::new(&format!("{:?}", sym.st_type())),
                ]));
            }
        }
        table.printstd();
    }
}

fn parse_string_tables(bytes: &[u8]) {
    if let Ok(elf) = Elf::parse(bytes) {
        println!("{}","\n\n📜 String Tables :".red().bold());
        println!("{}","\n   --strtab Contents :".blue().bold());
        if let Ok(strtab_vec) = elf.strtab.to_vec() {
            let mut table = Table::new();

            // Add header
            table.add_row(Row::new(vec![
                Cell::new("Index"),
                Cell::new("String"),
            ]));

            for (i, s) in strtab_vec.iter().enumerate() {
                table.add_row(Row::new(vec![
                    Cell::new(&i.to_string()),
                    Cell::new(s),
                ]));
            }
            table.printstd();
        } else {
            println!("Failed to parse .strtab");
        }

        println!("{}","\n  --.dynstr Contents :".blue().bold());
        if let Ok(dynstrtab_vec) = elf.dynstrtab.to_vec() {

            let mut table = Table::new();

            // Add header
            table.add_row(Row::new(vec![
                Cell::new("Index"),
                Cell::new("String"),
            ]));


            for (i, s) in dynstrtab_vec.iter().enumerate() {
                table.add_row(Row::new(vec![
                    Cell::new(&i.to_string()),
                    Cell::new(s),
                ]));
            }
            table.printstd();
        } else {
            println!("Failed to parse .dynstrtab");
        }
    }
}




fn parse_relocations(bytes: &[u8]) {
    if let Ok(elf) = Elf::parse(bytes) {
        println!("{}","\n\n📌 Relocation Entries :".red().bold());

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Offset"),
            Cell::new("Type"),
            Cell::new("Symbol Index"),
        ]));

        for rel in elf.dynrelas.iter().chain(elf.dynrels.iter()) {
            table.add_row(Row::new(vec![
                Cell::new(&format!("0x{:x}", rel.r_offset)),
                Cell::new(&rel.r_type.to_string()),
                Cell::new(&rel.r_sym.to_string()),
            ]));
        }
        table.printstd();
    }
}




fn parse_dynamic_section(bytes: &[u8]) {
    if let Ok(elf) = Elf::parse(bytes) {
        println!("{}","\n\n📦 Dynamic Entries :".red().bold());

        if let Some(dyns) = &elf.dynamic {

            
            let mut table = Table::new();
            table.add_row(Row::new(vec![
                Cell::new("Tag"),
                Cell::new("Value / Name"),
            ]));

    

            for dyn_ in dyns.dyns.iter() {
                let row = match dyn_.d_tag {
                    DT_NEEDED => {
                        let name = elf.dynstrtab.get_at(dyn_.d_val as usize)
                            .unwrap_or("<invalid>");
                        Row::new(vec![
                            Cell::new("DT_NEEDED"),
                            Cell::new(name),
                        ])
                    }
                    DT_INIT => Row::new(vec![
                        Cell::new("DT_INIT"),
                        Cell::new(&format!("0x{:x}", dyn_.d_val)),
                    ]),
                    DT_FINI => Row::new(vec![
                        Cell::new("DT_FINI"),
                        Cell::new(&format!("0x{:x}", dyn_.d_val)),
                    ]),
                    _ => continue,
                };
                table.add_row(row);
            }
            table.printstd();
        }
    }
}



fn parse_hash_tables(bytes: &[u8]) {
    if let Ok(elf) = Elf::parse(bytes) {
        println!("{}","\n\n🧮 Hash Sections :".red().bold());

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Section Name"),
            Cell::new("Offset"),
            Cell::new("Size"),
        ]));

        for section in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                if name == ".gnu.hash" || name == ".hash" {
                    table.add_row(Row::new(vec![
                        Cell::new(name),
                        Cell::new(&format!("{}", section.sh_offset)),
                        Cell::new(&format!("{}", section.sh_size)),
                    ]));
                }
            }
        }
        table.printstd();
    }
}



fn parse_notes(bytes: &[u8]) {
    if let Ok(elf) = Elf::parse(bytes) {
        println!("{}","\n\n📝 Note Sections :".red().bold());

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Section Name"),
            Cell::new("Offset"),
            Cell::new("Size"),
        ]));

        for section in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                if name.starts_with(".note") {
                    table.add_row(Row::new(vec![
                        Cell::new(name),
                        Cell::new(&format!("{}", section.sh_offset)),
                        Cell::new(&format!("{}", section.sh_size)),
                    ]));
                }
            }
        }
        table.printstd();
    }
}


fn parse_versioning_sections(bytes: &[u8]) {
    if let Ok(elf) = Elf::parse(bytes) {
        println!("{}","\n\n🧬 Versioning Sections :".red().bold());

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Section Name"),
            Cell::new("Offset"),
            Cell::new("Size"),
        ]));

        for section in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                if name.starts_with(".gnu.version") {
                    table.add_row(Row::new(vec![
                        Cell::new(name),
                        Cell::new(&format!("{}", section.sh_offset)),
                        Cell::new(&format!("{}", section.sh_size)),
                    ]));
                }
            }
        }
        table.printstd();
    }
}


pub fn parse_and_print_dwarf_functions(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let elf = Elf::parse(bytes)?; // Parse ELF file
    let endian = LittleEndian; // Set little endian format

    // Helper to extract a section
    let get_section = |name: &str| -> Result<&[u8], &'static str> {
        for section in &elf.section_headers {
            if let Some(sec_name) = elf.shdr_strtab.get_at(section.sh_name) {
                if sec_name == name {
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    return bytes.get(start..end).ok_or("Section out of bounds");
                }
            }
        }
        Err("Section not found")
    };

    // Load DWARF sections
    let debug_info_data = get_section(".debug_info")?;
    let debug_abbrev_data = get_section(".debug_abbrev")?;
    let debug_str_data = get_section(".debug_str")?;

    let debug_info = DebugInfo::new(debug_info_data, endian);
    let debug_abbrev = DebugAbbrev::new(debug_abbrev_data, endian);
    let debug_str = DebugStr::new(debug_str_data, endian);

    println!("{}","\n\n🐞 Functions in DWARF Debug Info :".red().bold());

    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Function Name"),
        Cell::new("File Index"),
        Cell::new("Line Number"),
    ]));

    // Iterate over Compilation Units (CUs)
    let mut iter = debug_info.units();
    while let Some(header) = iter.next()? {
        

        // Create a Dwarf instance
        let dwarf = gimli::Dwarf {
            debug_info,
            debug_abbrev,
            debug_str,
            debug_line: DebugLine::new(get_section(".debug_line")?, endian),
            ..Default::default() // Fill other fields with default values if not used
        };

        let unit = dwarf.unit(header)?;

        let mut entries = unit.entries(); // Get entries for the CU

        // Iterate over the entries in the current CU
        while let Some((_, entry)) = entries.next_dfs()? {
            if entry.tag() == DwTag(0x2e) /* DW_TAG_subprogram */ {
                let mut name = None;
                let mut file = None;
                let mut line = None;

                // Iterate over the attributes of the entry
                let mut attrs = entry.attrs(); // Get the iterator for the entry's attributes
                while let Some(attr) = attrs.next()? {
                    match attr.name() {
                        gimli::DW_AT_name => {
                            if let Some(val) = attr.string_value(&debug_str) {
                                name = Some(val.to_string_lossy().into_owned());
                            }
                        }
                        gimli::DW_AT_decl_file => {
                            file = attr.udata_value();
                        }
                        gimli::DW_AT_decl_line => {
                            line = attr.udata_value();
                        }
                        _ => {}
                    }
                }

                // If the function name is found, print the result
                if let Some(name) = name {
                    table.add_row(Row::new(vec![
                        Cell::new(&name),
                        Cell::new(&format!("{}", file.unwrap_or(0))),
                        Cell::new(&format!("{}", line.unwrap_or(0))),
                    ]));
                }
            }
        }
    }
     
    table.printstd();
    Ok(())
}
