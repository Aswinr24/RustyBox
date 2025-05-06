use goblin::Object;
use std::fs;

#[derive(Debug)]
pub struct BinaryMetadata {
    pub format: String,
    pub entry_point: Option<u64>,
    pub sections: Option<usize>,
    pub program_headers: Option<usize>,
    pub machine: Option<String>,
    pub image_base: Option<u64>,
    pub is_64: Option<bool>,
    pub load_commands: Option<u32>,
    pub cpu_type: Option<String>,
    pub arch_count: Option<usize>,
}

pub fn extract_metadata(file_path: &str) -> Result<BinaryMetadata, Box<dyn std::error::Error>> {
    let buffer = fs::read(file_path)?;
    let mut metadata = BinaryMetadata {
        format: String::new(),
        entry_point: None,
        sections: None,
        program_headers: None,
        machine: None,
        image_base: None,
        is_64: None,
        load_commands: None,
        cpu_type: None,
        arch_count: None,
    };

    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            metadata.format = "ELF".to_string();
            metadata.entry_point = Some(elf.entry);
            metadata.sections = Some(elf.section_headers.len());
            metadata.program_headers = Some(elf.program_headers.len());
            metadata.machine = Some(format!("{:?}", elf.header.e_machine));
        }
        Object::PE(pe) => {
            metadata.format = "PE".to_string();
            metadata.entry_point = Some(pe.entry);
            metadata.sections = Some(pe.sections.len());
            metadata.image_base = Some(pe.image_base);
            metadata.machine = Some(format!("{:?}", pe.header.coff_header.machine));
        }
        Object::Mach(mach_obj) => {
            metadata.format = "Mach-O".to_string();
            match mach_obj {
                goblin::mach::Mach::Binary(macho) => {
                    metadata.is_64 = Some(macho.is_64);
                    metadata.load_commands = Some(macho.header.ncmds);
                    metadata.cpu_type = Some(format!("{:?}", macho.header.cputype));
                }
                goblin::mach::Mach::Fat(fat) => {
                    metadata.arch_count = Some(fat.narches);
                }
            }
        }
        _ => {
            metadata.format = "Unknown".to_string();
        }
    }

    Ok(metadata)
}
