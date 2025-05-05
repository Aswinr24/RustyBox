use r2pipe::R2Pipe;
use serde_json::Value;

/// Disassemble the binary and return disassembly of `count` instructions as a String
pub fn disassemble_binary(file_path: &str, count: u32) -> Result<String, Box<dyn std::error::Error>> {
    let mut r2 = R2Pipe::spawn(file_path, None)?;
    r2.cmd("aaa")?; // Analyze everything

    let command = format!("pdj {}", count);
    let json_output = r2.cmd(&command)?;
    let instructions: Vec<Value> = serde_json::from_str(&json_output)?;

    let mut disassembly_output = String::new();
    for instr in instructions {
        let offset = instr["offset"].as_u64().unwrap_or(0);
        let mnemonic = instr["mnemonic"].as_str().unwrap_or("");
        let opcode = instr["opcode"].as_str().unwrap_or("");
        disassembly_output.push_str(&format!("{:#x}:\t{}\t{}\n", offset, mnemonic, opcode));
    }

    r2.close();
    Ok(disassembly_output)
}
