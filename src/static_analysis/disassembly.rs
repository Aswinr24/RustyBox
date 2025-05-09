use log::{debug, info};
use r2pipe::R2Pipe;
use serde_json::Value;

pub fn disassemble_binary(
    file_path: &str,
    count: u32,
    verbose: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    info!("Starting disassembly of {file_path} ({count} instructions)");

    // Initialize radare2 with appropriate verbosity
    let mut r2 = R2Pipe::spawn(file_path, None)?;

    // Configure radare2 based on verbosity
    if verbose {
        debug!("Running radare2 in verbose mode");
        r2.cmd("e log.quiet = false")?;
        r2.cmd("e asm.quiet = false")?;
    } else {
        debug!("Running radare2 in quiet mode");
        r2.cmd("e log.quiet = true")?;
        r2.cmd("e asm.quiet = true")?;
        r2.cmd("e bin.relocs.apply = true")?; // Fix the relocation warning
    }

    // Common configurations
    r2.cmd("e scr.utf8 = false")?;
    r2.cmd("e scr.interactive = false")?;
    r2.cmd("e bin.cache = true")?;

    // Perform analysis
    let analysis_cmd = if verbose { "aaa" } else { "aaa" }; // Can adjust analysis level
    debug!("Running analysis: {analysis_cmd}");
    r2.cmd(analysis_cmd)?;

    // Generate disassembly
    let command = format!("pdj {count}");
    debug!("Executing command: {command}");
    let json_output = r2.cmd(&command)?;

    // Parse and format output
    let instructions: Vec<Value> = serde_json::from_str(&json_output)?;
    let mut output = String::new();
    for instr in instructions {
        let offset = instr["offset"].as_u64().unwrap_or(0);
        let mnemonic = instr["mnemonic"].as_str().unwrap_or("");
        let opcode = instr["opcode"].as_str().unwrap_or("");
        output.push_str(&format!("{offset:#x}:\t{mnemonic}\t{opcode}\n"));
    }

    r2.close();
    Ok(output)
}
