use r2pipe::R2Pipe;

/// Use Radare2's native decompiler (pdd) and return the decompiled output as a String
pub fn decompile_binary(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut r2 = R2Pipe::spawn(file_path, None)?;
    r2.cmd("aaa")?; // Analyze all
    let decompiled_code = r2.cmd("pdd")?; // pdd = pseudo-code decompiler

    r2.close();
    Ok(decompiled_code)
}
