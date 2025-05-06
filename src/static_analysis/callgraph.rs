use std::fs;
use std::process::{Command, Stdio};
use std::path::Path;

pub fn analyze_callgraph(binary_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let dot_path = "callgraph.dot";

    // Step 1: Run radare2 to analyze and export the call graph in DOT format
    let r2_command = format!("e bin.relocs.apply=true; e bin.cache=true; aa; agfd > {}", dot_path);
    let status = Command::new("r2")
        .args(["-Aqc", &r2_command, binary_path])
        .status()?;

    if !status.success() {
        return Err("Failed to generate callgraph.dot using radare2".into());
    }

    if !Path::new(dot_path).exists() {
        return Err("DOT file not found after radare2 run".into());
    }

    // Step 2: Convert DOT to ASCII using graph-easy
    let output = Command::new("graph-easy")
        .arg(dot_path)
        .stdout(Stdio::piped())
        .output()?;

    // Cleanup DOT file regardless of result
    fs::remove_file(dot_path).ok();

    if output.status.success() {
        let ascii_graph = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(ascii_graph)
    } else {
        let err_msg = String::from_utf8_lossy(&output.stderr).to_string();
        Err(format!(
            "graph-easy error:\n{}\nHint: Install it using `cpanm Graph::Easy`",
            err_msg
        )
        .into())
    }
}
