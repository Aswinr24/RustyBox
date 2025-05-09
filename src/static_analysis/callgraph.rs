use std::fs;
use std::process::{Command, Stdio};
use std::path::Path;
use std::io::Write;

pub fn analyze_callgraph(binary_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let dot_path = "callgraph.dot";

    // Step 1: Run radare2 and capture DOT callgraph output
    let output = Command::new("r2")
        .args(["-Aqc", "e bin.relocs.apply=true; e bin.cache=true; aa; agfd", binary_path])
        .stdout(Stdio::piped())
        .output()?;

    if !output.status.success() {
        return Err("Failed to generate callgraph using radare2".into());
    }

    // Write output to DOT file
    fs::write(dot_path, &output.stdout)?;

    // Step 2: Convert DOT to ASCII using graph-easy
    let graph_output = Command::new("graph-easy")
        .arg(dot_path)
        .stdout(Stdio::piped())
        .output()?;

    // Cleanup DOT file
    fs::remove_file(dot_path).ok();

    if graph_output.status.success() {
        let ascii_graph = String::from_utf8_lossy(&graph_output.stdout).to_string();
        Ok(ascii_graph)
    } else {
        let err_msg = String::from_utf8_lossy(&graph_output.stderr).to_string();
        Err(format!(
            "graph-easy error:\n{}\nHint: Install it using `cpanm Graph::Easy`",
            err_msg
        )
        .into())
    }
}
