use std::process::Command;

pub fn run_capa_raw(file_path: &str, output_format: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut cmd = Command::new("capa");
    cmd.arg(file_path);
    
    match output_format {
        "json" => cmd.arg("-j"),
        "vverbose" => cmd.arg("-vv"),
        "verbose" => cmd.arg("-v"),
        _ => cmd.arg("-v"), // default to verbose
    };
    
    let output = cmd.output()?;
    
    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(format!("CAPA analysis failed: {}", error_msg).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    Ok(stdout)
}
