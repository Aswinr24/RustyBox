use log::{debug, error, info};
use r2pipe::R2Pipe;

/// Use Radare2's native decompiler (pdd) and return the decompiled output as a String
pub fn decompile_binary(
    file_path: &str,
    verbose: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    info!("Starting decompilation of {file_path}");

    // Initialize radare2 instance
    let mut r2 = match R2Pipe::spawn(file_path, None) {
        Ok(r2) => {
            debug!("Successfully spawned r2pipe instance for decompilation");
            r2
        }
        Err(e) => {
            error!("Failed to spawn r2pipe: {e}");
            return Err(e.into());
        }
    };

    // Configure radare2 based on verbosity
    if verbose {
        debug!("Configuring radare2 in verbose mode for decompilation");
        r2.cmd("e log.quiet = false")?;
    } else {
        debug!("Configuring radare2 in quiet mode for decompilation");
        r2.cmd("e log.quiet = true")?;
        r2.cmd("e asm.quiet = true")?;
        r2.cmd("e bin.relocs.apply = true")?; // Reduce warnings in quiet mode
    }

    // Common configurations
    r2.cmd("e scr.utf8 = false")?;
    r2.cmd("e scr.interactive = false")?;
    r2.cmd("e bin.cache = true")?;
    debug!("Applied standard radare2 configurations");

    // Perform analysis
    info!("Performing initial analysis (aaa)");
    match r2.cmd("aaa") {
        Ok(_) => debug!("Analysis completed successfully"),
        Err(e) => {
            error!("Analysis failed during decompilation: {e}");
            return Err(e.into());
        }
    }

    // Run decompiler command
    debug!("Running decompiler command: pdd");
    let decompiled_code = match r2.cmd("pdd") {
        Ok(code) => {
            debug!("Decompiled code retrieved ({} bytes)", code.len());
            code
        }
        Err(e) => {
            error!("Decompiler command failed: {e}");
            return Err(e.into());
        }
    };

    // Clean up
    r2.close();
    debug!("r2pipe closed after decompilation");

    info!("Decompilation completed successfully");
    Ok(decompiled_code)
}
