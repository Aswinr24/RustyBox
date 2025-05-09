use log::{LevelFilter, info};
use simplelog::{CombinedLogger, TermLogger, WriteLogger, TerminalMode, Config, ColorChoice};
use std::fs::File;
use std::path::Path;

pub fn init_logging(log_file: Option<&Path>, verbose: bool) {
    let log_level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let mut loggers: Vec<Box<dyn simplelog::SharedLogger>> = vec![
        TermLogger::new(
            log_level,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto
        ),
    ];

    if let Some(path) = log_file {
        match File::create(path) {
            Ok(file) => {
                loggers.push(WriteLogger::new(
                    LevelFilter::Debug,
                    Config::default(),
                    file,
                ));
            }
            Err(e) => {
                eprintln!("Failed to create log file: {}", e);
            }
        }
    }

    CombinedLogger::init(loggers).unwrap();
    
    info!("Logging initialized");
    if let Some(path) = log_file {
        info!("Logging to file: {:?}", path);
    }
}