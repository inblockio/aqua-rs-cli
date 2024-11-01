pub mod models;

use aqua_verifier_rs_types::models::page_data::HashChain;
use clap::{Command, Arg};
use std::path::Path;
use std::fs;
use std::error::Error;
use models::PageDataContainer;
extern crate serde_json_path_to_error as serde_json;
// use std::error::Error;
use tracing::{info, warn, error, Level};
use tracing_subscriber::{fmt, EnvFilter};
use console::Style;

const LONG_ABOUT: &str = r#"🔐 File Integrity Validator

This tool validates files using a aqua protocol. It can:
  • Verify aqua chain json file
  • Generate aqua chain.
  • Generate validation reports

EXAMPLES:
    file-validator -f document.json
    file-validator --file document.json --verbose
    file-validator -f document.json --output report.json

For more information, visit: https://github.com/inblockio/aqua-verifier-cli"#;

pub struct FileValidator {
    file_path: String,
}

impl FileValidator {
    pub fn new(file_path: String) -> Self {
        Self { file_path }
    }

    pub fn validate(&self, output_file : Option<&String>,verbose : bool, output_level : i8 ) -> Result<bool, Box<dyn Error>> {
        let path = Path::new(&self.file_path);
        let mut log_data: Vec<String> = Vec::new();

        if !path.exists() {
            return Err("File does not exist".into());
        }

        let data = fs::read(path)?;
        
         // Try to parse the file content into your struct
         match serde_json::from_slice::<PageDataContainer<HashChain>>(&data) {
            Ok(parsed_data) => {


                
                Ok(true)
            }
            Err(e) => {
               
                log_data.push(format!("Failed to parse JSON: {:?}", e));
               
               Err(format!("Error parsing the file {:#?}", e).into())
            }
        }
        
        
      
    }
}

fn build_cli() -> Command {
    Command::new("file-validator")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .long_about(LONG_ABOUT)
        // Main file argument
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .help("Path to the file to validate")
                .long_help("Full path to the file that needs to be validated. Supported formats include: PDF, DOC, TXT, etc.")
                .required(true)
                .value_name("FILE")
        )
        // Verbose output
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .long_help("Displays detailed information during the validation process, including:
                    • File metadata
                    • Validation steps
                    • Detailed error messages")
                .action(clap::ArgAction::SetTrue)
        )
        // Output format
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file for validation report")
                .long_help("Specify a file to save the validation report. Supported formats:
                    • JSON (.json)
                    • Text (.txt)
                    • HTML (.html)")
                .value_name("OUTPUT_FILE")
        )
        // Validation level
        .arg(
            Arg::new("level")
                .short('l')
                .long("level")
                .help("Set validation strictness level")
                .long_help("Define how strict the validation should be:
                    1: Basic validation
                    2: Standard validation
                    3: Strict validation")
                .value_parser(["1", "2", "3"])
                .default_value("2")
        )
}

pub fn run() -> Result<(), Box<dyn Error>> {
    // Build CLI and get matches
    let matches = build_cli().get_matches();

    // Extract arguments
    let file_path = matches.get_one::<String>("file")
        .expect("File argument is required");
    let verbose = matches.get_flag("verbose");
    let output = matches.get_one::<String>("output");
    
    // Fix the temporary value issue with level
    let default_level = String::from("2");
    let level = matches.get_one::<String>("level")
        .unwrap_or(&default_level);

    if verbose {
        info!("📋 Validation Settings:");
        info!("  • File: {}", file_path);
        info!("  • Validation Level: {}", level);
        if let Some(out) = output {
            info!("  • Output Report: {}", out);
        }
    }

    let validator = FileValidator::new(file_path.to_string());
    
     // Convert &str to i8
    let level_number = match level.parse::<i8>() {
        Ok(n) => {info!("Log number: {}", n); n},
        Err(e) => {error!("Failed to parse: {}", e); 2},
    };

    match validator.validate(output, verbose, level_number) {
        Ok(true) => {
            info!(
                target: "file_validator",
                "✅ {}",
                Style::new().green().apply_to("File validation successful")
            );
        }
        Ok(false) => {
           

            warn!(
                target: "file_validator",
                "❌ {}",
                Style::new().red().apply_to("File validation failed")
            );
        }
        Err(e) => {
            error!(
                target: "file_validator",
                "⚠️  Error: {}",
                Style::new().red().apply_to(e.to_string())
            );
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    run()
}