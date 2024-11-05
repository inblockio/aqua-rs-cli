pub mod models;
pub mod utils;
pub mod validate;

use clap::{Arg, Command};
use std::error::Error;

use crate::models::FileValidator;
extern crate serde_json_path_to_error as serde_json;

const LONG_ABOUT: &str = r#"🔐 Aqua CLI TOOL

========================================================

This tool validates files using a aqua protocol. It can:
  • Verify aqua chain json file
  • Generate aqua chain.
  • Generate validation reports

EXAMPLES:
    aqua-cli -v chain.json
    aqua-cli -s chain.json --output report.json
    aqua-cli -w chain.json --output report.json

    aqua-cli -f document.pdf
    aqua-cli --file image.png --verbose
    aqua-cli -f document.json --output report.json

For more information, visit: https://github.com/inblockio/aqua-verifier-cli"#;


fn build_cli() -> Command {
    Command::new("aqua-cli")
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
                    1: Strict validation
                    2: Standard validation
                   ")
                .value_parser(["1", "2"])
                .default_value("2")
        )
}

pub fn run() -> Result<(), Box<dyn Error>> {
    // Build CLI and get matches
    let matches = build_cli().get_matches();

    // Extract arguments
    let file_path = matches
        .get_one::<String>("file")
        .expect("File argument is required");
    let verbose = matches.get_flag("verbose");
    let output = matches.get_one::<String>("output");

    // Fix the temporary value issue with level
    let default_level = String::from("2");
    let level = matches.get_one::<String>("level").unwrap_or(&default_level);

    
        tracing::info!("📋 Validation Settings:");
        tracing::info!("  • File: {}", file_path);
        tracing::info!("  • Validation Level: {}", level);


        let validator = FileValidator::new(file_path.to_string());
      

    match validator.validate() {
        Ok((true, logs)) => {
           
            tracing::info!(
                
                "✅ Verification successful ",
                
            );

            for ele in logs {
                println!("{} \n", ele);
            }
        }
        Ok((false, logs)) => {
            tracing::error!(
                "❌ Verification Failed",
                
            );
            for ele in logs {
                println!("{} \n", ele);
            }
           
        }
        Err(logs) => {
            tracing::error!(
                "💣 Error occurred during validation",
                
            );
            for ele in logs {
                println!("{} \n", ele);
            }
           
        }
    }
    
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    run()
}
