pub mod models;
pub mod utils;

use aqua_verifier_rs_types::models::page_data::HashChain;
use clap::{Arg, Command};
use models::PageDataContainer;
use std::error::Error;
use std::fs;
use std::path::Path;
use crate::utils::compute_content_hash;
extern crate serde_json_path_to_error as serde_json;
use utils::check_if_page_data_revision_are_okay;
use console::Style;
use tracing::{error, info, warn, Level};
use tracing_subscriber::{fmt, EnvFilter};

const LONG_ABOUT: &str = r#"🔐 Aqua CLI TOOL

========================================================

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

    pub fn validate(
        &self,
        output_file: Option<&String>,
        verbose: bool,
        output_level: i8,
    ) -> Result<bool, Vec<String>> {
        let path = Path::new(&self.file_path);
        let mut log_data: Vec<String> = Vec::new();

        if !path.exists() {
            log_data.push("Error :  File does not exist".to_string());
            return Err(log_data);
        }else {
            log_data.push("Success :  File exists".to_string());
        }

        let data_file = fs::read(path);

        if data_file.is_err(){
            log_data.push("Error :  Unable to read file".to_string());
            return Err(log_data);  
        }else {
            log_data.push("Success :  File read sucessfuly".to_string());
        }

        let data = data_file.unwrap();

        // Try to parse the file content into your struct
        match serde_json::from_slice::<PageDataContainer<HashChain>>(&data) {
            Ok(parsed_data) => {
                log_data.push("Success  :  File JSON parsed successfully".to_string());

                        let mut matches = true;
                        let mut failure_reason = "".to_string();
                        let parsed_data_chain = parsed_data.pages.get(0).unwrap();
                        // if the aqua json file has more than one revision compare the has
                        // current has with the previous  metadata > verification_hash
                       
                        if parsed_data_chain.revisions.len() > 1 {
                            log_data.push("Info : revisions more than 1 result".to_string());
                            (matches, failure_reason) = check_if_page_data_revision_are_okay(
                                parsed_data_chain.revisions.clone(),
                            );
                            tracing::error!("revisions are valied ? {}", matches);
                        } else {
                            // let rev  = parsed_data_chain.revisions.get(0).unwrap();
                            // let hash =  compute_content_hash(rev);

                            let (verification_hash, revision) = parsed_data_chain
                                .revisions
                                .first()
                                .expect("No revisions found");

                            // Step 3: Recompute the content hash for the revision
                            let recomputed_content_hash = compute_content_hash(&revision.content);

                            match recomputed_content_hash {
                                Ok(data) => {
                                    // Step 4: Compare the recomputed content hash with the stored content hash

                                    let contnent_hash_str =
                                        format!("{:#?}", revision.content.content_hash);
                                    let data_str = format!("{:#?}", revision.content.content_hash);
                                    // data_str,
                                    // contnent_hash_str

                                    tracing::error!(
                                        " returd conetnet is   {} \n  my son content hash is {} \n",
                                        data_str,
                                        contnent_hash_str
                                    );
                                    if data == revision.content.content_hash {
                                        matches = true;
                                    } else {
                                        failure_reason = format!(
                                            "a hash is not valid : {:#?}",
                                            revision.content.content_hash
                                        )
                                    }
                                    //revision.content.content_hash;
                                }
                                Err(err) => {
                                    tracing::error!("❌ Error compute_content_hash {} ", err);
                                    log_data.push("Erorr :  recomputing content hash ".to_string());
                                   
                                   return Err(log_data);
                                    // Err(format!("❌ Error  compute_content_hash  {:#?}", err).into());
                                    // Err(Box::new(std::io::Error::new(
                                    //     std::io::ErrorKind::Other, 
                                    //     format!("❌ Error compute_content_hash {:#?}", err)
                                    // )))
                                }
                            }
                        }
                        tracing::info!("....Done  Checking all revisions, summarizing results....");
                        return if matches {
                            tracing::error!("Returning true");
                            log_data.push("AQUA Chain valid".to_string());
                            Ok(true)
                        } else {
                            tracing::error!("Validation fails");
                            log_data.push(failure_reason);
                            return Err(log_data);
                            // Err(format!("❌ Error validating the json file  {:#?}", failure_reason).into())
                            // Err(Box::new(std::io::Error::new(
                            //     std::io::ErrorKind::Other, 
                            //     format!("❌  Error validating the json file{:#?}", failure_reason)
                            // )))
                        };

               
            }
            Err(e) => {
                log_data.push(format!("error : Failed to parse JSON: {:?}", e));
                return Err(log_data);
                
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
        Ok(n) => {
            info!("Log number: {}", n);
            n
        }
        Err(e) => {
            error!("Failed to parse: {}", e);
            2
        }
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
            
                "⚠️  Error: {:#?}",e              
            );
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    run()
}
