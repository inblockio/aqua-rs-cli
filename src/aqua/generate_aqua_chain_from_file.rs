use std::fs;

use crate::models::CliArgs;
use crate::utils::{save_logs_to_file, save_page_data};
use aqua_verifier::aqua_verifier::AquaVerifier;

/// Generates an Aqua chain from a given file using the provided CLI arguments and Aqua verifier.
///
/// This function reads a file, processes it through the Aqua verification process, 
/// and handles logging and output based on the provided CLI arguments.
///
/// # Arguments
///
/// * `args` - Command-line arguments containing configuration for the Aqua chain generation
/// * `aqua_verifier` - An instance of AquaVerifier used to generate the Aqua chain
/// * `domain_id` - A string identifier for the domain
///
/// # Behavior
///
/// - Reads the file specified in the arguments
/// - Calls `generate_aqua_chain` method on the verifier
/// - Handles successful and failed generation scenarios
/// - Supports verbose logging and optional log file output
///
/// # Errors
///
/// - Prints error messages if file reading fails
/// - Logs generation errors if Aqua chain generation is unsuccessful
/// - Can save logs to a file if output path is specified
pub fn cli_generate_aqua_chain(args: CliArgs, aqua_verifier: AquaVerifier, domain_id: String) {
    let mut logs_data: Vec<String> = Vec::new();

    if let Some(file_path) = args.file {
        if let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) {
            // Read the file content into a Vec<u8>
            match fs::read(&file_path) {
                Ok(body_bytes) => {
                    // Convert the file name to a String
                    let file_name = file_name.to_string();

                    // Attempt to generate the Aqua chain
                    match aqua_verifier.generate_aqua_chain(body_bytes, file_name, domain_id) {
                        Ok(result) => {
                            // Process successful generation
                            for ele in result.logs {
                                logs_data.push(format!("\t\t {}", ele));
                            }

                            logs_data.push(
                                "Success :  Generating Aqua chain is successful ".to_string(),
                            );

                            // Save page data to a file
                            let e = save_page_data(
                                &result.page_data,
                                &file_path,
                                "chain.json".to_string(),
                            );

                            if e.is_err() {
                                logs_data.push(format!("Error saving page data: {:#?}", e.err()));
                            }

                            // Handle log output based on verbosity
                            if args.verbose {
                                for item in logs_data.clone() {
                                    println!("{}", item);
                                }
                            } else {
                                println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
                            }

                            // Optionally save logs to a file
                            if args.output.is_some() {
                                let logs = save_logs_to_file(&logs_data, args.output.unwrap());
                                if logs.is_err() {
                                    eprintln!("Error:  saving logs {}", logs.unwrap());
                                }
                            }
                        }
                        Err(logs) => {
                            // Process failed generation
                            for ele in logs {
                                logs_data.push(format!("\t\t {}", ele));
                            }

                            // Optionally save logs to a file
                            if args.output.is_some() {
                                let logs = save_logs_to_file(&logs_data, args.output.unwrap());
                                if logs.is_err() {
                                    eprintln!("Error:  saving logs {}", logs.unwrap());
                                }
                            }
                            logs_data.push("Error : Failed to generate aqua chain".to_string());

                            // Handle log output based on verbosity
                            if args.verbose {
                                for item in logs_data {
                                    println!("{}", item);
                                }
                            } else {
                                println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read file bytes: {}", e);
                }
            }
        } else {
            eprintln!("Error: Invalid file path provided with -f/--file");
        }
    } else {
        tracing::error!("Failed to generate Aqua file, check file path ")
    }
}