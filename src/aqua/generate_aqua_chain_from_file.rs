use std::fs;

use crate::models::CliArgs;
use crate::utils::{oprataion_logs_and_dumps, save_logs_to_file, save_page_data};
use aqua_verifier::aqua::AquaProtocol;

/// Generates an Aqua chain from a given file using the provided CLI arguments and Aqua verifier.
///
/// This function reads a file, processes it through the Aqua verification process,
/// and handles logging and output based on the provided CLI arguments.
///
/// # Arguments
///
/// * `args` - Command-line arguments containing configuration for the Aqua chain generation
/// * `aqua_verifier` - An instance of AquaVerifier used to generate the Aqua chain

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
pub fn cli_generate_aqua_chain(args: CliArgs, aqua_protocol: AquaProtocol) {
    let mut logs_data: Vec<String> = Vec::new();

    if let Some(file_path) = args.clone().file {
        if let Some(_file_name) = file_path.file_name().and_then(|n| n.to_str()) {
            // Read the file content into a Vec<u8>
            match fs::read(&file_path) {
                Ok(_body_bytes) => {
                    // Convert the file name to a String
                    // let file_name = file_name.to_string();

                    // Attempt to generate genesis the Aqua chain
                    let genesis_revision_result =
                        aqua_protocol.generate_genesis_revision(args.clone().file.unwrap());
                    if genesis_revision_result.is_successfull {
                        // Add success message
                        logs_data.push("✅ Successfully  generated Aqua chain ".to_string());

                        // Save modified page data to a new file
                        let e = save_page_data(
                            &genesis_revision_result.clone().aqua_chain.unwrap(),
                            &file_path,
                            "aqua.json".to_string(),
                        );

                        // Log any errors in saving page data
                        if e.is_err() {
                            logs_data.push(format!("Error saving page data: {:#?}", e.err()));
                        }
                    } else {
                        // Add success message
                        logs_data.push("Error : Generating Aqua chain ".to_string());
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read file bytes: {}", e);
                    logs_data.push("❌ failed to read file ".to_string());
                }
            }
        } else {
            eprintln!("Error: Invalid file path provided with -f/--file");

            logs_data.push("❌ Invalid file path provided with -f/--file ".to_string());
        }
    } else {
        tracing::error!("Failed to generate Aqua file, check file path ");
        logs_data.push("❌ Invalid file ,check file path ".to_string());
    }

    oprataion_logs_and_dumps(args, logs_data);
}
