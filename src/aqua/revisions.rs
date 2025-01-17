use std::fs;

use crate::models::CliArgs;
use crate::utils::{
    log_with_emoji, oprataion_logs_and_dumps, read_aqua_data, save_logs_to_file, save_page_data,
};
use aqua_verifier::aqua::AquaProtocol;

use std::path::PathBuf;

use aqua_verifier::model::aqua_chain_result::AquaChainResult;
use aqua_verifier_rs_types::models::chain::AquaChain;

/// Removes a specified number of revisions from an Aqua chain file.
///
/// This function performs the following key operations:
/// 1. Reads the Aqua chain data from a specified file
/// 2. Attempts to delete a specified number of revisions using an AquaVerifier
/// 3. Saves the modified page data to a new file
/// 4. Handles logging and output based on CLI arguments
///
/// # Arguments
/// * `args` - Command-line arguments specifying removal parameters
/// * `aqua_verifier` - The verifier used to remove revisions from the Aqua chain
/// * `aqua_chain_file_path` - Path to the Aqua chain file to be processed
///
/// # Behavior
/// - Reads the Aqua chain file
/// - Attempts to remove the specified number of revisions
/// - Saves modified data to a new file with '.modified.json' suffix
/// - Logs operations and potential errors
/// - Optionally prints logs based on verbosity setting
/// - Optionally saves logs to a specified output file
///
/// # Errors
/// - Handles and logs errors during file reading, revision removal, and log saving
/// - Does not panic, instead logs and returns from the function on errors
pub fn cli_remove_revisions_from_aqua_chain(
    args: CliArgs,
    aqua_protocol: AquaProtocol,
    aqua_chain_file_path: PathBuf,
) {
    // Number of revisions to remove
    // let revision_count_for_deletion = args.remove_count;

    // Vector to store log messages
    let mut logs_data: Vec<String> = Vec::new();

    // Print the file being processed
    println!("Verifying file: {:?}", aqua_chain_file_path);

    // Read Aqua data from the file
    let res: Result<AquaChain, String> = read_aqua_data(&aqua_chain_file_path);

    // Handle file reading errors
    if res.is_err() {
        logs_data.push(res.err().unwrap());

        // Attempt to save logs if output path is specified
        if args.output.is_some() {
            let logs = save_logs_to_file(&logs_data, args.output.unwrap());

            if logs.is_err() {
                eprintln!("Error: saving logs {}", logs.unwrap());
            }
        }
        return;
    }

    let remove_result: AquaChainResult = aqua_protocol.remove_last_revision(res.unwrap());
    logs_data.extend(log_with_emoji(remove_result.clone().logs));

    if remove_result.is_successfull {
        // Add success message
        logs_data.push("✅ Successfully  Removed last revision from Aqua chain ".to_string());

        // Save modified page data to a new file
        let e = save_page_data(
            &remove_result.clone().aqua_chain.unwrap(),
            &aqua_chain_file_path,
            "chain.modified.json".to_string(),
        );

        // Log any errors in saving page data
        if e.is_err() {
            logs_data.push(format!("Error saving page data: {:#?}", e.err()));
        }
    } else {
        // Add success message
        logs_data.push("❌ Error  creating Aqua chain ".to_string());
    }

    oprataion_logs_and_dumps(args, logs_data);
}

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

pub fn cli_generate_scalar_revision(args: CliArgs, aqua_protocol: AquaProtocol) {
    let mut logs_data: Vec<String> = Vec::new();

    if let Some(file_path) = args.clone().scalar {
        // Read the file content into a Vec<u8>
        match fs::read(&file_path) {
            Ok(body_bytes) => {
                // Convert the file name to a String
                // let file_name = file_name.to_string();

                // convert the file bytes to a string
                let file_data = String::from_utf8_lossy(&body_bytes).to_string();
                // parse the string to aquachain capture any errors
                // let aqua_chain = ::from_json(&file_string);
                let res = serde_json::from_str::<AquaChain>(&file_data);

                if res.is_err() {
                    logs_data.push("❌ Error parsing json data ".to_string());
                    return;
                }
                let res_data = res.unwrap();

                // Attempt to generate genesis the Aqua chain
                let genesis_revision_result = aqua_protocol.generate_scalar_revision(res_data);
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
        tracing::error!("Failed to generate Aqua file, check file path ");
        logs_data.push("❌ Invalid file ,check file path ".to_string());
    }

    oprataion_logs_and_dumps(args, logs_data);
}




pub fn cli_generate_content_revision(args: CliArgs, aqua_protocol: AquaProtocol) {
    let mut logs_data: Vec<String> = Vec::new();

    if let Some(file_path) = args.clone().file {
        // Read the file content into a Vec<u8>
        match fs::read(&file_path) {
            Ok(body_bytes) => {
                // Convert the file name to a String
                // let file_name = file_name.to_string();

                // convert the file bytes to a string
                let file_data = String::from_utf8_lossy(&body_bytes).to_string();
                // parse the string to aquachain capture any errors
                // let aqua_chain = ::from_json(&file_string);
                let res = serde_json::from_str::<AquaChain>(&file_data);

                if res.is_err() {
                    logs_data.push("❌ Error parsing json data ".to_string());
                    return;
                }
                let res_data = res.unwrap();

                // Attempt to generate genesis the Aqua chain
                let genesis_revision_result = aqua_protocol.generate_scalar_revision(res_data);
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
        tracing::error!("Failed to generate Aqua file, check file path ");
        logs_data.push("❌ Invalid file ,check file path ".to_string());
    }

    oprataion_logs_and_dumps(args, logs_data);
}
