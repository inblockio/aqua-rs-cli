use std::path::PathBuf;

use aqua_verifier::aqua_verifier::AquaVerifier;
use aqua_verifier_rs_types::models::page_data::PageData;

use crate::models::CliArgs;
use crate::utils::{read_aqua_data, save_logs_to_file, save_page_data};

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
    aqua_verifier: AquaVerifier,
    aqua_chain_file_path: PathBuf,
) {
    // Number of revisions to remove
    let revision_count_for_deletion = args.remove_count;

    // Vector to store log messages
    let mut logs_data: Vec<String> = Vec::new();

    // Print the file being processed
    println!("Verifying file: {:?}", aqua_chain_file_path);

    // Read Aqua data from the file
    let res: Result<PageData, String> = read_aqua_data(&aqua_chain_file_path);

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

    // Attempt to delete revisions from the Aqua chain
    match aqua_verifier.delete_revision_in_aqua_chain(res.unwrap(), revision_count_for_deletion) {
        Ok((page_data, logs)) => {
            // Collect logs with indentation
            for ele in logs {
                logs_data.push(format!("\t\t {}", ele));
            }

            // Add success message
            logs_data.push("Success: Removing revision from Aqua chain is successful".to_string());

            // Save modified page data to a new file
            let e = save_page_data(
                &page_data,
                &aqua_chain_file_path,
                "chain.modified.json".to_string(),
            );

            // Log any errors in saving page data
            if e.is_err() {
                logs_data.push(format!("Error saving page data: {:#?}", e.err()));
            }

            // Print logs based on verbosity setting
            if args.verbose {
                for item in logs_data.clone() {
                    println!("{}", item);
                }
            } else {
                println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
            }

            // Save logs to file if output path is specified
            if args.output.is_some() {
                let logs = save_logs_to_file(&logs_data, args.output.unwrap());
                if logs.is_err() {
                    eprintln!("Error: saving logs {}", logs.unwrap());
                }
            }
        }
        Err(logs) => {
            // Collect error logs with indentation
            for ele in logs {
                logs_data.push(format!("\t\t {}", ele));
            }

            // Save logs to file if output path is specified
            if args.output.is_some() {
                let logs = save_logs_to_file(&logs_data, args.output.unwrap());
                if logs.is_err() {
                    eprintln!("Error: saving logs {}", logs.unwrap());
                }
            }

            // Add error message
            logs_data.push("Error: Failed to remove revisions from Aqua chain".to_string());

            // Print logs based on verbosity setting
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
