use std::f32::consts::E;
use std::path::PathBuf;

use aqua_verifier::aqua::AquaProtocol;
use aqua_verifier::model::aqua_chain_result::AquaChainResult;
use aqua_verifier_rs_types::models::chain::AquaChain;
use aqua_verifier_rs_types::models::protocol_logs::ProtocolLogsType;

use crate::models::CliArgs;
use crate::utils::{
    log_with_emoji, oprataion_logs_and_dumps, read_aqua_data, save_logs_to_file, save_page_data,
};

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
    let revision_count_for_deletion = args.remove_count;

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
