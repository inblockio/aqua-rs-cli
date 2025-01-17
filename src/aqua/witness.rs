use std::{env, fs};
use std::path::PathBuf;

use aqua_verifier::aqua::AquaProtocol;
use aqua_verifier::model::signature::Credentials;
use aqua_verifier::model::witness::WitnessType;
use aqua_verifier_rs_types::models::chain::AquaChain;

use crate::models::{CliArgs};
use crate::utils::{oprataion_logs_and_dumps, save_page_data};

// use crate::models::{CliArgs, WitnessPayload};
// use crate::servers::server_witness::witness_message_server;
// use crate::utils::{read_aqua_data, save_logs_to_file, save_page_data};
// use aqua_verifier_rs_types::models::content::RevisionWitnessInput;
// use aqua_verifier_rs_types::models::page_data::PageData;
// use aqua_verifier::aqua_verifier::AquaVerifier;
// use aqua_verifier::util::get_hash_sum;

/// Generates a witness chain for an Aqua file using the provided CLI arguments and Aqua verifier.
///
/// This function performs the following key steps:
/// 1. Reads Aqua data from the specified witness path
/// 2. Validates the Aqua chain and its revisions
/// 3. Generates a witness event verification hash
/// 4. Interacts with a witness message server to obtain authentication
/// 5. Witnesses the Aqua chain using the obtained authentication
///
/// # Arguments
///
/// * `args` - Command-line arguments containing configuration for the witnessing process
/// * `aqua_verifier` - An instance of AquaVerifier used to witness the Aqua chain
/// * `witness_path` - Path to the file to be witnessed
///
/// # Behavior
///
/// - Validates the input Aqua chain
/// - Generates a witness event verification hash
/// - Obtains authentication from a witness message server
/// - Witnesses the Aqua chain
/// - Handles logging and output based on CLI arguments
///
/// # Errors
///
/// - Panics if:
///   - Unable to read the Aqua data file
///   - No Aqua chain is found
///   - Unable to initialize Tokio runtime
///   - Witnessing process fails
///
/// # Logging
///
/// - Supports verbose and non-verbose logging
/// - Can save logs to a file if an output path is specified
pub(crate) fn cli_winess_chain(args: CliArgs, aqua_protocol: AquaProtocol, witness_path: PathBuf, witness_type: WitnessType,  keys_file: Option<PathBuf>) {

    let mut logs_data: Vec<String> = Vec::new();
    let mut credentials : Option<Credentials> = None;

    if keys_file.is_some(){
        let keys_file_path = keys_file.unwrap();
        let keys_file_content = fs::read_to_string(&keys_file_path).expect("Unable to read keys file");
        let credentials_res: Result<Credentials, serde_json::Error> = serde_json::from_str::<Credentials>(&keys_file_content);
        if credentials_res.is_err() {
            logs_data.push("❌ Invalid keys file format".to_string());
            return;
        }
        credentials = Some(credentials_res.unwrap());
    }



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
                    logs_data.push("❌ Error parsing json data (check you aqua chain) ".to_string());
                    return;
                }
                let res_data = res.unwrap();

                // Attempt to generate genesis the Aqua chain
                let genesis_revision_result = aqua_protocol.witness_chain(
                    witness_type,
                    res_data,
                    credentials
                );
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
