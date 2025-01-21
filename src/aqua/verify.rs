use std::{fs, path::PathBuf};

use aqua_verifier::aqua::AquaProtocol;
use aqua_verifier_rs_types::models::chain::AquaChain;

use crate::{
    models::CliArgs,
    utils::{oprataion_logs_and_dumps, save_page_data},
};

pub fn cli_verify_chain(args: CliArgs, aqua_protocol: AquaProtocol, verify_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();

    // Read the file bytes
    match fs::read(&verify_path) {
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

            let folder_path = verify_path
                .parent()
                .unwrap()
                .to_path_buf()
                .to_string_lossy()
                .to_string();
            println!("folder_path : {:?}", folder_path);
            // Attempt to generate genesis the Aqua chain
            let genesis_revision_result = aqua_protocol.verify_aqua_chain(res_data, folder_path);
            if genesis_revision_result.is_successfull {
                // Add success message
                logs_data.push("✅ Successfully  verified Aqua chain ".to_string());
            } else {
                // Add success message
                logs_data.push("Error : Validating Aqua chain ".to_string());
            }
        }
        Err(e) => {
            eprintln!("Failed to read file bytes: {}", e);
            logs_data.push("❌ failed to read file ".to_string());
        }
    }

    
    oprataion_logs_and_dumps(args, logs_data);
}
