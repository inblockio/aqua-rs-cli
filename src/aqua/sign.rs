use std::{fs, path::PathBuf};

use aqua_verifier::{
    aqua::AquaProtocol,
    model::signature::{Credentials, SignatureType},
};
use aqua_verifier_rs_types::models::chain::AquaChain;

use crate::{
    models::CliArgs,
    utils::{oprataion_logs_and_dumps, save_page_data},
};

pub(crate) fn cli_sign_chain(
    args: CliArgs,
    aqua_protocol: AquaProtocol,
    sign_path: PathBuf,
    sign_type: SignatureType,
    keys_file: Option<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();
    let mut credentials: Option<Credentials> = None;

    if keys_file.is_some() {
        let keys_file_path = keys_file.unwrap();
        let keys_file_content =
            fs::read_to_string(&keys_file_path).expect("Unable to read keys file");
        let credentials_res: Result<Credentials, serde_json::Error> =
            serde_json::from_str::<Credentials>(&keys_file_content);
        if credentials_res.is_err() {
            logs_data.push("❌ Invalid keys file format".to_string());
            return;
        }
        credentials = Some(credentials_res.unwrap());
    } else {
        println!(" === Keys file is not provided === ");
    }

    // Read the file content into a Vec<u8>
    match fs::read(&sign_path) {
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

            // convert if to match
            match sign_type {
                SignatureType::DID => {
                    if credentials.is_none() {
                        logs_data.push("❌ DID signature requires keys file".to_string());
                        return;
                    }
                }
                SignatureType::CLI => {
                    if credentials.is_none() {
                        logs_data.push("❌ CLI signature requires keys file".to_string());
                        return;
                    }
                }
                SignatureType::METAMASK => {}
            }
            
            // Attempt to generate genesis the Aqua chain
            let genesis_revision_result =
                aqua_protocol.sign_chain(res_data, sign_type, credentials);
            if genesis_revision_result.is_successfull {
                // Add success message
                logs_data.push("✅ Successfully  generated Aqua chain ".to_string());

                // Save modified page data to a new file
                let e = save_page_data(
                    &genesis_revision_result.clone().aqua_chain.unwrap(),
                    &sign_path,
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

    oprataion_logs_and_dumps(args, logs_data);
}
