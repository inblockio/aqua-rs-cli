use std::{fs, path::PathBuf};

use aqua_verifier::    aqua::AquaProtocol;

use aqua_verifier_rs_types::models::chain::AquaChain;

use crate::{
    models::CliArgs,
    utils::{oprataion_logs_and_dumps, save_page_data},
};

pub(crate) fn cli_link_chain(
    args: CliArgs,
    aqua_protocol: AquaProtocol,
    parent_chain: PathBuf,
    child_chain: PathBuf,
) {
    let mut logs_data: Vec<String> = Vec::new();

    let parent_chain_data_string_result = fs::read_to_string(&parent_chain);
    if parent_chain_data_string_result.is_err() {
        logs_data.push("❌ Error reading parent chain file".to_string());
        return;
    }
    let parent_chain_data_string = parent_chain_data_string_result.unwrap();

    let child_chain_data_string_result = fs::read_to_string(&child_chain);
    if child_chain_data_string_result.is_err() {
        logs_data.push("❌ Error reading child chain file".to_string());
        return;
    }
    let child_chain_data_string = child_chain_data_string_result.unwrap();

    let parent_chain_data_result = serde_json::from_str::<AquaChain>(&parent_chain_data_string);
    if parent_chain_data_result.is_err() {
        logs_data.push("❌ Error parsing parent chain json data".to_string());
        return;
    }
    let parent_chain_data = parent_chain_data_result.unwrap();

    let child_chain_data_result = serde_json::from_str::<AquaChain>(&child_chain_data_string);
    if child_chain_data_result.is_err() {
        logs_data.push("❌ Error parsing child chain json data".to_string());
        return;
    }
    let child_chain_data = child_chain_data_result.unwrap();

    // Attempt to generate genesis the Aqua chain
    let link_chains_result = aqua_protocol.link_chain(parent_chain_data, child_chain_data);
    if link_chains_result.is_successfull {
        // Add success message
        logs_data.push("✅ Successfully  linked the two Aqua chain ".to_string());

        // Save modified page data to a new file
        let e = save_page_data(
            &link_chains_result.clone().aqua_chain.unwrap(),
            parent_chain.as_path(),
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

    oprataion_logs_and_dumps(args, logs_data);
}
