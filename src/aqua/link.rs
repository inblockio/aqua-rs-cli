// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use std::{fs, path::PathBuf};

use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::AquaTreeWrapper;
use aqua_rs_sdk::Aquafier;

use crate::{
    models::CliArgs,
    utils::{format_method_error, oprataion_logs_and_dumps, save_page_data},
};

extern crate serde_json_path_to_error as serde_json;

pub(crate) fn cli_link_chain(
    args: CliArgs,
    aquafier: &Aquafier,
    parent_chain: PathBuf,
    child_chains: Vec<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();

    let parent_chain_data_string_result = fs::read_to_string(&parent_chain);
    if parent_chain_data_string_result.is_err() {
        logs_data.push("❌ Error reading parent chain file".to_string());
        oprataion_logs_and_dumps(args, logs_data);
        return;
    }
    let parent_chain_data_string = parent_chain_data_string_result.unwrap();

    let parent_chain_data_result = serde_json::from_str::<Tree>(&parent_chain_data_string);
    if parent_chain_data_result.is_err() {
        logs_data.push("❌ Error parsing parent chain json data".to_string());
        oprataion_logs_and_dumps(args, logs_data);
        return;
    }
    let parent_tree = parent_chain_data_result.unwrap();

    let mut child_wrappers: Vec<AquaTreeWrapper> = Vec::new();
    for child_chain in &child_chains {
        let child_chain_data_string_result = fs::read_to_string(child_chain);
        if child_chain_data_string_result.is_err() {
            logs_data.push(format!(
                "❌ Error reading child chain file: {}",
                child_chain.display()
            ));
            oprataion_logs_and_dumps(args, logs_data);
            return;
        }
        let child_chain_data_string = child_chain_data_string_result.unwrap();

        let child_chain_data_result = serde_json::from_str::<Tree>(&child_chain_data_string);
        if child_chain_data_result.is_err() {
            logs_data.push(format!(
                "❌ Error parsing child chain json data: {}",
                child_chain.display()
            ));
            oprataion_logs_and_dumps(args, logs_data);
            return;
        }
        let child_tree = child_chain_data_result.unwrap();
        child_wrappers.push(AquaTreeWrapper::new(child_tree, None, None));
    }

    let revision = args.previous_hash.as_ref().map(|h| {
        h.parse::<aqua_rs_sdk::primitives::RevisionLink>()
            .expect("Invalid revision hash format (expected 0x-prefixed lowercase hex)")
    });
    let parent_wrapper = AquaTreeWrapper::new(parent_tree, None, revision);
    let child_count = child_wrappers.len();

    match aquafier.link_aqua_tree(parent_wrapper, child_wrappers, None) {
        Ok(linked_tree) => {
            logs_data.push(format!(
                "✅ Successfully linked {} child chain(s) into parent",
                child_count
            ));

            let e = save_page_data(
                &linked_tree,
                parent_chain.as_path(),
                "aqua.json".to_string(),
            );

            if e.is_err() {
                logs_data.push(format!("Error saving page data: {:#?}", e.err()));
            }
        }
        Err(err) => {
            logs_data.push("❌ Error linking Aqua chains".to_string());
            logs_data.extend(format_method_error(&err));
        }
    }

    oprataion_logs_and_dumps(args, logs_data);
}
