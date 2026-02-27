// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use std::{fs, path::PathBuf};

use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::{AquaTreeWrapper, FileData};
use aqua_rs_sdk::Aquafier;

use crate::{
    models::CliArgs,
    utils::{format_method_error, oprataion_logs_and_dumps},
};

extern crate serde_json_path_to_error as serde_json;

pub async fn cli_verify_chain(args: CliArgs, aquafier: &Aquafier, verify_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();

    match fs::read(&verify_path) {
        Ok(body_bytes) => {
            let file_data = String::from_utf8_lossy(&body_bytes).to_string();
            let res = serde_json::from_str::<Tree>(&file_data);

            if res.is_err() {
                logs_data.push("❌ Error parsing json data (check your aqua chain)".to_string());
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
            let tree = res.unwrap();

            // Build file objects from the tree's file_index
            let mut file_objects: Vec<FileData> = Vec::new();
            let folder_path = verify_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .to_path_buf();

            if let Some(main_file_name) = tree.get_main_file_name() {
                let file_path = folder_path.join(&main_file_name);
                if let Ok(content) = fs::read(&file_path) {
                    file_objects.push(FileData::new(main_file_name, content, file_path));
                }
            }

            // Load linked chains: file_index entries ending in .aqua.json
            // are external chain files referenced by anchor
            // link_verification_hashes. Load them so the verifier can
            // resolve cross-tree links.
            let mut linked_trees: Vec<AquaTreeWrapper> = Vec::new();
            for (_hash, name) in &tree.file_index {
                if name.ends_with(".aqua.json") {
                    let chain_path = folder_path.join(name);
                    if let Ok(chain_bytes) = fs::read_to_string(&chain_path) {
                        if let Ok(linked_tree) = serde_json::from_str::<Tree>(&chain_bytes) {
                            // Load the linked tree's content file for verification
                            let linked_file_obj =
                                linked_tree
                                    .get_main_file_name()
                                    .and_then(|linked_file_name| {
                                        let linked_file_path = folder_path.join(&linked_file_name);
                                        fs::read(&linked_file_path).ok().map(|content| {
                                            FileData::new(
                                                linked_file_name,
                                                content,
                                                linked_file_path,
                                            )
                                        })
                                    });
                            linked_trees.push(AquaTreeWrapper::new(
                                linked_tree,
                                linked_file_obj,
                                None,
                            ));
                        }
                    }
                }
            }

            let wrapper = AquaTreeWrapper::new(tree, None, None);

            let verify_result = if linked_trees.is_empty() {
                aquafier.verify_aqua_tree(wrapper, file_objects).await
            } else {
                aquafier
                    .verify_aqua_tree_with_linked_trees(wrapper, linked_trees, file_objects)
                    .await
            };

            match verify_result {
                Ok(res) => {
                    if res.is_valid {
                        logs_data.push("✅ Successfully verified Aqua chain".to_string());
                    } else {
                        logs_data.push(format!("❌ Verification failed: {}", res.status));
                    }

                    // Add detailed logs
                    for log_entry in &res.logs {
                        logs_data.push(log_entry.display());
                    }
                }
                Err(err) => {
                    logs_data.push("❌ Error verifying Aqua chain".to_string());
                    logs_data.extend(format_method_error(&err));
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read file bytes: {}", e);
            logs_data.push("❌ failed to read file".to_string());
        }
    }

    oprataion_logs_and_dumps(args, logs_data);
}
