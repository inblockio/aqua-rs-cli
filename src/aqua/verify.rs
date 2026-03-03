// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use std::collections::HashMap;
use std::sync::Arc;
use std::{fs, path::PathBuf};

use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::{AnyRevision, AquaTreeWrapper, FileData};
use aqua_rs_sdk::{Aquafier, DefaultTrustStore};

use crate::{
    aqua::target::push_tree_to_daemon,
    models::CliArgs,
    utils::{
        colored_error, colored_success, format_method_error, format_verification_summary,
        format_verification_summary_compact, format_verification_tree, oprataion_logs_and_dumps,
    },
};

extern crate serde_json_path_to_error as serde_json;

pub async fn cli_verify_chain(args: CliArgs, aquafier: &Aquafier, verify_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();

    // Attach an empty trust store so WASM compute verification runs,
    // matching the forest.rs behaviour (even without --trust).
    let aquafier = aquafier.with_trust_store(Arc::new(DefaultTrustStore::new(HashMap::new())));

    // Canonicalize the verify path so that bare filenames (no directory
    // component) resolve to the current working directory instead of an
    // empty parent path, which would silently break the directory scan.
    let verify_path = fs::canonicalize(&verify_path).unwrap_or(verify_path);

    match fs::read(&verify_path) {
        Ok(body_bytes) => {
            let file_data = String::from_utf8_lossy(&body_bytes).to_string();
            let res = serde_json::from_str::<Tree>(&file_data);

            if res.is_err() {
                logs_data.push(colored_error("❌ Error parsing json data (check your aqua chain)"));
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

            // Collect link_verification_hashes from anchor revisions
            let mut link_hashes = std::collections::HashSet::new();
            for revision in tree.revisions.values() {
                if let AnyRevision::Anchor(anchor) = revision {
                    for lh in anchor.link_verification_hashes() {
                        let lh_str = lh.to_string();
                        // Skip zero-sentinel links (headless attestations)
                        if lh_str != RevisionLink::zero().to_string() {
                            link_hashes.insert(lh_str);
                        }
                    }
                }
            }

            let mut linked_trees: Vec<AquaTreeWrapper> = Vec::new();

            if !link_hashes.is_empty() {
                // Scan the parent directory for all .aqua.json files and build
                // a rev_hash → Tree map for O(1) resolution of linked trees.
                let mut rev_to_tree: HashMap<String, Tree> = HashMap::new();

                if let Ok(entries) = fs::read_dir(&folder_path) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        // Skip self
                        if path == verify_path {
                            continue;
                        }
                        let is_aqua = path
                            .file_name()
                            .map_or(false, |n| n.to_string_lossy().ends_with(".aqua.json"));
                        if !is_aqua {
                            continue;
                        }
                        if let Ok(content) = fs::read_to_string(&path) {
                            if let Ok(sibling_tree) = serde_json::from_str::<Tree>(&content) {
                                for rev_hash in sibling_tree.revisions.keys() {
                                    rev_to_tree
                                        .insert(rev_hash.to_string(), sibling_tree.clone());
                                }
                            }
                        }
                    }
                }

                // Resolve each link hash to a tree
                for lh in &link_hashes {
                    if let Some(linked_tree) = rev_to_tree.get(lh) {
                        // Load the linked tree's content file for verification
                        let linked_file_obj =
                            linked_tree
                                .get_main_file_name()
                                .and_then(|linked_file_name| {
                                    let linked_file_path = folder_path.join(&linked_file_name);
                                    fs::read(&linked_file_path).ok().map(|content| {
                                        FileData::new(linked_file_name, content, linked_file_path)
                                    })
                                });
                        linked_trees
                            .push(AquaTreeWrapper::new(linked_tree.clone(), linked_file_obj, None));
                    }
                }
            }

            let wrapper = AquaTreeWrapper::new(tree.clone(), None, None);

            let verify_result = if linked_trees.is_empty() {
                aquafier.verify_aqua_tree(wrapper, file_objects).await
            } else {
                aquafier
                    .verify_aqua_tree_with_linked_trees(wrapper, linked_trees, file_objects)
                    .await
            };

            match verify_result {
                Ok(res) => {
                    // Filter out the SDK's final summary log (e.g. "Chain verification
                    // passed") — we render our own summary instead.
                    let detail_logs: Vec<_> = res
                        .logs
                        .iter()
                        .filter(|l| {
                            !(l.ident.is_none()
                                && (l.log.contains("Chain verification passed")
                                    || l.log.contains("Chain verification failed")))
                        })
                        .cloned()
                        .collect();

                    if args.verbose {
                        // Verbose: colored header + tree + summary
                        if res.is_valid {
                            logs_data.push(colored_success(
                                "✅ Successfully verified Aqua chain",
                            ));
                        } else {
                            logs_data.push(colored_error(&format!(
                                "❌ Verification failed: {}",
                                res.status
                            )));
                        }

                        let tree_lines = format_verification_tree(&detail_logs);
                        logs_data.extend(tree_lines);

                        logs_data.push(format_verification_summary(
                            &detail_logs,
                            res.is_valid,
                        ));
                    } else {
                        // Non-verbose: single compact summary line
                        logs_data.push(format_verification_summary_compact(
                            &detail_logs,
                            res.is_valid,
                        ));
                    }

                    // Push to daemon if --target is set
                    if let Some(target_id) = args.target {
                        match push_tree_to_daemon(target_id, &tree).await {
                            Ok(resp) => logs_data.push(format!("Pushed to daemon {}: {}", target_id, resp)),
                            Err(e) => logs_data.push(format!("Failed to push to daemon: {}", e)),
                        }
                    }
                }
                Err(err) => {
                    logs_data.push(colored_error("❌ Error verifying Aqua chain"));
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
