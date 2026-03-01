// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Ephemeral forest CLI command.
//!
//! `cli_ephemeral_forest` ingests one or more `.aqua.json` files into a
//! daemon `Forest` backed by `NullStorage`, resolving cross-tree dependencies
//! (attestation→claim, template hierarchies) via a pre-built revision index.
//! Prints a summary using the Forest API: node counts, genesis hashes, tip
//! revisions, and any genuinely unresolved L3 dependencies.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use aqua_rs_sdk::daemon::{topological_order, Forest, NullStorage};
use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::{AnyRevision, AquaTreeWrapper};
use aqua_rs_sdk::{Aquafier, DefaultTrustStore};

use crate::models::CliArgs;

extern crate serde_json_path_to_error as serde_json;

pub async fn cli_ephemeral_forest(args: CliArgs, aquafier: &Aquafier, files: Vec<PathBuf>) {
    // Build a local Aquafier with trust store if --trust was provided
    let aquafier = if let Some((ref did, level)) = args.trust {
        let mut levels = HashMap::new();
        levels.insert(did.clone(), level);
        println!("Trust store: {} at level {}", did, level);
        aquafier.with_trust_store(Arc::new(DefaultTrustStore::new(levels)))
    } else {
        aquafier.with_trust_store(Arc::new(DefaultTrustStore::new(HashMap::new())))
    };

    println!("Building ephemeral forest from {} file(s)...", files.len());
    println!();

    // ── Phase 1: Load all trees and build rev_hash → tree_index map ─────
    let mut trees: Vec<(String, Tree)> = Vec::new();
    let mut rev_to_idx: HashMap<String, usize> = HashMap::new();
    let mut load_failed = 0usize;

    for file in &files {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.to_string_lossy().into_owned());

        let file_content = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                println!("  [{}] FAILED — read error: {}", name, e);
                load_failed += 1;
                continue;
            }
        };

        let tree: Tree = match serde_json::from_str(&file_content) {
            Ok(t) => t,
            Err(e) => {
                println!("  [{}] FAILED — parse error: {}", name, e);
                load_failed += 1;
                continue;
            }
        };

        let idx = trees.len();
        for rev_hash in tree.revisions.keys() {
            rev_to_idx.insert(rev_hash.to_string(), idx);
        }
        trees.push((name, tree));
    }

    // ── Phase 2: Verify with pre-resolved linked trees, insert into Forest ──
    let mut forest = Forest::new("cli", "cli:session", Box::new(NullStorage));
    let mut results: Vec<(String, bool, String)> = Vec::new();

    for i in 0..trees.len() {
        let (name, tree) = &trees[i];

        // Extract link_verification_hashes from anchor revisions
        let mut link_hashes: Vec<String> = Vec::new();
        for revision in tree.revisions.values() {
            if let AnyRevision::Anchor(anchor) = revision {
                for lh in anchor.link_verification_hashes() {
                    let lh_str = lh.to_string();
                    // Skip zero-sentinel links (headless attestations)
                    if lh_str != RevisionLink::zero().to_string() {
                        link_hashes.push(lh_str);
                    }
                }
            }
        }

        // Resolve links to containing trees (O(1) per link via rev_to_idx)
        let mut linked_wrappers: Vec<AquaTreeWrapper> = Vec::new();
        for lh in &link_hashes {
            if let Some(&linked_idx) = rev_to_idx.get(lh) {
                if linked_idx != i {
                    let linked_tree = trees[linked_idx].1.clone();
                    linked_wrappers.push(AquaTreeWrapper::new(linked_tree, None, None));
                }
            }
        }

        let wrapper = AquaTreeWrapper::new(tree.clone(), None, None);
        let verify_result = if linked_wrappers.is_empty() {
            aquafier.verify_and_build_state(wrapper, vec![]).await
        } else {
            aquafier
                .verify_and_build_state_with_linked_trees(wrapper, linked_wrappers, vec![])
                .await
        };

        match verify_result {
            Ok((vr, state_nodes)) => {
                let node_count = state_nodes.len();
                let status = if vr.is_valid {
                    format!("OK  ({} node(s))", node_count)
                } else {
                    format!("WARN ({}, {} node(s))", vr.status, node_count)
                };

                // Insert state nodes into forest in topological order
                let ordered = topological_order(state_nodes);
                for node in ordered {
                    let node_links = node.link_verification_hashes.clone();
                    let rev_hash_str = node.revision_hash.clone();
                    forest.insert_node(node);

                    // Handle cross-tree dependencies
                    if let Some(links) = node_links {
                        for lh_str in &links {
                            if let Ok(lh) = lh_str.parse::<RevisionLink>() {
                                // Skip zero-sentinel
                                if lh == RevisionLink::zero() {
                                    continue;
                                }
                                // Try to load as built-in template first
                                if !forest.load_builtin_template(&lh) {
                                    // Not a builtin — register as L3 pending if unresolved
                                    if forest.get_node(&lh).is_none() {
                                        if let Ok(owner) = rev_hash_str.parse::<RevisionLink>() {
                                            forest.register_l3_pending(owner, lh);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                results.push((name.clone(), vr.is_valid, status));
            }
            Err(e) => {
                results.push((
                    name.clone(),
                    false,
                    format!("FAILED — verify error: {}", e),
                ));
            }
        }
    }

    // ── Phase 3: Post-insert L3 resolution ──────────────────────────────
    // Some pending entries may now be resolvable (later files contained
    // the awaited hashes).
    let pending_keys: Vec<RevisionLink> = forest.pending_dependencies().keys().cloned().collect();
    for awaited in &pending_keys {
        if forest.get_node(awaited).is_some() {
            forest.resolve_l3_pending(awaited);
        }
    }

    // ── Phase 4: Report ─────────────────────────────────────────────────
    // Per-file verification results
    println!("Per-file verification:");
    let mut pass_count = 0usize;
    let mut fail_count = 0usize;
    for (name, passed, status) in &results {
        println!("  [{}] {}", name, status);
        if *passed {
            pass_count += 1;
        } else {
            fail_count += 1;
        }
    }
    println!();

    // Forest summary via Forest API
    let summary = forest.summary();
    let genesis_hashes = forest.genesis_hashes();
    let tips = forest.tips();

    println!("Ephemeral Forest Summary");
    println!("========================");
    println!("  Session     : {}", summary.namespace_name);
    println!(
        "  Files       : {} ingested, {} failed",
        pass_count + fail_count,
        load_failed
    );
    println!("  Nodes       : {}", summary.node_count);
    println!("  Geneses     : {}", summary.genesis_count);
    println!("  Pending deps: {}", summary.pending_count);

    if !genesis_hashes.is_empty() {
        println!();
        println!("Genesis trees ({}):", genesis_hashes.len());
        for gh in &genesis_hashes {
            println!("  {}", gh);
        }
    }

    if !tips.is_empty() {
        println!();
        println!("Tip revisions ({}):", tips.len());
        for tip in &tips {
            println!("  {}", tip);
        }
    }

    let remaining_pending = forest.pending_dependencies();
    if !remaining_pending.is_empty() {
        println!();
        println!(
            "Unresolved cross-tree dependencies ({}):",
            remaining_pending.len()
        );
        for (awaited, owners) in remaining_pending {
            println!("  {} (awaited by {} node(s))", awaited, owners.len());
        }
    }

    // Outcome line
    println!();
    if fail_count == 0 && load_failed == 0 && summary.node_count > 0 {
        println!("Forest built successfully.");
    } else if load_failed + fail_count > 0 && pass_count == 0 {
        eprintln!("All files failed to ingest.");
        std::process::exit(1);
    } else if fail_count + load_failed > 0 {
        println!("Forest built with {} error(s).", fail_count + load_failed);
    }

    // Verbose: walk subtrees from genesis roots
    if args.verbose {
        println!();
        println!("Node details:");
        for gh in &genesis_hashes {
            print_forest_subtree(&forest, gh, 0);
        }
    }

    // Output file support
    if let Some(output_path) = &args.output {
        let report = build_forest_report(&forest);
        match fs::write(output_path, report) {
            Ok(_) => println!("Report written to {:?}", output_path),
            Err(e) => eprintln!("Failed to write report: {}", e),
        }
    }
}

/// Recursively print a forest node and its children with indentation (verbose mode).
fn print_forest_subtree(forest: &Forest, hash: &RevisionLink, depth: usize) {
    let indent = "  ".repeat(depth + 1);
    if let Some(node) = forest.get_node(hash) {
        let signer = node.state.signer.as_deref().unwrap_or("-");
        let rev_type = truncate(&node.state.revision_type, 12);
        let hash_str = hash.to_string();
        println!(
            "{}[{}] type={} signer={}",
            indent,
            truncate(&hash_str, 14),
            rev_type,
            signer
        );
        for child in forest.branches(hash) {
            if let Ok(child_link) = child.state.revision_hash.parse::<RevisionLink>() {
                print_forest_subtree(forest, &child_link, depth + 1);
            }
        }
    }
}

/// Truncate a string for display, appending "…" if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

/// Serialize a JSON report using Forest API data.
fn build_forest_report(forest: &Forest) -> String {
    let summary = forest.summary();
    let genesis_hashes: Vec<String> = forest.genesis_hashes().iter().map(|h| h.to_string()).collect();
    let tips: Vec<String> = forest.tips().iter().map(|h| h.to_string()).collect();
    let pending: Vec<String> = forest
        .pending_dependencies()
        .keys()
        .map(|h| h.to_string())
        .collect();

    let report = serde_json::json!({
        "session": summary.namespace_name,
        "node_count": summary.node_count,
        "genesis_count": summary.genesis_count,
        "genesis_hashes": genesis_hashes,
        "tips": tips,
        "pending_count": summary.pending_count,
        "pending_dependencies": pending,
    });

    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}
