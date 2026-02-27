// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Ephemeral forest CLI command.
//!
//! `cli_ephemeral_forest` ingests one or more `.aqua.json` files into a
//! session-bound in-memory forest (backed by `NullStorage`), then prints a
//! summary of the combined verified state: node counts, genesis hashes, tip
//! revisions, and any unresolved L3 cross-tree dependencies.
//!
//! # Architecture note
//!
//! This uses the SDK's daemon `EphemeralForest` (Mode 1 → L3-aware forest):
//!
//! ```text
//! file.aqua.json
//!   → serde_json::from_str::<Tree>
//!   → Aquafier::verify_and_build_state  (L1/L2/L3 + WASM)
//!   → topological_order                 (parents before children)
//!   → EphemeralForest::insert_node      (builds ownership DAG in memory)
//!   → Forest::summary / genesis_hashes / tips / pending_dependencies
//! ```
//!
//! The ephemeral forest is discarded when the function returns — no state
//! is written to disk.

use std::path::PathBuf;
use std::time::Duration;
use std::fs;

use aqua_rs_sdk::daemon::{topological_order, EphemeralForest, EphemeralId};
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::AquaTreeWrapper;
use aqua_rs_sdk::Aquafier;

use crate::models::CliArgs;

extern crate serde_json_path_to_error as serde_json;

pub async fn cli_ephemeral_forest(args: CliArgs, aquafier: &Aquafier, files: Vec<PathBuf>) {
    println!("Building ephemeral forest from {} file(s)...", files.len());
    println!();

    let ef = EphemeralForest::new(
        EphemeralId(1),
        "cli:session",
        Duration::from_secs(300),
    );

    let mut ingested = 0usize;
    let mut failed = 0usize;

    for file in &files {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.to_string_lossy().into_owned());

        print!("  [{}] ", name);

        let file_content = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                println!("FAILED — read error: {}", e);
                failed += 1;
                continue;
            }
        };

        let tree: Tree = match serde_json::from_str(&file_content) {
            Ok(t) => t,
            Err(e) => {
                println!("FAILED — parse error: {}", e);
                failed += 1;
                continue;
            }
        };

        let wrapper = AquaTreeWrapper::new(tree, None, None);
        let state_nodes = match aquafier.verify_and_build_state(wrapper, vec![]).await {
            Ok((_result, nodes)) => nodes,
            Err(e) => {
                println!("FAILED — verify error: {}", e);
                failed += 1;
                continue;
            }
        };

        let node_count = state_nodes.len();
        let ordered = topological_order(state_nodes);

        {
            let mut forest = ef.forest.lock().unwrap();
            for node in ordered {
                forest.insert_node(node);
            }
        }

        ef.touch();
        ingested += 1;
        println!("OK  ({} node(s))", node_count);
    }

    println!();

    let forest = ef.forest.lock().unwrap();
    let summary = forest.summary();

    println!("Ephemeral Forest Summary");
    println!("========================");
    println!("  Session     : {}", ef.id);
    println!("  Namespace   : {}", summary.namespace_name);
    println!("  Owner key   : {}", summary.namespace_key);
    println!("  Files       : {} ingested, {} failed", ingested, failed);
    println!("  Nodes       : {}", summary.node_count);
    println!("  Geneses     : {}", summary.genesis_count);
    println!("  Contracts   : {}", summary.contract_count);
    println!("  L3 pending  : {}", summary.pending_count);

    // Genesis trees
    let genesis_hashes = forest.genesis_hashes();
    if !genesis_hashes.is_empty() {
        println!();
        println!("Genesis trees ({}):", genesis_hashes.len());
        for gh in &genesis_hashes {
            println!("  {}", gh);
        }
    }

    // Tip revisions (leaves with no children)
    let tips = forest.tips();
    if !tips.is_empty() {
        println!();
        println!("Tip revisions ({}):", tips.len());
        for tip in &tips {
            println!("  {}", tip);
        }
    }

    // Unresolved L3 cross-tree dependencies
    let pending = forest.pending_dependencies();
    if !pending.is_empty() {
        println!();
        println!("Unresolved L3 dependencies ({}):", pending.len());
        for (awaited, owners) in pending {
            println!("  awaited : {}", awaited);
            for owner in owners {
                println!("    owner : {}", owner);
            }
        }
    } else if summary.genesis_count > 0 {
        println!();
        println!("  L3: all cross-tree links resolved.");
    }

    // Verbose: print each node's revision type and signer
    if args.verbose {
        println!();
        println!("Node details:");
        for gh in &genesis_hashes {
            print_node_subtree(&forest, gh, 0);
        }
    }

    // Outcome line
    println!();
    if failed == 0 && summary.node_count > 0 {
        println!("Forest built successfully.");
    } else if failed > 0 && ingested == 0 {
        eprintln!("All files failed to ingest.");
        std::process::exit(1);
    } else if failed > 0 {
        println!("Forest built with {} error(s).", failed);
    }

    // Output file support
    if let Some(output_path) = &args.output {
        let report = build_forest_report(&summary, &genesis_hashes, &tips, pending);
        match fs::write(output_path, report) {
            Ok(_) => println!("Report written to {:?}", output_path),
            Err(e) => eprintln!("Failed to write report: {}", e),
        }
    }
}

/// Recursively print a node and its children with indentation (verbose mode).
fn print_node_subtree(
    forest: &aqua_rs_sdk::daemon::Forest,
    hash: &aqua_rs_sdk::primitives::RevisionLink,
    depth: usize,
) {
    let indent = "  ".repeat(depth + 1);
    if let Some(node) = forest.get_state_node(hash) {
        let signer = node.signer.as_deref().unwrap_or("-");
        let rev_type = truncate(&node.revision_type, 12);
        println!("{}[{}] type={} signer={}", indent, truncate(&hash.to_string(), 14), rev_type, signer);
        for child in forest.branches(hash) {
            let child_hash: aqua_rs_sdk::primitives::RevisionLink =
                child.state.revision_hash.parse().unwrap();
            print_node_subtree(forest, &child_hash, depth + 1);
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

/// Serialize a basic JSON report for --output support.
fn build_forest_report(
    summary: &aqua_rs_sdk::daemon::ForestSummary,
    genesis_hashes: &[aqua_rs_sdk::primitives::RevisionLink],
    tips: &[aqua_rs_sdk::primitives::RevisionLink],
    pending: &std::collections::HashMap<
        aqua_rs_sdk::primitives::RevisionLink,
        Vec<aqua_rs_sdk::primitives::RevisionLink>,
    >,
) -> String {
    let genesis_list: Vec<String> = genesis_hashes.iter().map(|h| h.to_string()).collect();
    let tip_list: Vec<String> = tips.iter().map(|h| h.to_string()).collect();
    let pending_list: Vec<serde_json::Value> = pending
        .iter()
        .map(|(awaited, owners)| {
            serde_json::json!({
                "awaited": awaited.to_string(),
                "owners": owners.iter().map(|o| o.to_string()).collect::<Vec<_>>(),
            })
        })
        .collect();

    let report = serde_json::json!({
        "session": summary.namespace_name,
        "namespace_key": summary.namespace_key,
        "node_count": summary.node_count,
        "genesis_count": summary.genesis_count,
        "contract_count": summary.contract_count,
        "l3_pending_count": summary.pending_count,
        "genesis_hashes": genesis_list,
        "tips": tip_list,
        "l3_pending": pending_list,
    });

    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}
