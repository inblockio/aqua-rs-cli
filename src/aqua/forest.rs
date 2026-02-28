// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Ephemeral forest CLI command.
//!
//! `cli_ephemeral_forest` ingests one or more `.aqua.json` files into a
//! session-bound in-memory forest (backed by `StateNode` collections), then
//! prints a summary of the combined verified state: node counts, genesis
//! hashes, tip revisions, and any unresolved cross-tree dependencies.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use aqua_rs_sdk::daemon::topological_order;
use aqua_rs_sdk::policy::StateNode;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::AquaTreeWrapper;
use aqua_rs_sdk::Aquafier;

use crate::models::CliArgs;

extern crate serde_json_path_to_error as serde_json;

pub async fn cli_ephemeral_forest(args: CliArgs, aquafier: &Aquafier, files: Vec<PathBuf>) {
    println!("Building ephemeral forest from {} file(s)...", files.len());
    println!();

    let mut all_nodes: Vec<StateNode> = Vec::new();
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
        ingested += 1;
        println!("OK  ({} node(s))", node_count);
        all_nodes.extend(state_nodes);
    }

    println!();

    // Topological order all nodes across all files
    let ordered = topological_order(all_nodes);

    // Build index structures
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut genesis_hashes: Vec<String> = Vec::new();
    let node_map: HashMap<String, &StateNode> = ordered
        .iter()
        .map(|n| (n.revision_hash.clone(), n))
        .collect();

    for node in &ordered {
        match &node.parent_hash {
            Some(ph) => {
                children
                    .entry(ph.clone())
                    .or_default()
                    .push(node.revision_hash.clone());
            }
            None => {
                genesis_hashes.push(node.revision_hash.clone());
            }
        }
    }

    // Tips: nodes that are not referenced as anyone's parent
    let all_parents: HashSet<&String> = children.keys().collect();
    let tips: Vec<&str> = ordered
        .iter()
        .filter(|n| !all_parents.contains(&n.revision_hash))
        .map(|n| n.revision_hash.as_str())
        .collect();

    let node_count = ordered.len();

    println!("Ephemeral Forest Summary");
    println!("========================");
    println!("  Session     : cli:session");
    println!("  Files       : {} ingested, {} failed", ingested, failed);
    println!("  Nodes       : {}", node_count);
    println!("  Geneses     : {}", genesis_hashes.len());

    // Genesis trees
    if !genesis_hashes.is_empty() {
        println!();
        println!("Genesis trees ({}):", genesis_hashes.len());
        for gh in &genesis_hashes {
            println!("  {}", gh);
        }
    }

    // Tip revisions
    if !tips.is_empty() {
        println!();
        println!("Tip revisions ({}):", tips.len());
        for tip in &tips {
            println!("  {}", tip);
        }
    }

    // Outcome line
    println!();
    if failed == 0 && node_count > 0 {
        println!("Forest built successfully.");
    } else if failed > 0 && ingested == 0 {
        eprintln!("All files failed to ingest.");
        std::process::exit(1);
    } else if failed > 0 {
        println!("Forest built with {} error(s).", failed);
    }

    // Verbose: print each node subtree
    if args.verbose {
        println!();
        println!("Node details:");
        for gh in &genesis_hashes {
            print_node_subtree(gh, &node_map, &children, 0);
        }
    }

    // Output file support
    if let Some(output_path) = &args.output {
        let report = build_forest_report(&genesis_hashes, &tips, node_count);
        match fs::write(output_path, report) {
            Ok(_) => println!("Report written to {:?}", output_path),
            Err(e) => eprintln!("Failed to write report: {}", e),
        }
    }
}

/// Recursively print a node and its children with indentation (verbose mode).
fn print_node_subtree(
    hash: &str,
    node_map: &HashMap<String, &StateNode>,
    children: &HashMap<String, Vec<String>>,
    depth: usize,
) {
    let indent = "  ".repeat(depth + 1);
    if let Some(node) = node_map.get(hash) {
        let signer = node.signer.as_deref().unwrap_or("-");
        let rev_type = truncate(&node.revision_type, 12);
        println!(
            "{}[{}] type={} signer={}",
            indent,
            truncate(hash, 14),
            rev_type,
            signer
        );
        if let Some(child_hashes) = children.get(hash) {
            for child_hash in child_hashes {
                print_node_subtree(child_hash, node_map, children, depth + 1);
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

/// Serialize a basic JSON report for --output support.
fn build_forest_report(
    genesis_hashes: &[String],
    tips: &[&str],
    node_count: usize,
) -> String {
    let report = serde_json::json!({
        "session": "cli:session",
        "node_count": node_count,
        "genesis_count": genesis_hashes.len(),
        "genesis_hashes": genesis_hashes,
        "tips": tips,
    });

    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}
