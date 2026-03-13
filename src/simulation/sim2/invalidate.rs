// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Node removal / tree surgery for state-viewer invalidation demo.
//!
//! Loads a previously written `.aqua.json` tree from disk, surgically removes
//! the attester's signature revision, re-writes the modified tree, and prints
//! instructions for loading into the state-viewer to observe the state change
//! (e.g. `attested → unsigned`).

use std::path::{Path, PathBuf};

use aqua_rs_sdk::{
    primitives::HexString,
    schema::{tree::Tree, AnyRevision},
};

/// Known invalidation targets for `--simulate-2 --invalidate <target>`.
const KNOWN_TARGETS: &[(&str, &str)] = &[
    ("amara-attestation", "amara_attestation.aqua.json"),
    ("lars-attestation", "lars_attestation_untrusted.aqua.json"),
    ("priya-attestation-expired", "priya_attestation_expired.aqua.json"),
];

/// Run the invalidation sub-command.
///
/// `target` is the user-provided scenario name (e.g. "amara-attestation").
/// Searches for the latest `aqua-sim-*` directory in `/tmp` and operates on
/// the matching `.aqua.json` file.
pub fn run_invalidation(target: &str) {
    println!("SIM-2 Invalidation: {}", target);
    println!("{}", "─".repeat(24 + target.len()));
    println!();

    // Find matching file name
    let file_name = match KNOWN_TARGETS.iter().find(|(name, _)| *name == target) {
        Some((_, fname)) => *fname,
        None => {
            println!("  ERROR: unknown invalidation target '{}'", target);
            println!();
            println!("  Available targets:");
            for (name, fname) in KNOWN_TARGETS {
                println!("    {} → {}", name, fname);
            }
            return;
        }
    };

    // Find latest aqua-sim-* directory
    let sim_dir = match find_latest_sim_dir() {
        Some(d) => d,
        None => {
            println!("  ERROR: no aqua-sim-* directory found in /tmp");
            println!("  Run `--simulate-2 --keep` first to generate tree files.");
            return;
        }
    };

    let file_path = sim_dir.join(file_name);
    if !file_path.exists() {
        println!("  ERROR: file not found: {}", file_path.display());
        println!("  Run `--simulate-2 --keep` first to generate tree files.");
        return;
    }

    // Load tree
    let json_str = match std::fs::read_to_string(&file_path) {
        Ok(s) => s,
        Err(e) => {
            println!("  ERROR reading {}: {}", file_path.display(), e);
            return;
        }
    };
    let mut tree: Tree = match serde_json::from_str(&json_str) {
        Ok(t) => t,
        Err(e) => {
            println!("  ERROR parsing {}: {}", file_path.display(), e);
            return;
        }
    };

    // Find and remove signature revisions
    let sig_hashes: Vec<HexString<Vec<u8>>> = tree
        .revisions
        .iter()
        .filter(|(_, rev)| matches!(rev, AnyRevision::Signature(_)))
        .map(|(hash, _)| hash.clone())
        .collect();

    if sig_hashes.is_empty() {
        println!("  No signature revisions found in {} — nothing to remove.", file_name);
        return;
    }

    println!("  Found {} signature revision(s) to remove:", sig_hashes.len());
    for h in &sig_hashes {
        println!("    {}", h);
    }
    println!();

    // Remove signature revisions from the tree
    for h in &sig_hashes {
        tree.revisions.remove(h);
    }

    // Write modified tree back
    let modified_json = match serde_json::to_string_pretty(&tree) {
        Ok(j) => j,
        Err(e) => {
            println!("  ERROR serializing modified tree: {}", e);
            return;
        }
    };

    if let Err(e) = std::fs::write(&file_path, &modified_json) {
        println!("  ERROR writing {}: {}", file_path.display(), e);
        return;
    }

    println!("  Modified tree written to:");
    println!("  {}", file_path.display());
    println!();
    println!("  State change: attested → unsigned (signature node(s) removed)");
    println!();
    println!("  To observe in state-viewer:");
    println!("    1. Load the original dataset (before invalidation)");
    println!("    2. Run: cargo run --features simulation -- --simulate-2 --invalidate {}", target);
    println!("    3. Reload the file in the state-viewer to see the state transition");
}

/// Find the most recent `aqua-sim-*` directory in `/tmp`.
fn find_latest_sim_dir() -> Option<PathBuf> {
    let tmp = Path::new("/tmp");
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(tmp) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("aqua-sim-") && entry.path().is_dir() {
                candidates.push(entry.path());
            }
        }
    }

    // Sort by modification time, most recent first
    candidates.sort_by(|a, b| {
        let a_time = std::fs::metadata(a).and_then(|m| m.modified()).ok();
        let b_time = std::fs::metadata(b).and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    candidates.into_iter().next()
}
