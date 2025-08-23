use std::path::PathBuf;

use crate::models::{AquaTree, CliArgs};
use crate::utils::{read_aqua_data, save_aqua_tree, save_logs_to_file};
use aqua_verifier::aqua_verifier::AquaVerifier;

/// Removes specified number of revisions from an Aqua chain (v3 format)
pub fn cli_remove_revisions_from_aqua_chain(
    args: CliArgs,
    _aqua_verifier: AquaVerifier,
    aqua_chain_file_path: PathBuf,
) {
    let mut logs_data: Vec<String> = Vec::new();

    println!(
        "Starting revision removal from file: {:?}",
        aqua_chain_file_path
    );
    logs_data.push(format!(
        "Starting revision removal from: {:?}",
        aqua_chain_file_path
    ));

    match process_revision_removal(&args, aqua_chain_file_path, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Revision removal completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in revision removal: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

/// Process revision removal for v3 format
fn process_revision_removal(
    args: &CliArgs,
    aqua_chain_file_path: PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    let revision_count = args.remove_count;

    if revision_count <= 0 {
        return Err("Removal count must be positive".to_string());
    }

    logs_data.push(format!("Removing {} revision(s)", revision_count));

    // Read AquaTree
    let mut aqua_tree = read_aqua_data(&aqua_chain_file_path)?;

    // Validate tree before removal
    validate_removal_preconditions(&aqua_tree, revision_count, logs_data)?;

    // Perform removal
    remove_revisions_from_tree(&mut aqua_tree, revision_count, logs_data)?;

    // Save modified AquaTree
    save_aqua_tree(&aqua_tree, &aqua_chain_file_path, "modified")
        .map_err(|e| format!("Error saving modified AquaTree: {}", e))?;

    logs_data.push("Modified AquaTree saved successfully".to_string());
    Ok(())
}

/// Validate that removal is possible
fn validate_removal_preconditions(
    aqua_tree: &AquaTree,
    revision_count: i32,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push("Validating removal preconditions...".to_string());

    if aqua_tree.revisions.is_empty() {
        return Err("No revisions found in AquaTree".to_string());
    }

    let total_revisions = aqua_tree.revisions.len();
    logs_data.push(format!("Total revisions: {}", total_revisions));

    // Find genesis revision (cannot be removed)
    let genesis_count = count_genesis_revisions(aqua_tree);
    if genesis_count == 0 {
        return Err("No genesis revision found".to_string());
    }

    let removable_revisions = total_revisions - genesis_count;
    if revision_count as usize > removable_revisions {
        return Err(format!(
            "Cannot remove {} revisions. Only {} non-genesis revisions available",
            revision_count, removable_revisions
        ));
    }

    logs_data.push(format!(
        "Removal validation passed. {} revisions can be removed",
        removable_revisions
    ));
    Ok(())
}

/// Count genesis revisions in the tree
fn count_genesis_revisions(aqua_tree: &AquaTree) -> usize {
    aqua_tree
        .revisions
        .values()
        .filter(|revision| {
            revision
                .get("previous_verification_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.is_empty())
                .unwrap_or(false)
        })
        .count()
}

/// Remove revisions from the AquaTree
fn remove_revisions_from_tree(
    aqua_tree: &mut AquaTree,
    revision_count: i32,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push("Removing revisions from tree...".to_string());

    // Build removal chain starting from latest
    let removal_chain = build_removal_chain(aqua_tree, revision_count, logs_data)?;

    // Remove revisions from the tree
    for hash_to_remove in &removal_chain {
        aqua_tree.revisions.remove(hash_to_remove);
        logs_data.push(format!("Removed revision: {}", hash_to_remove));
    }

    // Update tree mapping
    update_tree_mapping_after_removal(aqua_tree, &removal_chain, logs_data)?;

    // Update file index
    update_file_index_after_removal(aqua_tree, &removal_chain, logs_data);

    logs_data.push(format!(
        "Successfully removed {} revisions",
        removal_chain.len()
    ));
    Ok(())
}

/// Build chain of revisions to remove (from latest backwards)
fn build_removal_chain(
    aqua_tree: &AquaTree,
    revision_count: i32,
    logs_data: &mut Vec<String>,
) -> Result<Vec<String>, String> {
    let mut removal_chain = Vec::new();
    let mut current_hash = aqua_tree.tree_mapping.latest_hash.clone();

    logs_data.push(format!(
        "Building removal chain starting from: {}",
        current_hash
    ));

    for i in 0..revision_count {
        if current_hash.is_empty() {
            return Err(format!("Reached end of chain after {} revisions", i));
        }

        let current_revision = aqua_tree
            .revisions
            .get(&current_hash)
            .ok_or_else(|| format!("Revision not found: {}", current_hash))?;

        // Check if this is a genesis revision (cannot remove)
        let prev_hash = current_revision
            .get("previous_verification_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if prev_hash.is_empty() {
            return Err(format!("Cannot remove genesis revision: {}", current_hash));
        }

        removal_chain.push(current_hash.clone());
        current_hash = prev_hash.to_string();
    }

    logs_data.push(format!(
        "Built removal chain with {} revisions",
        removal_chain.len()
    ));
    Ok(removal_chain)
}

/// Update tree mapping after removal
fn update_tree_mapping_after_removal(
    aqua_tree: &mut AquaTree,
    removal_chain: &[String],
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push("Updating tree mapping...".to_string());

    // Find new latest hash (the parent of the first removed revision)
    let first_removed = removal_chain.first().ok_or("Empty removal chain")?;

    let first_removed_revision = aqua_tree.revisions.get(first_removed).ok_or_else(|| {
        format!(
            "Revision not found during mapping update: {}",
            first_removed
        )
    })?;

    let new_latest_hash = first_removed_revision
        .get("previous_verification_hash")
        .and_then(|v| v.as_str())
        .ok_or("Cannot find previous hash for new latest")?
        .to_string();

    // Remove paths for removed revisions
    for removed_hash in removal_chain {
        aqua_tree.tree_mapping.paths.remove(removed_hash);
    }

    // Update latest hash
    aqua_tree.tree_mapping.latest_hash = new_latest_hash.clone();

    // Rebuild paths for remaining revisions
    rebuild_paths_from_latest(aqua_tree, logs_data)?;

    logs_data.push(format!("Updated latest hash to: {}", new_latest_hash));
    Ok(())
}

/// Rebuild paths from the new latest hash
fn rebuild_paths_from_latest(
    aqua_tree: &mut AquaTree,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    let latest_hash = aqua_tree.tree_mapping.latest_hash.clone();

    // Build path for the latest hash
    let path = build_path_to_genesis(aqua_tree, &latest_hash)?;
    aqua_tree.tree_mapping.paths.insert(latest_hash, path);

    logs_data.push("Rebuilt tree mapping paths".to_string());
    Ok(())
}

/// Build path from a given hash to genesis
fn build_path_to_genesis(aqua_tree: &AquaTree, start_hash: &str) -> Result<Vec<String>, String> {
    let mut path = Vec::new();
    let mut current_hash = start_hash.to_string();

    loop {
        path.insert(0, current_hash.clone());

        let current_revision = aqua_tree
            .revisions
            .get(&current_hash)
            .ok_or_else(|| format!("Revision not found while building path: {}", current_hash))?;

        let prev_hash = current_revision
            .get("previous_verification_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if prev_hash.is_empty() {
            // Reached genesis
            break;
        }

        current_hash = prev_hash.to_string();
    }

    Ok(path)
}

/// Update file index after removal
fn update_file_index_after_removal(
    aqua_tree: &mut AquaTree,
    removal_chain: &[String],
    logs_data: &mut Vec<String>,
) {
    let mut removed_files = 0;

    for removed_hash in removal_chain {
        if aqua_tree.file_index.remove(removed_hash).is_some() {
            removed_files += 1;
        }
    }

    logs_data.push(format!("Removed {} entries from file index", removed_files));
}

/// Remove specific revision by hash (utility function)
pub fn remove_revision_by_hash(
    aqua_tree: &mut AquaTree,
    revision_hash: &str,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push(format!("Removing specific revision: {}", revision_hash));

    // Check if revision exists
    if !aqua_tree.revisions.contains_key(revision_hash) {
        return Err(format!("Revision not found: {}", revision_hash));
    }

    // Check if it's genesis (cannot remove)
    let revision = aqua_tree.revisions.get(revision_hash).unwrap();
    if let Some(prev_hash) = revision
        .get("previous_verification_hash")
        .and_then(|v| v.as_str())
    {
        if prev_hash.is_empty() {
            return Err("Cannot remove genesis revision".to_string());
        }
    }

    // Check if removing this would break the chain
    let is_in_main_chain = is_revision_in_main_chain(aqua_tree, revision_hash);
    if is_in_main_chain {
        return Err(
            "Cannot remove revision from main chain without removing all descendants first"
                .to_string(),
        );
    }

    // Remove the revision
    aqua_tree.revisions.remove(revision_hash);
    aqua_tree.file_index.remove(revision_hash);
    aqua_tree.tree_mapping.paths.remove(revision_hash);

    logs_data.push("Revision removed successfully".to_string());
    Ok(())
}

/// Check if revision is part of the main chain
fn is_revision_in_main_chain(aqua_tree: &AquaTree, revision_hash: &str) -> bool {
    let latest_path = aqua_tree
        .tree_mapping
        .paths
        .get(&aqua_tree.tree_mapping.latest_hash)
        .cloned()
        .unwrap_or_default();

    latest_path.contains(&revision_hash.to_string())
}

/// Get removable revision count
pub fn get_removable_revision_count(aqua_tree: &AquaTree) -> usize {
    let total = aqua_tree.revisions.len();
    let genesis_count = count_genesis_revisions(aqua_tree);
    total - genesis_count
}

/// Output results based on CLI arguments
fn output_results(args: &CliArgs, logs_data: &Vec<String>) {
    if args.verbose {
        logs_data.iter().for_each(|log| println!("{}", log));
    } else if let Some(last_log) = logs_data.last() {
        println!("{}", last_log);
    }

    if let Some(output_path) = &args.output {
        if let Err(e) = save_logs_to_file(logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::TreeMapping;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn test_count_genesis_revisions() {
        let mut revisions = HashMap::new();
        revisions.insert(
            "0x123".to_string(),
            json!({
                "previous_verification_hash": ""
            }),
        );
        revisions.insert(
            "0x456".to_string(),
            json!({
                "previous_verification_hash": "0x123"
            }),
        );

        let tree = AquaTree {
            revisions,
            file_index: HashMap::new(),
            tree_mapping: TreeMapping {
                paths: HashMap::new(),
                latest_hash: "0x456".to_string(),
            },
        };

        assert_eq!(count_genesis_revisions(&tree), 1);
    }

    #[test]
    fn test_build_removal_chain() {
        let mut revisions = HashMap::new();
        revisions.insert(
            "0x123".to_string(),
            json!({
                "previous_verification_hash": ""
            }),
        );
        revisions.insert(
            "0x456".to_string(),
            json!({
                "previous_verification_hash": "0x123"
            }),
        );
        revisions.insert(
            "0x789".to_string(),
            json!({
                "previous_verification_hash": "0x456"
            }),
        );

        let tree = AquaTree {
            revisions,
            file_index: HashMap::new(),
            tree_mapping: TreeMapping {
                paths: HashMap::new(),
                latest_hash: "0x789".to_string(),
            },
        };

        let mut logs = Vec::new();
        let chain = build_removal_chain(&tree, 2, &mut logs).unwrap();

        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0], "0x789");
        assert_eq!(chain[1], "0x456");
    }

    #[test]
    fn test_build_path_to_genesis() {
        let mut revisions = HashMap::new();
        revisions.insert(
            "0x123".to_string(),
            json!({
                "previous_verification_hash": ""
            }),
        );
        revisions.insert(
            "0x456".to_string(),
            json!({
                "previous_verification_hash": "0x123"
            }),
        );
        revisions.insert(
            "0x789".to_string(),
            json!({
                "previous_verification_hash": "0x456"
            }),
        );

        let tree = AquaTree {
            revisions,
            file_index: HashMap::new(),
            tree_mapping: TreeMapping {
                paths: HashMap::new(),
                latest_hash: "0x789".to_string(),
            },
        };

        let path = build_path_to_genesis(&tree, "0x789").unwrap();

        assert_eq!(path.len(), 3);
        assert_eq!(path[0], "0x123");
        assert_eq!(path[1], "0x456");
        assert_eq!(path[2], "0x789");
    }

    #[test]
    fn test_get_removable_revision_count() {
        let mut revisions = HashMap::new();
        revisions.insert(
            "0x123".to_string(),
            json!({
                "previous_verification_hash": ""
            }),
        );
        revisions.insert(
            "0x456".to_string(),
            json!({
                "previous_verification_hash": "0x123"
            }),
        );

        let tree = AquaTree {
            revisions,
            file_index: HashMap::new(),
            tree_mapping: TreeMapping {
                paths: HashMap::new(),
                latest_hash: "0x456".to_string(),
            },
        };

        assert_eq!(get_removable_revision_count(&tree), 1);
    }
}
