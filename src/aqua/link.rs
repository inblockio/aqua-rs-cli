use std::path::PathBuf;

use crate::models::{
    create_version_string, AquaTree, BaseRevision, CliArgs, HashingMethod, LinkRevision,
    TreeMapping,
};
use crate::utils::{
    calculate_revision_hash, generate_timestamp, read_aqua_data, save_aqua_tree, save_logs_to_file,
};
use aqua_verifier::aqua_verifier::AquaVerifier;
use std::collections::HashMap;

/// Generate a link revision to reference other Aqua chains
pub fn cli_generate_link_revision(
    args: CliArgs,
    _aqua_verifier: AquaVerifier,
    source_path: PathBuf,
    target_path: PathBuf,
) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push("Starting link revision generation".to_string());

    match process_link_revision(&args, source_path, target_path, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Link revision generation completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in link revision generation: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

/// Process link revision generation
fn process_link_revision(
    _args: &CliArgs,
    source_path: PathBuf,
    target_path: PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push(format!("Creating link from source: {:?}", source_path));
    logs_data.push(format!("Linking to target: {:?}", target_path));

    // Read target AquaTree to get verification hashes
    let target_tree = read_aqua_data(&target_path)?;
    logs_data.push("Successfully read target AquaTree".to_string());

    // Extract verification hashes and file hashes from target
    let link_data = extract_link_data(&target_tree, logs_data)?;

    // Check if source is an existing AquaTree or a new file
    let mut source_tree = if source_path.exists()
        && source_path.extension().and_then(|e| e.to_str()) == Some("json")
    {
        // Existing AquaTree
        read_aqua_data(&source_path)?
    } else {
        // New file - create initial AquaTree
        create_initial_aqua_tree_for_link(&source_path, logs_data)?
    };

    // Add link revision to source tree
    let link_revision_hash = add_link_revision_to_tree(&mut source_tree, link_data, logs_data)?;

    // Save updated source tree
    save_aqua_tree(&source_tree, &source_path, "linked")
        .map_err(|e| format!("Failed to save linked AquaTree: {}", e))?;

    logs_data.push(format!("Link revision created: {}", link_revision_hash));
    Ok(())
}

/// Link data extracted from target AquaTree
struct LinkData {
    verification_hashes: Vec<String>,
    file_hashes: Vec<String>,
}

/// Extract link data from target AquaTree
fn extract_link_data(
    target_tree: &AquaTree,
    logs_data: &mut Vec<String>,
) -> Result<LinkData, String> {
    let mut verification_hashes = Vec::new();
    let mut file_hashes = Vec::new();

    // Extract verification hashes (revision keys)
    for hash in target_tree.revisions.keys() {
        verification_hashes.push(hash.clone());
    }

    // Extract file hashes from file/content revisions
    for revision in target_tree.revisions.values() {
        if let Some(revision_type) = revision.get("revision_type").and_then(|v| v.as_str()) {
            if revision_type == "file" || revision_type == "content" {
                if let Some(file_hash) = revision.get("file_hash").and_then(|v| v.as_str()) {
                    if !file_hashes.contains(&file_hash.to_string()) {
                        file_hashes.push(file_hash.to_string());
                    }
                }
            }
        }
    }

    logs_data.push(format!(
        "Found {} verification hashes",
        verification_hashes.len()
    ));
    logs_data.push(format!("Found {} unique file hashes", file_hashes.len()));

    if verification_hashes.is_empty() {
        return Err("No verification hashes found in target AquaTree".to_string());
    }

    Ok(LinkData {
        verification_hashes,
        file_hashes,
    })
}

/// Create initial AquaTree for a new file when creating link
fn create_initial_aqua_tree_for_link(
    _source_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<AquaTree, String> {
    // For link operations on new files, we create a minimal initial structure
    // This will be extended by the link revision
    logs_data.push("Creating initial AquaTree for new file".to_string());

    let revisions = HashMap::new();
    let file_index = HashMap::new();
    let paths = HashMap::new();

    let tree_mapping = TreeMapping {
        paths,
        latest_hash: String::new(), // Will be set when link revision is added
    };

    Ok(AquaTree {
        revisions,
        file_index,
        tree_mapping,
    })
}

/// Add link revision to AquaTree
fn add_link_revision_to_tree(
    tree: &mut AquaTree,
    link_data: LinkData,
    logs_data: &mut Vec<String>,
) -> Result<String, String> {
    // Get previous hash (empty if this is the first revision)
    let previous_hash = if tree.tree_mapping.latest_hash.is_empty() {
        String::new()
    } else {
        tree.tree_mapping.latest_hash.clone()
    };

    // Create link revision
    let link_revision = LinkRevision {
        base: BaseRevision {
            previous_verification_hash: previous_hash.clone(),
            local_timestamp: generate_timestamp(),
            revision_type: "link".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        link_type: "aqua".to_string(), // Standard aqua link type
        link_verification_hashes: link_data.verification_hashes.clone(),
        link_file_hashes: link_data.file_hashes.clone(),
    };

    // Serialize and hash
    let revision_json = serde_json::to_string(&link_revision)
        .map_err(|e| format!("Failed to serialize link revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;

    // Add to tree
    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;

    tree.revisions.insert(revision_hash.clone(), revision_value);

    // Update tree mapping
    let path = if previous_hash.is_empty() {
        vec![revision_hash.clone()]
    } else {
        let mut existing_path = tree
            .tree_mapping
            .paths
            .get(&previous_hash)
            .cloned()
            .unwrap_or_else(|| vec![previous_hash.clone()]);
        existing_path.push(revision_hash.clone());
        existing_path
    };

    tree.tree_mapping.paths.insert(revision_hash.clone(), path);
    tree.tree_mapping.latest_hash = revision_hash.clone();

    logs_data.push(format!(
        "Linked {} verification hashes",
        link_data.verification_hashes.len()
    ));
    logs_data.push(format!(
        "Linked {} file hashes",
        link_data.file_hashes.len()
    ));

    Ok(revision_hash)
}

/// Add link revision to existing AquaTree (utility function)
pub fn add_link_revision_to_aqua_tree(
    existing_tree: &mut AquaTree,
    target_tree: &AquaTree,
    logs_data: &mut Vec<String>,
) -> Result<String, String> {
    let link_data = extract_link_data(target_tree, logs_data)?;
    add_link_revision_to_tree(existing_tree, link_data, logs_data)
}

/// Link multiple AquaTrees to a source
pub fn link_multiple_targets(args: CliArgs, source_path: PathBuf, target_paths: Vec<PathBuf>) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push("Starting multiple link revision generation".to_string());

    match process_multiple_links(&args, source_path, target_paths, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Multiple link revisions completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in multiple link generation: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

fn process_multiple_links(
    _args: &CliArgs,
    source_path: PathBuf,
    target_paths: Vec<PathBuf>,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    // Read or create source tree
    let mut source_tree = if source_path.exists() {
        read_aqua_data(&source_path)?
    } else {
        create_initial_aqua_tree_for_link(&source_path, logs_data)?
    };

    // Process each target
    for target_path in target_paths {
        logs_data.push(format!("Processing target: {:?}", target_path));

        let target_tree = read_aqua_data(&target_path)?;
        let _link_hash = add_link_revision_to_aqua_tree(&mut source_tree, &target_tree, logs_data)?;
    }

    // Save final result
    save_aqua_tree(&source_tree, &source_path, "multi-linked")
        .map_err(|e| format!("Failed to save multi-linked AquaTree: {}", e))?;

    Ok(())
}

/// Validate link revision integrity
pub fn validate_link_revision(
    link_revision: &LinkRevision,
    available_trees: &HashMap<String, AquaTree>,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push("Validating link revision integrity".to_string());

    // Check that referenced verification hashes exist
    for verification_hash in &link_revision.link_verification_hashes {
        let mut found = false;
        for tree in available_trees.values() {
            if tree.revisions.contains_key(verification_hash) {
                found = true;
                break;
            }
        }

        if !found {
            return Err(format!(
                "Linked verification hash not found: {}",
                verification_hash
            ));
        }
    }

    // Check that referenced file hashes exist
    for file_hash in &link_revision.link_file_hashes {
        let mut found = false;
        for tree in available_trees.values() {
            for revision in tree.revisions.values() {
                if let Some(rev_file_hash) = revision.get("file_hash").and_then(|v| v.as_str()) {
                    if rev_file_hash == file_hash {
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
        }

        if !found {
            logs_data.push(format!(
                "Warning: Linked file hash not found: {}",
                file_hash
            ));
        }
    }

    logs_data.push("Link revision validation completed".to_string());
    Ok(())
}

/// Get all linked trees from a link revision
pub fn get_linked_trees(
    link_revision: &LinkRevision,
    available_trees: &HashMap<String, AquaTree>,
) -> Vec<String> {
    let mut linked_tree_ids = Vec::new();

    for verification_hash in &link_revision.link_verification_hashes {
        for (tree_id, tree) in available_trees {
            if tree.revisions.contains_key(verification_hash) {
                if !linked_tree_ids.contains(tree_id) {
                    linked_tree_ids.push(tree_id.clone());
                }
            }
        }
    }

    linked_tree_ids
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
    use crate::models::{AquaTree, TreeMapping};
    use serde_json::json;

    #[test]
    fn test_link_data_extraction() {
        let mut revisions = HashMap::new();
        revisions.insert(
            "0x123".to_string(),
            json!({
                "revision_type": "file",
                "file_hash": "abc123"
            }),
        );
        revisions.insert(
            "0x456".to_string(),
            json!({
                "revision_type": "signature",
                "signature": "def456"
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

        let mut logs = Vec::new();
        let link_data = extract_link_data(&tree, &mut logs).unwrap();

        assert_eq!(link_data.verification_hashes.len(), 2);
        assert_eq!(link_data.file_hashes.len(), 1);
        assert!(link_data.verification_hashes.contains(&"0x123".to_string()));
        assert!(link_data.verification_hashes.contains(&"0x456".to_string()));
        assert!(link_data.file_hashes.contains(&"abc123".to_string()));
    }

    #[test]
    fn test_get_linked_trees() {
        let link_revision = LinkRevision {
            base: BaseRevision {
                previous_verification_hash: "".to_string(),
                local_timestamp: "20240101120000".to_string(),
                revision_type: "link".to_string(),
                version: "test".to_string(),
            },
            link_type: "aqua".to_string(),
            link_verification_hashes: vec!["0x123".to_string()],
            link_file_hashes: vec![],
        };

        let mut tree1_revisions = HashMap::new();
        tree1_revisions.insert("0x123".to_string(), json!({}));

        let tree1 = AquaTree {
            revisions: tree1_revisions,
            file_index: HashMap::new(),
            tree_mapping: TreeMapping {
                paths: HashMap::new(),
                latest_hash: "0x123".to_string(),
            },
        };

        let mut available_trees = HashMap::new();
        available_trees.insert("tree1".to_string(), tree1);

        let linked = get_linked_trees(&link_revision, &available_trees);
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0], "tree1");
    }
}
