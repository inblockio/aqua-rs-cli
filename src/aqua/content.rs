use std::fs;
use std::path::PathBuf;

use crate::models::{
    create_version_string, AquaTree, BaseRevision, CliArgs, ContentRevision, HashingMethod,
    TreeMapping,
};
use crate::utils::{
    calculate_revision_hash, generate_file_hash, generate_nonce, generate_timestamp,
    save_aqua_tree, save_logs_to_file,
};
use aqua_verifier::aqua_verifier::AquaVerifier;
use std::collections::HashMap;

/// Generate a content revision from a file
///
/// Content revisions are file references without embedded content,
/// suitable for large files or when you want to keep content separate
pub fn cli_generate_content_revision(
    args: CliArgs,
    _aqua_verifier: AquaVerifier,
    domain_id: String,
    file_path: PathBuf,
) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push("Starting content revision generation".to_string());

    match process_content_revision(&args, file_path, &domain_id, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Content revision generation completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in content revision generation: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

/// Process content revision generation
fn process_content_revision(
    _args: &CliArgs,
    file_path: PathBuf,
    _domain_id: &str,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    // Read file content for hash calculation
    let file_content = fs::read(&file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?;

    logs_data.push(format!("Processing file: {}", file_name));
    logs_data.push(format!("File size: {} bytes", file_content.len()));

    // Generate nonce and calculate file hash
    let file_nonce = generate_nonce();
    let file_hash = generate_file_hash(&file_content, &file_nonce);

    logs_data.push(format!("Generated file hash: {}", file_hash));
    logs_data.push("Creating content revision (no embedded content)".to_string());

    // Create content revision
    let content_revision = ContentRevision {
        base: BaseRevision {
            previous_verification_hash: String::new(), // Genesis revision
            local_timestamp: generate_timestamp(),
            revision_type: "content".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        file_hash: file_hash.clone(),
        file_nonce,
    };

    // Serialize revision to calculate hash
    let revision_json = serde_json::to_string(&content_revision)
        .map_err(|e| format!("Failed to serialize revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;
    logs_data.push(format!("Generated revision hash: {}", revision_hash));

    // Create AquaTree structure
    let mut revisions = HashMap::new();
    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;
    revisions.insert(revision_hash.clone(), revision_value);

    let mut file_index = HashMap::new();
    file_index.insert(revision_hash.clone(), file_name.to_string());

    let mut paths = HashMap::new();
    paths.insert(revision_hash.clone(), vec![revision_hash.clone()]);

    let tree_mapping = TreeMapping {
        paths,
        latest_hash: revision_hash.clone(),
    };

    let aqua_tree = AquaTree {
        revisions,
        file_index,
        tree_mapping,
    };

    // Save AquaTree
    save_aqua_tree(&aqua_tree, &file_path, "content")
        .map_err(|e| format!("Failed to save AquaTree: {}", e))?;

    logs_data.push("Content revision saved successfully".to_string());
    Ok(())
}

/// Add content revision to existing AquaTree
pub fn add_content_revision_to_aqua_tree(
    existing_tree: &mut AquaTree,
    file_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<String, String> {
    // Read file content
    let file_content = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?;

    // Generate nonce and hash
    let file_nonce = generate_nonce();
    let file_hash = generate_file_hash(&file_content, &file_nonce);

    // Get previous hash from existing tree
    let previous_hash = existing_tree.tree_mapping.latest_hash.clone();

    // Create new content revision
    let content_revision = ContentRevision {
        base: BaseRevision {
            previous_verification_hash: previous_hash,
            local_timestamp: generate_timestamp(),
            revision_type: "content".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        file_hash: file_hash.clone(),
        file_nonce,
    };

    // Serialize and hash
    let revision_json = serde_json::to_string(&content_revision)
        .map_err(|e| format!("Failed to serialize revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;

    // Add to existing tree
    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;

    existing_tree
        .revisions
        .insert(revision_hash.clone(), revision_value);
    existing_tree
        .file_index
        .insert(revision_hash.clone(), file_name.to_string());

    // Update tree mapping
    let mut path = existing_tree
        .tree_mapping
        .paths
        .get(&existing_tree.tree_mapping.latest_hash)
        .cloned()
        .unwrap_or_default();
    path.push(revision_hash.clone());

    existing_tree
        .tree_mapping
        .paths
        .insert(revision_hash.clone(), path);
    existing_tree.tree_mapping.latest_hash = revision_hash.clone();

    logs_data.push(format!("Added content revision: {}", revision_hash));
    Ok(revision_hash)
}

/// Update existing file to content revision
pub fn update_file_to_content_revision(args: CliArgs, aqua_tree_path: PathBuf, file_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push("Updating existing AquaTree with content revision".to_string());

    match process_content_update(&args, aqua_tree_path, file_path, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Content revision update completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in content revision update: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

fn process_content_update(
    _args: &CliArgs,
    aqua_tree_path: PathBuf,
    file_path: PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    // Read existing AquaTree
    let mut aqua_tree = crate::utils::read_aqua_data(&aqua_tree_path)?;

    // Add content revision
    let revision_hash = add_content_revision_to_aqua_tree(&mut aqua_tree, &file_path, logs_data)?;

    // Save updated AquaTree
    save_aqua_tree(&aqua_tree, &aqua_tree_path, "updated")
        .map_err(|e| format!("Failed to save updated AquaTree: {}", e))?;

    logs_data.push(format!("Updated AquaTree with revision: {}", revision_hash));
    Ok(())
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
