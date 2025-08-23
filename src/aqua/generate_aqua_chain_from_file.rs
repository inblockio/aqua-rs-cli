use std::fs;
use std::path::PathBuf;

use crate::models::{
    create_version_string, AquaTree, BaseRevision, CliArgs, FileRevision, HashingMethod,
    TreeMapping,
};
use crate::utils::{
    calculate_revision_hash, generate_file_hash, generate_nonce, generate_timestamp,
    save_aqua_tree, save_logs_to_file,
};
use aqua_verifier::aqua_verifier::AquaVerifier;
use std::collections::HashMap;

/// Generate an Aqua chain from a file (v3 format)
/// Creates a file revision which can optionally include embedded content
pub fn cli_generate_aqua_chain(
    args: CliArgs,
    _aqua_verifier: AquaVerifier,
    domain_id: String,
    file_path: PathBuf,
) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push(format!(
        "Starting Aqua chain generation for: {:?}",
        file_path
    ));

    match process_file_generation(&args, file_path, &domain_id, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Aqua chain generation completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in Aqua chain generation: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

/// Process file chain generation
fn process_file_generation(
    args: &CliArgs,
    file_path: PathBuf,
    domain_id: &str,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    // Read file content
    let file_content = fs::read(&file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?;

    logs_data.push(format!("Processing file: {}", file_name));
    logs_data.push(format!("File size: {} bytes", file_content.len()));

    // Determine if we should embed content (based on file size)
    let embed_content = should_embed_content(&file_content, logs_data);

    // Generate nonce and calculate file hash
    let file_nonce = generate_nonce();
    let file_hash = generate_file_hash(&file_content, &file_nonce);

    logs_data.push(format!("Generated file hash: {}", file_hash));
    logs_data.push(format!("File nonce: {}", file_nonce));

    // Create file revision
    let file_revision = FileRevision {
        base: BaseRevision {
            previous_verification_hash: String::new(), // Genesis revision
            local_timestamp: generate_timestamp(),
            revision_type: "file".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        content: if embed_content {
            Some(base64::encode(&file_content))
        } else {
            None
        },
        file_hash: file_hash.clone(),
        file_nonce,
    };

    if embed_content {
        logs_data.push("Content embedded in revision".to_string());
    } else {
        logs_data.push("Content not embedded (file reference only)".to_string());
    }

    // Serialize revision to calculate hash
    let revision_json = serde_json::to_string(&file_revision)
        .map_err(|e| format!("Failed to serialize revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;
    logs_data.push(format!("Generated revision hash: {}", revision_hash));

    // Create AquaTree structure
    let aqua_tree = create_initial_aqua_tree(
        revision_hash.clone(),
        revision_json,
        file_name.to_string(),
        logs_data,
    )?;

    // Save AquaTree
    save_aqua_tree(&aqua_tree, &file_path, "chain")
        .map_err(|e| format!("Failed to save AquaTree: {}", e))?;

    logs_data.push("Aqua chain saved successfully".to_string());
    Ok(())
}

/// Determine if content should be embedded based on size and type
fn should_embed_content(file_content: &[u8], logs_data: &mut Vec<String>) -> bool {
    const MAX_EMBED_SIZE: usize = 1024 * 1024; // 1MB limit for embedding

    if file_content.len() > MAX_EMBED_SIZE {
        logs_data.push(format!(
            "File too large ({} bytes) for embedding, creating reference only",
            file_content.len()
        ));
        return false;
    }

    // Check if content appears to be binary
    let is_likely_text = file_content
        .iter()
        .take(1024)
        .all(|&b| b.is_ascii() || b == b'\n' || b == b'\r' || b == b'\t');

    if !is_likely_text {
        logs_data.push("Binary content detected, creating reference only".to_string());
        return false;
    }

    logs_data.push("Content suitable for embedding".to_string());
    true
}

/// Create initial AquaTree structure
fn create_initial_aqua_tree(
    revision_hash: String,
    revision_json: String,
    file_name: String,
    logs_data: &mut Vec<String>,
) -> Result<AquaTree, String> {
    logs_data.push("Creating AquaTree structure...".to_string());

    // Create revisions map
    let mut revisions = HashMap::new();
    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;
    revisions.insert(revision_hash.clone(), revision_value);

    // Create file index
    let mut file_index = HashMap::new();
    file_index.insert(revision_hash.clone(), file_name);

    // Create tree mapping
    let mut paths = HashMap::new();
    paths.insert(revision_hash.clone(), vec![revision_hash.clone()]);

    let tree_mapping = TreeMapping {
        paths,
        latest_hash: revision_hash.clone(),
    };

    logs_data.push("AquaTree structure created".to_string());

    Ok(AquaTree {
        revisions,
        file_index,
        tree_mapping,
    })
}

/// Add file revision to existing AquaTree
pub fn add_file_revision_to_aqua_tree(
    existing_tree: &mut AquaTree,
    file_path: &PathBuf,
    embed_content: Option<bool>,
    logs_data: &mut Vec<String>,
) -> Result<String, String> {
    // Read file content
    let file_content = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?;

    // Determine if content should be embedded
    let should_embed =
        embed_content.unwrap_or_else(|| should_embed_content(&file_content, logs_data));

    // Generate nonce and hash
    let file_nonce = generate_nonce();
    let file_hash = generate_file_hash(&file_content, &file_nonce);

    // Get previous hash from existing tree
    let previous_hash = existing_tree.tree_mapping.latest_hash.clone();

    // Create new file revision
    let file_revision = FileRevision {
        base: BaseRevision {
            previous_verification_hash: previous_hash,
            local_timestamp: generate_timestamp(),
            revision_type: "file".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        content: if should_embed {
            Some(base64::encode(&file_content))
        } else {
            None
        },
        file_hash: file_hash.clone(),
        file_nonce,
    };

    // Serialize and hash
    let revision_json = serde_json::to_string(&file_revision)
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

    logs_data.push(format!("Added file revision: {}", revision_hash));
    Ok(revision_hash)
}

/// Update existing file with new revision
pub fn update_aqua_chain_with_file(args: CliArgs, aqua_tree_path: PathBuf, new_file_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push("Updating existing AquaTree with new file revision".to_string());

    match process_chain_update(&args, aqua_tree_path, new_file_path, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Chain update completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in chain update: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

fn process_chain_update(
    args: &CliArgs,
    aqua_tree_path: PathBuf,
    new_file_path: PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    // Read existing AquaTree
    let mut aqua_tree = crate::utils::read_aqua_data(&aqua_tree_path)?;

    // Add new file revision
    let revision_hash =
        add_file_revision_to_aqua_tree(&mut aqua_tree, &new_file_path, None, logs_data)?;

    // Save updated AquaTree
    save_aqua_tree(&aqua_tree, &aqua_tree_path, "updated")
        .map_err(|e| format!("Failed to save updated AquaTree: {}", e))?;

    logs_data.push(format!("Updated AquaTree with revision: {}", revision_hash));
    Ok(())
}

/// Create file revision from raw content (for programmatic use)
pub fn create_file_revision_from_content(
    content: Vec<u8>,
    filename: String,
    previous_hash: Option<String>,
    embed_content: bool,
) -> Result<(String, serde_json::Value), String> {
    // Generate nonce and hash
    let file_nonce = generate_nonce();
    let file_hash = generate_file_hash(&content, &file_nonce);

    // Create file revision
    let file_revision = FileRevision {
        base: BaseRevision {
            previous_verification_hash: previous_hash.unwrap_or_default(),
            local_timestamp: generate_timestamp(),
            revision_type: "file".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        content: if embed_content {
            Some(base64::encode(&content))
        } else {
            None
        },
        file_hash,
        file_nonce,
    };

    // Serialize and hash
    let revision_json = serde_json::to_string(&file_revision)
        .map_err(|e| format!("Failed to serialize revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;

    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;

    Ok((revision_hash, revision_value))
}

/// Extract embedded content from file revision
pub fn extract_embedded_content(revision: &serde_json::Value) -> Result<Option<Vec<u8>>, String> {
    if let Some(content_b64) = revision.get("content").and_then(|v| v.as_str()) {
        let content = base64::decode(content_b64)
            .map_err(|e| format!("Failed to decode embedded content: {}", e))?;
        Ok(Some(content))
    } else {
        Ok(None)
    }
}

/// Validate file hash integrity
pub fn validate_file_hash(
    revision: &serde_json::Value,
    actual_content: &[u8],
) -> Result<bool, String> {
    let stored_hash = revision
        .get("file_hash")
        .and_then(|v| v.as_str())
        .ok_or("Missing file_hash in revision")?;

    let file_nonce = revision
        .get("file_nonce")
        .and_then(|v| v.as_str())
        .ok_or("Missing file_nonce in revision")?;

    let computed_hash = generate_file_hash(actual_content, file_nonce);
    Ok(stored_hash == computed_hash)
}

/// Get file information from revision
pub fn get_file_info_from_revision(revision: &serde_json::Value) -> Option<FileInfo> {
    Some(FileInfo {
        file_hash: revision.get("file_hash")?.as_str()?.to_string(),
        file_nonce: revision.get("file_nonce")?.as_str()?.to_string(),
        has_embedded_content: revision.get("content").is_some(),
        revision_type: revision.get("revision_type")?.as_str()?.to_string(),
        timestamp: revision.get("local_timestamp")?.as_str()?.to_string(),
    })
}

pub struct FileInfo {
    pub file_hash: String,
    pub file_nonce: String,
    pub has_embedded_content: bool,
    pub revision_type: String,
    pub timestamp: String,
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

    #[test]
    fn test_should_embed_content() {
        let mut logs = Vec::new();

        // Small text content should be embedded
        let small_text = b"Hello, world!";
        assert!(should_embed_content(small_text, &mut logs));

        // Large content should not be embedded
        let large_content = vec![0u8; 2 * 1024 * 1024]; // 2MB
        assert!(!should_embed_content(&large_content, &mut logs));

        // Binary content should not be embedded
        let binary_content = vec![0, 255, 128, 64, 32, 16, 8, 4, 2, 1];
        assert!(!should_embed_content(&binary_content, &mut logs));
    }

    #[test]
    fn test_file_revision_creation() {
        let content = b"Test file content";
        let filename = "test.txt".to_string();

        let result = create_file_revision_from_content(content.to_vec(), filename, None, true);

        assert!(result.is_ok());
        let (hash, revision) = result.unwrap();

        assert!(!hash.is_empty());
        assert!(revision.get("file_hash").is_some());
        assert!(revision.get("content").is_some());
        assert_eq!(
            revision.get("revision_type").unwrap().as_str().unwrap(),
            "file"
        );
    }

    #[test]
    fn test_embedded_content_extraction() {
        let content = b"Test content";
        let encoded = base64::encode(content);

        let revision = serde_json::json!({
            "content": encoded,
            "file_hash": "test_hash"
        });

        let extracted = extract_embedded_content(&revision).unwrap();
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap(), content);
    }

    #[test]
    fn test_file_hash_validation() {
        let content = b"Test content";
        let nonce = "test_nonce";
        let hash = generate_file_hash(content, nonce);

        let revision = serde_json::json!({
            "file_hash": hash,
            "file_nonce": nonce
        });

        assert!(validate_file_hash(&revision, content).unwrap());

        // Test with wrong content
        let wrong_content = b"Wrong content";
        assert!(!validate_file_hash(&revision, wrong_content).unwrap());
    }
}
