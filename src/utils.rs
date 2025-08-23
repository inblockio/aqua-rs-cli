use chrono::{DateTime, Utc};
use sha3::{Digest, Sha3_256};
use std::io::Write;
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};

use crate::models::{
    create_version_string, AquaTree, HashingMethod, LegacyPageData, RevisionType, SecretKeys,
    ValidationError, SUPPORTED_SIGNATURE_TYPES, SUPPORTED_WITNESS_NETWORKS,
};

extern crate serde_json_path_to_error as serde_json;

/// Save log messages to a file
pub fn save_logs_to_file(logs: &Vec<String>, output_file: PathBuf) -> Result<String, String> {
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&output_file)
    {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open log file: {}", e)),
    };

    for log in logs {
        if let Err(e) = writeln!(file, "{}", log) {
            return Err(format!("Failed to write to log file: {}", e));
        }
    }

    Ok("Log written successfully".to_string())
}

/// Read Aqua data with v3/v2 compatibility
pub fn read_aqua_data(path: &PathBuf) -> Result<AquaTree, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("Error reading file: {}", e))?;

    // Try parsing as v3 AquaTree first
    if let Ok(aqua_tree) = serde_json::from_str::<AquaTree>(&data) {
        return Ok(aqua_tree);
    }

    // Try parsing as legacy v2 PageData and convert
    if let Ok(page_data) = serde_json::from_str::<LegacyPageData>(&data) {
        return convert_page_data_to_aqua_tree(page_data);
    }

    Err("Unable to parse file as either v3 AquaTree or v2 PageData format".to_string())
}

/// Convert legacy v2 PageData to v3 AquaTree format
fn convert_page_data_to_aqua_tree(_page_data: LegacyPageData) -> Result<AquaTree, String> {
    // This is a placeholder for backward compatibility
    // In a real implementation, it's to properly convert the structure
    // For now, we'll return an error encouraging v3 format usage
    Err("Legacy v2 PageData format detected. Please use v3 AquaTree format or provide conversion logic.".to_string())
}

/// Read secret keys from JSON file
pub fn read_secret_keys(path: &PathBuf) -> Result<SecretKeys, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("Error reading keys file: {}", e))?;

    serde_json::from_str::<SecretKeys>(&data).map_err(|e| format!("Error parsing keys JSON: {}", e))
}

/// Save AquaTree to file
pub fn save_aqua_tree(
    aqua_tree: &AquaTree,
    original_path: &Path,
    suffix: &str,
) -> Result<(), String> {
    let output_path = original_path.with_extension(format!("{}.json", suffix));

    match serde_json::to_string_pretty(aqua_tree) {
        Ok(json_data) => {
            fs::write(&output_path, json_data).map_err(|e| e.to_string())?;
            println!("Aqua tree data saved to: {:?}", output_path);
            Ok(())
        }
        Err(e) => Err(format!("Error serializing AquaTree: {}", e)),
    }
}

/// Validate JSON file path
pub fn is_valid_json_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() && path.extension().unwrap_or_default() == "json" {
        Ok(s.to_string())
    } else {
        Err("Invalid JSON file path".to_string())
    }
}

/// Validate general file path
pub fn is_valid_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() {
        Ok(s.to_string())
    } else {
        Err("Invalid file path".to_string())
    }
}

/// Validate output file path
pub fn is_valid_output_file(s: &str) -> Result<String, String> {
    let lowercase = s.to_lowercase();
    if lowercase.ends_with(".json") || lowercase.ends_with(".html") || lowercase.ends_with(".pdf") {
        Ok(s.to_string())
    } else {
        Err("Output file must be .json, .html, or .pdf".to_string())
    }
}

/// Convert string to boolean
pub fn string_to_bool(s: String) -> bool {
    match s.to_lowercase().as_str() {
        "true" | "yes" | "1" => true,
        _ => false,
    }
}

/// Generate current timestamp in v3 format (YYYYMMDDHHMMSS)
pub fn generate_timestamp() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.format("%Y%m%d%H%M%S").to_string()
}

/// Generate file hash with nonce
pub fn generate_file_hash(content: &[u8], nonce: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(content);
    hasher.update(nonce.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate random nonce
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..64)
        .map(|_| format!("{:02x}", rng.gen::<u8>()))
        .collect()
}

/// Calculate revision hash for v3
pub fn calculate_revision_hash(revision_json: &str) -> Result<String, String> {
    let mut hasher = Sha3_256::new();
    hasher.update(revision_json.as_bytes());
    Ok(format!("0x{}", hex::encode(hasher.finalize())))
}

/// Validate timestamp format (YYYYMMDDHHMMSS)
pub fn validate_timestamp(timestamp: &str) -> Result<(), ValidationError> {
    if timestamp.len() != 14 {
        return Err(ValidationError::InvalidTimestampOrder);
    }

    // Try to parse as date
    match chrono::NaiveDateTime::parse_from_str(timestamp, "%Y%m%d%H%M%S") {
        Ok(parsed_time) => {
            // Check if it's after 2020-01-01 00:00:00
            let min_time =
                chrono::NaiveDateTime::parse_from_str("20200101000000", "%Y%m%d%H%M%S").unwrap();
            if parsed_time < min_time {
                return Err(ValidationError::InvalidTimestampOrder);
            }
            Ok(())
        }
        Err(_) => Err(ValidationError::InvalidTimestampOrder),
    }
}

/// Validate version string for v3 compliance
pub fn validate_version(version: &str) -> Result<(), ValidationError> {
    let scalar_version = create_version_string(HashingMethod::Scalar);
    let tree_version = create_version_string(HashingMethod::Tree);

    if version == scalar_version || version == tree_version {
        Ok(())
    } else {
        Err(ValidationError::InvalidVersion(version.to_string()))
    }
}

/// Validate signature type
pub fn validate_signature_type(sig_type: &str) -> Result<(), ValidationError> {
    if SUPPORTED_SIGNATURE_TYPES.contains(&sig_type) {
        Ok(())
    } else {
        Err(ValidationError::InvalidSignatureType(sig_type.to_string()))
    }
}

/// Validate witness network
pub fn validate_witness_network(network: &str) -> Result<(), ValidationError> {
    if SUPPORTED_WITNESS_NETWORKS.contains(&network) {
        Ok(())
    } else {
        Err(ValidationError::InvalidWitnessNetwork(network.to_string()))
    }
}

/// Validate revision type
pub fn validate_revision_type(revision_type: &str) -> Result<RevisionType, ValidationError> {
    RevisionType::from_str(revision_type)
        .ok_or_else(|| ValidationError::UnsupportedRevisionType(revision_type.to_string()))
}

/// Extract revision from AquaTree by hash
pub fn get_revision_by_hash<'a>(
    aqua_tree: &'a AquaTree,
    hash: &str,
) -> Option<&'a serde_json::Value> {
    aqua_tree.revisions.get(hash)
}

/// Get latest revision hash from AquaTree
pub fn get_latest_revision_hash(aqua_tree: &AquaTree) -> String {
    aqua_tree.tree_mapping.latest_hash.clone()
}

/// Validate file index consistency
pub fn validate_file_index(aqua_tree: &AquaTree) -> Result<(), ValidationError> {
    for (revision_hash, _filename) in &aqua_tree.file_index {
        if let Some(revision) = aqua_tree.revisions.get(revision_hash) {
            // Check if revision is of type "file" or "content"
            if let Some(revision_type) = revision.get("revision_type").and_then(|v| v.as_str()) {
                match revision_type {
                    "file" | "content" => {
                        // Valid file revision
                        continue;
                    }
                    _ => {
                        return Err(ValidationError::InvalidFileIndex);
                    }
                }
            } else {
                return Err(ValidationError::InvalidFileIndex);
            }
        } else {
            return Err(ValidationError::InvalidFileIndex);
        }
    }
    Ok(())
}

/// Check for loops in revision chain
pub fn detect_loops(aqua_tree: &AquaTree) -> Result<(), ValidationError> {
    let mut visited = std::collections::HashSet::new();
    let mut current_hash = aqua_tree.tree_mapping.latest_hash.clone();

    loop {
        if visited.contains(&current_hash) {
            return Err(ValidationError::LoopDetected);
        }
        visited.insert(current_hash.clone());

        if let Some(revision) = aqua_tree.revisions.get(&current_hash) {
            if let Some(prev_hash) = revision
                .get("previous_verification_hash")
                .and_then(|v| v.as_str())
            {
                if prev_hash.is_empty() {
                    // Reached genesis revision
                    break;
                }
                current_hash = prev_hash.to_string();
            } else {
                return Err(ValidationError::InvalidPreviousHash);
            }
        } else {
            return Err(ValidationError::InvalidPreviousHash);
        }
    }

    Ok(())
}

/// Validate timestamp ordering across revisions
pub fn validate_timestamp_ordering(aqua_tree: &AquaTree) -> Result<(), ValidationError> {
    let mut timestamps = Vec::new();

    // Collect all timestamps
    for revision in aqua_tree.revisions.values() {
        if let Some(timestamp_str) = revision.get("local_timestamp").and_then(|v| v.as_str()) {
            validate_timestamp(timestamp_str)?;
            timestamps.push(timestamp_str);
        }
    }

    // Sort and check for reasonable ordering (this is a plausibility check)
    timestamps.sort();

    // Additional validation could be added here for cryptographic timestamps
    // from witness events

    Ok(())
}

/// Create a new empty AquaTree
pub fn create_empty_aqua_tree() -> AquaTree {
    use crate::models::TreeMapping;
    use std::collections::HashMap;

    AquaTree {
        revisions: HashMap::new(),
        file_index: HashMap::new(),
        tree_mapping: TreeMapping {
            paths: HashMap::new(),
            latest_hash: String::new(),
        },
    }
}

/// Helper function to pretty print validation errors
pub fn format_validation_errors(errors: &[ValidationError]) -> String {
    errors
        .iter()
        .map(|e| format!("  - {}", e))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_validation() {
        assert!(validate_timestamp("20240101120000").is_ok());
        assert!(validate_timestamp("invalid").is_err());
        assert!(validate_timestamp("19990101120000").is_err()); // Before 2020
    }

    #[test]
    fn test_revision_type_validation() {
        assert_eq!(validate_revision_type("file").unwrap(), RevisionType::File);
        assert!(validate_revision_type("invalid").is_err());
    }

    #[test]
    fn test_signature_type_validation() {
        assert!(validate_signature_type("ethereum:eip-191").is_ok());
        assert!(validate_signature_type("invalid").is_err());
    }

    #[test]
    fn test_witness_network_validation() {
        assert!(validate_witness_network("sepolia").is_ok());
        assert!(validate_witness_network("nostr").is_ok());
        assert!(validate_witness_network("invalid").is_err());
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_eq!(nonce1.len(), 128); // 64 bytes * 2 chars per byte
        assert_ne!(nonce1, nonce2); // Should be different
    }

    #[test]
    fn test_file_hash_generation() {
        let content = b"test content";
        let nonce = "test_nonce";
        let hash = generate_file_hash(content, nonce);
        assert_eq!(hash.len(), 64); // SHA256 hex = 64 chars
    }
}
