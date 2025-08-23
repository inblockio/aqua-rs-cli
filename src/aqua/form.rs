use sha3::{Digest, Sha3_256};
use std::fs;
use std::path::PathBuf;

use crate::models::{
    create_version_string, AquaTree, BaseRevision, CliArgs, FormRevision, HashingMethod,
    TreeMapping,
};
use crate::utils::{
    calculate_revision_hash, generate_file_hash, generate_nonce, generate_timestamp,
    save_aqua_tree, save_logs_to_file,
};
use aqua_verifier::aqua_verifier::AquaVerifier;
use serde_json::Value;
use std::collections::HashMap;

/// Generate a form revision for identity claims and attestations
pub fn cli_generate_form_revision(
    args: CliArgs,
    _aqua_verifier: AquaVerifier,
    domain_id: String,
    form_path: PathBuf,
) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push("Starting form revision generation".to_string());

    match process_form_revision(&args, form_path, &domain_id, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Form revision generation completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in form revision generation: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

/// Process form revision generation
fn process_form_revision(
    _args: &CliArgs,
    form_path: PathBuf,
    _domain_id: &str,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    // Read form data
    let form_content =
        fs::read_to_string(&form_path).map_err(|e| format!("Failed to read form file: {}", e))?;

    let form_data: Value = serde_json::from_str(&form_content)
        .map_err(|e| format!("Failed to parse form JSON: {}", e))?;

    let file_name = form_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?;

    logs_data.push(format!("Processing form: {}", file_name));

    // Extract form fields
    let form_fields = extract_form_fields(&form_data, logs_data)?;

    // Determine if we should use tree method (for selective disclosure)
    let use_tree_method = should_use_tree_method(&form_fields);
    let method = if use_tree_method {
        HashingMethod::Tree
    } else {
        HashingMethod::Scalar
    };

    logs_data.push(format!("Using hashing method: {}", method.as_str()));

    // Generate nonce and file hash
    let file_nonce = generate_nonce();
    let file_hash = generate_file_hash(form_content.as_bytes(), &file_nonce);

    // Create form revision
    let mut form_revision = FormRevision {
        base: BaseRevision {
            previous_verification_hash: String::new(), // Genesis revision
            local_timestamp: generate_timestamp(),
            revision_type: "form".to_string(),
            version: create_version_string(method),
        },
        file_hash: file_hash.clone(),
        file_nonce,
        forms_type: form_fields.forms_type,
        forms_name: form_fields.forms_name,
        forms_surname: form_fields.forms_surname,
        forms_email: form_fields.forms_email,
        forms_date_of_birth: form_fields.forms_date_of_birth,
        forms_wallet_address: form_fields.forms_wallet_address,
        leaves: None,
    };

    // Generate merkle leaves if using tree method
    if use_tree_method {
        let leaves = generate_merkle_leaves(&form_revision)?;
        form_revision.leaves = Some(leaves);
        logs_data.push("Generated merkle leaves for tree verification".to_string());
    }

    // Serialize revision to calculate hash
    let revision_json = serde_json::to_string(&form_revision)
        .map_err(|e| format!("Failed to serialize revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;
    logs_data.push(format!("Generated revision hash: {}", revision_hash));

    // Create AquaTree structure
    let aqua_tree =
        create_form_aqua_tree(revision_hash.clone(), revision_json, file_name.to_string())?;

    // Save AquaTree
    save_aqua_tree(&aqua_tree, &form_path, "form")
        .map_err(|e| format!("Failed to save AquaTree: {}", e))?;

    logs_data.push("Form revision saved successfully".to_string());
    Ok(())
}

/// Extract form fields from JSON data
struct FormFields {
    forms_type: String,
    forms_name: Option<String>,
    forms_surname: Option<String>,
    forms_email: Option<String>,
    forms_date_of_birth: Option<String>,
    forms_wallet_address: Option<String>,
}

fn extract_form_fields(
    form_data: &Value,
    logs_data: &mut Vec<String>,
) -> Result<FormFields, String> {
    let forms_type = form_data
        .get("forms_type")
        .and_then(|v| v.as_str())
        .unwrap_or("identity_claim")
        .to_string();

    logs_data.push(format!("Form type: {}", forms_type));

    let forms_name = form_data
        .get("forms_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let forms_surname = form_data
        .get("forms_surname")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let forms_email = form_data
        .get("forms_email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let forms_date_of_birth = form_data
        .get("forms_date_of_birth")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let forms_wallet_address = form_data
        .get("forms_wallet_address")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Log extracted fields
    if let Some(ref name) = forms_name {
        logs_data.push(format!("Name: {}", name));
    }
    if let Some(ref surname) = forms_surname {
        logs_data.push(format!("Surname: {}", surname));
    }
    if let Some(ref email) = forms_email {
        logs_data.push(format!("Email: {}", email));
    }

    Ok(FormFields {
        forms_type,
        forms_name,
        forms_surname,
        forms_email,
        forms_date_of_birth,
        forms_wallet_address,
    })
}

/// Determine if tree method should be used for selective disclosure
fn should_use_tree_method(form_fields: &FormFields) -> bool {
    // Use tree method for identity claims with multiple fields
    form_fields.forms_type == "identity_claim"
        && [
            &form_fields.forms_name,
            &form_fields.forms_surname,
            &form_fields.forms_email,
            &form_fields.forms_date_of_birth,
            &form_fields.forms_wallet_address,
        ]
        .iter()
        .filter(|f| f.is_some())
        .count()
            > 2
}

/// Generate merkle leaves for tree method
fn generate_merkle_leaves(form_revision: &FormRevision) -> Result<Vec<String>, String> {
    let mut leaves = Vec::new();

    // Create leaf for each form field
    if let Some(ref forms_type) = Some(&form_revision.forms_type) {
        leaves.push(hash_form_field("forms_type", forms_type));
    }

    if let Some(ref name) = form_revision.forms_name {
        leaves.push(hash_form_field("forms_name", name));
    }

    if let Some(ref surname) = form_revision.forms_surname {
        leaves.push(hash_form_field("forms_surname", surname));
    }

    if let Some(ref email) = form_revision.forms_email {
        leaves.push(hash_form_field("forms_email", email));
    }

    if let Some(ref dob) = form_revision.forms_date_of_birth {
        leaves.push(hash_form_field("forms_date_of_birth", dob));
    }

    if let Some(ref wallet) = form_revision.forms_wallet_address {
        leaves.push(hash_form_field("forms_wallet_address", wallet));
    }

    // Add base fields
    leaves.push(hash_form_field(
        "previous_verification_hash",
        &form_revision.base.previous_verification_hash,
    ));
    leaves.push(hash_form_field(
        "local_timestamp",
        &form_revision.base.local_timestamp,
    ));
    leaves.push(hash_form_field(
        "revision_type",
        &form_revision.base.revision_type,
    ));
    leaves.push(hash_form_field("version", &form_revision.base.version));
    leaves.push(hash_form_field("file_hash", &form_revision.file_hash));
    leaves.push(hash_form_field("file_nonce", &form_revision.file_nonce));

    Ok(leaves)
}

/// Hash a form field for merkle leaf
fn hash_form_field(field_name: &str, field_value: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(field_name.as_bytes());
    hasher.update(b":");
    hasher.update(field_value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Create AquaTree structure for form revision
fn create_form_aqua_tree(
    revision_hash: String,
    revision_json: String,
    file_name: String,
) -> Result<AquaTree, String> {
    let mut revisions = HashMap::new();
    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;
    revisions.insert(revision_hash.clone(), revision_value);

    let mut file_index = HashMap::new();
    file_index.insert(revision_hash.clone(), file_name);

    let mut paths = HashMap::new();
    paths.insert(revision_hash.clone(), vec![revision_hash.clone()]);

    let tree_mapping = TreeMapping {
        paths,
        latest_hash: revision_hash.clone(),
    };

    Ok(AquaTree {
        revisions,
        file_index,
        tree_mapping,
    })
}

/// Add form revision to existing AquaTree
pub fn add_form_revision_to_aqua_tree(
    existing_tree: &mut AquaTree,
    form_data: &Value,
    logs_data: &mut Vec<String>,
) -> Result<String, String> {
    // Extract form fields
    let form_fields = extract_form_fields(form_data, logs_data)?;

    // Determine method
    let use_tree_method = should_use_tree_method(&form_fields);
    let method = if use_tree_method {
        HashingMethod::Tree
    } else {
        HashingMethod::Scalar
    };

    // Generate file hash
    let form_content = serde_json::to_string(form_data)
        .map_err(|e| format!("Failed to serialize form data: {}", e))?;
    let file_nonce = generate_nonce();
    let file_hash = generate_file_hash(form_content.as_bytes(), &file_nonce);

    // Get previous hash
    let previous_hash = existing_tree.tree_mapping.latest_hash.clone();

    // Create form revision
    let mut form_revision = FormRevision {
        base: BaseRevision {
            previous_verification_hash: previous_hash,
            local_timestamp: generate_timestamp(),
            revision_type: "form".to_string(),
            version: create_version_string(method),
        },
        file_hash: file_hash.clone(),
        file_nonce,
        forms_type: form_fields.forms_type,
        forms_name: form_fields.forms_name,
        forms_surname: form_fields.forms_surname,
        forms_email: form_fields.forms_email,
        forms_date_of_birth: form_fields.forms_date_of_birth,
        forms_wallet_address: form_fields.forms_wallet_address,
        leaves: None,
    };

    // Generate leaves if needed
    if use_tree_method {
        let leaves = generate_merkle_leaves(&form_revision)?;
        form_revision.leaves = Some(leaves);
    }

    // Serialize and hash
    let revision_json = serde_json::to_string(&form_revision)
        .map_err(|e| format!("Failed to serialize revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;

    // Add to existing tree
    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;

    existing_tree
        .revisions
        .insert(revision_hash.clone(), revision_value);

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

    logs_data.push(format!("Added form revision: {}", revision_hash));
    Ok(revision_hash)
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
    use serde_json::json;

    #[test]
    fn test_form_field_extraction() {
        let form_data = json!({
            "forms_type": "identity_claim",
            "forms_name": "John",
            "forms_surname": "Doe",
            "forms_email": "john.doe@example.com"
        });

        let mut logs = Vec::new();
        let fields = extract_form_fields(&form_data, &mut logs).unwrap();

        assert_eq!(fields.forms_type, "identity_claim");
        assert_eq!(fields.forms_name, Some("John".to_string()));
        assert_eq!(fields.forms_surname, Some("Doe".to_string()));
        assert_eq!(fields.forms_email, Some("john.doe@example.com".to_string()));
    }

    #[test]
    fn test_tree_method_decision() {
        let fields = FormFields {
            forms_type: "identity_claim".to_string(),
            forms_name: Some("John".to_string()),
            forms_surname: Some("Doe".to_string()),
            forms_email: Some("john@example.com".to_string()),
            forms_date_of_birth: None,
            forms_wallet_address: None,
        };

        assert!(should_use_tree_method(&fields));
    }

    #[test]
    fn test_merkle_leaf_generation() {
        let leaf = hash_form_field("forms_name", "John");
        assert_eq!(leaf.len(), 64); // SHA256 hex length

        // Same input should produce same hash
        let leaf2 = hash_form_field("forms_name", "John");
        assert_eq!(leaf, leaf2);

        // Different input should produce different hash
        let leaf3 = hash_form_field("forms_name", "Jane");
        assert_ne!(leaf, leaf3);
    }
}
