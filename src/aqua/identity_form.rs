use std::path::PathBuf;
use std::collections::HashMap;
use serde_json::Value;
use crate::models::CliArgs;
use crate::utils::{save_logs_to_file};
use aqua_verifier::aqua_verifier::AquaVerifier;
use colored::*;

/// Identity form functionality for v3.2
/// This module handles creating and managing identity forms and attestations

/// Form types supported in v3.2
#[derive(Debug, Clone, PartialEq)]
pub enum IdentityFormType {
    PersonalInfo,      // Personal information form
    Credential,        // Credential verification
    Attestation,       // Third-party attestation
    Declaration,        // Self-declaration
    Certification,     // Professional certification
}

impl std::fmt::Display for IdentityFormType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityFormType::PersonalInfo => write!(f, "personal_info"),
            IdentityFormType::Credential => write!(f, "credential"),
            IdentityFormType::Attestation => write!(f, "attestation"),
            IdentityFormType::Declaration => write!(f, "declaration"),
            IdentityFormType::Certification => write!(f, "certification"),
        }
    }
}

/// Form field definition
#[derive(Debug, Clone)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub required: bool,
    pub validation_rules: Option<Value>,
}

/// Identity form data structure
#[derive(Debug, Clone)]
pub struct IdentityFormData {
    pub form_id: String,
    pub form_type: IdentityFormType,
    pub domain_id: String,
    pub fields: Vec<FormField>,
    pub form_data: HashMap<String, Value>,
    pub verification_hash: String,
    pub timestamp: u64,
    pub metadata: HashMap<String, Value>,
}

/// Main CLI function for creating identity forms
pub fn cli_create_identity_form(
    args: CliArgs,
    _aqua_verifier: AquaVerifier,
    form_path: PathBuf,
    domain_id: String,
    form_type: IdentityFormType,
) -> Result<(), String> {
    let mut logs_data: Vec<String> = Vec::new();
    
    println!("{}", "📋 Creating Identity Form".blue().bold());
    logs_data.push("Starting identity form creation process".to_string());

    match process_identity_form_creation(&args, form_path, domain_id, form_type, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Identity form creation completed successfully".to_string());
            println!("{}", "✅ Identity form created successfully!".green());
        }
        Err(e) => {
            logs_data.push(format!("Error in identity form creation: {}", e));
            println!("{}", format!("❌ Error: {}", e).red());
        }
    }

    // Save logs if output path specified
    if let Some(output_path) = args.output {
        if let Err(e) = save_logs_to_file(&logs_data, output_path) {
            eprintln!("Failed to save logs to file: {}", e);
        }
    }

    Ok(())
}

/// Process the identity form creation
fn process_identity_form_creation(
    _args: &CliArgs,
    form_path: PathBuf,
    domain_id: String,
    form_type: IdentityFormType,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push(format!("Processing identity form: {} (type: {})", 
        form_path.display(), form_type));

    // For now, just create a placeholder form
    // In a real implementation, you would read and process the actual form file
    
    // Extract form fields and data
    let form_info = create_placeholder_form_data(&form_path, logs_data)?;
    
    // Create the form revision
    let form_revision = create_form_revision(
        form_info, 
        domain_id, 
        form_type, 
        logs_data
    )?;
    
    // Validate the form
    validate_identity_form(&form_revision, logs_data)?;
    
    logs_data.push("Identity form creation process completed".to_string());
    Ok(())
}

/// Create placeholder form data for demonstration
fn create_placeholder_form_data(
    _form_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<HashMap<String, Value>, String> {
    logs_data.push("Creating placeholder form data".to_string());

    let mut extracted_data = HashMap::new();
    
    // Create some placeholder form fields
    extracted_data.insert("name".to_string(), serde_json::json!("John Doe"));
    extracted_data.insert("email".to_string(), serde_json::json!("john@example.com"));
    extracted_data.insert("age".to_string(), serde_json::json!(30));

    logs_data.push(format!("Created {} placeholder form fields", extracted_data.len()));
    Ok(extracted_data)
}

/// Create the actual form revision
fn create_form_revision(
    form_data: HashMap<String, Value>,
    domain_id: String,
    form_type: IdentityFormType,
    logs_data: &mut Vec<String>,
) -> Result<Value, String> {
    logs_data.push("Creating form revision".to_string());

    // Generate unique form ID
    let form_id = generate_form_id(&domain_id, &form_type);
    
    // Generate verification hash
    let verification_hash = generate_form_verification_hash(&form_id, &form_data);
    
    // Get current timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let form_revision = serde_json::json!({
        "revision_type": "identity_form",
        "form_id": form_id,
        "form_type": form_type.to_string(),
        "domain_id": domain_id,
        "form_data": form_data,
        "verification_hash": verification_hash,
        "timestamp": timestamp,
        "version": "3.2.0",
        "metadata": {
            "created_at": timestamp,
            "form_version": "1.0",
            "compliance": "v3.2"
        }
    });

    logs_data.push("Form revision created successfully".to_string());
    Ok(form_revision)
}

/// Validate the created identity form
fn validate_identity_form(
    form_revision: &Value,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push("Validating identity form".to_string());

    // Basic validation checks
    let required_fields = ["revision_type", "form_id", "form_type", "domain_id", "verification_hash"];
    
    for field in required_fields {
        if !form_revision.get(field).is_some() {
            return Err(format!("Missing required field: {}", field));
        }
    }

    // Validate revision type
    if form_revision.get("revision_type").and_then(|v| v.as_str()) != Some("identity_form") {
        return Err("Invalid revision type".to_string());
    }

    // Validate form type
    let form_type = form_revision.get("form_type").and_then(|v| v.as_str())
        .ok_or_else(|| "Missing form type".to_string())?;
    
    let valid_types = ["personal_info", "credential", "attestation", "declaration", "certification"];
    if !valid_types.contains(&form_type) {
        return Err(format!("Invalid form type: {}", form_type));
    }

    logs_data.push("Identity form validation passed".to_string());
    Ok(())
}

/// Generate unique form ID
fn generate_form_id(domain_id: &str, form_type: &IdentityFormType) -> String {
    use sha3::{Digest, Sha3_256};
    
    let mut hasher = Sha3_256::new();
    hasher.update(format!("{}:{}:{}", domain_id, form_type, "form_id").as_bytes());
    let hash = hasher.finalize();
    
    format!("form_{:x}", hash[..8].iter().fold(0u64, |acc, &x| acc * 256 + x as u64))
}

/// Generate verification hash for the form
fn generate_form_verification_hash(form_id: &str, form_data: &HashMap<String, Value>) -> String {
    use sha3::{Digest, Sha3_256};
    
    let mut hasher = Sha3_256::new();
    hasher.update(form_id.as_bytes());
    
    // Include form data in hash
    for (key, value) in form_data {
        hasher.update(key.as_bytes());
        if let Some(str_val) = value.as_str() {
            hasher.update(str_val.as_bytes());
        }
    }
    
    format!("0x{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_form_type_display() {
        assert_eq!(IdentityFormType::PersonalInfo.to_string(), "personal_info");
        assert_eq!(IdentityFormType::Credential.to_string(), "credential");
        assert_eq!(IdentityFormType::Attestation.to_string(), "attestation");
        assert_eq!(IdentityFormType::Declaration.to_string(), "declaration");
        assert_eq!(IdentityFormType::Certification.to_string(), "certification");
    }

    #[test]
    fn test_generate_form_id() {
        let form_id = generate_form_id("test_domain", &IdentityFormType::PersonalInfo);
        assert!(form_id.starts_with("form_"));
        assert_eq!(form_id.len(), 19); // form_ + 15 hex chars
    }

    #[test]
    fn test_generate_form_verification_hash() {
        let mut form_data = HashMap::new();
        form_data.insert("name".to_string(), serde_json::json!("John Doe"));
        
        let hash = generate_form_verification_hash("test_form", &form_data);
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 66); // 0x + 64 hex chars
    }
} 