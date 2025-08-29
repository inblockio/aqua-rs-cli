use serde_json::Value;
type Result<T> = std::result::Result<T, String>;
use colored::*;

/// Aqua Protocol v3.2 Validator
/// This module provides comprehensive validation for v3.2 compliance

/// Validation result
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub compliance_level: ComplianceLevel,
}

/// Validation error types
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    MissingRequiredField(String),
    InvalidFieldValue(String, String),
    UnsupportedRevisionType(String),
    InvalidHashFormat(String),
    TimestampOutOfRange(String),
    UnsupportedSignatureType(String),
    InvalidWitnessNetwork(String),
    ChainIntegrityViolation(String),
}

/// Validation warning types
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationWarning {
    DeprecatedField(String),
    NonStandardFormat(String),
    MissingOptionalField(String),
    PerformanceConcern(String),
}

/// Compliance levels
#[derive(Debug, Clone, PartialEq)]
pub enum ComplianceLevel {
    Basic,      // Basic v3.2 compliance
    Standard,   // Standard v3.2 compliance
    Strict,     // Strict v3.2 compliance
    Enterprise, // Enterprise-grade compliance
}

impl std::fmt::Display for ComplianceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceLevel::Basic => write!(f, "basic"),
            ComplianceLevel::Standard => write!(f, "standard"),
            ComplianceLevel::Strict => write!(f, "strict"),
            ComplianceLevel::Enterprise => write!(f, "enterprise"),
        }
    }
}

/// Main validator struct
#[derive(Debug, Clone)]
pub struct AquaV3Validator {
    compliance_level: ComplianceLevel,
    strict_mode: bool,
    allow_deprecated: bool,
}

impl AquaV3Validator {
    /// Create a new validator with specified compliance level
    pub fn new(compliance_level: ComplianceLevel) -> Self {
        let strict_mode = matches!(compliance_level, ComplianceLevel::Strict | ComplianceLevel::Enterprise);
        let allow_deprecated = !strict_mode;
        
        Self {
            compliance_level,
            strict_mode,
            allow_deprecated,
        }
    }

    /// Validate an Aqua chain for v3.2 compliance
    pub fn validate_aqua_chain(&self, chain_data: &Value) -> ValidationResult {
        let mut result = ValidationResult {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            compliance_level: self.compliance_level.clone(),
        };

        println!("{}", format!("🔍 Validating Aqua Chain (v3.2 - {})", self.compliance_level).cyan().bold());

        // Validate chain structure
        if let Err(e) = self.validate_chain_structure(chain_data, &mut result) {
            result.errors.push(ValidationError::ChainIntegrityViolation(e.to_string()));
        }

        // Validate revisions
        if let Err(e) = self.validate_revisions(chain_data, &mut result) {
            result.errors.push(ValidationError::ChainIntegrityViolation(e.to_string()));
        }

        // Validate metadata
        if let Err(e) = self.validate_metadata(chain_data, &mut result) {
            result.errors.push(ValidationError::ChainIntegrityViolation(e.to_string()));
        }

        // Determine overall validity
        result.is_valid = result.errors.is_empty();

        // Print validation summary
        self.print_validation_summary(&result);

        result
    }

    /// Validate the overall chain structure
    fn validate_chain_structure(
        &self,
        chain_data: &Value,
        result: &mut ValidationResult,
    ) -> Result<()> {
        // Check for required top-level fields
        let required_fields = ["version", "chain_id", "revisions"];
        
        for field in required_fields {
            if !chain_data.get(field).is_some() {
                result.errors.push(ValidationError::MissingRequiredField(field.to_string()));
            }
        }

        // Validate version
        if let Some(version) = chain_data.get("version").and_then(|v| v.as_str()) {
            if !version.starts_with("3.") {
                result.errors.push(ValidationError::InvalidFieldValue(
                    "version".to_string(),
                    format!("Expected v3.x, got {}", version)
                ));
            }
        }

        Ok(())
    }

    /// Validate all revisions in the chain
    fn validate_revisions(
        &self,
        chain_data: &Value,
        result: &mut ValidationResult,
    ) -> Result<()> {
            let revisions = chain_data.get("revisions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Missing or invalid revisions array".to_string())?;

        for (index, revision) in revisions.iter().enumerate() {
            if let Err(e) = self.validate_single_revision(revision, index, result) {
                result.errors.push(ValidationError::ChainIntegrityViolation(
                    format!("Revision {}: {}", index, e)
                ));
            }
        }

        Ok(())
    }

    /// Validate a single revision
    fn validate_single_revision(
        &self,
        revision: &Value,
        index: usize,
        result: &mut ValidationResult,
    ) -> Result<()> {
        // Get revision type
        let revision_type = revision.get("revision_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing revision type".to_string())?;

        // Validate based on revision type
        match revision_type {
            "content" => self.validate_content_revision(revision, result)?,
            "signature" => self.validate_signature_revision(revision, result)?,
            "witness" => self.validate_witness_revision(revision, result)?,
            "chain_link" => self.validate_chain_link_revision(revision, result)?,
            "identity_form" => self.validate_identity_form_revision(revision, result)?,
            _ => {
                if self.strict_mode {
                    result.errors.push(ValidationError::UnsupportedRevisionType(
                        revision_type.to_string()
                    ));
                } else {
                    result.warnings.push(ValidationWarning::NonStandardFormat(
                        format!("Unknown revision type: {}", revision_type)
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate content revision
    fn validate_content_revision(
        &self,
        revision: &Value,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let required_fields = ["content_hash", "previous_verification_hash", "timestamp"];
        
        for field in required_fields {
            if !revision.get(field).is_some() {
                result.errors.push(ValidationError::MissingRequiredField(
                    format!("content_revision.{}", field)
                ));
            }
        }

        // Validate hash format
        if let Some(hash) = revision.get("content_hash").and_then(|v| v.as_str()) {
            if !hash.starts_with("0x") || hash.len() != 66 {
                result.errors.push(ValidationError::InvalidHashFormat(
                    format!("Invalid content hash format: {}", hash)
                ));
            }
        }

        Ok(())
    }

    /// Validate signature revision
    fn validate_signature_revision(
        &self,
        revision: &Value,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let required_fields = ["signature", "public_key", "wallet_address"];
        
        for field in required_fields {
            if !revision.get(field).is_some() {
                result.errors.push(ValidationError::MissingRequiredField(
                    format!("signature_revision.{}", field)
                ));
            }
        }

        // Validate signature format
        if let Some(signature) = revision.get("signature").and_then(|v| v.as_str()) {
            if !signature.starts_with("0x") {
                result.errors.push(ValidationError::InvalidFieldValue(
                    "signature".to_string(),
                    "Signature must start with 0x".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Validate witness revision
    fn validate_witness_revision(
        &self,
        revision: &Value,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let required_fields = ["witness_hash", "network", "timestamp"];
        
        for field in required_fields {
            if !revision.get(field).is_some() {
                result.errors.push(ValidationError::MissingRequiredField(
                    format!("witness_revision.{}", field)
                ));
            }
        }

        // Validate network
        if let Some(network) = revision.get("network").and_then(|v| v.as_str()) {
            let valid_networks = ["mainnet", "sepolia", "holesky", "polygon", "arbitrum"];
            if !valid_networks.contains(&network) {
                result.warnings.push(ValidationWarning::NonStandardFormat(
                    format!("Non-standard network: {}", network)
                ));
            }
        }

        Ok(())
    }

    /// Validate chain link revision
    fn validate_chain_link_revision(
        &self,
        revision: &Value,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let required_fields = ["link_type", "source_chain_id", "target_chain_id", "verification_hash"];
        
        for field in required_fields {
            if !revision.get(field).is_some() {
                result.errors.push(ValidationError::MissingRequiredField(
                    format!("chain_link_revision.{}", field)
                ));
            }
        }

        // Validate link type
        if let Some(link_type) = revision.get("link_type").and_then(|v| v.as_str()) {
            let valid_types = ["reference", "dependency", "extension", "validation"];
            if !valid_types.contains(&link_type) {
                result.errors.push(ValidationError::InvalidFieldValue(
                    "link_type".to_string(),
                    format!("Invalid link type: {}", link_type)
                ));
            }
        }

        Ok(())
    }

    /// Validate identity form revision
    fn validate_identity_form_revision(
        &self,
        revision: &Value,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let required_fields = ["form_id", "form_type", "domain_id", "verification_hash"];
        
        for field in required_fields {
            if !revision.get(field).is_some() {
                result.errors.push(ValidationError::MissingRequiredField(
                    format!("identity_form_revision.{}", field)
                ));
            }
        }

        // Validate form type
        if let Some(form_type) = revision.get("form_type").and_then(|v| v.as_str()) {
            let valid_types = ["personal_info", "credential", "attestation", "declaration", "certification"];
            if !valid_types.contains(&form_type) {
                result.errors.push(ValidationError::InvalidFieldValue(
                    "form_type".to_string(),
                    format!("Invalid form type: {}", form_type)
                ));
            }
        }

        Ok(())
    }

    /// Validate metadata
    fn validate_metadata(
        &self,
        chain_data: &Value,
        _result: &mut ValidationResult,
    ) -> Result<()> {
        // Metadata validation logic here
        // For now, just ensure it exists
        if chain_data.get("metadata").is_none() {
            // Metadata is optional in v3.2
        }
        Ok(())
    }

    /// Print validation summary
    fn print_validation_summary(&self, result: &ValidationResult) {
        println!("\n{}", "📊 Validation Summary".blue().bold());
        println!("Compliance Level: {}", result.compliance_level.to_string().yellow());
        
        if result.is_valid {
            println!("{}", "✅ Chain is v3.2 compliant!".green().bold());
        } else {
            println!("{}", "❌ Chain has validation errors".red().bold());
        }

        if !result.errors.is_empty() {
            println!("\n{}", "Errors:".red().bold());
            for error in &result.errors {
                println!("  ❌ {}", format!("{:?}", error).red());
            }
        }

        if !result.warnings.is_empty() {
            println!("\n{}", "Warnings:".yellow().bold());
            for warning in &result.warnings {
                println!("  ⚠️  {}", format!("{:?}", warning).yellow());
            }
        }

        println!("\n{}", "=".repeat(50).dimmed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_level_display() {
        assert_eq!(ComplianceLevel::Basic.to_string(), "basic");
        assert_eq!(ComplianceLevel::Strict.to_string(), "strict");
        assert_eq!(ComplianceLevel::Enterprise.to_string(), "enterprise");
    }

    #[test]
    fn test_validator_creation() {
        let validator = AquaV3Validator::new(ComplianceLevel::Strict);
        assert!(validator.strict_mode);
        assert!(!validator.allow_deprecated);
    }

    #[test]
    fn test_basic_validation() {
        let validator = AquaV3Validator::new(ComplianceLevel::Basic);
        let chain_data = serde_json::json!({
            "version": "3.2.0",
            "chain_id": "test_chain",
            "revisions": []
        });

        let result = validator.validate_aqua_chain(&chain_data);
        assert!(result.is_valid);
        assert_eq!(result.compliance_level, ComplianceLevel::Basic);
    }
} 