use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};

use crate::models::{AquaTree, RevisionType, ValidationError};
use crate::utils::{
    validate_revision_type, validate_signature_type, validate_timestamp, validate_version,
    validate_witness_network,
};

/// Complete v3 compliance validator
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AquaV3Validator {
    strict_mode: bool,
}

impl AquaV3Validator {
    pub fn new(strict_mode: bool) -> Self {
        Self { strict_mode }
    }

    /// Validate entire AquaTree for v3 compliance
    pub fn validate_aqua_tree(&self, aqua_tree: &AquaTree) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        // Revision verification tests (RV-01 to RV-08)
        if let Err(mut rev_errors) = self.validate_revisions(&aqua_tree.revisions) {
            errors.append(&mut rev_errors);
        }

        // Relational verification tests (RL-01 to RL-05)
        if let Err(mut rel_errors) = self.validate_relations(aqua_tree) {
            errors.append(&mut rel_errors);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// RV-01 to RV-08: Revision Verification Tests
    fn validate_revisions(
        &self,
        revisions: &HashMap<String, Value>,
    ) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        for (hash, revision) in revisions {
            if let Err(mut rev_errors) = self.validate_single_revision(hash, revision) {
                errors.append(&mut rev_errors);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate a single revision
    fn validate_single_revision(
        &self,
        hash: &str,
        revision: &Value,
    ) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        // RV-01: Version Compliance
        if let Some(version) = revision.get("version").and_then(|v| v.as_str()) {
            if let Err(e) = validate_version(version) {
                errors.push(e);
            }
        } else {
            errors.push(ValidationError::MissingRequiredField("version".to_string()));
        }

        // RV-02: Required Fields
        let required_fields = [
            "previous_verification_hash",
            "local_timestamp",
            "revision_type",
            "version",
        ];
        for field in &required_fields {
            if revision.get(field).is_none() {
                errors.push(ValidationError::MissingRequiredField(field.to_string()));
            }
        }

        // Validate timestamp format
        if let Some(timestamp) = revision.get("local_timestamp").and_then(|v| v.as_str()) {
            if let Err(e) = validate_timestamp(timestamp) {
                errors.push(e);
            }
        }

        // Get revision type for specific validation
        if let Some(revision_type) = revision.get("revision_type").and_then(|v| v.as_str()) {
            match validate_revision_type(revision_type) {
                Ok(rev_type) => {
                    // Type-specific validation
                    if let Err(mut type_errors) =
                        self.validate_revision_by_type(&rev_type, revision)
                    {
                        errors.append(&mut type_errors);
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        // Validate hash integrity
        if let Err(e) = self.validate_revision_hash(hash, revision) {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate revision by its specific type
    fn validate_revision_by_type(
        &self,
        rev_type: &RevisionType,
        revision: &Value,
    ) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        match rev_type {
            RevisionType::File | RevisionType::Content => {
                // RV-03: File Revision Integrity
                if let Err(e) = self.validate_file_revision(revision) {
                    errors.push(e);
                }
            }
            RevisionType::Form => {
                // Form revision validation (similar to file but with form fields)
                if let Err(e) = self.validate_form_revision(revision) {
                    errors.push(e);
                }
            }
            RevisionType::Signature => {
                // RV-04: Signature Verification
                if let Err(e) = self.validate_signature_revision(revision) {
                    errors.push(e);
                }
            }
            RevisionType::Witness => {
                // RV-05: Witness Verification
                if let Err(e) = self.validate_witness_revision(revision) {
                    errors.push(e);
                }
            }
            RevisionType::Link => {
                // Link revision validation
                if let Err(e) = self.validate_link_revision(revision) {
                    errors.push(e);
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// RV-03: File Revision Integrity
    fn validate_file_revision(&self, revision: &Value) -> Result<(), ValidationError> {
        let file_hash = revision
            .get("file_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField("file_hash".to_string()))?;

        let file_nonce = revision
            .get("file_nonce")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField("file_nonce".to_string()))?;

        // Check if content field exists for hash validation
        if let Some(content) = revision.get("content").and_then(|v| v.as_str()) {
            let computed_hash = self.compute_file_hash(content.as_bytes(), file_nonce);
            if computed_hash != file_hash {
                return Err(ValidationError::InvalidFileHash);
            }
        }
        // Note: If no content field, external file validation would be needed

        Ok(())
    }

    /// Validate form revision
    fn validate_form_revision(&self, revision: &Value) -> Result<(), ValidationError> {
        // Form revisions have the same file hash requirements as file revisions
        self.validate_file_revision(revision)?;

        // Check for forms_type field
        revision
            .get("forms_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField("forms_type".to_string()))?;

        // If tree method is used, validate leaves
        if let Some(version) = revision.get("version").and_then(|v| v.as_str()) {
            if version.contains("Method: tree") {
                revision
                    .get("leaves")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| ValidationError::MissingRequiredField("leaves".to_string()))?;
            }
        }

        Ok(())
    }

    /// RV-04: Signature Verification
    fn validate_signature_revision(&self, revision: &Value) -> Result<(), ValidationError> {
        let _signature = revision
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField("signature".to_string()))?;

        let _public_key = revision
            .get("signature_public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ValidationError::MissingRequiredField("signature_public_key".to_string())
            })?;

        let _wallet_address = revision
            .get("signature_wallet_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ValidationError::MissingRequiredField("signature_wallet_address".to_string())
            })?;

        let signature_type = revision
            .get("signature_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField("signature_type".to_string()))?;

        // RV-06: Signature Type Restriction
        validate_signature_type(signature_type)?;

        // Note: Actual signature verification would require the message that was signed
        // This would typically be the previous_verification_hash

        Ok(())
    }

    /// RV-05: Witness Verification
    fn validate_witness_revision(&self, revision: &Value) -> Result<(), ValidationError> {
        let witness_network = revision
            .get("witness_network")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField("witness_network".to_string()))?;

        // RV-07: Witness Type Restriction
        validate_witness_network(witness_network)?;

        // Validate optional witness fields based on network type
        match witness_network {
            "mainnet" | "sepolia" | "holesky" => {
                // Ethereum-based witnessing
                if let Some(contract_addr) = revision.get("witness_smart_contract_address") {
                    // Validate Ethereum address format
                    let addr_str = contract_addr
                        .as_str()
                        .ok_or_else(|| ValidationError::InvalidWitness)?;
                    if !self.is_valid_ethereum_address(addr_str) {
                        return Err(ValidationError::InvalidWitness);
                    }
                }

                if let Some(tx_hash) = revision.get("witness_transaction_hash") {
                    // Validate transaction hash format
                    let hash_str = tx_hash
                        .as_str()
                        .ok_or_else(|| ValidationError::InvalidWitness)?;
                    if !self.is_valid_ethereum_tx_hash(hash_str) {
                        return Err(ValidationError::InvalidWitness);
                    }
                }
            }
            "nostr" => {
                // Nostr-specific validation could be added here
            }
            "TSA_RFC3161" => {
                // TSA-specific validation could be added here
            }
            _ => {
                return Err(ValidationError::InvalidWitnessNetwork(
                    witness_network.to_string(),
                ))
            }
        }

        // Validate merkle proof if present
        if let Some(_merkle_root) = revision.get("witness_merkle_root").and_then(|v| v.as_str()) {
            if let Some(merkle_proof) = revision
                .get("witness_merkle_proof")
                .and_then(|v| v.as_array())
            {
                // Basic merkle proof validation could be added here
                if merkle_proof.is_empty() {
                    return Err(ValidationError::InvalidWitness);
                }
            }
        }

        Ok(())
    }

    /// Validate link revision
    fn validate_link_revision(&self, revision: &Value) -> Result<(), ValidationError> {
        let _link_type = revision
            .get("link_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField("link_type".to_string()))?;

        let verification_hashes = revision
            .get("link_verification_hashes")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                ValidationError::MissingRequiredField("link_verification_hashes".to_string())
            })?;

        let file_hashes = revision
            .get("link_file_hashes")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ValidationError::MissingRequiredField("link_file_hashes".to_string()))?;

        if verification_hashes.is_empty() || file_hashes.is_empty() {
            return Err(ValidationError::InvalidLinkRevision);
        }

        // Validate hash formats
        for hash in verification_hashes.iter().chain(file_hashes.iter()) {
            if let Some(hash_str) = hash.as_str() {
                if !self.is_valid_hash_format(hash_str) {
                    return Err(ValidationError::InvalidLinkRevision);
                }
            } else {
                return Err(ValidationError::InvalidLinkRevision);
            }
        }

        Ok(())
    }

    /// RL-01 to RL-05: Relational Verification Tests
    fn validate_relations(&self, aqua_tree: &AquaTree) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        // RL-01: Previous Hash Linking
        if let Err(e) = self.validate_hash_chain(&aqua_tree.revisions) {
            errors.push(e);
        }

        // RL-02: Link Revision validation
        if let Err(mut link_errors) = self.validate_link_references(aqua_tree) {
            errors.append(&mut link_errors);
        }

        // RL-03: Loop Detection
        if let Err(e) = self.detect_loops(&aqua_tree.revisions) {
            errors.push(e);
        }

        // RL-04: Fork Detection
        if let Err(e) = self.detect_forks(&aqua_tree.revisions) {
            errors.push(e);
        }

        // RL-05: Timestamp Order
        if let Err(e) = self.validate_timestamp_order(&aqua_tree.revisions) {
            errors.push(e);
        }

        // RV-08: Indexed Content Verification
        if let Err(e) = self.validate_file_index_consistency(aqua_tree) {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// RL-01: Previous Hash Linking
    fn validate_hash_chain(
        &self,
        revisions: &HashMap<String, Value>,
    ) -> Result<(), ValidationError> {
        for (_hash, revision) in revisions {
            if let Some(prev_hash) = revision
                .get("previous_verification_hash")
                .and_then(|v| v.as_str())
            {
                if !prev_hash.is_empty() && !revisions.contains_key(prev_hash) {
                    return Err(ValidationError::InvalidPreviousHash);
                }
            }
        }
        Ok(())
    }

    /// RL-02: Link Revision References
    fn validate_link_references(&self, aqua_tree: &AquaTree) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        for revision in aqua_tree.revisions.values() {
            if let Some("link") = revision.get("revision_type").and_then(|v| v.as_str()) {
                if let Some(verification_hashes) = revision
                    .get("link_verification_hashes")
                    .and_then(|v| v.as_array())
                {
                    for hash_value in verification_hashes {
                        if let Some(hash_str) = hash_value.as_str() {
                            if !aqua_tree.revisions.contains_key(hash_str) {
                                errors.push(ValidationError::InvalidLinkRevision);
                            }
                        }
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// RL-03: Loop Detection
    fn detect_loops(&self, revisions: &HashMap<String, Value>) -> Result<(), ValidationError> {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for hash in revisions.keys() {
            if !visited.contains(hash) {
                if self.detect_loops_dfs(hash, revisions, &mut visited, &mut rec_stack) {
                    return Err(ValidationError::LoopDetected);
                }
            }
        }

        Ok(())
    }

    fn detect_loops_dfs(
        &self,
        hash: &str,
        revisions: &HashMap<String, Value>,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
    ) -> bool {
        visited.insert(hash.to_string());
        rec_stack.insert(hash.to_string());

        if let Some(revision) = revisions.get(hash) {
            if let Some(prev_hash) = revision
                .get("previous_verification_hash")
                .and_then(|v| v.as_str())
            {
                if !prev_hash.is_empty() {
                    if !visited.contains(prev_hash) {
                        if self.detect_loops_dfs(prev_hash, revisions, visited, rec_stack) {
                            return true;
                        }
                    } else if rec_stack.contains(prev_hash) {
                        return true;
                    }
                }
            }
        }

        rec_stack.remove(hash);
        false
    }

    /// RL-04: Fork Detection
    fn detect_forks(&self, revisions: &HashMap<String, Value>) -> Result<(), ValidationError> {
        let mut children_count: HashMap<String, usize> = HashMap::new();

        for revision in revisions.values() {
            if let Some(prev_hash) = revision
                .get("previous_verification_hash")
                .and_then(|v| v.as_str())
            {
                if !prev_hash.is_empty() {
                    *children_count.entry(prev_hash.to_string()).or_insert(0) += 1;
                }
            }
        }

        for (_, count) in children_count {
            if count > 1 {
                return Err(ValidationError::ForkDetected);
            }
        }

        Ok(())
    }

    /// RL-05: Timestamp Order validation
    fn validate_timestamp_order(
        &self,
        revisions: &HashMap<String, Value>,
    ) -> Result<(), ValidationError> {
        // Basic timestamp plausibility check
        // More sophisticated validation could compare timestamps in chain order
        for revision in revisions.values() {
            if let Some(timestamp) = revision.get("local_timestamp").and_then(|v| v.as_str()) {
                validate_timestamp(timestamp)?;
            }
        }

        // Validate cryptographic timestamps from witness events
        for revision in revisions.values() {
            if let Some("witness") = revision.get("revision_type").and_then(|v| v.as_str()) {
                if let Some(witness_timestamp) =
                    revision.get("witness_timestamp").and_then(|v| v.as_i64())
                {
                    // Basic sanity check - timestamp should be reasonable
                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;

                    if witness_timestamp > current_time || witness_timestamp < 1577836800 {
                        // Before 2020-01-01
                        return Err(ValidationError::InvalidTimestampOrder);
                    }
                }
            }
        }

        Ok(())
    }

    /// RV-08: File Index Consistency
    fn validate_file_index_consistency(&self, aqua_tree: &AquaTree) -> Result<(), ValidationError> {
        for (revision_hash, _filename) in &aqua_tree.file_index {
            if let Some(revision) = aqua_tree.revisions.get(revision_hash) {
                match revision.get("revision_type").and_then(|v| v.as_str()) {
                    Some("file") | Some("content") => {
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
        }
        Ok(())
    }

    /// Validate revision hash integrity
    fn validate_revision_hash(&self, hash: &str, revision: &Value) -> Result<(), ValidationError> {
        // Convert revision to canonical JSON
        let canonical_json = self.to_canonical_json(revision)?;
        let computed_hash = self.compute_revision_hash(&canonical_json);

        if computed_hash != hash {
            return Err(ValidationError::InvalidRevision(
                "Hash mismatch".to_string(),
            ));
        }

        Ok(())
    }

    /// Compute file hash with nonce
    fn compute_file_hash(&self, content: &[u8], nonce: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(content);
        hasher.update(nonce.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Compute revision hash
    fn compute_revision_hash(&self, canonical_json: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(canonical_json.as_bytes());
        format!("0x{}", hex::encode(hasher.finalize()))
    }

    /// Convert to canonical JSON (sorted keys, no whitespace)
    fn to_canonical_json(&self, value: &Value) -> Result<String, ValidationError> {
        // This is a simplified version - a full implementation would need
        // proper canonical JSON serialization
        serde_json::to_string(value)
            .map_err(|_| ValidationError::InvalidRevision("JSON serialization failed".to_string()))
    }

    /// Validate Ethereum address format
    fn is_valid_ethereum_address(&self, addr: &str) -> bool {
        addr.starts_with("0x")
            && addr.len() == 42
            && addr[2..].chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Validate Ethereum transaction hash format
    fn is_valid_ethereum_tx_hash(&self, hash: &str) -> bool {
        hash.starts_with("0x")
            && hash.len() == 66
            && hash[2..].chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Validate general hash format
    fn is_valid_hash_format(&self, hash: &str) -> bool {
        (hash.starts_with("0x")
            && hash.len() == 66
            && hash[2..].chars().all(|c| c.is_ascii_hexdigit()))
            || (hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_valid_ethereum_address() {
        let validator = AquaV3Validator::new(false);
        assert!(validator.is_valid_ethereum_address("0x45f59310ADD88E6d23ca58A0Fa7A55BEE6d2a611"));
        assert!(!validator.is_valid_ethereum_address("invalid_address"));
    }

    #[test]
    fn test_signature_revision_validation() {
        let validator = AquaV3Validator::new(false);
        let revision = json!({
            "previous_verification_hash": "",
            "local_timestamp": "20240101120000",
            "revision_type": "signature",
            "version": "https://aqua-protocol.org/docs/v3/schema_2 | SHA256 | Method: scalar",
            "signature": "0x799cd8177dc2c5dc34d389601175d550466a73509b71d533aaa3ff0ee958b3b31b574bdfd158a7ad0b186da5f5b440bc18453a6848bc659ccd6de06a09d6ea6e1b",
            "signature_public_key": "0x0380a77a1a6d59be5c10d7ee5e10def79283938bb8a60025d0fe5404e650e8ccc1",
            "signature_wallet_address": "0x568a94a8f0f3dc0b245b853bef572075c1df5c50",
            "signature_type": "ethereum:eip-191"
        });

        assert!(validator.validate_signature_revision(&revision).is_ok());
    }

    #[test]
    fn test_invalid_signature_type() {
        let validator = AquaV3Validator::new(false);
        let revision = json!({
            "previous_verification_hash": "",
            "local_timestamp": "20240101120000",
            "revision_type": "signature",
            "version": "https://aqua-protocol.org/docs/v3/schema_2 | SHA256 | Method: scalar",
            "signature": "test_signature",
            "signature_public_key": "test_key",
            "signature_wallet_address": "test_address",
            "signature_type": "invalid_type"
        });

        assert!(validator.validate_signature_revision(&revision).is_err());
    }
}
