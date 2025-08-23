#[cfg(test)]
pub mod tests {
    use crate::aqua::sign;
    use crate::models::*;
    use crate::utils::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_aqua_tree() -> AquaTree {
        let mut revisions = HashMap::new();

        revisions.insert(
            "0xabc123".to_string(),
            json!({
                "previous_verification_hash": "",
                "local_timestamp": "20240101120000",
                "revision_type": "file",
                "version": "https://aqua-protocol.org/docs/v3/schema_2 | SHA256 | Method: scalar",
                "file_hash": "bd2e8e2a1b3c5d008e1d43ecb11105f42c5ad4e05922bab98981840b636c661e",
                "file_nonce": "65eddd0e16a995170dbef8feaf86a7928678426f20a309bb6627887915c04efb"
            }),
        );

        let mut file_index = HashMap::new();
        file_index.insert("0xabc123".to_string(), "test_file.txt".to_string());

        let mut paths = HashMap::new();
        paths.insert("0xabc123".to_string(), vec!["0xabc123".to_string()]);

        AquaTree {
            revisions,
            file_index,
            tree_mapping: TreeMapping {
                paths,
                latest_hash: "0xabc123".to_string(),
            },
        }
    }

    #[test]
    fn test_signature_revision_creation() {
        let mut aqua_tree = create_test_aqua_tree();
        let original_count = aqua_tree.revisions.len();

        let mut logs = Vec::new();
        let result = sign::add_signature_revision_to_aqua_tree(
            &mut aqua_tree,
            "0xtest_signature".to_string(),
            "0xtest_pubkey".to_string(),
            "0xtest_address".to_string(),
            "ethereum:eip-191".to_string(),
            &mut logs,
        );

        assert!(result.is_ok());
        assert_eq!(aqua_tree.revisions.len(), original_count + 1);

        let new_revision_hash = result.unwrap();
        let revision = aqua_tree.revisions.get(&new_revision_hash).unwrap();
        assert_eq!(
            revision.get("revision_type").unwrap().as_str().unwrap(),
            "signature"
        );
        assert_eq!(
            revision.get("signature_type").unwrap().as_str().unwrap(),
            "ethereum:eip-191"
        );
    }

    #[test]
    fn test_signature_type_validation() {
        assert!(validate_signature_type("ethereum:eip-191").is_ok());
        assert!(validate_signature_type("did_key").is_ok());
        assert!(validate_signature_type("invalid_type").is_err());
    }

    #[test]
    fn test_genesis_filename_extraction() {
        let aqua_tree = create_test_aqua_tree();

        // Find genesis revision
        for (hash, revision) in &aqua_tree.revisions {
            if let Some(prev_hash) = revision
                .get("previous_verification_hash")
                .and_then(|v| v.as_str())
            {
                if prev_hash.is_empty() {
                    // This should be genesis
                    if let Some(filename) = aqua_tree.file_index.get(hash) {
                        assert_eq!(filename, "test_file.txt");
                    }
                    break;
                }
            }
        }
    }

    #[test]
    fn test_signing_data_extraction() {
        let aqua_tree = create_test_aqua_tree();

        // Test that we can get the latest hash for signing
        let latest_hash = get_latest_revision_hash(&aqua_tree);
        assert!(!latest_hash.is_empty());
        assert_eq!(latest_hash, "0xabc123");
    }

    #[test]
    fn test_signature_validation_structure() {
        // Test signature structure validation
        let signature_revision = SignatureRevision {
            base: BaseRevision {
                previous_verification_hash: "0xtest".to_string(),
                local_timestamp: generate_timestamp(),
                revision_type: "signature".to_string(),
                version: create_version_string(HashingMethod::Scalar),
            },
            signature: "0xtest_signature".to_string(),
            signature_public_key: "0xtest_pubkey".to_string(),
            signature_wallet_address: "0xtest_address".to_string(),
            signature_type: "ethereum:eip-191".to_string(),
        };

        // Basic structure validation
        assert_eq!(signature_revision.base.revision_type, "signature");
        assert_eq!(signature_revision.signature_type, "ethereum:eip-191");
        assert!(!signature_revision.signature.is_empty());
        assert!(!signature_revision.signature_public_key.is_empty());
        assert!(!signature_revision.signature_wallet_address.is_empty());
    }

    #[test]
    fn test_cli_args_for_signing() {
        use std::path::PathBuf;

        let args = CliArgs {
            authenticate: None,
            sign: Some(PathBuf::from("test.json")),
            witness: None,
            file: None,
            remove: None,
            remove_count: 1,
            verbose: false,
            output: None,
            level: Some("2".to_string()),
            keys_file: Some(PathBuf::from("keys.json")),
            content: false,
            form: None,
            link: None,
            revision_type: None,
        };

        assert!(args.sign.is_some());
        assert!(args.keys_file.is_some());
        assert_eq!(args.level.as_ref().unwrap(), "2");
    }
}
