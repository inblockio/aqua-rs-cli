#[cfg(test)]
mod content_tests {
    use crate::aqua::content;
    use crate::models::*;
    use crate::utils::*;
    use base64::{engine::general_purpose, Engine as _};
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn create_empty_aqua_tree() -> AquaTree {
        AquaTree {
            revisions: HashMap::new(),
            file_index: HashMap::new(),
            tree_mapping: TreeMapping {
                paths: HashMap::new(),
                latest_hash: String::new(),
            },
        }
    }

    #[test]
    fn test_content_revision_creation() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "Test content for content revision").unwrap();

        let mut aqua_tree = create_empty_aqua_tree();

        let mut logs = Vec::new();
        let result =
            content::add_content_revision_to_aqua_tree(&mut aqua_tree, &test_file, &mut logs);

        assert!(result.is_ok());
        let revision_hash = result.unwrap();
        assert!(aqua_tree.revisions.contains_key(&revision_hash));
        assert_eq!(aqua_tree.tree_mapping.latest_hash, revision_hash);

        let revision = aqua_tree.revisions.get(&revision_hash).unwrap();
        assert_eq!(
            revision.get("revision_type").unwrap().as_str().unwrap(),
            "content"
        );
        assert!(revision.get("content").is_none()); // Content revisions don't embed content
    }

    #[test]
    fn test_content_vs_file_revision() {
        // Content revision should not have embedded content
        let content_revision = ContentRevision {
            base: BaseRevision {
                previous_verification_hash: String::new(),
                local_timestamp: generate_timestamp(),
                revision_type: "content".to_string(),
                version: create_version_string(HashingMethod::Scalar),
            },
            file_hash: "test_hash".to_string(),
            file_nonce: "test_nonce".to_string(),
        };

        // File revision can have embedded content
        let file_revision = FileRevision {
            base: BaseRevision {
                previous_verification_hash: String::new(),
                local_timestamp: generate_timestamp(),
                revision_type: "file".to_string(),
                version: create_version_string(HashingMethod::Scalar),
            },
            content: Some(general_purpose::STANDARD.encode("embedded_content")),
            file_hash: "test_hash".to_string(),
            file_nonce: "test_nonce".to_string(),
        };

        assert_eq!(content_revision.base.revision_type, "content");
        assert_eq!(file_revision.base.revision_type, "file");
        assert!(file_revision.content.is_some());
    }

    #[test]
    fn test_content_revision_structure() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("large_file.txt");
        let large_content = "x".repeat(2 * 1024 * 1024); // 2MB file
        fs::write(&test_file, &large_content).unwrap();

        let mut aqua_tree = create_empty_aqua_tree();
        let mut logs = Vec::new();

        let result =
            content::add_content_revision_to_aqua_tree(&mut aqua_tree, &test_file, &mut logs);

        assert!(result.is_ok());

        // Large files should use content revision (reference only)
        let revision_hash = result.unwrap();
        let revision = aqua_tree.revisions.get(&revision_hash).unwrap();
        assert_eq!(
            revision.get("revision_type").unwrap().as_str().unwrap(),
            "content"
        );
    }

    #[test]
    fn test_hash_generation_consistency() {
        let content = b"Test content";
        let nonce = "test_nonce";

        let hash1 = generate_file_hash(content, nonce);
        let hash2 = generate_file_hash(content, nonce);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        assert_eq!(nonce1.len(), 128); // 64 bytes * 2 chars per byte
        assert_ne!(nonce1, nonce2); // Should be different
        assert!(nonce1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_base64_encoding_decoding() {
        let original_content = b"Test content for base64 encoding";
        let encoded = general_purpose::STANDARD.encode(original_content);
        let decoded = general_purpose::STANDARD.decode(&encoded).unwrap();

        assert_eq!(original_content, decoded.as_slice());
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "=+/".contains(c)));
    }
}
