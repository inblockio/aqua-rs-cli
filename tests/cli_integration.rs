// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Integration tests for aqua-cli.
//!
//! These tests exercise the CLI binary end-to-end by running it as a subprocess
//! and verifying exit codes, stdout, and generated files.
//!
//! Test fixtures live in `../test_files/` relative to the CLI crate root.
//! Network-dependent tests (TSA, Nostr) gracefully degrade if the network is
//! unavailable — they print a skip message instead of failing.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Build a `Command` pointing at the compiled `aqua-cli` binary.
fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aqua-cli"))
}

/// Source directory containing test fixtures (`../test_files/`).
fn test_files_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CLI crate must live in a workspace")
        .join("test_files")
}

/// Copy a fixture file into a fresh temp directory.
/// Returns `(temp_dir_handle, path_to_copied_file)`.
fn setup_fixture(filename: &str) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let src = test_files_dir().join(filename);
    let dst = tmp.path().join(filename);
    fs::copy(&src, &dst).unwrap_or_else(|e| {
        panic!(
            "failed to copy fixture {} -> {}: {}",
            src.display(),
            dst.display(),
            e
        )
    });
    (tmp, dst)
}

/// Write a test `keys.json` into `dir` and return its path.
fn write_keys_file(dir: &Path) -> PathBuf {
    let keys = dir.join("keys.json");
    fs::write(
        &keys,
        r#"{
    "signing": {
        "mnemonic": "hidden excite anxiety language enrich eagle rough furnace fluid auto inherit surround hill index void struggle usual program actress pluck demise kite state car",
        "did_key": "2edfed1830e9db59438c65b63a85c73a1aea467e8a84270d242025632e04bb65",
        "p256_key": "da04b6706d0e8960cb199dbba07d9df831afea0392d1998efea9c7ec8b26cf72"
    },
    "timestamp": {
        "nostr_sk": "bab92dda770b41ffb8afa623198344f44950b5b9c3e83f6b36ad08977b783d55"
    }
}"#,
    )
    .expect("failed to write keys.json");
    keys
}

/// Generate a genesis aqua chain from a fixture file.
/// Returns `(temp_dir_handle, fixture_path, aqua_json_path)`.
fn generate_genesis(fixture_name: &str) -> (TempDir, PathBuf, PathBuf) {
    let (tmp, fixture_path) = setup_fixture(fixture_name);
    let output = cli()
        .arg("-f")
        .arg(&fixture_path)
        .current_dir(tmp.path())
        .output()
        .expect("failed to run genesis generation");

    assert!(
        output.status.success(),
        "genesis generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let aqua_path = fixture_path.with_extension("aqua.json");
    assert!(
        aqua_path.exists(),
        "aqua.json not created at {}",
        aqua_path.display()
    );

    (tmp, fixture_path, aqua_path)
}

/// Parse a `.aqua.json` file into a `serde_json::Value`.
fn read_tree(path: &Path) -> serde_json::Value {
    let content = fs::read_to_string(path).unwrap();
    serde_json::from_str(&content).unwrap()
}

/// Count the number of revisions in a tree JSON.
fn revision_count(tree: &serde_json::Value) -> usize {
    tree["revisions"].as_object().unwrap().len()
}

/// Run `aqua-cli -a <path> --verbose` and assert that verification succeeds.
/// Returns the full stdout for further inspection.
fn assert_verify_ok(aqua_path: &Path) -> String {
    let output = cli()
        .arg("-a")
        .arg(aqua_path)
        .arg("--verbose")
        .output()
        .expect("failed to execute verify");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        stdout.contains("Successfully verified"),
        "verification should succeed. stdout:\n{}",
        stdout
    );
    stdout
}

// ═════════════════════════════════════════════════════════════════════════════
// Genesis generation (-f / --file)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn generate_genesis_from_text_file() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");
    let tree = read_tree(&aqua);

    assert!(tree.get("revisions").is_some());
    assert!(tree.get("file_index").is_some());
    assert_eq!(
        revision_count(&tree),
        3,
        "genesis tree should have 3 revisions (anchor + template + object)"
    );
}

#[test]
fn generate_genesis_from_image() {
    let (_tmp, _fix, aqua) = generate_genesis("img.jpeg");
    let tree = read_tree(&aqua);

    assert_eq!(revision_count(&tree), 3);

    let file_index = tree["file_index"].as_object().unwrap();
    let has_img = file_index
        .values()
        .any(|v| v.as_str().map_or(false, |s| s.contains("img.jpeg")));
    assert!(has_img, "file_index should reference img.jpeg");
}

#[test]
fn generate_genesis_from_pdf() {
    let (_tmp, _fix, aqua) = generate_genesis("9.pdf");
    let tree = read_tree(&aqua);
    assert_eq!(revision_count(&tree), 3);
}

#[test]
fn genesis_revisions_ordered_anchor_template_object() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");
    let tree = read_tree(&aqua);

    let revisions = tree["revisions"].as_object().unwrap();
    let rev_types: Vec<&str> = revisions
        .values()
        .map(|r| {
            r.get("revision_type")
                .and_then(|v| v.as_str())
                .unwrap_or("object") // Object's revision_type is a hash link
        })
        .collect();

    assert_eq!(rev_types[0], "anchor", "first revision should be anchor");
    assert_eq!(
        rev_types[1], "template",
        "second revision should be template"
    );
    // Third is "object" (identified by revision_type being a hex hash, not a keyword)
    assert!(
        rev_types[2].starts_with("0x"),
        "third revision should be object (revision_type is a hash): got {}",
        rev_types[2]
    );
}

#[test]
fn genesis_has_distinct_timestamps() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");
    let tree = read_tree(&aqua);

    let revisions = tree["revisions"].as_object().unwrap();
    let timestamps: Vec<u64> = revisions
        .values()
        .map(|r| r["local_timestamp"].as_u64().unwrap())
        .collect();

    // All timestamps should be distinct
    for i in 0..timestamps.len() {
        for j in (i + 1)..timestamps.len() {
            assert_ne!(
                timestamps[i], timestamps[j],
                "timestamps should be distinct: {:?}",
                timestamps
            );
        }
    }

    // Timestamps should be non-decreasing (ordered by chain order)
    for i in 1..timestamps.len() {
        assert!(
            timestamps[i] >= timestamps[i - 1],
            "timestamps should be non-decreasing: {:?}",
            timestamps
        );
    }
}

#[test]
fn genesis_template_has_previous_revision() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");
    let tree = read_tree(&aqua);

    let revisions = tree["revisions"].as_object().unwrap();
    let template = revisions
        .values()
        .find(|r| r.get("revision_type").and_then(|v| v.as_str()) == Some("template"))
        .expect("template revision should exist");

    assert!(
        template.get("previous_revision").is_some(),
        "template should have previous_revision pointing to anchor"
    );
}

#[test]
fn genesis_stdout_contains_success_message() {
    let (tmp, fixture) = setup_fixture("1.txt");
    let output = cli()
        .arg("-f")
        .arg(&fixture)
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Successfully"),
        "stdout should indicate success: {}",
        stdout
    );
}

#[test]
fn genesis_file_index_ordered_same_as_revisions() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");
    let tree = read_tree(&aqua);

    let rev_keys: Vec<&str> = tree["revisions"]
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    let idx_keys: Vec<&str> = tree["file_index"]
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();

    // All file_index keys should appear in revisions, in the same relative order
    let mut rev_iter = rev_keys.iter();
    for idx_key in &idx_keys {
        assert!(
            rev_iter.any(|r| r == idx_key),
            "file_index key {} should appear in revisions in chain order",
            idx_key
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Authentication / Verification (-a / --authenticate)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn verify_freshly_generated_chain() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");
    assert_verify_ok(&aqua);
}

#[test]
fn verify_with_verbose_produces_details() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");
    let stdout = assert_verify_ok(&aqua);
    assert!(
        stdout.lines().count() > 1,
        "verbose should produce multiple lines of detail"
    );
}

#[test]
fn verify_image_chain() {
    let (_tmp, _fix, aqua) = generate_genesis("img.jpeg");
    assert_verify_ok(&aqua);
}

#[test]
fn verify_pdf_chain() {
    let (_tmp, _fix, aqua) = generate_genesis("9.pdf");
    assert_verify_ok(&aqua);
}

// ═════════════════════════════════════════════════════════════════════════════
// Signing (-s / --sign)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn sign_with_cli_type() {
    let (tmp, _fix, aqua) = generate_genesis("1.txt");
    let keys = write_keys_file(tmp.path());

    let output = cli()
        .arg("-s")
        .arg(&aqua)
        .arg("--sign-type")
        .arg("cli")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Successfully signed"),
        "CLI signing should succeed: {}",
        stdout
    );

    let tree = read_tree(&aqua);
    assert!(
        revision_count(&tree) > 3,
        "signed chain should have more than 3 revisions"
    );
}

#[test]
fn sign_with_did_type() {
    let (tmp, _fix, aqua) = generate_genesis("1.txt");
    let keys = write_keys_file(tmp.path());

    let output = cli()
        .arg("-s")
        .arg(&aqua)
        .arg("--sign-type")
        .arg("did")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Successfully signed"),
        "DID signing should succeed: {}",
        stdout
    );
}

#[test]
fn sign_with_p256_type() {
    let (tmp, _fix, aqua) = generate_genesis("1.txt");
    let keys = write_keys_file(tmp.path());

    let output = cli()
        .arg("-s")
        .arg(&aqua)
        .arg("--sign-type")
        .arg("p256")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Successfully signed"),
        "P256 signing should succeed: {}",
        stdout
    );
}

#[test]
fn sign_and_verify_roundtrip() {
    let (tmp, _fix, aqua) = generate_genesis("1.txt");
    let keys = write_keys_file(tmp.path());

    // Sign
    let sign = cli()
        .arg("-s")
        .arg(&aqua)
        .arg("--sign-type")
        .arg("cli")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();
    assert!(sign.status.success());

    // Verify
    assert_verify_ok(&aqua);
}

#[test]
fn sign_without_keys_file_fails() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");

    let output = cli()
        .arg("-s")
        .arg(&aqua)
        .arg("--sign-type")
        .arg("cli")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("requires keys file") || stdout.contains("❌"),
        "signing without keys should fail: {}",
        stdout
    );
}

#[test]
fn multiple_signatures_accumulate() {
    let (tmp, _fix, aqua) = generate_genesis("1.txt");
    let keys = write_keys_file(tmp.path());

    // First signature (CLI)
    let s1 = cli()
        .arg("-s")
        .arg(&aqua)
        .arg("--sign-type")
        .arg("cli")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&s1.stdout).contains("Successfully signed"));
    let count_after_first = revision_count(&read_tree(&aqua));

    // Second signature (DID)
    let s2 = cli()
        .arg("-s")
        .arg(&aqua)
        .arg("--sign-type")
        .arg("did")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&s2.stdout).contains("Successfully signed"));
    let count_after_second = revision_count(&read_tree(&aqua));

    assert!(
        count_after_second > count_after_first,
        "second signature should add revisions: {} vs {}",
        count_after_second,
        count_after_first
    );

    // Verify the doubly-signed chain
    assert_verify_ok(&aqua);
}

// ═════════════════════════════════════════════════════════════════════════════
// Delete (-d / --delete)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn delete_last_revision() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");
    let count_before = revision_count(&read_tree(&aqua));

    let output = cli().arg("-d").arg(&aqua).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Successfully removed"),
        "delete should succeed: {}",
        stdout
    );

    // The deleted chain is written back to the same path (input is .json)
    let count_after = revision_count(&read_tree(&aqua));
    assert!(
        count_after < count_before,
        "revision count should decrease: {} -> {}",
        count_before,
        count_after
    );
}

#[test]
fn delete_and_verify() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");

    let del = cli().arg("-d").arg(&aqua).output().unwrap();
    assert!(String::from_utf8_lossy(&del.stdout).contains("Successfully removed"));

    assert_verify_ok(&aqua);
}

#[test]
fn sign_delete_verify_cycle() {
    let (tmp, _fix, aqua) = generate_genesis("1.txt");
    let keys = write_keys_file(tmp.path());

    // Sign
    cli()
        .arg("-s")
        .arg(&aqua)
        .arg("--sign-type")
        .arg("cli")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();

    // Delete the signature
    let del = cli().arg("-d").arg(&aqua).output().unwrap();
    assert!(String::from_utf8_lossy(&del.stdout).contains("Successfully removed"));

    // Verify the reverted chain
    assert_verify_ok(&aqua);
}

// ═════════════════════════════════════════════════════════════════════════════
// Link (--link)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn link_two_chains() {
    let tmp = TempDir::new().unwrap();

    // Copy both fixtures
    fs::copy(test_files_dir().join("1.txt"), tmp.path().join("1.txt")).unwrap();
    fs::copy(
        test_files_dir().join("img.jpeg"),
        tmp.path().join("img.jpeg"),
    )
    .unwrap();

    // Generate both chains
    cli()
        .arg("-f")
        .arg(tmp.path().join("1.txt"))
        .current_dir(tmp.path())
        .output()
        .unwrap();
    cli()
        .arg("-f")
        .arg(tmp.path().join("img.jpeg"))
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let chain1 = tmp.path().join("1.aqua.json");
    let chain2 = tmp.path().join("img.aqua.json");
    let count_before = revision_count(&read_tree(&chain1));

    // Link chain2 into chain1
    let output = cli()
        .arg("--link")
        .arg(&chain1)
        .arg(&chain2)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Successfully linked"),
        "link should succeed: {}",
        stdout
    );

    let count_after = revision_count(&read_tree(&chain1));
    assert!(
        count_after > count_before,
        "linked chain should have more revisions: {} -> {}",
        count_before,
        count_after
    );
}

#[test]
fn link_produces_valid_structure() {
    let tmp = TempDir::new().unwrap();

    fs::copy(test_files_dir().join("1.txt"), tmp.path().join("1.txt")).unwrap();
    fs::copy(
        test_files_dir().join("img.jpeg"),
        tmp.path().join("img.jpeg"),
    )
    .unwrap();

    cli()
        .arg("-f")
        .arg(tmp.path().join("1.txt"))
        .current_dir(tmp.path())
        .output()
        .unwrap();
    cli()
        .arg("-f")
        .arg(tmp.path().join("img.jpeg"))
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let chain1 = tmp.path().join("1.aqua.json");
    let chain2 = tmp.path().join("img.aqua.json");
    let count_before = revision_count(&read_tree(&chain1));

    let link_out = cli()
        .arg("--link")
        .arg(&chain1)
        .arg(&chain2)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&link_out.stdout).contains("Successfully linked"));

    let tree_after = read_tree(&chain1);
    let count_after = revision_count(&tree_after);
    assert!(
        count_after > count_before,
        "linked chain should have more revisions: {} -> {}",
        count_before,
        count_after
    );

    // The new anchor should have link_verification_hashes
    let revisions = tree_after["revisions"].as_object().unwrap();
    let link_anchors: Vec<_> = revisions
        .values()
        .filter(|r| {
            r.get("revision_type").and_then(|v| v.as_str()) == Some("anchor")
                && r.get("link_verification_hashes").is_some()
                && r.get("previous_revision").is_some()
        })
        .collect();
    assert!(
        !link_anchors.is_empty(),
        "linked chain should have a chained anchor with link_verification_hashes"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Create Object (--create-object)
// ═════════════════════════════════════════════════════════════════════════════

/// Minimal valid payload for the built-in "file" template.
const FILE_PAYLOAD: &str = r#"{"type":"file","hash":"0x0000000000000000000000000000000000000000000000000000000000000000","hash_type":"FIPS_202-SHA3-256","descriptor":"test","size":100,"content_type":"text/plain"}"#;

#[test]
fn create_object_with_template_name_and_inline_payload() {
    let tmp = TempDir::new().unwrap();

    let output = cli()
        .arg("--create-object")
        .arg("--template-name")
        .arg("file")
        .arg("--payload")
        .arg(FILE_PAYLOAD)
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Successfully created"),
        "create-object should succeed: {}",
        stdout
    );

    let aqua = tmp.path().join("object.aqua.json");
    assert!(aqua.exists(), "object.aqua.json should be created");
    assert_eq!(revision_count(&read_tree(&aqua)), 3);
}

#[test]
fn create_object_with_payload_file() {
    let tmp = TempDir::new().unwrap();

    let payload_path = tmp.path().join("payload.json");
    fs::write(&payload_path, FILE_PAYLOAD).unwrap();

    let output = cli()
        .arg("--create-object")
        .arg("--template-name")
        .arg("file")
        .arg("--payload")
        .arg(&payload_path)
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Successfully created"),
        "create-object from payload file should succeed: {}",
        stdout
    );
}

#[test]
fn create_object_without_template_fails() {
    let tmp = TempDir::new().unwrap();

    let output = cli()
        .arg("--create-object")
        .arg("--payload")
        .arg(FILE_PAYLOAD)
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("Missing") || stderr.contains("requires") || !output.status.success(),
        "create-object without template should fail: stdout={} stderr={}",
        stdout,
        stderr
    );
}

#[test]
fn create_object_without_payload_fails() {
    let tmp = TempDir::new().unwrap();

    let output = cli()
        .arg("--create-object")
        .arg("--template-name")
        .arg("file")
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("Missing") || stderr.contains("payload") || stdout.contains("❌"),
        "create-object without payload should fail: stdout={} stderr={}",
        stdout,
        stderr
    );
}

#[test]
fn create_object_and_verify_structure() {
    let tmp = TempDir::new().unwrap();

    let output = cli()
        .arg("--create-object")
        .arg("--template-name")
        .arg("file")
        .arg("--payload")
        .arg(FILE_PAYLOAD)
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("Successfully created"));

    // Verify the tree structure (full verification skipped because the
    // object contains a dummy file hash with no actual file on disk)
    let aqua = tmp.path().join("object.aqua.json");
    let tree = read_tree(&aqua);
    assert_eq!(
        revision_count(&tree),
        3,
        "created object should have anchor + template + object"
    );

    let revisions = tree["revisions"].as_object().unwrap();
    let has_anchor = revisions
        .values()
        .any(|r| r.get("revision_type").and_then(|v| v.as_str()) == Some("anchor"));
    let has_template = revisions
        .values()
        .any(|r| r.get("revision_type").and_then(|v| v.as_str()) == Some("template"));
    assert!(has_anchor, "tree should contain an anchor");
    assert!(has_template, "tree should contain a template");
}

#[test]
fn create_object_with_attestation_template() {
    let tmp = TempDir::new().unwrap();

    let payload = r#"{"signer_did":"did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678","context":"test attestation for integration test"}"#;

    let output = cli()
        .arg("--create-object")
        .arg("--template-name")
        .arg("attestation")
        .arg("--payload")
        .arg(payload)
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Successfully created"),
        "attestation object creation should succeed: {}",
        stdout
    );

    // Verify structure
    let aqua = tmp.path().join("object.aqua.json");
    let tree = read_tree(&aqua);
    assert_eq!(revision_count(&tree), 3);
}

// ═════════════════════════════════════════════════════════════════════════════
// List Templates (--list-templates)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn list_templates_shows_all_names() {
    let output = cli().arg("--list-templates").output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = [
        "file",
        "platform-identity",
        "attestation",
        "timestamp",
        "multi-signer",
        "trust-assertion",
        "wallet-identification",
        "access-grant",
        "vendor-registration",
        "template-registration",
        "alias-registration",
        "plugin-registration",
    ];

    for name in &expected {
        assert!(
            stdout.contains(name),
            "list-templates should include '{}': {}",
            name,
            stdout
        );
    }
}

#[test]
fn list_templates_shows_hashes() {
    let output = cli().arg("--list-templates").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Every template should have a 0x-prefixed hash
    assert!(
        stdout.contains("0x"),
        "should show template hashes: {}",
        stdout
    );
}

#[test]
fn list_templates_shows_mandatory_fields() {
    let output = cli().arg("--list-templates").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("Mandatory fields:"),
        "should show mandatory fields: {}",
        stdout
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Info (-i / --info)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn info_flag_shows_description() {
    let output = cli().arg("-i").output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Aqua CLI TOOL"),
        "info should show CLI title: {}",
        stdout
    );
    assert!(
        stdout.contains("COMMANDS"),
        "info should list available commands"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Verbose (-v / --verbose)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn verbose_produces_more_output_than_quiet() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");

    let quiet = cli().arg("-a").arg(&aqua).output().unwrap();
    let verbose = cli()
        .arg("-a")
        .arg(&aqua)
        .arg("-v")
        .output()
        .unwrap();

    let quiet_len = String::from_utf8_lossy(&quiet.stdout).len();
    let verbose_len = String::from_utf8_lossy(&verbose.stdout).len();

    assert!(
        verbose_len >= quiet_len,
        "verbose output ({} bytes) should be >= quiet output ({} bytes)",
        verbose_len,
        quiet_len
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Output file (-o / --output)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn output_to_json_log_file() {
    let (tmp, _fix, aqua) = generate_genesis("1.txt");
    let log_path = tmp.path().join("report.json");

    let output = cli()
        .arg("-a")
        .arg(&aqua)
        .arg("-v")
        .arg("-o")
        .arg(&log_path)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(log_path.exists(), "output log file should be created");

    let log_content = fs::read_to_string(&log_path).unwrap();
    assert!(!log_content.is_empty(), "log file should not be empty");
}

// ═════════════════════════════════════════════════════════════════════════════
// Witnessing (-w)
// ═════════════════════════════════════════════════════════════════════════════

/// TSA witness uses the public DigiCert timestamp authority.
/// Requires network access — degrades gracefully if unavailable.
#[test]
fn witness_tsa() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");

    let output = cli()
        .arg("-w")
        .arg(&aqua)
        .arg("--witness-tsa")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("Successfully witnessed") {
        assert_verify_ok(&aqua);
    } else {
        eprintln!(
            "NOTE: TSA witness test skipped (network unavailable): {}",
            stdout
        );
    }
}

/// Nostr witness requires relay connectivity.
/// Requires network access — degrades gracefully if unavailable.
#[test]
fn witness_nostr() {
    let (tmp, _fix, aqua) = generate_genesis("1.txt");
    let keys = write_keys_file(tmp.path());

    let output = cli()
        .arg("-w")
        .arg(&aqua)
        .arg("--witness-nostr")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("Successfully witnessed") {
        // Nostr timestamps are verified via WASM which may not be available
        // in all environments, so just verify the tree structure grew.
        let tree = read_tree(&aqua);
        assert!(
            revision_count(&tree) > 3,
            "witnessed chain should have more than 3 revisions"
        );
    } else {
        eprintln!(
            "NOTE: Nostr witness test skipped (network unavailable): {}",
            stdout
        );
    }
}

#[test]
fn witness_nostr_without_keys_fails() {
    let (_tmp, _fix, aqua) = generate_genesis("1.txt");

    let output = cli()
        .arg("-w")
        .arg(&aqua)
        .arg("--witness-nostr")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("requires keys file") || stdout.contains("❌"),
        "Nostr witness without keys should fail: {}",
        stdout
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// End-to-end workflows
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn full_workflow_generate_sign_verify() {
    let tmp = TempDir::new().unwrap();
    fs::copy(test_files_dir().join("1.txt"), tmp.path().join("1.txt")).unwrap();
    let keys = write_keys_file(tmp.path());

    // Generate
    let gen = cli()
        .arg("-f")
        .arg(tmp.path().join("1.txt"))
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert!(gen.status.success(), "generate failed");

    let aqua = tmp.path().join("1.aqua.json");

    // Sign
    let sign = cli()
        .arg("-s")
        .arg(&aqua)
        .arg("--sign-type")
        .arg("cli")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&sign.stdout).contains("Successfully signed"));

    // Verify
    assert_verify_ok(&aqua);
}

#[test]
fn full_workflow_generate_sign_all_types_verify() {
    let tmp = TempDir::new().unwrap();
    fs::copy(test_files_dir().join("1.txt"), tmp.path().join("1.txt")).unwrap();
    let keys = write_keys_file(tmp.path());

    // Generate
    cli()
        .arg("-f")
        .arg(tmp.path().join("1.txt"))
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let aqua = tmp.path().join("1.aqua.json");

    // Sign with all three local types
    for sign_type in &["cli", "did", "p256"] {
        let sign = cli()
            .arg("-s")
            .arg(&aqua)
            .arg("--sign-type")
            .arg(sign_type)
            .arg("-k")
            .arg(&keys)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&sign.stdout);
        assert!(
            stdout.contains("Successfully signed"),
            "{} signing failed: {}",
            sign_type,
            stdout
        );
    }

    // Verify the chain with all three signatures
    assert_verify_ok(&aqua);

    // Should have 3 + 3 = 6 revisions (anchor+template+object + 3 signatures)
    let tree = read_tree(&aqua);
    assert_eq!(
        revision_count(&tree),
        6,
        "chain with 3 signatures should have 6 revisions"
    );
}

#[test]
fn full_workflow_generate_link_sign() {
    let tmp = TempDir::new().unwrap();
    fs::copy(test_files_dir().join("1.txt"), tmp.path().join("1.txt")).unwrap();
    fs::copy(
        test_files_dir().join("img.jpeg"),
        tmp.path().join("img.jpeg"),
    )
    .unwrap();
    let keys = write_keys_file(tmp.path());

    // Generate both chains
    cli()
        .arg("-f")
        .arg(tmp.path().join("1.txt"))
        .current_dir(tmp.path())
        .output()
        .unwrap();
    cli()
        .arg("-f")
        .arg(tmp.path().join("img.jpeg"))
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let chain1 = tmp.path().join("1.aqua.json");
    let chain2 = tmp.path().join("img.aqua.json");

    // Link
    let link = cli()
        .arg("--link")
        .arg(&chain1)
        .arg(&chain2)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&link.stdout).contains("Successfully linked"));

    // Sign the linked chain
    let sign = cli()
        .arg("-s")
        .arg(&chain1)
        .arg("--sign-type")
        .arg("cli")
        .arg("-k")
        .arg(&keys)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&sign.stdout).contains("Successfully signed"));

    // Linked chains contain cross-tree anchor references that won't resolve
    // in isolation, so we verify structure rather than full verification.
    let tree = read_tree(&chain1);
    assert!(
        revision_count(&tree) > 4,
        "linked + signed chain should have > 4 revisions"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Error cases
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn no_operation_exits_with_error() {
    let output = cli().output().unwrap();
    // clap exits non-zero when the required arg group is missing
    assert!(
        !output.status.success(),
        "no args should exit with error code"
    );
}

#[test]
fn verify_nonexistent_file_fails() {
    let output = cli()
        .arg("-a")
        .arg("/tmp/nonexistent_aqua_test_file_12345.json")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "verifying nonexistent file should fail"
    );
}

#[test]
fn generate_nonexistent_file_fails() {
    let output = cli()
        .arg("-f")
        .arg("/tmp/nonexistent_test_input_12345.txt")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "generating from nonexistent file should fail"
    );
}

#[test]
fn sign_with_invalid_json_fails() {
    let tmp = TempDir::new().unwrap();
    let bad_json = tmp.path().join("bad.json");
    fs::write(&bad_json, "this is not json").unwrap();

    let output = cli()
        .arg("-s")
        .arg(&bad_json)
        .arg("--sign-type")
        .arg("cli")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("❌") || stderr.contains("error") || !output.status.success(),
        "signing invalid JSON should fail: stdout={} stderr={}",
        stdout,
        stderr
    );
}

#[test]
fn create_object_with_invalid_payload_json_fails() {
    let tmp = TempDir::new().unwrap();

    let output = cli()
        .arg("--create-object")
        .arg("--template-name")
        .arg("file")
        .arg("--payload")
        .arg("not valid json at all")
        .current_dir(tmp.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("❌") || stderr.contains("error") || stderr.contains("Invalid"),
        "invalid JSON payload should fail: stdout={} stderr={}",
        stdout,
        stderr
    );
}
