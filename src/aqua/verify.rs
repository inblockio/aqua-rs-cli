use aqua_verifier::aqua_verifier::AquaVerifier;
use std::path::PathBuf;

use crate::models::{AquaTree, CliArgs};
use crate::utils::{read_aqua_data, save_logs_to_file};
use crate::validation::AquaV3Validator;

/// Main function to verify v3 Aqua chains
pub fn cli_verify_chain(args: CliArgs, aqua_verifier: AquaVerifier, verify_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();

    println!("🔍 Verifying Aqua Protocol v3 file: {:?}", verify_path);
    logs_data.push(format!("Starting verification of: {:?}", verify_path));

    // Read AquaTree data (with v2 compatibility)
    let aqua_tree = match read_aqua_data(&verify_path) {
        Ok(data) => data,
        Err(error) => {
            handle_file_error(&args, &mut logs_data, error);
            return;
        }
    };

    logs_data.push(format!(
        "Successfully loaded AquaTree with {} revisions",
        aqua_tree.revisions.len()
    ));

    // Verify using v3 validator
    let strict_mode = args.level.as_ref().map(|l| l == "1").unwrap_or(false);
    let v3_validator = AquaV3Validator::new(strict_mode);

    match v3_validator.validate_aqua_tree(&aqua_tree) {
        Ok(()) => {
            logs_data.push("✅ SUCCESS: AquaTree v3 validation passed".to_string());

            // Additional legacy verification if available
            if let Some(legacy_results) =
                try_legacy_verification(&aqua_verifier, &aqua_tree, &mut logs_data)
            {
                process_legacy_results(legacy_results, &mut logs_data);
            }
        }
        Err(validation_errors) => {
            logs_data.push("❌ FAILED: AquaTree v3 validation failed".to_string());

            for error in &validation_errors {
                logs_data.push(format!("  - {}", error));
            }

            if !strict_mode {
                logs_data.push("Note: Running in standard mode (level 2). Use --level 1 for strict validation.".to_string());
            }
        }
    }

    // Detailed revision analysis
    perform_detailed_analysis(&aqua_tree, &mut logs_data);

    // Output results
    output_verification_results(&args, &logs_data);
}

/// Try to perform legacy verification for backward compatibility
fn try_legacy_verification(
    _aqua_verifier: &AquaVerifier,
    aqua_tree: &AquaTree,
    logs_data: &mut Vec<String>,
) -> Option<LegacyResults> {
    logs_data.push("Attempting legacy verification compatibility...".to_string());

    // Check if this looks like it might have legacy v2 structure
    let has_legacy_structure = aqua_tree
        .revisions
        .values()
        .any(|rev| rev.get("content").is_some() && rev.get("metadata").is_some());

    if has_legacy_structure {
        logs_data
            .push("Legacy v2 structure detected - compatibility verification skipped".to_string());
        logs_data
            .push("Recommendation: Migrate to pure v3 format for best performance".to_string());
    }

    None // For now, we focus on v3 validation
}

struct LegacyResults {
    successful: bool,
    details: Vec<String>,
}

fn process_legacy_results(results: LegacyResults, logs_data: &mut Vec<String>) {
    if results.successful {
        logs_data.push("Legacy verification: ✅ PASSED".to_string());
    } else {
        logs_data.push("Legacy verification: ❌ FAILED".to_string());
    }

    for detail in results.details {
        logs_data.push(format!("  Legacy: {}", detail));
    }
}

/// Perform detailed analysis of the AquaTree
fn perform_detailed_analysis(aqua_tree: &AquaTree, logs_data: &mut Vec<String>) {
    logs_data.push("🔍 Detailed Analysis:".to_string());

    // Count revision types
    let mut revision_counts = std::collections::HashMap::new();
    for revision in aqua_tree.revisions.values() {
        if let Some(rev_type) = revision.get("revision_type").and_then(|v| v.as_str()) {
            *revision_counts.entry(rev_type.to_string()).or_insert(0) += 1;
        }
    }

    logs_data.push("Revision Type Summary:".to_string());
    for (rev_type, count) in &revision_counts {
        logs_data.push(format!("  - {}: {} revision(s)", rev_type, count));
    }

    // File index analysis
    logs_data.push(format!(
        "File Index: {} entries",
        aqua_tree.file_index.len()
    ));

    // Tree mapping analysis
    logs_data.push(format!(
        "Tree Mapping: {} paths tracked",
        aqua_tree.tree_mapping.paths.len()
    ));
    logs_data.push(format!(
        "Latest Hash: {}",
        aqua_tree.tree_mapping.latest_hash
    ));

    // Chain integrity check
    check_chain_integrity(aqua_tree, logs_data);

    // Timestamp analysis
    analyze_timestamps(aqua_tree, logs_data);
}

/// Check chain integrity
fn check_chain_integrity(aqua_tree: &AquaTree, logs_data: &mut Vec<String>) {
    let mut chain_length = 0;
    let mut current_hash = aqua_tree.tree_mapping.latest_hash.clone();
    let mut visited = std::collections::HashSet::new();

    logs_data.push("Chain Integrity Check:".to_string());

    loop {
        if visited.contains(&current_hash) {
            logs_data.push("  ⚠️  Loop detected in chain".to_string());
            break;
        }
        visited.insert(current_hash.clone());

        if let Some(revision) = aqua_tree.revisions.get(&current_hash) {
            chain_length += 1;

            if let Some(prev_hash) = revision
                .get("previous_verification_hash")
                .and_then(|v| v.as_str())
            {
                if prev_hash.is_empty() {
                    logs_data.push(format!("  ✅ Complete chain: {} revisions", chain_length));
                    break;
                }
                current_hash = prev_hash.to_string();
            } else {
                logs_data.push("  ❌ Missing previous_verification_hash".to_string());
                break;
            }
        } else {
            logs_data.push(format!("  ❌ Broken chain at hash: {}", current_hash));
            break;
        }

        if chain_length > 1000 {
            logs_data.push("  ⚠️  Chain too long, stopping analysis".to_string());
            break;
        }
    }
}

/// Analyze timestamps in the chain
fn analyze_timestamps(aqua_tree: &AquaTree, logs_data: &mut Vec<String>) {
    let mut timestamps = Vec::new();

    for revision in aqua_tree.revisions.values() {
        if let Some(timestamp) = revision.get("local_timestamp").and_then(|v| v.as_str()) {
            timestamps.push(timestamp.to_string());
        }
    }

    if !timestamps.is_empty() {
        timestamps.sort();
        logs_data.push("Timestamp Analysis:".to_string());
        logs_data.push(format!("  First: {}", timestamps.first().unwrap()));
        logs_data.push(format!("  Latest: {}", timestamps.last().unwrap()));

        // Check for timestamp ordering issues
        let mut prev_timestamp = "";
        let mut order_issues = 0;

        for timestamp in &timestamps {
            if !prev_timestamp.is_empty() && timestamp < prev_timestamp {
                order_issues += 1;
            }
            prev_timestamp = timestamp;
        }

        if order_issues > 0 {
            logs_data.push(format!(
                "  ⚠️  {} timestamp ordering issues detected",
                order_issues
            ));
        } else {
            logs_data.push("  ✅ Timestamps in correct order".to_string());
        }
    }
}

/// Handle file reading errors
fn handle_file_error(args: &CliArgs, logs_data: &mut Vec<String>, error_message: String) {
    logs_data.push(format!("❌ File Error: {}", error_message));

    // Provide helpful suggestions
    if error_message.contains("v2 PageData") {
        logs_data.push("💡 Suggestion: This appears to be a v2 format file.".to_string());
        logs_data
            .push("   Consider migrating to v3 format using the conversion tools.".to_string());
    } else if error_message.contains("JSON") {
        logs_data.push(
            "💡 Suggestion: Check that the file is valid JSON and follows v3 schema.".to_string(),
        );
    } else if error_message.contains("No such file") {
        logs_data.push(
            "💡 Suggestion: Verify the file path is correct and the file exists.".to_string(),
        );
    }

    if let Some(output_path) = &args.output {
        if let Err(log_error) = save_logs_to_file(logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", log_error);
        }
    }
}

/// Output verification results
fn output_verification_results(args: &CliArgs, logs_data: &Vec<String>) {
    if args.verbose {
        for item in logs_data {
            println!("{}", item);
        }
    } else {
        let vc = "Verification completed".to_string();
        // Show summary in non-verbose mode
        let summary = logs_data.last().unwrap_or(&vc);
        println!("{}", summary);

        // Show any critical errors even in non-verbose mode
        for log in logs_data {
            if log.contains("❌") || log.contains("FAILED") {
                println!("{}", log);
            }
        }
    }

    // Save logs to file if specified
    if let Some(output_path) = &args.output {
        if let Err(log_error) = save_logs_to_file(logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", log_error);
        } else if args.verbose {
            println!("📄 Verification report saved to: {:?}", output_path);
        }
    }
}

/// Verify specific revision by hash
pub fn verify_revision_by_hash(
    aqua_tree: &AquaTree,
    revision_hash: &str,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    let revision = aqua_tree
        .revisions
        .get(revision_hash)
        .ok_or_else(|| format!("Revision not found: {}", revision_hash))?;

    logs_data.push(format!("Verifying specific revision: {}", revision_hash));

    let validator = AquaV3Validator::new(false);
    match validator.validate_aqua_tree(aqua_tree) {
        Ok(()) => {
            logs_data.push("✅ Revision verification passed".to_string());
            Ok(())
        }
        Err(errors) => {
            for error in errors {
                logs_data.push(format!("❌ {}", error));
            }
            Err("Revision verification failed".to_string())
        }
    }
}

/// Quick verification without detailed analysis (for programmatic use)
pub fn quick_verify(aqua_tree: &AquaTree) -> Result<(), Vec<crate::models::ValidationError>> {
    let validator = AquaV3Validator::new(false);
    validator.validate_aqua_tree(aqua_tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AquaTree, TreeMapping};
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn test_chain_integrity_check() {
        let mut revisions = HashMap::new();
        revisions.insert(
            "0x123".to_string(),
            json!({
                "previous_verification_hash": "",
                "local_timestamp": "20240101120000",
                "revision_type": "file"
            }),
        );
        revisions.insert(
            "0x456".to_string(),
            json!({
                "previous_verification_hash": "0x123",
                "local_timestamp": "20240101130000",
                "revision_type": "signature"
            }),
        );

        let tree = AquaTree {
            revisions,
            file_index: HashMap::new(),
            tree_mapping: TreeMapping {
                paths: HashMap::new(),
                latest_hash: "0x456".to_string(),
            },
        };

        let mut logs = Vec::new();
        check_chain_integrity(&tree, &mut logs);

        // Should find complete chain with 2 revisions
        assert!(logs
            .iter()
            .any(|log| log.contains("Complete chain: 2 revisions")));
    }

    #[test]
    fn test_timestamp_analysis() {
        let mut revisions = HashMap::new();
        revisions.insert(
            "0x123".to_string(),
            json!({
                "local_timestamp": "20240101120000"
            }),
        );
        revisions.insert(
            "0x456".to_string(),
            json!({
                "local_timestamp": "20240101130000"
            }),
        );

        let tree = AquaTree {
            revisions,
            file_index: HashMap::new(),
            tree_mapping: TreeMapping {
                paths: HashMap::new(),
                latest_hash: "0x456".to_string(),
            },
        };

        let mut logs = Vec::new();
        analyze_timestamps(&tree, &mut logs);

        assert!(logs
            .iter()
            .any(|log| log.contains("Timestamps in correct order")));
    }
}
