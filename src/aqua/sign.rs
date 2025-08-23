use crate::aqua::wallet::{create_ethereum_signature, get_wallet};
use crate::models::{
    create_version_string, AquaTree, BaseRevision, CliArgs, HashingMethod, SignatureRevision,
};
use crate::servers::server_sign::sign_message_server;
use crate::utils::{
    calculate_revision_hash, generate_timestamp, get_latest_revision_hash, read_aqua_data,
    read_secret_keys, save_aqua_tree, save_logs_to_file,
};
use aqua_verifier::aqua_verifier::AquaVerifier;
use std::env;
use std::path::PathBuf;

/// Main function to handle CLI signing chain process for v3
pub fn cli_sign_chain(
    args: CliArgs,
    _aqua_verifier: AquaVerifier,
    sign_path: PathBuf,
    keys_file: Option<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push(format!(
        "Starting v3 signing process for file: {:?}",
        sign_path
    ));

    match process_signing_chain(&args, &sign_path, keys_file, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Signing process completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in signing process: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

/// Process the signing chain operation for v3
fn process_signing_chain(
    args: &CliArgs,
    sign_path: &PathBuf,
    keys_file: Option<PathBuf>,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    // Read and validate AquaTree
    let aqua_tree = read_and_validate_tree(sign_path, logs_data)?;

    // Extract data needed for signing
    let sign_data = extract_signing_data(&aqua_tree, logs_data)?;

    // Perform signing operation
    let sign_result = perform_signing(&sign_data.message_to_sign, keys_file, logs_data, args)?;

    // Create signature revision
    let signature_revision = create_signature_revision(sign_data, sign_result, logs_data)?;

    // Add signature revision to tree and save
    add_signature_to_tree(aqua_tree, signature_revision, sign_path, logs_data)?;

    Ok(())
}

/// Data extracted from AquaTree for signing
#[derive(Debug, Clone, PartialEq, Eq)]
struct SigningData {
    message_to_sign: String,
    latest_hash: String,
    genesis_filename: String,
}

/// Result of signing operation
struct SigningResult {
    signature: String,
    public_key: String,
    wallet_address: String,
    signature_type: String,
}

/// Read and validate the AquaTree
fn read_and_validate_tree(
    sign_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<AquaTree, String> {
    logs_data.push("Reading and validating AquaTree...".to_string());

    let aqua_tree = read_aqua_data(sign_path).map_err(|e| {
        logs_data.push(format!("Error reading AquaTree: {}", e));
        e
    })?;

    // Basic validation
    if aqua_tree.revisions.is_empty() {
        return Err("No revisions found in AquaTree".to_string());
    }

    logs_data.push(format!(
        "Successfully loaded AquaTree with {} revisions",
        aqua_tree.revisions.len()
    ));
    Ok(aqua_tree)
}

/// Extract data needed for signing from AquaTree
fn extract_signing_data(
    aqua_tree: &AquaTree,
    logs_data: &mut Vec<String>,
) -> Result<SigningData, String> {
    logs_data.push("Extracting signing data...".to_string());

    // Get latest revision hash (this is what we'll sign)
    let latest_hash = get_latest_revision_hash(aqua_tree);
    if latest_hash.is_empty() {
        return Err("No latest revision hash found".to_string());
    }

    // Find genesis revision to get filename
    let genesis_filename = find_genesis_filename(aqua_tree)?;

    logs_data.push(format!("Message to sign: {}", latest_hash));
    logs_data.push(format!("Genesis filename: {}", genesis_filename));

    Ok(SigningData {
        message_to_sign: latest_hash.clone(),
        latest_hash,
        genesis_filename,
    })
}

/// Find genesis revision filename
fn find_genesis_filename(aqua_tree: &AquaTree) -> Result<String, String> {
    // Look for revision with empty previous_verification_hash
    for (hash, revision) in &aqua_tree.revisions {
        if let Some(prev_hash) = revision
            .get("previous_verification_hash")
            .and_then(|v| v.as_str())
        {
            if prev_hash.is_empty() {
                // This is genesis revision, get filename from file_index
                if let Some(filename) = aqua_tree.file_index.get(hash) {
                    return Ok(filename.clone());
                }
                // If not in file_index, try to extract from revision itself
                if let Some("file") = revision.get("revision_type").and_then(|v| v.as_str()) {
                    return Ok("genesis_file".to_string()); // fallback
                }
            }
        }
    }
    Err("Genesis revision not found".to_string())
}

/// Perform signing operation (local or server-based)
fn perform_signing(
    message_to_sign: &str,
    keys_file: Option<PathBuf>,
    logs_data: &mut Vec<String>,
    args: &CliArgs,
) -> Result<SigningResult, String> {
    logs_data.push("Starting signing process...".to_string());

    if let Some(keys_path) = keys_file {
        perform_local_signing(message_to_sign, keys_path, logs_data, args)
    } else {
        perform_server_signing(message_to_sign, logs_data)
    }
}

/// Perform signing using local keys
fn perform_local_signing(
    message_to_sign: &str,
    keys_path: PathBuf,
    logs_data: &mut Vec<String>,
    args: &CliArgs,
) -> Result<SigningResult, String> {
    logs_data.push("Performing local signing with ethereum:eip-191...".to_string());

    let secret_keys = read_secret_keys(&keys_path).map_err(|e| {
        let error = format!("Error reading secret keys: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    let mnemonic = secret_keys.mnemonic.ok_or_else(|| {
        let error = "Mnemonic not found in secret keys".to_string();
        logs_data.push(error.clone());
        error
    })?;

    // Determine wallet generation behavior
    let gen_wallet_on_fail = match args.level.as_ref() {
        Some(level) => level.trim() != "1",
        None => true,
    };

    let (address, public_key, private_key) =
        get_wallet(&mnemonic, gen_wallet_on_fail).map_err(|e| {
            let error = format!("Error getting wallet: {}", e);
            logs_data.push(error.clone());
            error
        })?;

    let signature = create_ethereum_signature(&private_key, message_to_sign).map_err(|e| {
        let error = format!("Error creating signature: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    logs_data.push("Local signing completed successfully".to_string());

    Ok(SigningResult {
        signature,
        public_key,
        wallet_address: address,
        signature_type: "ethereum:eip-191".to_string(),
    })
}

/// Perform signing using MetaMask server
fn perform_server_signing(
    message_to_sign: &str,
    logs_data: &mut Vec<String>,
) -> Result<SigningResult, String> {
    logs_data.push("Performing server signing with MetaMask...".to_string());

    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        let error = format!("Error initializing tokio runtime: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    let chain = env::var("chain").unwrap_or("sepolia".to_string());

    let sign_payload = runtime
        .block_on(async { sign_message_server(message_to_sign.to_string(), chain).await })
        .map_err(|e| {
            let error = format!("Error in server signing: {}", e);
            logs_data.push(error.clone());
            error
        })?;

    logs_data.push("Server signing completed successfully".to_string());

    Ok(SigningResult {
        signature: sign_payload.signature,
        public_key: sign_payload.public_key,
        wallet_address: sign_payload.wallet_address,
        signature_type: sign_payload.signature_type,
    })
}

/// Create signature revision from signing data and result
fn create_signature_revision(
    sign_data: SigningData,
    sign_result: SigningResult,
    logs_data: &mut Vec<String>,
) -> Result<SignatureRevision, String> {
    logs_data.push("Creating signature revision...".to_string());

    let signature_revision = SignatureRevision {
        base: BaseRevision {
            previous_verification_hash: sign_data.latest_hash,
            local_timestamp: generate_timestamp(),
            revision_type: "signature".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        signature: sign_result.signature,
        signature_public_key: sign_result.public_key,
        signature_wallet_address: sign_result.wallet_address,
        signature_type: sign_result.signature_type,
    };

    logs_data.push("Signature revision created".to_string());
    Ok(signature_revision)
}

/// Add signature revision to AquaTree and save
fn add_signature_to_tree(
    mut aqua_tree: AquaTree,
    signature_revision: SignatureRevision,
    sign_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push("Adding signature revision to AquaTree...".to_string());

    // Serialize signature revision
    let revision_json = serde_json::to_string(&signature_revision)
        .map_err(|e| format!("Failed to serialize signature revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;
    logs_data.push(format!(
        "Generated signature revision hash: {}",
        revision_hash
    ));

    // Add to revisions
    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;

    aqua_tree
        .revisions
        .insert(revision_hash.clone(), revision_value);

    // Update tree mapping
    let previous_hash = signature_revision.base.previous_verification_hash.clone();
    let mut path = aqua_tree
        .tree_mapping
        .paths
        .get(&previous_hash)
        .cloned()
        .unwrap_or_else(|| vec![previous_hash.clone()]);
    path.push(revision_hash.clone());

    aqua_tree
        .tree_mapping
        .paths
        .insert(revision_hash.clone(), path);
    aqua_tree.tree_mapping.latest_hash = revision_hash.clone();

    // Save updated AquaTree
    save_aqua_tree(&aqua_tree, sign_path, "signed").map_err(|e| {
        let error = format!("Error saving signed AquaTree: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    logs_data.push("Signed AquaTree saved successfully".to_string());
    Ok(())
}

/// Add signature revision to existing AquaTree (utility function)
pub fn add_signature_revision_to_aqua_tree(
    aqua_tree: &mut AquaTree,
    signature: String,
    public_key: String,
    wallet_address: String,
    signature_type: String,
    logs_data: &mut Vec<String>,
) -> Result<String, String> {
    let previous_hash = aqua_tree.tree_mapping.latest_hash.clone();

    let signature_revision = SignatureRevision {
        base: BaseRevision {
            previous_verification_hash: previous_hash,
            local_timestamp: generate_timestamp(),
            revision_type: "signature".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        signature,
        signature_public_key: public_key,
        signature_wallet_address: wallet_address,
        signature_type,
    };

    // Serialize and hash
    let revision_json = serde_json::to_string(&signature_revision)
        .map_err(|e| format!("Failed to serialize signature revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;

    // Add to tree
    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;

    aqua_tree
        .revisions
        .insert(revision_hash.clone(), revision_value);

    // Update tree mapping
    let mut path = aqua_tree
        .tree_mapping
        .paths
        .get(&aqua_tree.tree_mapping.latest_hash)
        .cloned()
        .unwrap_or_default();
    path.push(revision_hash.clone());

    aqua_tree
        .tree_mapping
        .paths
        .insert(revision_hash.clone(), path);
    aqua_tree.tree_mapping.latest_hash = revision_hash.clone();

    logs_data.push(format!("Added signature revision: {}", revision_hash));
    Ok(revision_hash)
}

/// Validate signature revision integrity
pub fn validate_signature_revision(
    signature_revision: &SignatureRevision,
    _message_hash: &str,
) -> Result<bool, String> {
    // This is a placeholder for actual signature verification
    // In a real implementation, you would:
    // 1. Recover public key from signature
    // 2. Verify it matches signature_public_key
    // 3. Verify the signature against the message_hash

    match signature_revision.signature_type.as_str() {
        "ethereum:eip-191" => {
            // Ethereum EIP-191 signature validation would go here
            Ok(true) // Placeholder
        }
        "did_key" => {
            // DID key signature validation would go here
            Ok(true) // Placeholder
        }
        _ => Err(format!(
            "Unsupported signature type: {}",
            signature_revision.signature_type
        )),
    }
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
    use crate::models::TreeMapping;

    #[test]
    fn test_find_genesis_filename() {
        let mut revisions = std::collections::HashMap::new();
        revisions.insert(
            "0x123".to_string(),
            serde_json::json!({
                "previous_verification_hash": "",
                "revision_type": "file"
            }),
        );

        let mut file_index = std::collections::HashMap::new();
        file_index.insert("0x123".to_string(), "genesis.txt".to_string());

        let tree = AquaTree {
            revisions,
            file_index,
            tree_mapping: TreeMapping {
                paths: std::collections::HashMap::new(),
                latest_hash: "0x123".to_string(),
            },
        };

        let filename = find_genesis_filename(&tree).unwrap();
        assert_eq!(filename, "genesis.txt");
    }

    #[test]
    fn test_signature_revision_creation() {
        let sign_data = SigningData {
            message_to_sign: "test_message".to_string(),
            latest_hash: "0x123".to_string(),
            genesis_filename: "test.txt".to_string(),
        };

        let sign_result = SigningResult {
            signature: "0xtest_signature".to_string(),
            public_key: "0xtest_pubkey".to_string(),
            wallet_address: "0xtest_address".to_string(),
            signature_type: "ethereum:eip-191".to_string(),
        };

        let mut logs = Vec::new();
        let signature_rev = create_signature_revision(sign_data, sign_result, &mut logs).unwrap();

        assert_eq!(signature_rev.base.revision_type, "signature");
        assert_eq!(signature_rev.signature_type, "ethereum:eip-191");
        assert_eq!(signature_rev.base.previous_verification_hash, "0x123");
    }
}
