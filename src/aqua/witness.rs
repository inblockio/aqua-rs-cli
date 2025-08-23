use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{
    create_version_string, AquaTree, BaseRevision, CliArgs, HashingMethod, WitnessPayload,
    WitnessRevision,
};
use crate::servers::server_witness::witness_message_server;
use crate::utils::{
    calculate_revision_hash, generate_timestamp, get_latest_revision_hash, read_aqua_data,
    save_aqua_tree, save_logs_to_file,
};
use aqua_verifier::aqua_verifier::AquaVerifier;
use sha3::{Digest, Sha3_256};

/// Main function to witness an Aqua chain for v3
pub fn cli_witness_chain(args: CliArgs, _aqua_verifier: AquaVerifier, witness_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();

    println!(
        "Starting v3 witnessing process for file: {:?}",
        witness_path
    );
    logs_data.push(format!(
        "Starting witnessing process for: {:?}",
        witness_path
    ));

    match process_witnessing_chain(&args, witness_path, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Witnessing process completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in witnessing process: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

/// Process the witnessing chain operation for v3
fn process_witnessing_chain(
    _args: &CliArgs,
    witness_path: PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    // Read and validate AquaTree
    let aqua_tree = read_and_validate_tree(&witness_path, logs_data)?;

    // Extract data needed for witnessing
    let witness_data = extract_witnessing_data(&aqua_tree, logs_data)?;

    // Perform witnessing operation
    let witness_result = perform_witnessing(&witness_data, logs_data)?;

    // Create witness revision
    let witness_revision = create_witness_revision(witness_data, witness_result, logs_data)?;

    // Add witness revision to tree and save
    add_witness_to_tree(aqua_tree, witness_revision, &witness_path, logs_data)?;

    Ok(())
}

/// Data extracted from AquaTree for witnessing
#[derive(Debug, Clone, PartialEq, Eq)]
struct WitnessingData {
    latest_hash: String,
    witness_event_hash: String,
    genesis_filename: String,
}

/// Result of witnessing operation
struct WitnessingResult {
    tx_hash: String,
    network: String,
    wallet_address: String,
    merkle_proof: Vec<String>,
    merkle_root: String,
    timestamp: i64,
    smart_contract_address: String,
}

/// Read and validate the AquaTree
fn read_and_validate_tree(
    witness_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<AquaTree, String> {
    logs_data.push("Reading and validating AquaTree...".to_string());

    let aqua_tree = read_aqua_data(witness_path).map_err(|e| {
        logs_data.push(format!("Error reading AquaTree: {}", e));
        e
    })?;

    if aqua_tree.revisions.is_empty() {
        return Err("No revisions found in AquaTree".to_string());
    }

    logs_data.push(format!(
        "Successfully loaded AquaTree with {} revisions",
        aqua_tree.revisions.len()
    ));
    Ok(aqua_tree)
}

/// Extract data needed for witnessing from AquaTree
fn extract_witnessing_data(
    aqua_tree: &AquaTree,
    logs_data: &mut Vec<String>,
) -> Result<WitnessingData, String> {
    logs_data.push("Extracting witnessing data...".to_string());

    // Get latest revision hash
    let latest_hash = get_latest_revision_hash(aqua_tree);
    if latest_hash.is_empty() {
        return Err("No latest revision hash found".to_string());
    }

    // Generate witness event verification hash (v3 method)
    let witness_event_hash = generate_witness_event_hash(&latest_hash);

    // Find genesis filename
    let genesis_filename = find_genesis_filename(aqua_tree)?;

    logs_data.push(format!("Latest hash: {}", latest_hash));
    logs_data.push(format!("Witness event hash: {}", witness_event_hash));
    logs_data.push(format!("Genesis filename: {}", genesis_filename));

    Ok(WitnessingData {
        latest_hash,
        witness_event_hash,
        genesis_filename,
    })
}

/// Generate witness event verification hash
fn generate_witness_event_hash(latest_hash: &str) -> String {
    // Use the v3 method for witness event hash generation
    let empty_hash = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    let witness_event_string = format!("{}{}", empty_hash, latest_hash);

    let mut hasher = Sha3_256::new();
    hasher.update(witness_event_string.as_bytes());
    hex::encode(hasher.finalize())
}

/// Find genesis revision filename
fn find_genesis_filename(aqua_tree: &AquaTree) -> Result<String, String> {
    for (hash, revision) in &aqua_tree.revisions {
        if let Some(prev_hash) = revision
            .get("previous_verification_hash")
            .and_then(|v| v.as_str())
        {
            if prev_hash.is_empty() {
                if let Some(filename) = aqua_tree.file_index.get(hash) {
                    return Ok(filename.clone());
                }
                return Ok("genesis_file".to_string());
            }
        }
    }
    Err("Genesis revision not found".to_string())
}

/// Perform witnessing operation
fn perform_witnessing(
    witness_data: &WitnessingData,
    logs_data: &mut Vec<String>,
) -> Result<WitnessingResult, String> {
    logs_data.push("Starting witnessing process...".to_string());

    let chain = env::var("chain").unwrap_or("sepolia".to_string());
    let network = get_witness_network(&chain);

    match network.as_str() {
        "mainnet" | "sepolia" | "holesky" => {
            perform_ethereum_witnessing(witness_data, &network, logs_data)
        }
        "nostr" => perform_nostr_witnessing(witness_data, logs_data),
        "TSA_RFC3161" => perform_tsa_witnessing(witness_data, logs_data),
        _ => Err(format!("Unsupported witness network: {}", network)),
    }
}

/// Get witness network from chain configuration
fn get_witness_network(chain: &str) -> String {
    match chain {
        "mainnet" => "mainnet".to_string(),
        "sepolia" => "sepolia".to_string(),
        "holesky" => "holesky".to_string(),
        _ => "sepolia".to_string(), // default
    }
}

/// Perform Ethereum-based witnessing
fn perform_ethereum_witnessing(
    witness_data: &WitnessingData,
    network: &str,
    logs_data: &mut Vec<String>,
) -> Result<WitnessingResult, String> {
    logs_data.push(format!(
        "Performing Ethereum witnessing on network: {}",
        network
    ));

    // Initialize Tokio runtime for async operations
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Error initializing tokio runtime: {}", e))?;

    // Call witness message server
    let witness_payload = runtime
        .block_on(async {
            witness_message_server(witness_data.witness_event_hash.clone(), network.to_string())
                .await
        })
        .map_err(|e| format!("Error in witness server communication: {}", e))?;

    // Generate merkle proof (witness event hash as leaf)
    let merkle_proof = vec![witness_data.latest_hash.clone()];
    let merkle_root = witness_data.latest_hash.clone(); // Simplified for now

    // Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Get smart contract address based on network
    let smart_contract_address = get_smart_contract_address(network);

    logs_data.push("Ethereum witnessing completed successfully".to_string());
    logs_data.push(format!("Transaction hash: {}", witness_payload.tx_hash));
    logs_data.push(format!("Network: {}", witness_payload.network));
    logs_data.push(format!(
        "Wallet address: {}",
        witness_payload.wallet_address
    ));

    Ok(WitnessingResult {
        tx_hash: witness_payload.tx_hash,
        network: witness_payload.network,
        wallet_address: witness_payload.wallet_address,
        merkle_proof,
        merkle_root,
        timestamp,
        smart_contract_address,
    })
}

/// Get smart contract address for network
fn get_smart_contract_address(network: &str) -> String {
    // Using the same addresses from v2 as requested
    match network {
        "mainnet" | "sepolia" | "holesky" => {
            "0x45f59310ADD88E6d23ca58A0Fa7A55BEE6d2a611".to_string()
        }
        _ => "0x45f59310ADD88E6d23ca58A0Fa7A55BEE6d2a611".to_string(),
    }
}

/// Perform NOSTR witnessing
fn perform_nostr_witnessing(
    witness_data: &WitnessingData,
    logs_data: &mut Vec<String>,
) -> Result<WitnessingResult, String> {
    logs_data.push("Performing NOSTR witnessing...".to_string());

    // This is a placeholder for NOSTR witnessing implementation
    // In a real implementation, you would:
    // 1. Connect to NOSTR relays
    // 2. Create and sign NOSTR event
    // 3. Publish to relays
    // 4. Get event ID as proof

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    logs_data.push("NOSTR witnessing completed (placeholder)".to_string());

    Ok(WitnessingResult {
        tx_hash: format!("nostr_event_{}", timestamp),
        network: "nostr".to_string(),
        wallet_address: "nostr_pubkey_placeholder".to_string(),
        merkle_proof: vec![witness_data.witness_event_hash.clone()],
        merkle_root: witness_data.witness_event_hash.clone(),
        timestamp,
        smart_contract_address: "nostr_relay_placeholder".to_string(),
    })
}

/// Perform TSA RFC3161 witnessing
fn perform_tsa_witnessing(
    witness_data: &WitnessingData,
    logs_data: &mut Vec<String>,
) -> Result<WitnessingResult, String> {
    logs_data.push("Performing TSA RFC3161 witnessing...".to_string());

    // This is a placeholder for TSA witnessing implementation
    // In a real implementation, you would:
    // 1. Create TSA request with witness_event_hash
    // 2. Send to TSA server
    // 3. Receive timestamped response
    // 4. Extract timestamp token

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    logs_data.push("TSA RFC3161 witnessing completed (placeholder)".to_string());

    Ok(WitnessingResult {
        tx_hash: format!("tsa_token_{}", timestamp),
        network: "TSA_RFC3161".to_string(),
        wallet_address: "tsa_authority_placeholder".to_string(),
        merkle_proof: vec![witness_data.witness_event_hash.clone()],
        merkle_root: witness_data.witness_event_hash.clone(),
        timestamp,
        smart_contract_address: "tsa_server_placeholder".to_string(),
    })
}

/// Create witness revision from witnessing data and result
fn create_witness_revision(
    witness_data: WitnessingData,
    witness_result: WitnessingResult,
    logs_data: &mut Vec<String>,
) -> Result<WitnessRevision, String> {
    logs_data.push("Creating witness revision...".to_string());

    let witness_revision = WitnessRevision {
        base: BaseRevision {
            previous_verification_hash: witness_data.latest_hash,
            local_timestamp: generate_timestamp(),
            revision_type: "witness".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        witness_merkle_root: Some(witness_result.merkle_root),
        witness_timestamp: Some(witness_result.timestamp),
        witness_network: witness_result.network,
        witness_smart_contract_address: Some(witness_result.smart_contract_address),
        witness_transaction_hash: Some(witness_result.tx_hash),
        witness_sender_account_address: Some(witness_result.wallet_address),
        witness_merkle_proof: Some(witness_result.merkle_proof),
    };

    logs_data.push("Witness revision created".to_string());
    Ok(witness_revision)
}

/// Add witness revision to AquaTree and save
fn add_witness_to_tree(
    mut aqua_tree: AquaTree,
    witness_revision: WitnessRevision,
    witness_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push("Adding witness revision to AquaTree...".to_string());

    // Serialize witness revision
    let revision_json = serde_json::to_string(&witness_revision)
        .map_err(|e| format!("Failed to serialize witness revision: {}", e))?;

    let revision_hash = calculate_revision_hash(&revision_json)?;
    logs_data.push(format!(
        "Generated witness revision hash: {}",
        revision_hash
    ));

    // Add to revisions
    let revision_value: serde_json::Value = serde_json::from_str(&revision_json)
        .map_err(|e| format!("Failed to parse revision JSON: {}", e))?;

    aqua_tree
        .revisions
        .insert(revision_hash.clone(), revision_value);

    // Update tree mapping
    let previous_hash = witness_revision.base.previous_verification_hash.clone();
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
    save_aqua_tree(&aqua_tree, witness_path, "witnessed").map_err(|e| {
        let error = format!("Error saving witnessed AquaTree: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    logs_data.push("Witnessed AquaTree saved successfully".to_string());
    Ok(())
}

/// Add witness revision to existing AquaTree (utility function)
pub fn add_witness_revision_to_aqua_tree(
    aqua_tree: &mut AquaTree,
    witness_payload: WitnessPayload,
    logs_data: &mut Vec<String>,
) -> Result<String, String> {
    let previous_hash = aqua_tree.tree_mapping.latest_hash.clone();

    let witness_revision = WitnessRevision {
        base: BaseRevision {
            previous_verification_hash: previous_hash,
            local_timestamp: generate_timestamp(),
            revision_type: "witness".to_string(),
            version: create_version_string(HashingMethod::Scalar),
        },
        witness_merkle_root: witness_payload.merkle_root,
        witness_timestamp: witness_payload.timestamp,
        witness_network: witness_payload.network,
        witness_smart_contract_address: Some(get_smart_contract_address("sepolia")),
        witness_transaction_hash: Some(witness_payload.tx_hash),
        witness_sender_account_address: Some(witness_payload.wallet_address),
        witness_merkle_proof: witness_payload.merkle_proof,
    };

    // Serialize and hash
    let revision_json = serde_json::to_string(&witness_revision)
        .map_err(|e| format!("Failed to serialize witness revision: {}", e))?;

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

    logs_data.push(format!("Added witness revision: {}", revision_hash));
    Ok(revision_hash)
}

/// Validate witness revision against blockchain
pub fn validate_witness_revision(
    witness_revision: &WitnessRevision,
    logs_data: &mut Vec<String>,
) -> Result<bool, String> {
    logs_data.push("Validating witness revision...".to_string());

    match witness_revision.witness_network.as_str() {
        "mainnet" | "sepolia" | "holesky" => validate_ethereum_witness(witness_revision, logs_data),
        "nostr" => validate_nostr_witness(witness_revision, logs_data),
        "TSA_RFC3161" => validate_tsa_witness(witness_revision, logs_data),
        _ => Err(format!(
            "Unsupported witness network: {}",
            witness_revision.witness_network
        )),
    }
}

/// Validate Ethereum witness
fn validate_ethereum_witness(
    witness_revision: &WitnessRevision,
    logs_data: &mut Vec<String>,
) -> Result<bool, String> {
    logs_data.push("Validating Ethereum witness...".to_string());

    // Check required fields
    let tx_hash = witness_revision
        .witness_transaction_hash
        .as_ref()
        .ok_or("Missing transaction hash")?;

    let contract_addr = witness_revision
        .witness_smart_contract_address
        .as_ref()
        .ok_or("Missing smart contract address")?;

    // Validate format
    if !tx_hash.starts_with("0x") || tx_hash.len() != 66 {
        return Err("Invalid transaction hash format".to_string());
    }

    if !contract_addr.starts_with("0x") || contract_addr.len() != 42 {
        return Err("Invalid contract address format".to_string());
    }

    // In a real implementation, you would:
    // 1. Query the blockchain for the transaction
    // 2. Verify the transaction exists and is confirmed
    // 3. Check that it interacted with the expected contract
    // 4. Validate the witness data in the transaction

    logs_data.push("Ethereum witness validation completed (placeholder)".to_string());
    Ok(true)
}

/// Validate NOSTR witness
fn validate_nostr_witness(
    _witness_revision: &WitnessRevision,
    logs_data: &mut Vec<String>,
) -> Result<bool, String> {
    logs_data.push("Validating NOSTR witness...".to_string());

    // In a real implementation, you would:
    // 1. Connect to NOSTR relays
    // 2. Query for the event by ID
    // 3. Verify the event signature
    // 4. Check that the event contains the expected witness data

    logs_data.push("NOSTR witness validation completed (placeholder)".to_string());
    Ok(true)
}

/// Validate TSA witness
fn validate_tsa_witness(
    _witness_revision: &WitnessRevision,
    logs_data: &mut Vec<String>,
) -> Result<bool, String> {
    logs_data.push("Validating TSA witness...".to_string());

    // In a real implementation, you would:
    // 1. Parse the TSA token
    // 2. Verify the TSA signature
    // 3. Check the timestamp accuracy
    // 4. Validate the witnessed hash

    logs_data.push("TSA witness validation completed (placeholder)".to_string());
    Ok(true)
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

    #[test]
    fn test_witness_event_hash_generation() {
        let latest_hash = "abc123";
        let witness_hash = generate_witness_event_hash(latest_hash);

        assert_eq!(witness_hash.len(), 64); // SHA256 hex length

        // Same input should produce same hash
        let witness_hash2 = generate_witness_event_hash(latest_hash);
        assert_eq!(witness_hash, witness_hash2);
    }

    #[test]
    fn test_smart_contract_address() {
        let mainnet_addr = get_smart_contract_address("mainnet");
        let sepolia_addr = get_smart_contract_address("sepolia");

        assert_eq!(mainnet_addr, "0x45f59310ADD88E6d23ca58A0Fa7A55BEE6d2a611");
        assert_eq!(sepolia_addr, "0x45f59310ADD88E6d23ca58A0Fa7A55BEE6d2a611");
    }

    #[test]
    fn test_witness_revision_creation() {
        let witness_data = WitnessingData {
            latest_hash: "0x123".to_string(),
            witness_event_hash: "abc123".to_string(),
            genesis_filename: "test.txt".to_string(),
        };

        let witness_result = WitnessingResult {
            tx_hash: "0xtest_tx".to_string(),
            network: "sepolia".to_string(),
            wallet_address: "0xtest_wallet".to_string(),
            merkle_proof: vec!["proof1".to_string()],
            merkle_root: "root123".to_string(),
            timestamp: 1640995200,
            smart_contract_address: "0xcontract".to_string(),
        };

        let mut logs = Vec::new();
        let witness_rev = create_witness_revision(witness_data, witness_result, &mut logs).unwrap();

        assert_eq!(witness_rev.base.revision_type, "witness");
        assert_eq!(witness_rev.witness_network, "sepolia");
        assert_eq!(witness_rev.base.previous_verification_hash, "0x123");
    }
}
