use std::fmt::format;
use std::path::PathBuf;
use crate::aqua::wallet::{create_ethereum_signature, get_wallet};
use crate::models::{CliArgs, SecreatKeys, SignPayload};
use crate::servers::server_sign::sign_message_server;
use crate::utils::{read_aqua_data, read_secreat_keys, save_logs_to_file, save_page_data};
use aqua_verifier_rs_types::models::content::RevisionContentSignature;
use aqua_verifier_rs_types::models::page_data::PageData;
use verifier::aqua_verifier::AquaVerifier;

/// Represents the result of extracting chain data
struct ChainExtractionResult {
    last_revision_hash: String,
    genesis_revision_filename: String,
}

/// Represents the result of signing operations
struct SigningResult {
    signature: String,
    public_key: String,
    wallet_address: String,
}

/// Main function to handle the CLI signing chain process
/// 
/// # Arguments
/// * `args` - CLI arguments
/// * `aqua_verifier` - Instance of AquaVerifier
/// * `sign_path` - Path to the file to be signed
/// * `keys_file` - Optional path to the keys file
pub(crate) fn cli_sign_chain(
    args: CliArgs,
    aqua_verifier: AquaVerifier,
    sign_path: PathBuf,
    keys_file: Option<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push(format!("Starting signing process for file: {:?}", sign_path));

    match process_signing_chain(&args, aqua_verifier, &sign_path, keys_file, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Signing process completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in signing process: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

/// Process the signing chain operation
fn process_signing_chain(
    args: &CliArgs,
    aqua_verifier: AquaVerifier,
    sign_path: &PathBuf,
    keys_file: Option<PathBuf>,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    let aqua_page_data = read_and_validate_data(sign_path, logs_data)?;
    let chain_data = extract_chain_data(&aqua_page_data, logs_data)?;
    let sign_result = perform_signing(&chain_data.last_revision_hash, keys_file, logs_data)?;
    
    let rev_sig = RevisionContentSignature {
        signature: sign_result.signature,
        wallet_address: sign_result.wallet_address,
        publickey: sign_result.public_key,
        filename: chain_data.genesis_revision_filename,
    };

    process_verification_and_save(aqua_verifier, aqua_page_data, rev_sig, sign_path, logs_data)?;
    Ok(())
}

/// Read and validate the input data file
fn read_and_validate_data(
    sign_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<PageData, String> {
    logs_data.push("Info : Reading and validating input data...".to_string());
    read_aqua_data(sign_path).map_err(|e| {
        logs_data.push(format!("Error : Error reading aqua data: {}", e));
        e
    })
}

/// Extract necessary chain data from the page data
fn extract_chain_data(
    aqua_page_data: &PageData,
    logs_data: &mut Vec<String>,
) -> Result<ChainExtractionResult, String> {
    logs_data.push("Info : Extracting chain data...".to_string());

    let aqua_chain = aqua_page_data.pages.get(0).ok_or_else(|| {
        let error = "Error : No aqua chain found in page data".to_string();
        logs_data.push(error.clone());
        error
    })?;

    let genesis_hash_revision = aqua_chain.revisions.get(0).ok_or_else(|| {
        let error = "Error : Error fetching genesis revision".to_string();
        logs_data.push(error.clone());
        error
    })?;

    let (_genesis_hash, genesis_revision) = genesis_hash_revision;

    let genesis_filename = genesis_revision
        .content
        .clone()
        .file
        .ok_or_else(|| "Error : No filename found in genesis revision".to_string())?
        .filename;

    let last_revision_hash = if aqua_chain.revisions.len() == 1 {
        genesis_revision.metadata.verification_hash.to_string()
    } else {
        let (_last_hash, last_rev) = aqua_chain
            .revisions
            .get(aqua_chain.revisions.len() - 1)
            .ok_or_else(|| "Error : error getting last revision".to_string())?;
        last_rev.metadata.verification_hash.to_string()
    };

    Ok(ChainExtractionResult {
        last_revision_hash,
        genesis_revision_filename: genesis_filename,
    })
}

/// Perform the signing operation either through server or local keys
fn perform_signing(
    last_revision_hash: &str,
    keys_file: Option<PathBuf>,
    logs_data: &mut Vec<String>,
) -> Result<SigningResult, String> {
    logs_data.push("Info : Starting signing process...".to_string());

    if let Some(keys_path) = keys_file {
        perform_local_signing(last_revision_hash, keys_path, logs_data)
    } else {
        perform_server_signing(last_revision_hash, logs_data)
    }
}

/// Perform signing using local keys
fn perform_local_signing(
    last_revision_hash: &str,
    keys_path: PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<SigningResult, String> {
    logs_data.push("Info : Performing local signing...".to_string());

    let secret_keys = read_secreat_keys(&keys_path).map_err(|e| {
        let error = format!("Error :  error reading secret keys: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    let mnemonic = secret_keys.mnemonic.ok_or_else(|| {
        let error = "Error : Mnemonic not found in secret keys".to_string();
        logs_data.push(error.clone());
        error
    })?;

    let (address, public_key, private_key) = get_wallet(&mnemonic).map_err(|e| {
        let error = format!("Error : getting wallet: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    let signature = create_ethereum_signature(&private_key, last_revision_hash).map_err(|e| {
        let error = format!("Error : creating signature: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    Ok(SigningResult {
        signature,
        public_key,
        wallet_address: address,
    })
}

/// Perform signing using the server
fn perform_server_signing(
    last_revision_hash: &str,
    logs_data: &mut Vec<String>,
) -> Result<SigningResult, String> {
    logs_data.push("Info : Performing server signing...".to_string());

    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        let error = format!("Error initializing tokio runtime: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    let sign_payload = runtime
        .block_on(async { sign_message_server(last_revision_hash.to_string()).await })
        .map_err(|e| {
            let error = format!("Error in server signing: {}", e);
            logs_data.push(error.clone());
            error
        })?;

    Ok(SigningResult {
        signature: sign_payload.signature,
        public_key: sign_payload.public_key,
        wallet_address: sign_payload.wallet_address,
    })
}

/// Process verification and save the results
fn process_verification_and_save(
    aqua_verifier: AquaVerifier,
    aqua_page_data: PageData,
    rev_sig: RevisionContentSignature,
    sign_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    logs_data.push("Info : Processing verification and saving results...".to_string());

    // println!("Error cause {:#?} ",rev_sig);
    
    let (res_page_data, res_logs) = aqua_verifier
        .sign_aqua_chain(aqua_page_data, rev_sig)
        .map_err(|errors| {
            let error_msg = errors.join("\n");
            logs_data.push(format!("Verification errors:\n{}", error_msg));
            error_msg
        })?;

    res_logs.iter().for_each(|item| {
        logs_data.push(format!("\t {}", item));
    });

    save_page_data(&res_page_data, sign_path, "signed.json".to_string()).map_err(|e| {
        let error = format!("Error saving page data: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    Ok(())
}

/// Output the results based on CLI arguments
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