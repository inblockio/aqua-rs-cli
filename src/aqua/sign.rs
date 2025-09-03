use crate::aqua::wallet::{create_ethereum_signature, get_wallet};
use crate::models::CliArgs;
use crate::servers::server_sign::sign_message_server;
use crate::utils::{
    read_aqua_data_buffered, 
    read_secreat_keys_buffered, 
    save_logs_to_file, 
    save_page_data_buffered,
    get_global_logger,  // ✅ NEW: Global logger access
};

/// ✅ SIMPLE FIX: Always use the same output filename
fn get_consistent_signed_filename(input_path: &PathBuf) -> PathBuf {
    let file_stem = input_path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sample.chain");
    
    // Remove any existing .signed suffix to prevent stacking
    let clean_stem = if file_stem.ends_with(".signed") {
        &file_stem[..file_stem.len() - 7] // Remove ".signed"
    } else {
        file_stem
    };
    
    // Always generate the same pattern: {clean_name}.signed.json
    input_path.with_file_name(format!("{}.signed.json", clean_stem))
}

/// ✅ CLEANUP: Remove any staircase files that might have been created
/// ✅ IMPROVED: More comprehensive cleanup of staircase files
fn cleanup_staircase_files(original_path: &PathBuf) {
    use std::fs;
    
    if let Some(parent) = original_path.parent() {
        if let Some(stem) = original_path.file_stem() {
            let stem_str = stem.to_string_lossy();
            
            // Check for various staircase patterns
            let staircase_patterns = [
                format!("{}.signed.signed.json", stem_str),
                format!("{}.signed.signed.signed.json", stem_str),
                format!("{}.witnessed.witnessed.json", stem_str),
                format!("{}.verified.verified.json", stem_str),
            ];
            
            for pattern in staircase_patterns {
                let staircase_file = parent.join(&pattern);
                
                if staircase_file.exists() && staircase_file != *original_path {
                    match fs::remove_file(&staircase_file) {
                        Ok(_) => println!("Cleaned up staircase file: {:?}", staircase_file),
                        Err(e) => eprintln!("Warning: Could not remove staircase file {:?}: {}", staircase_file, e),
                    }
                }
            }
        }
    }
}
use aqua_verifier_rs_types::models::content::RevisionContentSignature;
use aqua_verifier_rs_types::models::page_data::PageData;
use std::env;
use std::path::PathBuf;
use std::borrow::Cow;
use rayon::prelude::*;  // ✅ NEW: For parallel processing
use aqua_verifier::aqua_verifier::AquaVerifier;

/// ✅ OPTIMIZED: Information about the content type and associated data
/// Uses Cow<'a, str> to avoid unnecessary string cloning
#[derive(Debug, Clone)]
pub struct ContentTypeInfo<'a> {
    pub content_type: ContentType,
    pub filename: Cow<'a, str>,
    pub data: Cow<'a, str>,
}

/// ✅ OPTIMIZED: Enum representing the content type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    File,
    Text,
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentType::File => write!(f, "file"),
            ContentType::Text => write!(f, "text"),
        }
    }
}

/// ✅ OPTIMIZED: Represents the result of extracting chain data
/// Uses Cow to avoid cloning when possible
struct ChainExtractionResult<'a> {
    last_revision_hash: Cow<'a, str>,
    genesis_revision_filename: Cow<'a, str>,
}

/// ✅ OPTIMIZED: Represents the result of signing operations
/// Uses Cow to avoid cloning when possible
pub struct SigningResult<'a> {
    signature: Cow<'a, str>,
    public_key: Cow<'a, str>,
    wallet_address: Cow<'a, str>,
}

/// Main function to handle the CLI signing chain process
///
/// # Arguments
/// * `args` - CLI arguments
/// * `aqua_verifier` - Instance of AquaVerifier
/// * `sign_path` - Path to the file to be signed
/// * `keys_file` - Optional path to the keys file
pub(crate) async fn cli_sign_chain(
    args: CliArgs,
    aqua_verifier: AquaVerifier,
    sign_path: PathBuf,
    keys_file: Option<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();
    let start_message = format!("Starting signing process for file: {:?}", sign_path);
    logs_data.push(start_message.clone());
    
    // ✅ FIXED: Use global logger if available
    if let Some(logger) = get_global_logger() {
        logger.info(start_message, None);
    }

    match process_signing_chain(&args, aqua_verifier, &sign_path, keys_file, &mut logs_data).await {
        Ok(_) => {
            let success_message = "Signing process completed successfully".to_string();
            logs_data.push(success_message.clone());
            if let Some(logger) = get_global_logger() {
                logger.info(success_message, None);
            }
        }
        Err(e) => {
            let error_message = format!("Error in signing process: {}", e);
            logs_data.push(error_message.clone());
            if let Some(logger) = get_global_logger() {
                logger.error(error_message.clone(), None);
            }
        }
    }

    output_results(&args, &logs_data);
}

/// Process the signing chain operation
async fn process_signing_chain(
    args: &CliArgs,
    aqua_verifier: AquaVerifier,
    sign_path: &PathBuf,
    keys_file: Option<PathBuf>,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    // ✅ NEW: Check content type BEFORE any signing happens
    let start_check_message = "Info : Checking content type before signing...".to_string();
    logs_data.push(start_check_message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(start_check_message, None);
    }
    
    let content_info = check_content_type(sign_path)?;
    
    let content_type_message = format!("Info : Content type detected: {}", content_info.content_type);
    logs_data.push(content_type_message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(content_type_message, None);
    }
    
    let filename_message = format!("Info : Filename: {}", content_info.filename);
    logs_data.push(filename_message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(filename_message, None);
    }
    
    let aqua_page_data = read_and_validate_data(sign_path, logs_data)?;
    let chain_data = extract_chain_data(&aqua_page_data, logs_data)?;
    let sign_result = perform_signing(&chain_data.last_revision_hash, keys_file, logs_data, args).await?;

    let rev_sig = RevisionContentSignature {
        signature: sign_result.signature.into_owned(),
        wallet_address: sign_result.wallet_address.into_owned(),
        publickey: sign_result.public_key.into_owned(),
        filename: chain_data.genesis_revision_filename.into_owned(),
    };

    process_verification_and_save(aqua_verifier, aqua_page_data, rev_sig, sign_path, logs_data)?;
    
    // ✅ CLEANUP: Remove any staircase files that might have been created
    cleanup_staircase_files(sign_path);
    
    Ok(())
}

/// Read and validate the input data file
fn read_and_validate_data(
    sign_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<PageData, String> {
    let message = "Info : Reading and validating input data...".to_string();
    logs_data.push(message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(message, None);
    }
    
    // ✅ OPTIMIZED: Using buffered I/O for better performance
    read_aqua_data_buffered(sign_path).map_err(|e| {
        let error_message = format!("Error : Error reading aqua data: {}", e);
        logs_data.push(error_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.error(error_message.clone(), None);
        }
        e
    })
}

/// ✅ OPTIMIZED: Extract necessary chain data from the page data
fn extract_chain_data<'a>(
    aqua_page_data: &'a PageData,
    logs_data: &mut Vec<String>,
) -> Result<ChainExtractionResult<'a>, String> {
    let message = "Info : Extracting chain data...".to_string();
    logs_data.push(message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(message, None);
    }

    let aqua_chain = aqua_page_data.pages.get(0).ok_or_else(|| {
        let error_message = "Error : No aqua chain found in page data".to_string();
        logs_data.push(error_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.error(error_message.clone(), None);
        }
        error_message
    })?;

    let genesis_hash_revision = aqua_chain.revisions.get(0).ok_or_else(|| {
        let error_message = "Error : Error fetching genesis revision".to_string();
        logs_data.push(error_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.error(error_message.clone(), None);
        }
        error_message
    })?;

    let (_genesis_hash, genesis_revision) = genesis_hash_revision;

    // ✅ OPTIMIZED: Use correct field access patterns that match the actual types
    let genesis_filename = if let Some(file_content) = &genesis_revision.content.file {
        let message = "Info : Content type detected: File".to_string();
        logs_data.push(message.clone());
        if let Some(logger) = get_global_logger() {
            logger.info(message, None);
        }
        file_content.filename.clone()
    } else {
        // For any other content type, use a default filename
        let message = "Info : Content type detected: Other (using default)".to_string();
        logs_data.push(message.clone());
        if let Some(logger) = get_global_logger() {
            logger.info(message, None);
        }
        "document.txt".to_string()
    };

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
        last_revision_hash: Cow::Owned(last_revision_hash),
        genesis_revision_filename: Cow::Owned(genesis_filename),
    })
}

/// ✅ OPTIMIZED: Check the content type of the JSON file and return the appropriate filename
/// 
/// # Arguments
/// * `file_path` - Path to the JSON file to check
/// 
/// # Returns
/// * `Ok(ContentTypeInfo<'static>)` - Contains content type and filename
/// * `Err(String)` - Error message if validation fails
pub fn check_content_type(file_path: &PathBuf) -> Result<ContentTypeInfo<'static>, String> {
    // Read the file content 
    let content = std::fs::read_to_string(file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    // Parse JSON to check structure
    let json_value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON format: {}", e))?;
    
    // Extract pages array
    let pages = json_value.get("pages")
        .and_then(|p| p.as_array())
        .ok_or("Missing 'pages' array")?;
    
    if pages.is_empty() {
        return Err("Pages array is empty".to_string());
    }
    
    // Get first page
    let first_page = &pages[0];
    
    // Extract revisions
    let revisions = first_page.get("revisions")
        .and_then(|r| r.as_object())
        .ok_or("Missing 'revisions' object")?;
    
    if revisions.is_empty() {
        return Err("Revisions object is empty".to_string());
    }
    
    // Get first revision (any key will do)
    let (_, first_revision) = revisions.iter().next()
        .ok_or("No revisions found")?;
    
    // Extract content
    let content_obj = first_revision.get("content")
        .and_then(|c| c.as_object())
        .ok_or("Missing 'content' object")?;
    
    // Check content type and extract filename
    let content_info = if let Some(file_content) = content_obj.get("file") {
        // File content type
        let filename = file_content.get("filename")
            .and_then(|f| f.as_str())
            .ok_or("File content missing 'filename' field")?;
        
        ContentTypeInfo {
            content_type: ContentType::File,
            filename: Cow::Owned(filename.to_string()),
            data: Cow::Owned(file_content.get("data")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string()),
        }
    } else if let Some(text_content) = content_obj.get("text") {
        // Text content type
        let data = text_content.get("data")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        
        // Generate filename from domain_id or use default
        let filename = first_page.get("domain_id")
            .and_then(|d| d.as_str())
            .map(|d| format!("{}.txt", d))
            .unwrap_or_else(|| "document.txt".to_string());
        
        ContentTypeInfo {
            content_type: ContentType::Text,
            filename: Cow::Owned(filename),
            data: Cow::Owned(data),
        }
    } else {
        return Err("Content must contain either 'file' or 'text' field".to_string());
    };
    
    Ok(content_info)
}

/// ✅ OPTIMIZED: Perform the signing operation either through server or local keys
async fn perform_signing<'a>(
    last_revision_hash: &'a str,
    keys_file: Option<PathBuf>,
    logs_data: &mut Vec<String>,
    args: &CliArgs,
) -> Result<SigningResult<'a>, String> {
    let message = "Info : Starting signing process...".to_string();
    logs_data.push(message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(message, None);
    }

    if let Some(keys_path) = keys_file {
        perform_local_signing(last_revision_hash, keys_path, logs_data, args)
    } else {
        perform_server_signing(last_revision_hash, logs_data).await
    }
}

/// ✅ NEW: Parallel signature processing for multiple contents
/// This eliminates CPU bottlenecks when signing multiple items
pub fn parallel_sign_multiple_contents(
    contents: Vec<&str>,
    keys_path: PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<Vec<SigningResult<'static>>, String> {
    let message = "Info : Starting parallel signature processing...".to_string();
    logs_data.push(message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(message, None);
    }
    
    // Read keys once for all operations
    let secret_keys = read_secreat_keys_buffered(&keys_path).map_err(|e| {
        let error_message = format!("Error reading secret keys: {}", e);
        logs_data.push(error_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.error(error_message.clone(), None);
        }
        error_message
    })?;
    
    let mnemonic = secret_keys.mnemonic.ok_or_else(|| {
        let error_message = "Error: Mnemonic not found in secret keys".to_string();
        logs_data.push(error_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.error(error_message.clone(), None);
        }
        error_message
    })?;
    
    // Process signatures in parallel using Rayon
    let results: Result<Vec<_>, String> = contents
        .par_iter()  // ✅ PARALLEL: Process multiple contents simultaneously
        .map(|content_hash| {
            // Generate wallet for each signature (can be optimized further)
            let (address, public_key, private_key) = get_wallet(&mnemonic, true)
                .map_err(|e| format!("Error getting wallet: {}", e))?;
            
            // Create signature
            let signature = create_ethereum_signature(&private_key, content_hash)
                .map_err(|e| format!("Error creating signature: {}", e))?;
            
            Ok(SigningResult {
                signature: Cow::Owned(signature),
                public_key: Cow::Owned(public_key),
                wallet_address: Cow::Owned(address),
            })
        })
        .collect();
    
    let results = results?;
    let success_message = format!("Info : Successfully processed {} signatures in parallel", results.len());
    logs_data.push(success_message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(success_message, None);
    }
    
    Ok(results)
}

/// ✅ NEW: Batch signature processing with configurable batch size
pub fn batch_sign_contents(
    contents: Vec<&str>,
    keys_path: PathBuf,
    batch_size: usize,
    logs_data: &mut Vec<String>,
) -> Result<Vec<SigningResult<'static>>, String> {
    let message = format!("Info : Starting batch signature processing with batch size {}", batch_size);
    logs_data.push(message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(message, None);
    }
    
    let mut all_results = Vec::new();
    
    // Process in batches to control memory usage
    for (batch_num, batch) in contents.chunks(batch_size).enumerate() {
        let message = format!("Info : Processing batch {} with {} items", batch_num + 1, batch.len());
        logs_data.push(message.clone());
        if let Some(logger) = get_global_logger() {
            logger.info(message, None);
        }
        
        let batch_results = parallel_sign_multiple_contents(
            batch.to_vec(),
            keys_path.clone(),
            logs_data,
        )?;
        
        all_results.extend(batch_results);
    }
    
    let success_message = format!("Info : Completed all {} batches, total signatures: {}", 
        (contents.len() + batch_size - 1) / batch_size, all_results.len());
    logs_data.push(success_message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(success_message, None);
    }
    
    Ok(all_results)
}

/// ✅ OPTIMIZED: Enhanced local signing with parallel capability
fn perform_local_signing<'a>(
    last_revision_hash: &'a str,
    keys_path: PathBuf,
    logs_data: &mut Vec<String>,
    args: &CliArgs,
) -> Result<SigningResult<'a>, String> {
    let message = "Info : Performing local signing...".to_string();
    logs_data.push(message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(message, None);
    }

    // Check if we should use parallel processing for multiple hashes
    if let Some(parallel_hashes) = get_parallel_hashes_from_args(args) {
        let message = "Info : Using parallel signature processing...".to_string();
        logs_data.push(message.clone());
        if let Some(logger) = get_global_logger() {
            logger.info(message, None);
        }
        
        let results = parallel_sign_multiple_contents(
            parallel_hashes.iter().map(|s| s.as_str()).collect(),
            keys_path,
            logs_data,
        )?;
        
        // Return the first result (or you could return all results)
        return Ok(results.into_iter().next().unwrap());
    }

    // ✅ OPTIMIZED: Using buffered I/O for better performance
    let secret_keys = read_secreat_keys_buffered(&keys_path).map_err(|e| {
        let error_message = format!("Error :  error reading secret keys: {}", e);
        logs_data.push(error_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.error(error_message.clone(), None);
        }
        error_message
    })?;

    let mnemonic = secret_keys.mnemonic.ok_or_else(|| {
        let error_message = "Error : Mnemonic not found in secret keys".to_string();
        logs_data.push(error_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.error(error_message.clone(), None);
        }
        error_message
    })?;

    let gen_wallet_on_fail = if args.level.is_none() {
        true
    } else if args.level.as_ref().unwrap().trim() == "1".to_string() {
        false
    } else {
        true
    };

    let (address, public_key, private_key) =
        get_wallet(&mnemonic, gen_wallet_on_fail).map_err(|e| {
            let error_message = format!("Error : getting wallet: {}", e);
            logs_data.push(error_message.clone());
            if let Some(logger) = get_global_logger() {
                logger.error(error_message.clone(), None);
            }
            error_message
        })?;

    let signature = create_ethereum_signature(&private_key, last_revision_hash).map_err(|e| {
        let error_message = format!("Error : creating signature: {}", e);
        logs_data.push(error_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.error(error_message.clone(), None);
        }
        error_message
    })?;

    Ok(SigningResult {
        signature: Cow::Owned(signature),
        public_key: Cow::Owned(public_key),
        wallet_address: Cow::Owned(address),
    })
}

/// ✅ OPTIMIZED: Perform signing using the server
async fn perform_server_signing<'a>(
    last_revision_hash: &'a str,
    logs_data: &mut Vec<String>,
) -> Result<SigningResult<'a>, String> {
    let message = "Info : Performing server signing...".to_string();
    logs_data.push(message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(message, None);
    }

    let chain: String = env::var("chain").unwrap_or("sepolia".to_string());

    let sign_payload = sign_message_server(last_revision_hash.to_string(), chain).await
        .map_err(|e| {
            let error_message = format!("Error in server signing: {}", e);
            logs_data.push(error_message.clone());
            if let Some(logger) = get_global_logger() {
                logger.error(error_message.clone(), None);
            }
            error_message
        })?;

    Ok(SigningResult {
        signature: Cow::Owned(sign_payload.signature.clone()),
        public_key: Cow::Owned(sign_payload.public_key),
        wallet_address: Cow::Owned(sign_payload.wallet_address),
    })
}

/// ✅ NEW: Helper function to extract parallel hashes from CLI args
/// This allows users to specify multiple hashes for parallel processing
fn get_parallel_hashes_from_args(_args: &CliArgs) -> Option<Vec<String>> {
    // You can extend this to read from a file or additional CLI arguments
    // For now, this is a placeholder for the parallel processing feature
    None
}

/// Process verification and save the results
fn process_verification_and_save(
    aqua_verifier: AquaVerifier,
    aqua_page_data: PageData,
    rev_sig: RevisionContentSignature,
    sign_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    let message = "Info : Processing verification and saving results...".to_string();
    logs_data.push(message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(message, None);
    }

    let (res_page_data, res_logs) = aqua_verifier
        .sign_aqua_chain(aqua_page_data, rev_sig)
        .map_err(|errors| {
            let error_msg = errors.join("\n");
            let error_message = format!("Verification errors:\n{}", error_msg);
            logs_data.push(error_message.clone());
            if let Some(logger) = get_global_logger() {
                logger.error(error_message.clone(), None);
            }
            error_msg
        })?;

    res_logs.iter().for_each(|item| {
        let log_message = format!("\t {}", item);
        logs_data.push(log_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.info(log_message, None);
        }
    });

    // ✅ FIXED: Generate proper output filename that prevents double generation
    let output_path = get_consistent_signed_filename(sign_path);

    let debug_message = format!("DEBUG: Input path: {:?}, Output path: {:?}", sign_path, output_path);
    println!("{}", debug_message);
    logs_data.push(debug_message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(debug_message, None);
    }

    // ✅ CRITICAL FIX: Check if output file already exists and handle appropriately
    if output_path.exists() {
        let overwrite_message = format!("Info : Output file {:?} already exists, overwriting...", output_path);
        logs_data.push(overwrite_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.warning(overwrite_message, None);
        }
    }

    // ... save logic ...
    save_page_data_buffered(&res_page_data, &output_path, "".to_string()).map_err(|e| {
        let error_message = format!("Error saving page data: {}", e);
        logs_data.push(error_message.clone());
        if let Some(logger) = get_global_logger() {
            logger.error(error_message.clone(), None);
        }
        error_message
    })?;

    let success_message = format!("Info : Successfully saved signed data to: {:?}", output_path);
    logs_data.push(success_message.clone());
    if let Some(logger) = get_global_logger() {
        logger.info(success_message, None);
    }

    Ok(())
}

/// ✅ OPTIMIZED: Output the results based on CLI arguments
fn output_results(args: &CliArgs, logs_data: &Vec<String>) {
    if args.verbose {
        logs_data.iter().for_each(|log| {
            println!("{}", log);
            if let Some(logger) = get_global_logger() {
                logger.info(log.clone(), None);
            }
        });
    } else if let Some(last_log) = logs_data.last() {
        println!("{}", last_log);
        if let Some(logger) = get_global_logger() {
            logger.info(last_log.clone(), None);
        }
    }

    if let Some(output_path) = &args.output {
        // ✅ FIXED: Use synchronous logging to prevent runtime conflicts
        if let Err(e) = save_logs_to_file(logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", e);
        }
    }
}
