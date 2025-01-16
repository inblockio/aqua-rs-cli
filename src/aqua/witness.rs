use std::env;
use std::path::PathBuf;

use aqua_verifier::aqua::AquaProtocol;

use crate::models::CliArgs;

// use crate::models::{CliArgs, WitnessPayload};
// use crate::servers::server_witness::witness_message_server;
// use crate::utils::{read_aqua_data, save_logs_to_file, save_page_data};
// use aqua_verifier_rs_types::models::content::RevisionWitnessInput;
// use aqua_verifier_rs_types::models::page_data::PageData;
// use aqua_verifier::aqua_verifier::AquaVerifier;
// use aqua_verifier::util::get_hash_sum;

/// Generates a witness chain for an Aqua file using the provided CLI arguments and Aqua verifier.
///
/// This function performs the following key steps:
/// 1. Reads Aqua data from the specified witness path
/// 2. Validates the Aqua chain and its revisions
/// 3. Generates a witness event verification hash
/// 4. Interacts with a witness message server to obtain authentication
/// 5. Witnesses the Aqua chain using the obtained authentication
///
/// # Arguments
///
/// * `args` - Command-line arguments containing configuration for the witnessing process
/// * `aqua_verifier` - An instance of AquaVerifier used to witness the Aqua chain
/// * `witness_path` - Path to the file to be witnessed
///
/// # Behavior
///
/// - Validates the input Aqua chain
/// - Generates a witness event verification hash
/// - Obtains authentication from a witness message server
/// - Witnesses the Aqua chain
/// - Handles logging and output based on CLI arguments
///
/// # Errors
///
/// - Panics if:
///   - Unable to read the Aqua data file
///   - No Aqua chain is found
///   - Unable to initialize Tokio runtime
///   - Witnessing process fails
///
/// # Logging
///
/// - Supports verbose and non-verbose logging
/// - Can save logs to a file if an output path is specified
pub(crate) fn cli_winess_chain(args: CliArgs, aqua_protocol: AquaProtocol, witness_path: PathBuf) {}
//     let mut logs_data: Vec<String> = Vec::new();

//     println!("Witnessing file: {:?}", witness_path);

//     // Read Aqua data from the specified file
//     let res: Result<PageData, String> = read_aqua_data(&witness_path);

//     // Handle file reading errors
//     if res.is_err() {
//         logs_data.push(res.err().unwrap());

//         if args.output.is_some() {
//             let logs = save_logs_to_file(&logs_data, args.output.unwrap());

//             if logs.is_err() {
//                 eprintln!("Error:  saving logs {}", logs.unwrap());
//             }
//         }
//         return;
//     }

//     // Extract Aqua page data
//     let aqua_page_data = res.unwrap();
//     let aqua_chain_option = aqua_page_data.pages.get(0);

//     // Validate Aqua chain exists
//     if aqua_chain_option.is_none() {
//         logs_data.push("no aqua chain found in page data".to_string());
//         if args.output.is_some() {
//             let logs = save_logs_to_file(&logs_data, args.output.unwrap());

//             if logs.is_err() {
//                 eprintln!("Error:  saving logs {}", logs.unwrap());
//             }
//         }
//         return;
//     }
//     let aqua_chain = aqua_chain_option.unwrap();

//     // Get genesis revision
//     let genesis_hash_revision_option = aqua_chain.revisions.get(0);

//     if genesis_hash_revision_option.is_none() {
//         println!("Error fetching genesis revision");
//         panic!("Aqua cli encountered an error")
//     }

//     let (_genesis_hash, genesis_revision) = genesis_hash_revision_option.unwrap();

//     // Initialize Tokio runtime
//     let runtime_result = tokio::runtime::Runtime::new().map_err(|e| e.to_string());

//     if runtime_result.is_err() {
//         println!(
//             "Error initializing tokio runtime {:#?}",
//             runtime_result.err()
//         );
//         panic!("Aqua cli encountered an error")
//     }

//     let runtime = runtime_result.unwrap();

//     // Determine the last revision hash
//     let mut last_revision_hash = "".to_string();

//     if aqua_chain.revisions.len() == 1 {
//         last_revision_hash = genesis_revision.metadata.verification_hash.to_string();
//     } else {
//         let (_last_hash, last_rev) = aqua_chain
//             .revisions
//             .get(aqua_chain.revisions.len() - 1)
//             .expect("Expected a revision as revisions are more than one");
//         last_revision_hash = last_rev.metadata.verification_hash.to_string();
//     }

//     // Generate witness event verification hash
//     let empty_hash: String = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26".to_string();
//     let witness_event_verification_string = format!("{}{}", empty_hash, last_revision_hash);
//     let witness_event_verification_hash = get_hash_sum(&witness_event_verification_string);
//     let chain: String = env::var("chain").unwrap_or("sepolia".to_string());

//     // Obtain witness authentication via message server
//     let result: Result<WitnessPayload, String> =
//         runtime.block_on(async { witness_message_server(witness_event_verification_hash, chain).await });

//     if result.is_err() {
//         println!("Signing failed: {:#?}", result.err());
//         panic!("Aqua cli encountered an error")
//     }
//     let auth_payload = result.unwrap();

//     // Print witnessing details
//     println!("Witnessing successful!");
//     println!("Network: {}", auth_payload.network);
//     println!("Tx hash: {}", auth_payload.tx_hash);
//     println!("Wallet Address: {}", auth_payload.wallet_address);

//     // Prepare revision witness input
//     let params = RevisionWitnessInput {
//         filename: genesis_revision
//             .content
//             .file.clone()
//             .expect("unable to find file")
//             .filename,
//         tx_hash: auth_payload.tx_hash,
//         wallet_address: auth_payload.wallet_address,
//         network: auth_payload.network,
//     };

//     // Witness the Aqua chain
//     let res = aqua_verifier.witness_aqua_chain(aqua_page_data.clone(), params);

//     if res.is_err(){
//         res.clone().unwrap_err().iter().for_each(|item| println!("\t\t {}", item));
//         panic!("Error .... check logs above");
//     }

//     let (res_page_data, res_logs ) =  res.clone().unwrap();

//     // Collect logs
//     res_logs.iter().for_each(|item| logs_data.push(format!("\t {}", item)));

//     // Determine success or failure log
//     let log_line = if res.is_ok() {
//         "Success :  Witnessing Aqua chain is successful ".to_string()
//     } else {
//         "Error : Witnessing Aqua chain  failed".to_string()
//     };
//     logs_data.push(log_line);

//     // Save page data
//     if let Err(e) = save_page_data(&res_page_data, &witness_path, "witness.json".to_string()) {
//         logs_data.push(format!("Error saving page data: {}", e));
//     }

//     // Handle logging based on verbosity
//     if args.verbose {
//         for item in logs_data.clone() {
//             println!("{}", item);
//         }
//     } else {
//         println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
//     }

//     // Save logs to file if output path is specified
//     if args.output.is_some() {
//         let logs = save_logs_to_file(&logs_data, args.output.unwrap());
//         if logs.is_err() {
//             eprintln!("Error:  saving logs {}", logs.unwrap());
//         }
//     }
// }
