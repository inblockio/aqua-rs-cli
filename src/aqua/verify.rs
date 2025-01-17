use std::{fs, path::PathBuf};

use aqua_verifier::aqua::AquaProtocol;
use aqua_verifier_rs_types::models::chain::AquaChain;

use crate::{models::CliArgs, utils::{oprataion_logs_and_dumps, save_page_data}};



pub fn cli_verify_chain(args: CliArgs, aqua_protocol: AquaProtocol, verify_path: PathBuf, keys_file: Option<PathBuf>) {

    let mut logs_data: Vec<String> = Vec::new();

    if let Some(file_path) = args.clone().file {
        // Read the file content into a Vec<u8>
        match fs::read(&file_path) {
            Ok(body_bytes) => {
                // Convert the file name to a String
                // let file_name = file_name.to_string();

                // convert the file bytes to a string
                let file_data = String::from_utf8_lossy(&body_bytes).to_string();
                // parse the string to aquachain capture any errors
                // let aqua_chain = ::from_json(&file_string);
                let res = serde_json::from_str::<AquaChain>(&file_data);

                if res.is_err() {
                    logs_data.push("❌ Error parsing json data (check you aqua chain) ".to_string());
                    return;
                }
                let res_data = res.unwrap();

                // Attempt to generate genesis the Aqua chain
                let genesis_revision_result = aqua_protocol.verify_aqua_chain(
                    res_data,
                    verify_path.parent().unwrap().to_path_buf().to_string_lossy().to_string(),
                );
                if genesis_revision_result.is_successfull {
                    // Add success message
                    logs_data.push("✅ Successfully  generated Aqua chain ".to_string());

                    // Save modified page data to a new file
                    let e = save_page_data(
                        &genesis_revision_result.clone().aqua_chain.unwrap(),
                        &file_path,
                        "aqua.json".to_string(),
                    );

                    // Log any errors in saving page data
                    if e.is_err() {
                        logs_data.push(format!("Error saving page data: {:#?}", e.err()));
                    }
                } else {
                    // Add success message
                    logs_data.push("Error : Generating Aqua chain ".to_string());
                }
            }
            Err(e) => {
                eprintln!("Failed to read file bytes: {}", e);
                logs_data.push("❌ failed to read file ".to_string());
            }
        }
    } else {
        tracing::error!("Failed to generate Aqua file, check file path ");
        logs_data.push("❌ Invalid file ,check file path ".to_string());
    }

    oprataion_logs_and_dumps(args, logs_data);



}
// use std::path::PathBuf;
// use aqua_verifier::model::ResultStatusEnum;
// use aqua_verifier::aqua_verifier::AquaVerifier;

// use crate::models::CliArgs;
// use crate::utils::{read_aqua_data, save_logs_to_file};

// /// Log verification details for a specific verification type
// fn log_verification_details(
//     logs_data: &mut Vec<String>,
//     verification_type: &str,
//     status: ResultStatusEnum,
//     successful: bool,
//     logs: &[String]
// ) {
//     if status == ResultStatusEnum::AVAILABLE {
//         let verification_log = if successful {
//             format!("\t\t Success : {} verification is successful", verification_type)
//         } else {
//             format!("\t\t Error : {} verification is not valid", verification_type)
//         };
//         logs_data.push(verification_log);

//         for log in logs {
//             logs_data.push(format!("\t\t\t {}", log));
//         }
//     } else {
//         logs_data.push(format!("Info : {} verification not found", verification_type));
//     }
// }

// /// Handle logs when file reading fails
// fn handle_file_error(
//     args: &CliArgs,
//     logs_data: &mut Vec<String>,
//     error_message: String
// ) {
//     logs_data.push(error_message);

//     if let Some(output_path) = &args.output {
//         if let Err(log_error) = save_logs_to_file(logs_data, output_path.clone()) {
//             eprintln!("Error saving logs: {}", log_error);
//         }
//     }
// }

// /// Main function to verify the Aqua chain
// 
//     let mut logs_data: Vec<String> = Vec::new();

//     println!("Verifying file: {:?}", verify_path);

//     // Read Aqua data
//     let aqua_page_data = match read_aqua_data(&verify_path) {
//         Ok(data) => data,
//         Err(error) => {
//             handle_file_error(&args, &mut logs_data, error);
//             return;
//         }
//     };

//     // Extract first Aqua chain
//     let aqua_chain = match aqua_page_data.pages.get(0) {
//         Some(chain) => chain,
//         None => {
//             handle_file_error(&args, &mut logs_data, "No Aqua chain found in page data".to_string());
//             return;
//         }
//     };

//     // Verify Aqua chain
//     let res_results = aqua_verifier.verify_aqua_chain(aqua_chain);

//     // Process verification results
//     match res_results {
//         Ok(res) => {
//             logs_data.push("Info: Looping through revisions".to_string());

//             // Process each revision
//             for revision_result in res.revision_results {
//                 // Log revision success status
//                 let revision_log = if revision_result.successful {
//                     "\t Success: Revision is successful".to_string()
//                 } else {
//                     "\t Error: Revision is not valid".to_string()
//                 };
//                 logs_data.push(revision_log);

//                 // Log different verification types
//                 log_verification_details(
//                     &mut logs_data,
//                     "File",
//                     revision_result.file_verification.status,
//                     revision_result.file_verification.successful,
//                     &revision_result.file_verification.logs
//                 );
//                 log_verification_details(
//                     &mut logs_data,
//                     "Content",
//                     revision_result.content_verification.status,
//                     revision_result.content_verification.successful,
//                     &revision_result.content_verification.logs
//                 );
//                 log_verification_details(
//                     &mut logs_data,
//                     "Metadata",
//                     revision_result.metadata_verification.status,
//                     revision_result.metadata_verification.successful,
//                     &revision_result.metadata_verification.logs
//                 );
//                 log_verification_details(
//                     &mut logs_data,
//                     "Witness",
//                     revision_result.witness_verification.status,
//                     revision_result.witness_verification.successful,
//                     &revision_result.witness_verification.logs
//                 );
//                 log_verification_details(
//                     &mut logs_data,
//                     "Signature",
//                     revision_result.signature_verification.status,
//                     revision_result.signature_verification.successful,
//                     &revision_result.signature_verification.logs
//                 );

//                 logs_data.push(
//                     "Info: ============= Proceeding to the next revision ============="
//                         .to_string(),
//                 );
//             }

//             // Log overall validation result
//             let log_line = if res.successful {
//                 "Success: Validation is successful".to_string()
//             } else {
//                 "Error: Validation failed".to_string()
//             };
//             logs_data.push(log_line);
//         }
//         Err(error) => {
//             let log_line = format!("An error occurred: {}", error);
//             logs_data.push(log_line);
//         }
//     }

//     // Output logs based on verbosity
//     if args.verbose {
//         for item in &logs_data {
//             println!("{}", item);
//         }
//     } else {
//         println!("{}", logs_data.last().unwrap_or(&"Result".to_string()));
//     }

//     // Save logs to file if output path is specified
//     if let Some(output_path) = &args.output {
//         if let Err(log_error) = save_logs_to_file(&logs_data, output_path.clone()) {
//             eprintln!("Error saving logs: {}", log_error);
//         }
//     }
// }
