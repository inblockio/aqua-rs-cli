use std::path::PathBuf;
use verifier::model::ResultStatusEnum;
use verifier::aqua_verifier::AquaVerifier;

use crate::models::CliArgs;
use crate::utils::{read_aqua_data, save_logs_to_file};

/// Log verification details for a specific verification type
fn log_verification_details(
    logs_data: &mut Vec<String>, 
    verification_type: &str, 
    status: ResultStatusEnum,
    successful: bool,
    logs: &[String]
) {
    if status == ResultStatusEnum::AVAILABLE {
        let verification_log = if successful {
            format!("\t\t Success : {} verification is successful", verification_type)
        } else {
            format!("\t\t Error : {} verification is not valid", verification_type)
        };
        logs_data.push(verification_log);

        for log in logs {
            logs_data.push(format!("\t\t\t {}", log));
        }
    } else {
        logs_data.push(format!("Info : {} verification not found", verification_type));
    }
}

/// Handle logs when file reading fails
fn handle_file_error(
    args: &CliArgs, 
    logs_data: &mut Vec<String>, 
    error_message: String
) {
    logs_data.push(error_message);

    if let Some(output_path) = &args.output {
        if let Err(log_error) = save_logs_to_file(logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", log_error);
        }
    }
}

/// Main function to verify the Aqua chain
pub fn cli_verify_chain(args: CliArgs, aqua_verifier: AquaVerifier, verify_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();

    println!("Verifying file: {:?}", verify_path);
    
    // Read Aqua data
    let aqua_page_data = match read_aqua_data(&verify_path) {
        Ok(data) => data,
        Err(error) => {
            handle_file_error(&args, &mut logs_data, error);
            return;
        }
    };

    // Extract first Aqua chain
    let aqua_chain = match aqua_page_data.pages.get(0) {
        Some(chain) => chain,
        None => {
            handle_file_error(&args, &mut logs_data, "No Aqua chain found in page data".to_string());
            return;
        }
    };

    // Verify Aqua chain
    let res_results = aqua_verifier.verify_aqua_chain(aqua_chain);

    // Process verification results
    match res_results {
        Ok(res) => {
            logs_data.push("Info: Looping through revisions".to_string());

            // Process each revision
            for revision_result in res.revision_results {
                // Log revision success status
                let revision_log = if revision_result.successful {
                    "\t Success: Revision is successful".to_string()
                } else {
                    "\t Error: Revision is not valid".to_string()
                };
                logs_data.push(revision_log);

                // Log different verification types
                log_verification_details(
                    &mut logs_data, 
                    "File", 
                    revision_result.file_verification.status,
                    revision_result.file_verification.successful,
                    &revision_result.file_verification.logs
                );
                log_verification_details(
                    &mut logs_data, 
                    "Content", 
                    revision_result.content_verification.status,
                    revision_result.content_verification.successful,
                    &revision_result.content_verification.logs
                );
                log_verification_details(
                    &mut logs_data, 
                    "Metadata", 
                    revision_result.metadata_verification.status,
                    revision_result.metadata_verification.successful,
                    &revision_result.metadata_verification.logs
                );
                log_verification_details(
                    &mut logs_data, 
                    "Witness", 
                    revision_result.witness_verification.status,
                    revision_result.witness_verification.successful,
                    &revision_result.witness_verification.logs
                );
                log_verification_details(
                    &mut logs_data, 
                    "Signature", 
                    revision_result.signature_verification.status,
                    revision_result.signature_verification.successful,
                    &revision_result.signature_verification.logs
                );

                logs_data.push(
                    "Info: ============= Proceeding to the next revision ============="
                        .to_string(),
                );
            }

            // Log overall validation result
            let log_line = if res.successful {
                "Success: Validation is successful".to_string()
            } else {
                "Error: Validation failed".to_string()
            };
            logs_data.push(log_line);
        }
        Err(error) => {
            let log_line = format!("An error occurred: {}", error);
            logs_data.push(log_line);
        }
    }

    // Output logs based on verbosity
    if args.verbose {
        for item in &logs_data {
            println!("{}", item);
        }
    } else {
        println!("{}", logs_data.last().unwrap_or(&"Result".to_string()));
    }

    // Save logs to file if output path is specified
    if let Some(output_path) = &args.output {
        if let Err(log_error) = save_logs_to_file(&logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", log_error);
        }
    }
}