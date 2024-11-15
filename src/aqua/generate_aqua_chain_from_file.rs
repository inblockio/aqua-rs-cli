use std::fs;

use crate::models::CliArgs;
use crate::utils::{save_logs_to_file, save_page_data};
use verifier::aqua_verifier::AquaVerifier;

pub fn cli_generate_aqua_chain(args: CliArgs, aqua_verifier: AquaVerifier, domain_id: String) {
    let mut logs_data: Vec<String> = Vec::new();

    if let Some(file_path) = args.file {
      
        if let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) {
            
            // Read the file content into a Vec<u8>
            match fs::read(&file_path) {
                Ok(body_bytes) => {
                    // Convert the file name to a String
                    let file_name = file_name.to_string();

                    // let  = std::env::var("API_DOMAIN")
                    //     .unwrap_or_else(|_| "cli_domain_id".to_string());

                    // Call generate_aqua_chain with the necessary arguments
                    match aqua_verifier.generate_aqua_chain(body_bytes, file_name, domain_id) {
                        Ok(result) => {
                            for ele in result.logs {
                                logs_data.push(format!("\t\t {}", ele));
                            }

                            logs_data.push(
                                "Success :  Generating Aqua chain is successful ".to_string(),
                            );

                            let e = save_page_data(
                                &result.page_data,
                                &file_path,
                                "chain.json".to_string(),
                            );

                            if e.is_err() {
                                logs_data.push(format!("Error saving page data: {:#?}", e.err()));
                            }

                            //if verbose print out the logs if not print the last line
                            if args.details {
                                for item in logs_data.clone() {
                                    println!("{}", item);
                                }
                            } else {
                                println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
                            }

                            // if output is specified save the logs
                            if args.output.is_some() {
                                let logs = save_logs_to_file(&logs_data, args.output.unwrap());
                                if logs.is_err() {
                                    eprintln!("Error:  saving logs {}", logs.unwrap());
                                }
                            }
                        }
                        Err(logs) => {
                            for ele in logs {
                                logs_data.push(format!("\t\t {}", ele));
                            }

                            // if output is specified save the logs
                            if args.output.is_some() {
                                let logs = save_logs_to_file(&logs_data, args.output.unwrap());
                                if logs.is_err() {
                                    eprintln!("Error:  saving logs {}", logs.unwrap());
                                }
                            }
                            logs_data.push("Error : Failed to generate aqua chain".to_string());

                            //if verbose print out the logs if not print the last line
                            if args.details {
                                for item in logs_data {
                                    println!("{}", item);
                                }
                            } else {
                                println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read file bytes: {}", e);
                }
            }
            
        } else {
            eprintln!("Error: Invalid file path provided with -f/--file");
        }
    } else {
        tracing::error!("Failed to generate Aqua file, check file path ")
    }
}
