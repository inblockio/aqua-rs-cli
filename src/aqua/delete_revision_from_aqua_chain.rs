use std::path::PathBuf;

use aqua_verifier_rs_types::models::page_data::PageData;
use verifier::aqua_verifier::AquaVerifier;

use crate::models::CliArgs;
use crate::utils::{read_aqua_data, save_logs_to_file, save_page_data};

pub fn  cli_remove_revisions_from_aqua_chain(args : CliArgs, aqua_verifier : AquaVerifier, aqua_chain_file_path : PathBuf){

    let revision_count_for_deletion = args.remove_count;

    let mut logs_data: Vec<String> = Vec::new();

    println!("Verifying file: {:?}", aqua_chain_file_path);
    // Verify the file
    let res: Result<PageData, String> = read_aqua_data(&aqua_chain_file_path);
    // file reading error
    if res.is_err() {
        logs_data.push(res.err().unwrap());

        if args.output.is_some() {
            let logs = save_logs_to_file(&logs_data, args.output.unwrap());

            if logs.is_err() {
                eprintln!("Error:  saving logs {}", logs.unwrap());
            }
        }
        return;
    }

     match aqua_verifier.delete_revision_in_aqua_chain(res.unwrap(),  revision_count_for_deletion) {
        Ok((page_data , logs)) => {
            for ele in logs {
                logs_data.push(format!("\t\t {}", ele));
            }

            logs_data.push(
                "Success :  Removing revision from  Aqua chain is successful ".to_string(),
            );

            let e = save_page_data(
                &page_data,
                &aqua_chain_file_path,
                "chain.modified.json".to_string(),
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
            logs_data.push("Error : Failed to remove revisions from  aqua chain".to_string());

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