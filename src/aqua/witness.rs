use std::path::PathBuf;

use aqua_verifier_rs_types::models::page_data::PageData;
use verifier::{aqua_verifier_struct_impl::AquaVerifier, verifier::witness_aqua_chain};

use crate::models::CliArgs;
use crate::utils::{read_aqua_data, save_logs_to_file, save_page_data};

pub fn  cli_winess_chain(args : CliArgs, _aqua_verifier : AquaVerifier, witness_path : PathBuf){
    let mut logs_data: Vec<String> = Vec::new();

    println!("Witnessing file: {:?}", witness_path);
    // Witness the file

    let res: Result<PageData, String> = read_aqua_data(&witness_path);
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
    let aqua_page_data = res.unwrap();
    let aqua_chain = aqua_page_data.pages.get(0);
    if aqua_chain.is_none() {
        logs_data.push("no aqua chain found in page data".to_string());
        if args.output.is_some() {
            let logs = save_logs_to_file(&logs_data, args.output.unwrap());

            if logs.is_err() {
                eprintln!("Error:  saving logs {}", logs.unwrap());
            }
        }
        return;
    }

    let res = witness_aqua_chain(aqua_chain.unwrap().clone());

    let log_line = if res.is_ok() {
        "Success :  Witnessing Aqua chain is successful ".to_string()
    } else {
        "Error : Witnessing Aqua chain  failed".to_string()
    };
    logs_data.push(log_line);

    // In your main code, replace the TODO with:
    if let Err(e) =
        save_page_data(&aqua_page_data, &witness_path, ".witness.json".to_string())
    {
        logs_data.push(format!("Error saving page data: {}", e));
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