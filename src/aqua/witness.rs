use std::path::PathBuf;

use crate::models::{CliArgs, WitnessPayload};
use crate::server_witness::witness_message_server;
use crate::utils::{read_aqua_data, save_logs_to_file, save_page_data};
use aqua_verifier_rs_types::models::content::RevisionWitnessInput;
use aqua_verifier_rs_types::models::page_data::PageData;
use verifier::aqua_verifier::AquaVerifier;

pub fn cli_winess_chain(args: CliArgs, aqua_verifier: AquaVerifier, witness_path: PathBuf) {
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
    let aqua_chain_option = aqua_page_data.pages.get(0);
    if aqua_chain_option.is_none() {
        logs_data.push("no aqua chain found in page data".to_string());
        if args.output.is_some() {
            let logs = save_logs_to_file(&logs_data, args.output.unwrap());

            if logs.is_err() {
                eprintln!("Error:  saving logs {}", logs.unwrap());
            }
        }
        return;
    }
    let aqua_chain = aqua_chain_option.unwrap();

    let genesis_hash_revision_option = aqua_chain.revisions.get(0);

    if genesis_hash_revision_option.is_none() {
        println!("Error fetching genesis revsion");
        panic!("Aqua cli encountered an error")
    }

    let (_genesis_hash, genesis_revision) = genesis_hash_revision_option.unwrap();
    println!("7");
    // Create a new tokio runtime
    let runtime_result = tokio::runtime::Runtime::new().map_err(|e| e.to_string());

    if runtime_result.is_err() {
        println!(
            "Error initializing tokio runtime {:#?}",
            runtime_result.err()
        );
        panic!("Aqua cli encountered an error")
    }

    let runtime = runtime_result.unwrap();

    let mut last_revision_hash = "".to_string();

    if aqua_chain.revisions.len() == 1 {
        last_revision_hash = genesis_revision.metadata.verification_hash.to_string();
    } else {
        let (_last_hash, last_rev) = aqua_chain
            .revisions
            .get(aqua_chain.revisions.len() - 1)
            .expect("Expected a revision as revision are more than one");
        last_revision_hash = last_rev.metadata.verification_hash.to_string();
    }

    // Run the async server in the runtime
    let result: Result<WitnessPayload, String> =
        runtime.block_on(async { witness_message_server(last_revision_hash).await });

    if result.is_err() {
        println!("Signing failed: {:#?}", result.err());
        panic!("Aqua cli encountered an error")
    }
    let auth_payload = result.unwrap();
    println!("Witnessing successful!");
    println!("Network: {}", auth_payload.network);
    println!("Tx hash: {}", auth_payload.tx_hash);
    println!("Wallet Address: {}", auth_payload.wallet_address);

    let params = RevisionWitnessInput {
        filename: genesis_revision
            .content
            .file.clone()
            .expect("unable to find file")
            .filename,
        tx_hash: auth_payload.tx_hash,
        wallet_address: auth_payload.wallet_address,
        network: auth_payload.network,
    };

    let res = aqua_verifier.witness_aqua_chain(aqua_page_data.clone(), params);

    let log_line = if res.is_ok() {
        "Success :  Witnessing Aqua chain is successful ".to_string()
    } else {
        "Error : Witnessing Aqua chain  failed".to_string()
    };
    logs_data.push(log_line);

    // In your main code, replace the TODO with:
    if let Err(e) = save_page_data(&aqua_page_data, &witness_path, ".witness.json".to_string()) {
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
