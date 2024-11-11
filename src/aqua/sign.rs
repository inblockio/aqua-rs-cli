use std::path::PathBuf;

use aqua_verifier_rs_types::models::content::RevisionContentSignature;
use aqua_verifier_rs_types::models::page_data::PageData;
use verifier::verifier::sign_aqua_chain;
use verifier::aqua_verifier_struct_impl::AquaVerifier;
use crate::server::sign_message_server;
use crate::models::CliArgs;
use crate::utils::{read_aqua_data, save_logs_to_file, save_page_data};

pub fn  cli_sign_chain(args : CliArgs, _aqua_verifier : AquaVerifier, sign_path : PathBuf){
    let mut logs_data: Vec<String> = Vec::new();

    println!("Signing file: {:?}", sign_path);

    let res: Result<PageData, String> = read_aqua_data(&sign_path);
    println!("1");
    // file reading error
    if res.is_err() {
        println!("2");
        // logs_data.push(res.err().unwrap());
        println!("3 {:#?}", res.err());
        if args.output.is_some() {
            let logs = save_logs_to_file(&logs_data, args.output.unwrap());

            if logs.is_err() {
                eprintln!("Error:  saving logs {}", logs.unwrap());
            }
        }
        return;
    }
    println!("4");
    let aqua_page_data = res.unwrap();
    let aqua_chain_option = aqua_page_data.pages.get(0);
    println!("5");
    if aqua_chain_option.is_none() {
        println!("6");
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

    let mut last_revision_hash="".to_string();

    if aqua_chain.revisions.len() ==1 {
        last_revision_hash = genesis_revision.metadata.verification_hash.to_string();
    }else{
       let (_last_hash ,last_rev) = aqua_chain.revisions.get(aqua_chain.revisions.len()-1).expect("Expected a revision as revision are more than one");
       last_revision_hash= last_rev.metadata.verification_hash.to_string();
    }
    // Run the async server in the runtime
    let result =
        runtime.block_on(async { sign_message_server(last_revision_hash).await });

    if result.is_err() {
        println!("Signing failed: {:#?}", result.err());
        panic!("Aqua cli encountered an error")
    }
    let auth_payload = result.unwrap();
    println!("Authentication successful!");
    println!("Signature: {}", auth_payload.signature);
    println!("Public Key: {}", auth_payload.public_key);
    println!("Wallet Address: {}", auth_payload.wallet_address);

    let rev_sig = RevisionContentSignature {
        signature: auth_payload.signature,
        wallet_address: auth_payload.wallet_address,
        filename: genesis_revision
            .content.clone()
            .file
            .expect("Expected to find file name in genesis reviion")
            .filename.clone(),
    };

    let res = sign_aqua_chain(aqua_chain.clone(), rev_sig);

    let log_line = if res.is_ok() {
        "Success :  Signing Aqua chain is successful ".to_string()
    } else {
        "Error : Signing Aqua chain  failed".to_string()
    };
    logs_data.push(log_line);

    if let Err(e) = save_page_data(&aqua_page_data, &sign_path, ".signed.json".to_string())
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

    return;

}