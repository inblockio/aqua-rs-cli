use std::fmt::format;
use std::path::PathBuf;

use crate::aqua::wallet::{create_ethereum_signature, get_wallet};
use crate::models::{CliArgs, SecreatKeys, SignPayload};
use crate::servers::server_sign::sign_message_server;
use crate::utils::{read_aqua_data, read_secreat_keys, save_logs_to_file, save_page_data};
use aqua_verifier_rs_types::models::content::RevisionContentSignature;
use aqua_verifier_rs_types::models::page_data::PageData;
use verifier::aqua_verifier::AquaVerifier;

pub(crate) fn cli_sign_chain(
    args: CliArgs,
    aqua_verifier: AquaVerifier,
    sign_path: PathBuf,
    keys_file: Option<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();

    println!("Signing file: {:?}", sign_path);

    let res: Result<PageData, String> = read_aqua_data(&sign_path);

    if res.is_err() {
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

    let mut sign_result: Option<SignPayload> = None;
    if keys_file.is_none() {
        let runtime_result = tokio::runtime::Runtime::new().map_err(|e| e.to_string());

        if runtime_result.is_err() {
            println!(
                "Error initializing tokio runtime {:#?}",
                runtime_result.err()
            );
            panic!("Aqua cli encountered an error")
        }

        let runtime = runtime_result.unwrap();

        // Run the async server in the runtime
        let result = runtime.block_on(async { sign_message_server(last_revision_hash).await });

        if result.is_err() {
            println!("Signing failed: {:#?}", result.err());
            panic!("Aqua cli encountered an error")
        }
        let auth_payload: SignPayload = result.unwrap();
        println!("Metamask Authentication & Signing Message successful ");
        println!("Signature: {}", auth_payload.signature);
        println!("Public Key: {}", auth_payload.public_key);
        println!("Wallet Address: {}", auth_payload.wallet_address);

        sign_result = Some(auth_payload);
    } else {
        //read mneomonic

        let res: Result<SecreatKeys, String> =
            read_secreat_keys(&keys_file.expect("the keys file has an error "));

        if res.is_err() {
            logs_data.push(format!(
                "Error : an error occured while reading and parsing secreats file {:#?}",
                res.err()
            ));
            if args.output.is_some() {
                let logs = save_logs_to_file(&logs_data, args.output.unwrap());

                if logs.is_err() {
                    eprintln!("Error:  saving logs {}", logs.unwrap());
                }
            }
            return;
        }

        let wallet_result = get_wallet(
            res.expect("error reading mnemonic")
                .mnemonic
                .expect("Mnemonic not found")
                .as_str(),
        );

        if wallet_result.is_err() {
            logs_data.push(format!(
                "Error : an error getting wallet  {:#?}",
                wallet_result.err()
            ));
            if args.output.is_some() {
                let logs = save_logs_to_file(&logs_data, args.output.unwrap());

                if logs.is_err() {
                    eprintln!("Error:  saving logs {}", logs.unwrap());
                }
            }
            return;
        }

        let (address, public_key, private_key) = wallet_result.unwrap();

        match create_ethereum_signature(&private_key, last_revision_hash.as_str()) {
            Ok(signature) => {
                println!("Metamask Authentication & Signing Message successful ");
                println!("Signature: {}", signature);
                println!("Public Key: {}", public_key);
                println!("Wallet Address: {}", address);

                let auth_payload = SignPayload {
                    signature: signature,
                    public_key: public_key,
                    wallet_address: address,
                };
                sign_result = Some(auth_payload);
            }
            Err(e) => {
                println!("Error signing message: {}", e);

                logs_data.push(format!("Error : an error signing message  {:#?}", e));
                if args.output.is_some() {
                    let logs = save_logs_to_file(&logs_data, args.output.unwrap());

                    if logs.is_err() {
                        eprintln!("Error:  saving logs {}", logs.unwrap());
                    }
                }
                return;
            }
        }
    }

    if sign_result.is_none() {
        panic!("The message  signing failed somewhere");
    }

    let sign_result_data = sign_result.unwrap();
    let rev_sig = RevisionContentSignature {
        signature: sign_result_data.signature,
        wallet_address: sign_result_data.wallet_address,
        publickey: sign_result_data.public_key,
        filename: genesis_revision
            .content
            .clone()
            .file
            .expect("Expected to find file name in genesis reviion")
            .filename
            .clone(),
    };

    let res = aqua_verifier.sign_aqua_chain(aqua_page_data.clone(), rev_sig);

    if res.is_err() {
        res.clone()
            .unwrap_err()
            .iter()
            .for_each(|item| println!("\t\t {}", item));
        panic!("Error .... check logs above");
    }

    let (res_page_data, res_logs) = res.clone().unwrap();

    res_logs
        .iter()
        .for_each(|item| logs_data.push(format!("\t {}", item)));

    let log_line = if res.is_ok() {
        "Success :  Signing Aqua chain is successful ".to_string()
    } else {
        "Error : Signing Aqua chain  failed".to_string()
    };
    logs_data.push(log_line);

    if let Err(e) = save_page_data(&res_page_data, &sign_path, "signed.json".to_string()) {
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
