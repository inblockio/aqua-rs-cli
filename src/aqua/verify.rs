use std::path::PathBuf;

use aqua_verifier_rs_types::models::page_data::PageData;
use verifier::model::ResultStatusEnum;
use verifier::aqua_verifier::AquaVerifier;

use crate::models::CliArgs;
use crate::utils::{read_aqua_data, save_logs_to_file};

pub fn  cli_verify_chain(args : CliArgs, aqua_verifier : AquaVerifier, verify_path : PathBuf){

    let mut logs_data: Vec<String> = Vec::new();

    println!("Verifying file: {:?}", verify_path);
    // Verify the file
    let res: Result<PageData, String> = read_aqua_data(&verify_path);
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
    // aqua json file read
    let res_results = aqua_verifier.verify_aqua_chain(
        &aqua_chain.unwrap().clone(),
        // args.alchemy.unwrap_or("no_key".to_string()),
        // args.level.unwrap_or("2".to_string()) == "1".to_string(),
    );

    // go through the Revision Aqua chain result

    if res_results.is_ok(){ 
    let res = res_results.unwrap();

    logs_data.push("Info : Looping through a revisions ".to_string());
    for i in res.revision_results {
        let log_line = if i.successful {
            "\t Success :  Revision is succefull".to_string()
        } else {
            "\t Error : Revision is not valid".to_string()
        };
        logs_data.push(log_line);

        // file verification
        if i.file_verification.status == ResultStatusEnum::AVAILABLE {
            let file_verification_log = if i.file_verification.successful {
                "\t\t Success :  File verification is succefull".to_string()
            } else {
                "\t\t Error : File verification failed".to_string()
            };
            logs_data.push(file_verification_log);

            for ele in i.file_verification.logs {
                logs_data.push(format!("\t\t\t {}", ele))
            }
        } else {
            logs_data.push("Info : File verification not found".to_string());
        }

        // content verification
        if i.content_verification.status == ResultStatusEnum::AVAILABLE {
            let content_verification_log = if i.content_verification.successful {
                "\t\t Success : Content verification is succefull".to_string()
            } else {
                "\t\t Error : Content verification is not valid".to_string()
            };
            logs_data.push(content_verification_log);

            for ele in i.content_verification.logs {
                logs_data.push(format!("\t\t\t {}", ele))
            }
        } else {
            logs_data.push("Info : content verification not found".to_string());
        }

        // metadata verification
        if i.metadata_verification.status == ResultStatusEnum::AVAILABLE {
            let metadata_verification_log = if i.metadata_verification.successful {
                "\t\t Success : metadata verification is succefull".to_string()
            } else {
                "\t\t Error : metadata verification is not valid".to_string()
            };
            logs_data.push(metadata_verification_log);

            for ele in i.metadata_verification.logs {
                logs_data.push(format!("\t\t\t {}", ele))
            }
        } else {
            logs_data.push("Info : metadata verification not found".to_string());
        }

        //witness verification
        if i.witness_verification.status == ResultStatusEnum::AVAILABLE {
            let witness_verification_log = if i.witness_verification.successful {
                "\t\t Success : witness verification is succefull".to_string()
            } else {
                "\t\t Error : witness verification is not valid".to_string()
            };
            logs_data.push(witness_verification_log);

            for ele in i.witness_verification.logs {
                logs_data.push(format!("\t\t\t {}", ele))
            }
        } else {
            logs_data.push("Info : witness verification not found".to_string());
        }

        //signature verification
        if i.signature_verification.status == ResultStatusEnum::AVAILABLE {
            let signature_verification_log = if i.signature_verification.successful {
                "\t\t Success : signature verification is succefull".to_string()
            } else {
                "\t\t Error : signature verification is not valid".to_string()
            };
            logs_data.push(signature_verification_log);

            for ele in i.signature_verification.logs {
                logs_data.push(format!("\t\t\t {}", ele))
            }
        } else {
            logs_data.push("Info : signature verification not found".to_string());
        }

        logs_data.push(
            "Info : ============= Proceeding to the next revision ============="
                .to_string(),
        );
    }

    let log_line = if res.successful {
        "Success :  Validation is successful ".to_string()
    } else {
        "Error : Validation  failed".to_string()
    };
    logs_data.push(log_line);

}else{
    let log_line = format!("An error occured {}", res_results.unwrap_err());
    logs_data.push(log_line);
}
    //if verbose print out the logs if not print the last line
    if args.verbose {
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