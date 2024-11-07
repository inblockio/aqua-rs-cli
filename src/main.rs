pub mod models;
pub mod utils;

use aqua_verifier_rs_types::models::page_data::HashChain;
use clap::{Arg, ArgAction, ArgGroup, Command};
use models::PageDataContainer;
use std::fs;
use std::path::{Path, PathBuf};
use utils::{read_aqua_data, save_logs_to_file};
use verifier::model::ResultStatusEnum;
use verifier::verifier::verify_aqua_chain;

const LONG_ABOUT: &str = r#"🔐 Aqua CLI TOOL

========================================================

This tool validates files using a aqua protocol. It can:
  • Verify aqua chain json file
  • Generate aqua chain.
  • Generate validation reports

COMMANDS: 
   • -v  or --verify  to verify an aqua json file.
   • -s or --sign to sign an aqua json file.
   • -w or --witness to witness an aqua json file.
   • -f or --file to generate an aqua json file.
   • -d or --details to provide logs about the  process when using  -v,-s,-w or -f command (verbose option).
   • -o or --output to save the output to a file (json, html or pdf).
   • -l  or --level  define how strict the validation should be 1 or 2
        1: Strict validation
        2: Standard validation 
   • -h or --help to show usage, about aqua-cli.
   • -i or --info to show the cli version.
   • -a or --alchemy to specify the achemy paskey for strict validation (this is optional)

EXAMPLES:
    aqua-cli -v chain.json
    aqua-cli -s chain.json --output report.json
    aqua-cli -w chain.json --output report.json

    aqua-cli -f document.pdf
    aqua-cli --file image.png --details
    aqua-cli -f document.json --output report.json


SUMMARY
   aquq-cli expects ateast parameter -s,-v,-w or -f.

For more information, visit: https://github.com/inblockio/aqua-verifier-cli"#;

#[derive(Debug)]
pub struct CliArgs {
    pub verify: Option<PathBuf>,
    pub sign: Option<PathBuf>,
    pub witness: Option<PathBuf>,
    pub file: Option<PathBuf>,
    pub details: bool,
    pub output: Option<PathBuf>,
    pub level: Option<String>,
    pub alchemy: Option<String>,
}

pub fn parse_args() -> Result<CliArgs, String> {
    let matches = Command::new("aqua-cli")
    .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .long_about(LONG_ABOUT)
        .about("🔐 Aqua CLI Tool - Validates, Verifies, Signs , Witness aqua chain file and genreates aqua chain files  using aqua protocol")
        .arg(Arg::new("verify")
            .short('v')
            .long("verify")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Verify an aqua json file"))
        .arg(Arg::new("sign")
            .short('s')
            .long("sign")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Sign an aqua json file"))
        .arg(Arg::new("witness")
            .short('w')
            .long("witness")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Witness an aqua json file"))
        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_file))
            .help("Generate an aqua json file")
            .conflicts_with_all(["verify", "sign", "witness"]))
        .arg(Arg::new("details")
            .short('d')
            .long("details")
            .action(ArgAction::SetTrue)
            .help("Provide additional details")
            .long_help("to provide logs about the  process when using  -v,-s,-w or -f command (verbose option)"))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_output_file))
            .help("Save the output to a file (json, html or pdf)"))
        .arg(Arg::new("level")
            .short('l')
            .long("level")
            .help("Define how strict the validation should be")
            .long_help("Define how strict the validation should be:\n 1: Strict validation\n 2: Standard validation")
            .value_parser(["1", "2"])
            .default_value("2")
            .action(ArgAction::Set))
        .arg(Arg::new("alchemy")
            .short('a')
            .long("alchemy")
            .action(ArgAction::Set)
            .help("Specify the alchemy passkey for strict validation"))
        .group(ArgGroup::new("operation")
            .args(["verify", "sign", "witness", "file"])
            .required(true))
        .get_matches();

    let verify = matches
        .get_one::<String>("verify")
        .map(|p| PathBuf::from(p));
    let sign = matches.get_one::<String>("sign").map(|p| PathBuf::from(p));
    let witness = matches
        .get_one::<String>("witness")
        .map(|p| PathBuf::from(p));
    let file = matches.get_one::<String>("file").map(|p| PathBuf::from(p));
    let details = matches.get_flag("details");
    let output = matches
        .get_one::<String>("output")
        .map(|o| PathBuf::from(o));
    let level = matches.get_one::<String>("level").cloned();
    let alchemy = matches.get_one::<String>("alchemy").cloned();

    Ok(CliArgs {
        verify,
        sign,
        witness,
        file,
        details,
        output,
        level,
        alchemy,
    })
}

fn is_valid_json_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() && path.extension().unwrap_or_default() == "json" {
        Ok(s.to_string())
    } else {
        Err("Invalid JSON file path".to_string())
    }
}

fn is_valid_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() {
        Ok(s.to_string())
    } else {
        Err("Invalid file path".to_string())
    }
}

fn is_valid_output_file(s: &str) -> Result<String, String> {
    let lowercase = s.to_lowercase();
    if lowercase.ends_with(".json") || lowercase.ends_with(".html") || lowercase.ends_with(".pdf") {
        Ok(s.to_string())
    } else {
        Err("Output file must be .json, .html, or .pdf".to_string())
    }
}

// Example usage in main function
fn main() {
    let mut logs_data: Vec<String> = Vec::new();

    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });

    // Example validation of combined flags
    if args.verify.is_some() || args.sign.is_some() || args.witness.is_some() {
        if args.file.is_some() {
            eprintln!("Error: -f/--file cannot be used with -v, -s, or -w");
            std::process::exit(1);
        }
    }

    // Process the arguments based on the combination
    match (args.verify, args.sign, args.witness, args.file.is_some()) {
        (Some(verify_path), _, _, _) => {
            println!("Verifying file: {:?}", verify_path);
            // Verify the file
            let res: Result<PageDataContainer, String> = read_aqua_data(&verify_path);
            // file reading error
            if res.is_err() {
                logs_data.push(res.err().unwrap());

                if args.output.is_some() {
                    let logs = save_logs_to_file(logs_data, args.output.unwrap());

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
                    let logs = save_logs_to_file(logs_data, args.output.unwrap());

                    if logs.is_err() {
                        eprintln!("Error:  saving logs {}", logs.unwrap());
                    }
                }
                return;
            }
            // aqua json file read
            let res = verify_aqua_chain(
                aqua_chain.unwrap().clone(),
                args.alchemy.unwrap_or("no_key".to_string()),
                args.level.unwrap_or("2".to_string()) == "1".to_string(),
            );

            // go through the Revision Aqua chain result

            logs_data.push("Info : Looping through a revisions ".to_string());
            for i in res.revisionResults {
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

                logs_data.push("Info : ============= Proceeding to the next revision =============".to_string());

            }

            let log_line = if res.successful {
                "Success :  Validation is successful ".to_string()
            } else {
                "Error : Validation  failed".to_string()
            };
            logs_data.push(log_line);
            return;
        }
        (_, Some(sign_path), _, _) => {
            println!("Signing file: {:?}", sign_path);
            // Sign the file
        }
        (_, _, Some(witness_path), _) => {
            println!("Witnessing file: {:?}", witness_path);
            // Witness the file
        }
        (_, _, _, true) => {
            if let Some(file_path) = args.file {
                tracing::info!("Generating aqua file from: {:?}", file_path);
                // Generate the aqua file
                if let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) {
                    let json_path = file_path.with_extension("json");
                    match fs::write(&json_path, "{}") {
                        Ok(_) => {
                            println!("Generating aqua file: {:?}", json_path);
                            // Generate the aqua file
                        }
                        Err(err) => {
                            eprintln!("Error generating aqua file: {}", err);
                        }
                    }
                } else {
                    eprintln!("Error: Invalid file path provided with -f/--file");
                }
            }
        }
        _ => unreachable!("Clap ensures at least one operation is selected"),
    }
}
