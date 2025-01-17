pub mod aqua;
pub mod models;
pub mod tests;
pub mod utils;

use crate::models::CliArgs;
use aqua::link::cli_link_chain;
use aqua::revisions::cli_generate_scalar_revision;
use aqua::sign::cli_sign_chain;
use aqua::verify::cli_verify_chain;
use aqua::witness::cli_winess_chain;
use aqua::{
    revisions::cli_remove_revisions_from_aqua_chain,
    revisions::cli_generate_aqua_chain,
};
use aqua_verifier::aqua::AquaProtocol;
use aqua_verifier::model::aqua_protocol_options::AquaProtocolOptions;
use aqua_verifier::model::signature::SignatureType;
use aqua_verifier::model::witness::WitnessType;
use clap::{Arg, ArgAction, ArgGroup, Command};
use std::{env, path::PathBuf};
use utils::{is_valid_file, is_valid_json_file, is_valid_output_file};

const BASE_LONG_ABOUT: &str = r#"🔐 Aqua CLI TOOL

========================================================

This tool validates files using an aqua protocol. It can:
  • Verify aqua chain json file
  • Generate aqua chain.
  • Generate validation reports

COMMANDS: 
   • -a  or --authenticate  to verify an aqua json file.
   • -s or --sign to sign an aqua json file with options [cli|metamask|did].
   • -w or --witness to witness an aqua json file with options [--witness-eth, --witness-nostr, --witness-tsa].
   • -f or --file to generate an aqua json file.
   • -v or --verbose  to provide logs about the process when using -v,-s,-w or -f command (verbose option).
   • -o or --output to save the output to a file (json, html or pdf).
   • -l  or --level  define how strict the validation should be 1 or 2
        1: Strict validation (does look up, if local wallet mnemonic fails it panic).
        2: Standard validation (create a new mnemonic if one in keys.json fails).
   • -h or --help to show usage, about aqua-cli.
   • -i or --info to show the cli version.
   • -k or --key-file to specify the file containing keys (this can also be set in the env).
   • -d or --delete remove revision from an aqua json file, by default removes the last revision but can be used with -c or --count parameter to specify the number of revisions.
   • --scalar for scalar operation (no additional parameter needed).
   • --link to link files (requires a filename or path as parameter).

EXAMPLES:
    aqua-cli -a chain.json
    aqua-cli -s chain.json --sign cli --output report.json
    aqua-cli -w chain.json --witness-eth --output report.json

    aqua-cli -f document.pdf
    aqua-cli --file image.png --verbose
    aqua-cli -f document.json --output report.json

    aqua-cli file.json --link file2.json
    aqua-cli --scalar file.json

SUMMARY
   * aqua-cli expects at least one parameter -s,-v,-w or -f.
   * in your environment set the
    1. aqua_domain="random_alphanumeric".
    2. aqua_network="sepolia" or "holesky" or "mainnet".
    3. verification_platform="alchemy" or "infura" or "none" for witnessing (default "none").
    4. aqua_alchemy_look_up= false or true.

For more information, visit: https://github.com/inblockio/aqua-cli-rs

"#;

pub fn parse_args() -> Result<CliArgs, String> {
    let long_about = format!(
        "{}\n\nVersion: {}",
        BASE_LONG_ABOUT,
        env!("CARGO_PKG_VERSION")
    );
    let matches = Command::new("aqua-cli")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .long_about(long_about)
        .about("🔐 Aqua CLI Tool - Validates, Verifies, Signs, Witness aqua chain file and generates aqua chain files using aqua protocol")
        .arg(
            Arg::new("authenticate")
                .short('a')
                .long("authenticate")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
                .help("Authenticate (verify) an aqua json file"),
        )
        .arg(
            Arg::new("sign")
                .short('s')
                .long("sign")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
                .help("Sign an aqua json file"),
        )
        .arg(
            Arg::new("sign-type")
                .long("sign-type")
                .action(ArgAction::Set)
                .value_parser(["cli", "metamask", "did"])
                .help("Specify the signing method: cli, metamask, or did"),
        )
        .arg(
            Arg::new("witness")
                .short('w')
                .long("witness")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
                .help("Witness an aqua json file"),
        )
        .arg(
            Arg::new("witness-eth")
                .long("witness-eth")
                .action(ArgAction::SetTrue)
                .help("Witness to Ethereum on-chain with MetaMask"),
        )
        .arg(
            Arg::new("witness-nostr")
                .long("witness-nostr")
                .action(ArgAction::SetTrue)
                .help("Witness to Nostr network"),
        )
        .arg(
            Arg::new("witness-tsa")
                .long("witness-tsa")
                .action(ArgAction::SetTrue)
                .help("Witness to TSA DigiCert"),
        )
        .arg(
            Arg::new("delete")
                .short('d')
                .long("delete")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
                .help("Delete/remove revision from an aqua json file, removes last revision"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(is_valid_file))
                .help("Generate an aqua json file")
                .conflicts_with_all(["authenticate", "sign", "witness"]),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Provide additional details")
                .long_help("Provide logs about the process when using -v,-s,-w or -f command (verbose option)"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(is_valid_output_file))
                .help("Save the output to a file (json, html or pdf)"),
        )
        .arg(
            Arg::new("level")
                .short('l')
                .long("level")
                .help("Define how strict the validation should be")
                .long_help("Define how strict the validation should be:\n 1: Strict validation\n 2: Standard validation")
                .value_parser(["1", "2"])
                .default_value("2")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("keys_file")
                .short('k')
                .long("keys_file")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
                .help("Keys file json containing nonce, nostr_sk and did:key"),
        )
        .arg(
            Arg::new("info")
                .short('i')
                .long("info")
                .action(ArgAction::SetTrue)
                .help("Show detailed information about the CLI"),
        )
        .arg(
            Arg::new("scalar")
                .long("scalar")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
                .help("Create a scalar revision (requires a filename or path as parameter)"),
        )
        .arg(
            Arg::new("link")
            .long("link")
            .action(ArgAction::Set)
            .num_args(2) // Accept exactly two arguments for linking
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Link two files (requires two filenames or paths as parameters)"),
        )
        .group(
            ArgGroup::new("operation")
                .args(["authenticate", "sign", "witness", "file", "delete", "scalar", "link", "info"])
                .required(true),
        )
        .get_matches();

    let authenticate = matches
        .get_one::<String>("authenticate")
        .map(|p| PathBuf::from(p));
    let sign = matches.get_one::<String>("sign").map(|p| PathBuf::from(p));
    let sign_type = matches.get_one::<String>("sign-type").cloned().map(|s| match s.as_str() {
        "cli" => SignatureType::CLI,
        "metamask" => SignatureType::METAMASK,
        "did" => SignatureType::DID,
        _ => unreachable!(),
    });
    let witness = matches
        .get_one::<String>("witness")
        .map(|p| PathBuf::from(p));
    let witness_type = if matches.get_flag("witness-eth") {
        Some(WitnessType::METAMASK)
    } else if matches.get_flag("witness-nostr") {
        Some(WitnessType::NOSTR)
    } else if matches.get_flag("witness-tsa") {
        Some(WitnessType::TSA)
    } else {
        None
    };
    let file = matches.get_one::<String>("file").map(|p| PathBuf::from(p));
    let verbose = matches.get_flag("verbose");
    let output = matches
        .get_one::<String>("output")
        .map(|o| PathBuf::from(o));
    let level = matches.get_one::<String>("level").cloned();
    let keys_file = matches
        .get_one::<String>("keys_file")
        .map(|p| PathBuf::from(p));
    let delete = matches.get_one::<String>("delete").map(|p| PathBuf::from(p));
    // let link = matches.get_one::<String>("link").map(|p| PathBuf::from(p));
    let link = matches
    .get_many::<String>("link")
    .map(|vals| vals.map(PathBuf::from).collect());

    let scalar = matches.get_one::<String>("scalar").map(|p| PathBuf::from(p));
    let info = matches.get_flag("info");

    Ok(CliArgs {
        authenticate,
        sign,
        sign_type,
        witness,
        witness_type,
        file,
        verbose,
        output,
        level,
        keys_file,
        scalar,
        link,
        delete,
        info
    })
}

fn main() {
    dotenv::dotenv().ok();

    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });

    if args.info {
        println!("{}", BASE_LONG_ABOUT);
        return;
    }

    if args.authenticate.is_none()
        && args.sign.is_none()
        && args.witness.is_none()
        && args.file.is_none()
        && args.scalar.is_none()
        && args.link.is_none()
        && args.delete.is_none()
    {
        println!("{}", BASE_LONG_ABOUT);
        return;
    }


    // let aqua_network = env::var("aqua_network").unwrap_or("sepolia".to_string());
    let verification_platform: String =
        env::var("verification_platform").unwrap_or("none".to_string());
    let chain: String = env::var("chain").unwrap_or("sepolia".to_string());
    let api_key = env::var("api_key").unwrap_or("".to_string());
    let keys_file_env = env::var("keys_file").unwrap_or("".to_string());

    let option = AquaProtocolOptions {
        version: 1.3,
        strict: false,
        allow_null: false,
        verification_platform: verification_platform,
        verification_platform_key: api_key,
        chain_network: chain,
    };

    let aqua_protocol = AquaProtocol::new(option);
    let mut keys_file: Option<PathBuf> = None;
    // attempt to read aregiument keys , if none attempt to rread from environment variables
    if args.clone().keys_file.is_none() {
        if !keys_file_env.is_empty() {
            let res = is_valid_json_file(&keys_file_env);
            if res.is_ok() {
                println!("Reading keys file from env");
                keys_file = Some(PathBuf::from(keys_file_env))
            } else {
                panic!("Error with key file provided in the env {:#?}", res.err())
            }
        }
    } else {
        println!("Reading keys file from arguments");
        keys_file = args.clone().keys_file;
    }
    
    match (
        &args.authenticate,
        &args.sign,
        &args.sign_type,
        &args.witness,
        &args.witness_type,
        &args.file,
        &args.scalar,
        &args.link,
        &args.delete,
    ) {
        (Some(verify_path), _, _, _, _, _, _, _,_) => {
            println!("Authenticating file: {:?}", verify_path);
            cli_verify_chain(args.clone(), aqua_protocol, verify_path.to_path_buf());
        }
        (_, Some(sign_path), Some(sign_type), _, _, _, _, _,_) => {
            println!("Signing file: {:?} using {:?}", sign_path, sign_type);
           cli_sign_chain(args.clone(), aqua_protocol, sign_path.to_path_buf(), sign_type.clone(), keys_file);

        }
        (_, _, _, Some(witness_path), Some(witness_type), _, _, _,_) => {
            println!("Witnessing file: {:?} using {:?}", witness_path, witness_type);
            
            cli_winess_chain(args.clone(), aqua_protocol, witness_path.to_path_buf(), witness_type.clone(), keys_file);
        }
        (_, _, _, _, _, Some(file_path), _, _,_) => {
            println!("Generating aqua json file from: {:?}", file_path);
          
            cli_generate_aqua_chain(args.clone(), aqua_protocol);
        }
        (_, _, _, _, _, _, Some(_file_path), _,_) => {
            println!("Performing scalar operation");
            cli_generate_scalar_revision(args.clone(), aqua_protocol);
        }
        (_, _, _, _, _, _, _, Some(link_paths),_) => {
            if link_paths.len() != 2 {
                eprintln!("Error: Linking requires exactly two file paths.");
                std::process::exit(1);
            }
            let file1 = &link_paths[0];
            let file2 = &link_paths[1];
            println!("Linking files: {:?} and {:?}", file1, file2);
            cli_link_chain(args.clone(), aqua_protocol, file1.clone(), file2.clone());
        }
        (_, _, _, _, _, _, _, _,Some(file_path)) => {
            println!("delete last revision");
            cli_remove_revisions_from_aqua_chain(
                args.clone(),
                aqua_protocol,
                file_path.to_path_buf());
        }
        _ => {
            println!("Error: Unsupported operation or missing parameters");
        }
    }   
}