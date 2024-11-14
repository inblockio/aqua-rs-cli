pub mod aqua;
pub mod models;
pub mod  servers;
pub mod utils;

use crate::models::CliArgs;
use aqua::gen_aqua_file::cli_generate_aqua_chain;
use aqua::sign::cli_sign_chain;
use aqua::verify::cli_verify_chain;
use aqua::witness::cli_winess_chain;
use clap::{Arg, ArgAction, ArgGroup, Command};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{env, path::PathBuf};
use utils::{is_valid_file, is_valid_json_file, is_valid_output_file, string_to_bool};
use verifier::aqua_verifier::{AquaVerifier, VerificationOptions};

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
   • -k or --key-file to specify the file containings  (this can also be set in the env  )
   

EXAMPLES:
    aqua-cli -v chain.json
    aqua-cli -s chain.json --output report.json
    aqua-cli -w chain.json --output report.json

    aqua-cli -f document.pdf
    aqua-cli --file image.png --details
    aqua-cli -f document.json --output report.json


SUMMARY
   * aquq-cli expects ateast parameter -s,-v,-w or -f.
   * in your environment set the
    1. aqua_domain="random_alphanumeric"
    2. aqua_network="sepolia" or  "holesky" or "mainnet"
    3. alchemy_key="alchemy_key" for witnessing
    4. aqua_alchemy_look_up=  false or true

For more information, visit: https://github.com/inblockio/aqua-verifier-cli"#;

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
        .arg(Arg::new("keys_file")
            .short('k')
            .long("keys_file")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("keys file json containing nounce, nostr_sk and did:key"))
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
    let keys_file = matches
        .get_one::<String>("keys_file")
        .map(|p| PathBuf::from(p));

    // Ensure only one of -v, -s, or -w is selected
    let operations_selected = [verify.is_some(), sign.is_some(), witness.is_some()]
        .iter()
        .filter(|&&x| x)
        .count();

    if operations_selected > 1 {
        return Err(
            "Error: You can only use one of --verify, --sign, or --witness independently."
                .to_string(),
        );
    }

    Ok(CliArgs {
        verify,
        sign,
        witness,
        file,
        details,
        output,
        level,
        keys_file,
    })
}

fn main() {
    dotenv::dotenv().ok();

    // Generate a random alphanumeric string
    let random_domain: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    // Check if API_DOMAIN is set
    let aqua_domain = env::var("aqua_domain").unwrap_or(random_domain);
    let _aqua_network = env::var("aqua_network").unwrap_or("sepolia".to_string());
    let alchemy_key = env::var("aqua_alchemy_key").unwrap_or("".to_string());
    let aqua_alchemy_look_up = env::var("aqua_alchemy_look_up").unwrap_or("".to_string());
    let keys_file_env = env::var("keys_file").unwrap_or("".to_string());

    let option = VerificationOptions {
        version: 1.2,
        strict: false,
        allow_null: false,
        alchemy_key: alchemy_key,
        do_alchemy_key_lookup: string_to_bool(aqua_alchemy_look_up),
    };

    let aqua_verifier = AquaVerifier::new(Some(option));

    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });

    // validation of combined flags
    if args.verify.is_some() || args.sign.is_some() || args.witness.is_some() {
        if args.file.is_some() {
            eprintln!("Error: -f/--file cannot be used with -v, -s, or -w");
            std::process::exit(1);
        }
    }

    let mut keys_file: Option<PathBuf> = None;
    // attempt to read aregiument keys , if none attempt to rread from environment variables
    if args.clone().keys_file.is_none() {
        if !keys_file_env.is_empty() {
            let res = is_valid_json_file(&keys_file_env);
            if res.is_ok() {
                println!("Reading keys file from env");
                keys_file = Some(PathBuf::from(keys_file_env))
            }else{
                panic!("Error with key file provided in the env {:#?}",res.err() )
            }
        }
    } else {
        println!("Reading keys file from arguments");
        keys_file = args.clone().keys_file;
    }
    // Process the arguments based on the combination
    match (
        args.clone().verify,
        args.clone().sign,
        args.clone().witness,
        args.clone().file.is_some(),
    ) {
        (Some(verify_path), _, _, _) => cli_verify_chain(args, aqua_verifier, verify_path),
        (_, Some(sign_path), _, _) => cli_sign_chain(args, aqua_verifier, sign_path, keys_file),
        (_, _, Some(witness_path), _) => {
            cli_winess_chain(args.clone(), aqua_verifier, witness_path);
        }
        (_, _, _, true) => {
            cli_generate_aqua_chain(args.clone(), aqua_verifier, aqua_domain);
        }
        _ => unreachable!(
            "Unable to determin course of action **Clap ensures at least one operation is selected"
        ),
    }
}
