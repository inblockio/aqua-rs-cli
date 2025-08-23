pub mod aqua;
pub mod models;
pub mod servers;
pub mod tests;
pub mod utils;
pub mod validation;

use crate::models::CliArgs;
use aqua::sign::cli_sign_chain;
use aqua::verify::cli_verify_chain;
use aqua::witness::cli_witness_chain;
use aqua::{
    content::cli_generate_content_revision,
    delete_revision_from_aqua_chain::cli_remove_revisions_from_aqua_chain,
    form::cli_generate_form_revision, generate_aqua_chain_from_file::cli_generate_aqua_chain,
    link::cli_generate_link_revision,
};
use aqua_verifier::aqua_verifier::{AquaVerifier, VerificationOptions};
use clap::{Arg, ArgAction, ArgGroup, Command};
use rand::{distributions::Alphanumeric, Rng};
use std::{env, path::PathBuf};
use utils::{is_valid_file, is_valid_json_file, is_valid_output_file};

const LONG_ABOUT: &str = r#"🔐 Aqua CLI v3.2 - Aqua Protocol Version 3

========================================================

This tool validates and manages Aqua protocol v3 files. It can:
  • Verify Aqua chain JSON files (v3 format)
  • Generate new Aqua chains from files
  • Sign Aqua chains with cryptographic signatures
  • Witness Aqua chains on blockchain networks
  • Create different revision types (file, content, form, link)
  • Generate validation reports

  COMMANDS:
     • -a  or --authenticate     Verify an Aqua JSON file
     • -s  or --sign            Sign an Aqua JSON file
     • -w  or --witness         Witness an Aqua JSON file
     • -f  or --file            Generate an Aqua JSON file (file revision)
     • -c  or --content         Generate content revision (reference only)
     • --form                   Generate form revision for identity claims
     • --link                   Create link revision to other Aqua chains
     • -d  or --delete          Remove revision(s) from Aqua chain
     • -v  or --verbose         Provide detailed logs
     • -o  or --output          Save output to file (json, html, pdf)
     • -l  or --level           Validation strictness (1=strict, 2=standard)
     • -k  or --key-file        Specify keys file location
     • --count                  Number of revisions to remove (with --delete)

  REVISION TYPES (v3):
     • file      - File with optional embedded content
     • content   - File reference without embedded content
     • form      - Identity claims and attestations
     • signature - Cryptographic signatures (ethereum:eip-191, did_key)
     • witness   - Blockchain timestamping (mainnet, sepolia, nostr, TSA_RFC3161)
     • link      - References to other Aqua chains

EXAMPLES:
    # Verify v3 Aqua chain
    aqua-cli -a chain.json

    # Generate file revision with embedded content
    aqua-cli -f document.pdf

    # Generate content revision (reference only)
    aqua-cli -c document.pdf

    # Create form revision for identity
    aqua-cli --form identity-form.json

    # Sign with local keys
    aqua-cli -s chain.json -k keys.json

    # Witness on blockchain
    aqua-cli -w chain.json

    # Link to another Aqua chain
    aqua-cli --link target-chain.json source-file.txt

    # Remove last 2 revisions
    aqua-cli -d chain.json --count 2


ENVIRONMENT VARIABLES:
    aqua_domain="random_alphanumeric"     Domain identifier
    aqua_network="sepolia"                Network (sepolia, holesky, mainnet)
    verification_platform="none"         Platform (alchemy, infura, none)
    chain="sepolia"                       Blockchain for witnessing
    api_key=""                           API key for verification platform
    keys_file=""                         Path to keys file

SCHEMA COMPLIANCE:
    This tool implements Aqua Protocol v3.2 schema:
    https://aqua-protocol.org/docs/v3/schema_2

For more information, visit: https://github.com/inblockio/aqua-verifier-cli"#;

pub fn parse_args() -> Result<CliArgs, String> {
    let matches = Command::new("aqua-cli")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .long_about(LONG_ABOUT)
        .about("🔐 Aqua CLI v3.2 - Validates, Signs, Witnesses and Generates Aqua Protocol v3 chains")

        // Main operation arguments
        .arg(Arg::new("authenticate")
            .short('a')
            .long("authenticate")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Authenticate (verify) an Aqua JSON file"))

        .arg(Arg::new("sign")
            .short('s')
            .long("sign")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Sign an Aqua JSON file"))

        .arg(Arg::new("witness")
            .short('w')
            .long("witness")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Witness an Aqua JSON file"))

        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_file))
            .help("Generate file revision (with optional embedded content)")
            .conflicts_with_all(["authenticate", "sign", "witness"]))

        // New v3 revision type arguments
        .arg(Arg::new("content")
            .short('c')
            .long("content")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_file))
            .help("Generate content revision (reference only, no embedded content)")
            .conflicts_with_all(["authenticate", "sign", "witness", "file"]))

        .arg(Arg::new("form")
            .long("form")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Generate form revision for identity claims and attestations")
            .conflicts_with_all(["authenticate", "sign", "witness", "file", "content"]))

        .arg(Arg::new("link")
            .long("link")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Create link revision to reference other Aqua chains")
            .requires("file")
            .help("Create link revision (requires --file for source)"))

        // Management arguments
        .arg(Arg::new("delete")
            .short('d')
            .long("delete")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Remove revision(s) from Aqua chain"))

        .arg(Arg::new("count")
            .long("count")
            .value_parser(clap::value_parser!(i32))
            .help("Number of revisions to remove (use with --delete)")
            .default_value("1"))

        // Configuration arguments
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .action(ArgAction::SetTrue)
            .help("Provide detailed logs and process information"))

        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_output_file))
            .help("Save output to file (json, html, pdf)"))

        .arg(Arg::new("level")
            .short('l')
            .long("level")
            .help("Validation strictness level")
            .long_help("1: Strict validation (fails on any error)\n2: Standard validation (more permissive)")
            .value_parser(["1", "2"])
            .default_value("2")
            .action(ArgAction::Set))

        .arg(Arg::new("keys_file")
            .short('k')
            .long("keys_file")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Keys file containing mnemonic, nostr_sk and did:key"))

        // Operation groups
        .group(ArgGroup::new("operation")
            .args(["authenticate", "sign", "witness", "file", "content", "form", "delete"])
            .required(true))

        .get_matches();

    // Parse arguments
    let authenticate = matches
        .get_one::<String>("authenticate")
        .map(|p| PathBuf::from(p));
    let sign = matches.get_one::<String>("sign").map(|p| PathBuf::from(p));
    let witness = matches
        .get_one::<String>("witness")
        .map(|p| PathBuf::from(p));
    let file = matches.get_one::<String>("file").map(|p| PathBuf::from(p));
    let content_file = matches
        .get_one::<String>("content")
        .map(|p| PathBuf::from(p));
    let form = matches.get_one::<String>("form").map(|p| PathBuf::from(p));
    let link = matches.get_one::<String>("link").map(|p| PathBuf::from(p));
    let remove = matches
        .get_one::<String>("delete")
        .map(|p| PathBuf::from(p));
    let remove_count = matches.get_one::<i32>("count").cloned().unwrap_or(1);
    let verbose = matches.get_flag("verbose");
    let output = matches
        .get_one::<String>("output")
        .map(|o| PathBuf::from(o));
    let level = matches.get_one::<String>("level").cloned();
    let keys_file = matches
        .get_one::<String>("keys_file")
        .map(|p| PathBuf::from(p));

    // Validate mutual exclusivity for main operations
    let operations_selected = [
        authenticate.is_some(),
        sign.is_some(),
        witness.is_some(),
        file.is_some(),
        content_file.is_some(),
        form.is_some(),
        remove.is_some(),
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    if operations_selected > 1 {
        return Err("Error: Only one main operation (authenticate, sign, witness, file, content, form, delete) can be used at a time.".to_string());
    }

    Ok(CliArgs {
        authenticate,
        sign,
        witness,
        file: if content_file.is_some() {
            content_file.clone()
        } else {
            file
        },
        remove,
        remove_count,
        verbose,
        output,
        level,
        keys_file,
        content: content_file.is_some(),
        form,
        link,
        revision_type: None, // Will be determined by the operation
    })
}

fn main() {
    dotenv::dotenv().ok();

    // Generate random domain if not set
    let random_domain: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    // Environment variables
    let aqua_domain = env::var("aqua_domain").unwrap_or(random_domain);
    let verification_platform = env::var("verification_platform").unwrap_or("none".to_string());
    let chain = env::var("chain").unwrap_or("sepolia".to_string());
    let api_key = env::var("api_key").unwrap_or("".to_string());
    let keys_file_env = env::var("keys_file").unwrap_or("".to_string());

    println!("🔐 Aqua CLI v3.2 - Protocol Version 3");
    println!("Verification platform: {}", verification_platform);
    if !api_key.is_empty() {
        println!("API key configured: ✓");
    }

    // Initialize AquaVerifier with v3 options
    let option = VerificationOptions {
        version: 3.2, // Updated to v3.2
        strict: false,
        allow_null: false,
        verification_platform,
        chain,
        api_key,
    };

    let aqua_verifier = AquaVerifier::new(Some(option));

    // Parse CLI arguments
    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });

    // Determine keys file (CLI arg takes precedence over env var)
    let mut keys_file: Option<PathBuf> = args.keys_file.clone();
    if keys_file.is_none() && !keys_file_env.is_empty() {
        match is_valid_json_file(&keys_file_env) {
            Ok(_) => {
                println!("Using keys file from environment variable");
                keys_file = Some(PathBuf::from(keys_file_env));
            }
            Err(e) => {
                eprintln!("Error with keys file from environment: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Route to appropriate functionality based on CLI arguments
    match determine_operation(&args, None) {
        Operation::Authenticate(path) => {
            cli_verify_chain(args, aqua_verifier, path);
        }
        Operation::Sign(path) => {
            cli_sign_chain(args, aqua_verifier, path, keys_file);
        }
        Operation::Witness(path) => {
            cli_witness_chain(args, aqua_verifier, path);
        }
        Operation::GenerateFile(path) => {
            cli_generate_aqua_chain(args, aqua_verifier, aqua_domain, path);
        }
        Operation::GenerateContent(content_file) => {
            cli_generate_content_revision(args, aqua_verifier, aqua_domain, content_file);
        }
        Operation::GenerateForm(form_path) => {
            cli_generate_form_revision(args, aqua_verifier, aqua_domain, form_path);
        }
        Operation::GenerateLink(source_path, target_path) => {
            cli_generate_link_revision(args, aqua_verifier, source_path, target_path);
        }
        Operation::DeleteRevisions(path) => {
            cli_remove_revisions_from_aqua_chain(args, aqua_verifier, path);
        }
    }
}

#[derive(Debug)]
enum Operation {
    Authenticate(PathBuf),
    Sign(PathBuf),
    Witness(PathBuf),
    GenerateFile(PathBuf),
    GenerateContent(PathBuf),
    GenerateForm(PathBuf),
    GenerateLink(PathBuf, PathBuf),
    DeleteRevisions(PathBuf),
}

fn determine_operation(args: &CliArgs, _content_file: Option<PathBuf>) -> Operation {
    if let Some(path) = &args.authenticate {
        Operation::Authenticate(path.clone())
    } else if let Some(path) = &args.sign {
        Operation::Sign(path.clone())
    } else if let Some(path) = &args.witness {
        Operation::Witness(path.clone())
    } else if let Some(path) = &args.file {
        if let Some(target_path) = &args.link {
            Operation::GenerateLink(path.clone(), target_path.clone())
        } else if args.content {
            Operation::GenerateContent(path.clone())
        } else {
            Operation::GenerateFile(path.clone())
        }
    } else if let Some(form_path) = &args.form {
        Operation::GenerateForm(form_path.clone())
    } else if let Some(path) = &args.remove {
        Operation::DeleteRevisions(path.clone())
    } else {
        panic!("No valid operation determined - this should not happen due to clap validation");
    }
}
