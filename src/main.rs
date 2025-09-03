
pub mod aqua;
pub mod models;
pub mod servers;
pub mod utils;
pub mod tests;

use crate::models::CliArgs;
use aqua::sign::cli_sign_chain;
use aqua::verify::cli_verify_chain;
use aqua::witness::cli_winess_chain;
use aqua::{
    delete_revision_from_aqua_chain::cli_remove_revisions_from_aqua_chain,
    generate_aqua_chain_from_file::cli_generate_aqua_chain,
    // New v3.2 functionality
    chain_link::cli_create_chain_link,
    identity_form::cli_create_identity_form,
    v3_validator::AquaV3Validator,
};
use clap::{Arg, ArgAction, ArgGroup, Command};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{env, path::PathBuf};
use utils::{is_valid_file, is_valid_json_file, is_valid_output_file};
use aqua_verifier::aqua_verifier::{AquaVerifier, VerificationOptions};

const LONG_ABOUT: &str = r#"🔐 Aqua CLI TOOL v3.2.0

========================================================

This tool validates files using the aqua protocol v3.2. It can:
  • Verify aqua chain json file
  • Generate aqua chain
  • Generate validation reports
  • Create chain links between aqua chains (v3.2)
  • Generate identity forms and attestations (v3.2)
  • Validate aqua chains for v3.2 compliance

COMMANDS: 
   • -a  or --authenticate  to verify an aqua json file.
   • -s or --sign to sign an aqua json file.
   • -w or --witness to witness an aqua json file.
   • -f or --file to generate an aqua json file.
   • -v or --verbose  to provide logs about the  process when using  -v,-s,-w or -f command (verbose option).
   • -o or --output to save the output to a file (json, html or pdf).
   • -l  or --level  define how strict the validation should be 1 or 2
        1: Strict validation (does look up, if local wallet mnemonic fails it panic)
        2: Standard validation (create a new mnemonic if one in keys.json faile)
   • -h or --help to show usage, about aqua-cli.
   • -i or --info to show the cli version.
   • -k or --key-file to specify the file containings  (this can also be set in the env  )
   • -d or --delete remove revision from an aqua json file, bydefault removes last revsion but can be used with -c or --count parameter to specifiy the number of revisions
   • -c or --count to specify the number of revisions to remove (note a genesis revision cannot be removed)

NEW v3.2 FEATURES:
   • --link and --target to create chain links between aqua chains
   • --identity-form to generate identity forms and attestations
   • --validate-v3 to validate aqua chains for v3.2 compliance
   • --compliance-level to set validation strictness (basic/standard/strict/enterprise)

EXAMPLES:
    aqua-cli -a chain.json
    aqua-cli -s chain.json --output report.json
    aqua-cli -w chain.json --output report.json

    aqua-cli -f document.pdf
    aqua-cli --file image.png --verbose
    aqua-cli -f document.json --output report.json

v3.2 EXAMPLES:
    aqua-cli --link source.chain.json --target target.chain.json --link-type reference
    aqua-cli --identity-form form.json --domain-id "example.com" --form-type credential
    aqua-cli --validate-v3 chain.json --compliance-level strict


SUMMARY
   * aquq-cli expects ateast parameter -s,-v,-w or -f.
   * in your environment set the
    1. aqua_domain="random_alphanumeric"
    2. aqua_network="sepolia" or  "holesky" or "mainnet"
    3. verification_platform="alchemy" or "infura" or "none"  for witnessing (default "none")
    4. aqua_alchemy_look_up=  false or true

For more information, visit: https://github.com/inblockio/aqua-verifier-cli"#;

pub fn parse_args() -> Result<CliArgs, String> {
    let matches = Command::new("aqua-cli")
    .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .long_about(LONG_ABOUT)
        .about("🔐 Aqua CLI Tool - Validates, Verifies, Signs , Witness aqua chain file and genreates aqua chain files  using aqua protocol")
        .arg(Arg::new("authenticate")
            .short('a')
            .long("authenticate")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("authenticate (verify) an aqua json file"))
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
        .arg(Arg::new("count")
                    .short('c')
                    .long("count")
                    .value_parser(clap::value_parser!(i32)) // Ensures it's a valid unsigned integer
                    .help("Sets a count value")           )
        .arg(Arg::new("delete")
            .short('d')
            .long("delete")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("delete/remove revision from an aqua json file, bydefault removes last revsion but can be used with -c or --count parameter to specifiy the number of revisions"))
        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_file))
            .help("Generate an aqua json file")
            .conflicts_with_all(["authenticate", "sign", "witness"]))
        // New v3.2 CLI arguments
        .arg(Arg::new("link")
            .short('x')
            .long("link")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Create a chain link between two aqua chains"))
        .arg(Arg::new("target")
            .short('t')
            .long("target")
            .action(ArgAction::Set)
            .help("Target chain file for linking"))
        .arg(Arg::new("link-type")
            .long("link-type")
            .action(ArgAction::Set)
            .value_parser(["reference", "dependency", "extension", "validation"])
            .help("Type of chain link to create"))
        .arg(Arg::new("identity-form")
            .long("identity-form")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Create an identity form revision"))
        .arg(Arg::new("domain-id")
            .long("domain-id")
            .action(ArgAction::Set)
            .help("Domain ID for identity form"))
        .arg(Arg::new("form-type")
            .long("form-type")
            .action(ArgAction::Set)
            .value_parser(["personal_info", "credential", "attestation", "declaration", "certification"])
            .help("Type of identity form to create"))
        .arg(Arg::new("validate-v3")
            .long("validate-v3")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Validate an aqua chain for v3.2 compliance"))
        .arg(Arg::new("compliance-level")
            .long("compliance-level")
            .action(ArgAction::Set)
            .value_parser(["basic", "standard", "strict", "enterprise"])
            .default_value("standard")
            .help("Compliance level for v3.2 validation"))
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
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
            .args(["authenticate", "sign", "witness", "file", "delete", "link", "identity-form", "validate-v3"])
            .required(true))
        .get_matches();

    let authenticate = matches
        .get_one::<String>("authenticate")
        .map(|p| PathBuf::from(p));
    let remove = matches
        .get_one::<String>("delete")
        .map(|p| PathBuf::from(p));
    let sign = matches.get_one::<String>("sign").map(|p| PathBuf::from(p));
    let witness = matches
        .get_one::<String>("witness")
        .map(|p| PathBuf::from(p));
    let file = matches.get_one::<String>("file").map(|p| PathBuf::from(p));
    let verbose = matches.get_flag("verbose");
    let output = matches
        .get_one::<String>("output")
        .map(|o| PathBuf::from(o));
    let level = matches.get_one::<String>("level").cloned();
    let keys_file = matches
        .get_one::<String>("keys_file")
        .map(|p| PathBuf::from(p));
    let remove_count_string = matches.get_one::<i32>("count").cloned();

    // New v3.2 arguments
    let link = matches.get_one::<String>("link").map(|p| PathBuf::from(p));
    let target = matches.get_one::<String>("target").map(|p| PathBuf::from(p));
    let link_type = matches.get_one::<String>("link-type").cloned();
    let identity_form = matches.get_one::<String>("identity-form").map(|p| PathBuf::from(p));
    let domain_id = matches.get_one::<String>("domain-id").cloned();
    let form_type = matches.get_one::<String>("form-type").cloned();
    let validate_v3 = matches.get_one::<String>("validate-v3").map(|p| PathBuf::from(p));
    let compliance_level = matches.get_one::<String>("compliance-level").cloned();

    // Ensure only one of -v, -s, or -w is selected
    let operations_selected = [authenticate.is_some(), sign.is_some(), witness.is_some()]
        .iter()
        .filter(|&&x| x)
        .count();

    if operations_selected > 1 {
        return Err(
            "Error: You can only use one of --authenticate, --sign, or --witness independently."
                .to_string(),
        );
    }
    let mut remove_count = 1;
    if remove_count_string.is_some() {
       
        remove_count = remove_count_string.unwrap_or(1);
    }

    Ok(CliArgs {
        authenticate,
        sign,
        witness,
        file,
        remove,
        remove_count,
        verbose,
        output,
        level,
        keys_file,
        // New v3.2 fields
        link,
        target,
        link_type,
        identity_form,
        domain_id,
        form_type,
        validate_v3,
        compliance_level,
    })
}

async fn handle_signing(args: CliArgs, aqua_verifier: AquaVerifier, sign_path: PathBuf, keys_file: Option<PathBuf>) {
    // Your signing logic - now in async context
    // You can safely use the async logger and other async functions here
    
    if let Some(logger) = crate::utils::get_global_logger() {
        logger.info(format!("Starting to sign file: {}", sign_path.display()), None);
    }
    
    // Your existing signing code...
    cli_sign_chain(args, aqua_verifier, sign_path, keys_file).await;
}

async fn handle_witnessing(args: CliArgs, aqua_verifier: AquaVerifier, witness_path: PathBuf) {
    // Your witnessing logic - now in async context
    // You can safely use the async logger and other async functions here
    
    if let Some(logger) = crate::utils::get_global_logger() {
        logger.info(format!("Starting to witness file: {}", witness_path.display()), None);
    }
    
    // Call the async witnessing function with .await
    cli_winess_chain(args, aqua_verifier, witness_path).await;
}

#[tokio::main]
async fn main() {
    // Initialize the global logger first
    crate::utils::init_global_logger();
    
    dotenv::dotenv().ok();

    // Generate a random alphanumeric string
    let random_domain: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    // Check if API_DOMAIN is set
    let aqua_domain = env::var("aqua_domain").unwrap_or(random_domain);
    // let aqua_network = env::var("aqua_network").unwrap_or("sepolia".to_string());
    let verification_platform: String = env::var("verification_platform").unwrap_or("none".to_string());
    let chain: String = env::var("chain").unwrap_or("sepolia".to_string());
    let api_key = env::var("api_key").unwrap_or("".to_string());
    let keys_file_env = env::var("keys_file").unwrap_or("".to_string());

    println!("verification_platform  {} and api key {}  ", verification_platform, api_key);
    
    // Now you can safely use async logging
    if let Some(logger) = crate::utils::get_global_logger() {
        logger.info("Application started".to_string(), None);
    }

    let option = VerificationOptions {
        version: 1.2,
        strict: false,
        allow_null: false,
        verification_platform: verification_platform,
        chain: chain,
        api_key: api_key,
    };

    let aqua_verifier = AquaVerifier::new(Some(option));

    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });

    // validation of combined flags
    if args.authenticate.is_some() || args.sign.is_some() || args.witness.is_some() {
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
            } else {
                panic!("Error with key file provided in the env {:#?}", res.err())
            }
        }
    } else {
        println!("Reading keys file from arguments");
        keys_file = args.clone().keys_file;
    }
    // Process the arguments based on the combination
    // Check for v3.2 operations first
    if let (Some(link_path), Some(target_path), Some(link_type)) = (&args.link, &args.target, &args.link_type) {
        let link_type_enum = match link_type.as_str() {
            "reference" => aqua::chain_link::ChainLinkType::Reference,
            "dependency" => aqua::chain_link::ChainLinkType::Dependency,
            "extension" => aqua::chain_link::ChainLinkType::Extension,
            "validation" => aqua::chain_link::ChainLinkType::Validation,
            _ => {
                eprintln!("Error: Invalid link type: {}", link_type);
                std::process::exit(1);
            }
        };
        cli_create_chain_link(args.clone(), aqua_verifier, link_path.clone(), target_path.clone(), link_type_enum)
            .unwrap_or_else(|e| {
                eprintln!("Error creating chain link: {}", e);
                std::process::exit(1);
            });
        return;
    }

    if let (Some(form_path), Some(domain), Some(form_type)) = (&args.identity_form, &args.domain_id, &args.form_type) {
        let form_type_enum = match form_type.as_str() {
            "personal_info" => aqua::identity_form::IdentityFormType::PersonalInfo,
            "credential" => aqua::identity_form::IdentityFormType::Credential,
            "attestation" => aqua::identity_form::IdentityFormType::Attestation,
            "declaration" => aqua::identity_form::IdentityFormType::Declaration,
            "certification" => aqua::identity_form::IdentityFormType::Certification,
            _ => {
                eprintln!("Error: Invalid form type: {}", form_type);
                std::process::exit(1);
            }
        };
        cli_create_identity_form(args.clone(), aqua_verifier, form_path.clone(), domain.clone(), form_type_enum)
            .unwrap_or_else(|e| {
                eprintln!("Error creating identity form: {}", e);
                std::process::exit(1);
            });
        return;
    }

    if let Some(validate_path) = &args.validate_v3 {
        let compliance_level = match args.compliance_level.as_deref() {
            Some("basic") => aqua::v3_validator::ComplianceLevel::Basic,
            Some("standard") => aqua::v3_validator::ComplianceLevel::Standard,
            Some("strict") => aqua::v3_validator::ComplianceLevel::Strict,
            Some("enterprise") => aqua::v3_validator::ComplianceLevel::Enterprise,
            _ => aqua::v3_validator::ComplianceLevel::Standard,
        };
        
        let validator = AquaV3Validator::new(compliance_level);
        let chain_data = serde_json::from_str(&std::fs::read_to_string(validate_path)
            .unwrap_or_else(|e| {
                eprintln!("Error reading file: {}", e);
                std::process::exit(1);
            }))
            .unwrap_or_else(|e| {
                eprintln!("Error parsing JSON: {}", e);
                std::process::exit(1);
            });
        
        let _result = validator.validate_aqua_chain(&chain_data);
        return;
    }

    // Process legacy operations
    match (
        args.clone().authenticate,
        args.clone().sign,
        args.clone().witness,
        args.clone().file.is_some(),
        args.clone().remove.is_some(),
    ) {
        (Some(verify_path), _, _, _, _) => cli_verify_chain(args, aqua_verifier, verify_path),
        (_, Some(sign_path), _, _, _) => {
            // Your signing logic - now in async context
            handle_signing(args, aqua_verifier, sign_path, keys_file).await;
        },
        (_, _, Some(witness_path), _, _) => {
            // Your witnessing logic - now in async context
            handle_witnessing(args.clone(), aqua_verifier, witness_path).await;
        }
        (_, _, _, true, _) => cli_generate_aqua_chain(args.clone(), aqua_verifier, aqua_domain),
        (_, _, _, _, true) => cli_remove_revisions_from_aqua_chain(
            args.clone(),
            aqua_verifier,
            args.clone()
                .remove
                .expect("aqua chain file to delete revision"),
        ),
        _ => unreachable!(
            "Unable to determin course of action **Clap ensures at least one operation is selected"
        ),
    }
}
