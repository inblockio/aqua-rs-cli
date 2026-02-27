// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

pub mod aqua;
pub mod models;
#[cfg(feature = "simulation")]
pub mod simulation;
pub mod tests;
pub mod utils;

use crate::models::{CliArgs, SignType, WitnessType};
use aqua::forest::cli_ephemeral_forest;
use aqua::link::cli_link_chain;
use aqua::object::{cli_create_object, cli_list_templates};
use aqua::sign::cli_sign_chain;
use aqua::verify::cli_verify_chain;
use aqua::witness::cli_winess_chain;
use aqua::{revisions::cli_generate_aqua_chain, revisions::cli_remove_revisions_from_aqua_chain};
use aqua_rs_sdk::Aquafier;
use clap::{Arg, ArgAction, ArgGroup, Command};
use std::{env, path::PathBuf};
use utils::{is_valid_file, is_valid_json_file, is_valid_output_file};

const BASE_LONG_ABOUT: &str = r#"Aqua CLI TOOL

========================================================

This tool validates files using an aqua protocol. It can:
  * Verify aqua chain json file
  * Generate aqua chain.
  * Generate validation reports

COMMANDS:
   * -a  or --authenticate  to verify an aqua json file.
   * -s or --sign to sign an aqua json file with options [cli|metamask|did|p256].
   * -w or --witness to witness an aqua json file with options [--witness-eth, --witness-nostr, --witness-tsa].
   * -f or --file to generate an aqua json file.
   * -v or --verbose  to provide logs about the process when using -v,-s,-w or -f command (verbose option).
   * -o or --output to save the output to a file (json, html or pdf).
   * -l  or --level  define how strict the validation should be 1 or 2
        1: Strict validation (does look up, if local wallet mnemonic fails it panic).
        2: Standard validation (create a new mnemonic if one in keys.json fails).
   * -h or --help to show usage, about aqua-cli.
   * -i or --info to show the cli version.
   * -k or --key-file to specify the file containing keys (this can also be set in the env).
   * -d or --delete remove revision from an aqua json file, by default removes the last revision.
   * --link to link files (requires parent + one or more child filenames/paths).
   * --previous-hash to target a specific revision instead of the latest (enables tree/DAG structures).
   * --create-object to create a genesis object revision with a custom template and JSON payload.
       Requires --template-name <NAME> or --template-hash <HASH>, and --payload <PATH_OR_JSON>.
   * --list-templates to list all available built-in templates with their hashes.
   * --forest to ingest one or more .aqua.json files into an ephemeral in-memory forest
       and display the combined verified state: node counts, genesis trees, tip revisions,
       and unresolved L3 cross-tree dependencies. Accepts one or more file paths.
       Use -v (--verbose) to print per-node details.

EXAMPLES:
    aqua-cli -a chain.json
    aqua-cli -s chain.json --sign-type cli --output report.json
    aqua-cli -w chain.json --witness-eth --output report.json

    aqua-cli -f document.pdf
    aqua-cli --file image.png --verbose
    aqua-cli -f document.json --output report.json

    aqua-cli --link parent.aqua.json child.aqua.json
    aqua-cli --link parent.aqua.json child1.aqua.json child2.aqua.json

    # Sign targeting a specific revision (enables tree/DAG branching):
    aqua-cli -s chain.json --sign-type cli -k keys.json --previous-hash 0x<revision_hash>
    # Witness targeting a specific revision:
    aqua-cli -w chain.json --witness-tsa --previous-hash 0x<revision_hash>

    # Create object with a built-in template name:
    aqua-cli --create-object --template-name domain --payload domain_data.json
    # Create object with inline JSON:
    aqua-cli --create-object --template-name name --payload '{"first_name": "Alice", "last_name": "Smith"}'
    # Create object with a custom template hash:
    aqua-cli --create-object --template-hash 0x<hash> --payload data.json

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
        .about("Aqua CLI Tool - Validates, Verifies, Signs, Witness aqua chain file and generates aqua chain files using aqua protocol")
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
                .value_parser(["cli", "metamask", "did", "p256"])
                .help("Specify the signing method: cli, metamask, did, or p256"),
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
            Arg::new("link")
            .long("link")
            .action(ArgAction::Set)
            .num_args(2..) // Accept parent + one or more children
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Link files: first arg is parent, rest are children linked in one anchor revision"),
        )
        .arg(
            Arg::new("previous-hash")
                .long("previous-hash")
                .action(ArgAction::Set)
                .help("Target a specific revision as previous_revision (0x-prefixed lowercase hex hash)")
                .long_help("Instead of appending to the latest revision, target a specific revision by its hash. This enables tree/DAG structures (e.g., branching from genesis). Only usable with --sign, --witness, or --link."),
        )
        .arg(
            Arg::new("create-object")
                .long("create-object")
                .action(ArgAction::SetTrue)
                .help("Create a genesis object revision with a custom template and JSON payload"),
        )
        .arg(
            Arg::new("template-hash")
                .long("template-hash")
                .action(ArgAction::Set)
                .help("Template hash (0x-prefixed lowercase hex) for --create-object"),
        )
        .arg(
            Arg::new("template-name")
                .long("template-name")
                .action(ArgAction::Set)
                .value_parser([
                    "file", "domain", "email", "name", "phone", "attestation",
                    "timestamp", "multi-signer", "trust-assertion",
                    "wallet-identification", "access-grant", "vendor-registration",
                    "template-registration", "alias-registration", "plugin-registration",
                ])
                .help("Built-in template name for --create-object"),
        )
        .arg(
            Arg::new("payload")
                .long("payload")
                .action(ArgAction::Set)
                .help("JSON payload: a file path to a JSON file, or an inline JSON string"),
        )
        .arg(
            Arg::new("list-templates")
                .long("list-templates")
                .action(ArgAction::SetTrue)
                .help("List all available built-in templates with their hashes"),
        )
        .arg(
            Arg::new("minimal")
                .long("minimal")
                .action(ArgAction::SetTrue)
                .help("Generate a single-revision genesis (no anchor or template revisions). Only used with -f/--file"),
        )
        .arg(
            Arg::new("forest")
                .long("forest")
                .action(ArgAction::Set)
                .num_args(1..)
                .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
                .help("Ingest one or more .aqua.json files into an ephemeral in-memory forest and display the combined verified state"),
        )
        .arg(
            Arg::new("simulate")
                .long("simulate")
                .action(ArgAction::SetTrue)
                .help("Run the identity simulation suite — exercises all 12 PlatformIdentityClaim/Attestation WASM states (requires --features simulation)"),
        )
        .arg(
            Arg::new("keep")
                .long("keep")
                .action(ArgAction::SetTrue)
                .help("Keep simulation tree files on disk for inspection (use with --simulate)"),
        )
        .group(
            ArgGroup::new("template")
                .args(["template-hash", "template-name"])
        )
        .group(
            ArgGroup::new("operation")
                .args(["authenticate", "sign", "witness", "file", "delete", "link", "info", "create-object", "list-templates", "forest", "simulate"])
                .required(true),
        )
        .get_matches();

    let authenticate = matches
        .get_one::<String>("authenticate")
        .map(|p| PathBuf::from(p));
    let sign = matches.get_one::<String>("sign").map(|p| PathBuf::from(p));
    let sign_type = matches
        .get_one::<String>("sign-type")
        .cloned()
        .map(|s| match s.as_str() {
            "cli" => SignType::Cli,
            "metamask" => SignType::Metamask,
            "did" => SignType::Did,
            "p256" => SignType::P256,
            _ => unreachable!(),
        });
    let witness = matches
        .get_one::<String>("witness")
        .map(|p| PathBuf::from(p));
    let witness_type = if matches.get_flag("witness-eth") {
        Some(WitnessType::Eth)
    } else if matches.get_flag("witness-nostr") {
        Some(WitnessType::Nostr)
    } else if matches.get_flag("witness-tsa") {
        Some(WitnessType::Tsa)
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
    let delete = matches
        .get_one::<String>("delete")
        .map(|p| PathBuf::from(p));
    let link = matches
        .get_many::<String>("link")
        .map(|vals| vals.map(PathBuf::from).collect());
    let info = matches.get_flag("info");
    let previous_hash = matches.get_one::<String>("previous-hash").cloned();
    let create_object = matches.get_flag("create-object");
    let template_hash = matches.get_one::<String>("template-hash").cloned();
    let template_name = matches.get_one::<String>("template-name").cloned();
    let payload = matches.get_one::<String>("payload").cloned();
    let list_templates = matches.get_flag("list-templates");
    let minimal = matches.get_flag("minimal");
    let forest_files = matches
        .get_many::<String>("forest")
        .map(|vals| vals.map(PathBuf::from).collect());
    let simulate = matches.get_flag("simulate");
    let keep = matches.get_flag("keep");

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
        link,
        delete,
        info,
        previous_hash,
        create_object,
        template_hash,
        template_name,
        payload,
        list_templates,
        minimal,
        forest_files,
        simulate,
        keep,
    })
}

/// Search from CWD upward for the directory containing .env (mirrors dotenv's behavior)
fn find_dotenv_dir() -> Option<PathBuf> {
    let mut dir = env::current_dir().ok()?;
    loop {
        if dir.join(".env").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });

    if args.info {
        println!("{}", BASE_LONG_ABOUT);
        return;
    }

    if args.list_templates {
        cli_list_templates();
        return;
    }

    if args.simulate {
        #[cfg(feature = "simulation")]
        {
            simulation::run_simulation(args.verbose, args.keep).await;
            return;
        }
        #[cfg(not(feature = "simulation"))]
        {
            eprintln!("Error: --simulate requires building with `cargo build --features simulation`");
            std::process::exit(1);
        }
    }

    if args.authenticate.is_none()
        && args.sign.is_none()
        && args.witness.is_none()
        && args.file.is_none()
        && args.link.is_none()
        && args.delete.is_none()
        && !args.create_object
        && args.forest_files.is_none()
        && !args.simulate
    {
        println!("{}", BASE_LONG_ABOUT);
        return;
    }

    let api_key = env::var("api_key").unwrap_or_default();
    let keys_file_env = env::var("keys_file").unwrap_or_default();

    let aquafier = if let Some(host) = aqua_rs_sdk::build_default_blockchain_host(&api_key) {
        Aquafier::builder().blockchain_host(host).build()
    } else {
        Aquafier::new()
    };

    let mut keys_file: Option<PathBuf> = None;
    // attempt to read argument keys, if none attempt to read from environment variables
    if args.clone().keys_file.is_none() {
        if !keys_file_env.is_empty() {
            let keys_path = PathBuf::from(&keys_file_env);
            if is_valid_json_file(&keys_file_env).is_ok() {
                // Found directly (absolute path or relative to CWD)
                println!("Reading keys file from env");
                keys_file = Some(keys_path);
            } else if keys_path.is_relative() {
                // If relative path, try resolving relative to the .env file's directory
                if let Some(env_dir) = find_dotenv_dir() {
                    let resolved = env_dir.join(&keys_path);
                    if is_valid_json_file(&resolved.to_string_lossy()).is_ok() {
                        println!("Reading keys file from env (resolved from .env directory)");
                        keys_file = Some(resolved);
                    } else {
                        eprintln!("Warning: keys file '{}' from .env not found, signing/witnessing will require --keys-file argument", keys_file_env);
                    }
                } else {
                    eprintln!("Warning: keys file '{}' from .env not found, signing/witnessing will require --keys-file argument", keys_file_env);
                }
            } else {
                eprintln!("Warning: keys file '{}' from .env not found, signing/witnessing will require --keys-file argument", keys_file_env);
            }
        }
    } else {
        println!("Reading keys file from arguments");
        keys_file = args.clone().keys_file;
    }

    if args.create_object {
        println!("Creating genesis object revision");
        cli_create_object(args.clone(), &aquafier);
        return;
    }

    if let Some(forest_files) = args.forest_files.clone() {
        cli_ephemeral_forest(args.clone(), &aquafier, forest_files).await;
        return;
    }

    match (
        &args.authenticate,
        &args.sign,
        &args.sign_type,
        &args.witness,
        &args.witness_type,
        &args.file,
        &args.link,
        &args.delete,
    ) {
        (Some(verify_path), _, _, _, _, _, _, _) => {
            println!("Authenticating file: {:?}", verify_path);
            cli_verify_chain(args.clone(), &aquafier, verify_path.to_path_buf()).await;
        }
        (_, Some(sign_path), Some(sign_type), _, _, _, _, _) => {
            println!("Signing file: {:?} using {:?}", sign_path, sign_type);
            cli_sign_chain(
                args.clone(),
                &aquafier,
                sign_path.to_path_buf(),
                sign_type.clone(),
                keys_file,
            )
            .await;
        }
        (_, _, _, Some(witness_path), Some(witness_type), _, _, _) => {
            println!(
                "Witnessing file: {:?} using {:?}",
                witness_path, witness_type
            );
            cli_winess_chain(
                args.clone(),
                &aquafier,
                witness_path.to_path_buf(),
                witness_type.clone(),
                keys_file,
            )
            .await;
        }
        (_, _, _, _, _, Some(file_path), _, _) => {
            println!("Generating aqua json file from: {:?}", file_path);
            cli_generate_aqua_chain(args.clone(), &aquafier);
        }
        (_, _, _, _, _, _, Some(link_paths), _) => {
            let parent = link_paths[0].clone();
            let children: Vec<PathBuf> = link_paths[1..].to_vec();
            println!(
                "Linking {} child chain(s) into parent {:?}",
                children.len(),
                parent
            );
            cli_link_chain(args.clone(), &aquafier, parent, children);
        }
        (_, _, _, _, _, _, _, Some(file_path)) => {
            println!("Deleting last revision");
            cli_remove_revisions_from_aqua_chain(args.clone(), &aquafier, file_path.to_path_buf());
        }
        _ => {
            println!("Error: Unsupported operation or missing parameters (if witness or signing ensure to pass in witness_type or sign_type)");
        }
    }
}
