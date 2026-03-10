// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

pub mod aqua;
pub mod models;
#[cfg(feature = "simulation")]
pub mod simulation;
pub mod tests;
pub mod utils;

use crate::models::{CliArgs, SignType, WitnessType};
use aqua::connect::cli_connect_forest;
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
use utils::{is_valid_file, is_valid_json_file, is_valid_output_file, resolve_aqua_file};

const BASE_LONG_ABOUT: &str = r#"Aqua CLI — verify, sign, witness, and generate Aqua trees using the Aqua Protocol

USAGE:
    aqua-cli <COMMAND> [OPTIONS]

COMMANDS:
    -a, --authenticate <FILE>   Verify an Aqua tree file (.aqua.json auto-detected)
    -s, --sign <FILE>           Sign an Aqua tree file (requires --sign-type)
    -w, --witness <FILE>        Witness an Aqua tree file (requires --witness-eth, --witness-nostr, or --witness-tsa)
    -f, --file <FILE>           Generate a new Aqua tree from a file
    -d, --delete <FILE>         Remove the last revision from an Aqua tree file
    --link <PARENT> <CHILD...>  Link child trees into a parent tree
    --create-object             Create a genesis object revision (requires --template-name or --template-hash, and --payload)
    --list-templates            List all available built-in templates with their hashes
    --forest <FILES...>         Ingest .aqua.json files into an ephemeral in-memory forest
    --connect <ID>              Connect to a running forest daemon via Unix socket
    -i, --info                  Show detailed CLI information

MODIFIERS:
    -k, --keys-file <FILE>      Keys file (JSON) containing mnemonic, nostr_sk, did:key, etc.
    -o, --output <FILE>         Save output to a file (.json, .html, or .pdf)
    -v, --verbose               Show detailed logs
    -l, --level <1|2>           Validation strictness: 1 = strict, 2 = standard (default: 2)
    --sign-type <TYPE>          Signing method: cli, metamask, did, or p256
    --previous-hash <HASH>      Target a specific revision (enables tree/DAG branching)
    --trust <DID> <LEVEL>       Populate trust store for forest verification (1=marginal, 2=full, 3=ultimate)
    --daemon [SECONDS]          Keep forest alive as persistent daemon (default: 600s idle timeout)
    --target <ID>               Push operation results into a running daemon's forest
    --listen <PORT>         Start HTTP API on PORT for state viewer integration (requires --daemon)

    The .aqua.json extension is auto-detected: `aqua-cli -a README.md` will find README.md.aqua.json.

EXAMPLES:
    # Verify an Aqua tree (auto-detects .aqua.json extension):
    aqua-cli -a README.md
    aqua-cli -a document.aqua.json -v

    # Generate an Aqua tree from a file:
    aqua-cli -f document.pdf
    aqua-cli -f image.png --verbose

    # Sign and witness:
    aqua-cli -s tree.aqua.json --sign-type cli -k keys.json
    aqua-cli -w tree.aqua.json --witness-tsa

    # Link child trees into a parent:
    aqua-cli --link parent.aqua.json child.aqua.json

    # Tree/DAG branching with --previous-hash:
    aqua-cli -s tree.aqua.json --sign-type cli -k keys.json --previous-hash 0x<hash>

    # Create object with a built-in template:
    aqua-cli --create-object --template-name domain --payload data.json

    # Ephemeral forest with cross-tree resolution:
    aqua-cli --forest dir/*.aqua.json -v

    # Persistent forest daemon:
    aqua-cli --forest dir/*.aqua.json --daemon
    aqua-cli --connect 12345

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
        .about("Aqua CLI — verify, sign, witness, and generate Aqua trees using the Aqua Protocol")
        .arg(
            Arg::new("authenticate")
                .short('a')
                .long("authenticate")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(resolve_aqua_file))
                .help("Authenticate (verify) an Aqua tree file"),
        )
        .arg(
            Arg::new("sign")
                .short('s')
                .long("sign")
                .action(ArgAction::Set)
                .value_parser(clap::builder::ValueParser::new(resolve_aqua_file))
                .help("Sign an Aqua tree file"),
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
                .value_parser(clap::builder::ValueParser::new(resolve_aqua_file))
                .help("Witness an Aqua tree file"),
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
                .value_parser(clap::builder::ValueParser::new(resolve_aqua_file))
                .help("Delete/remove the last revision from an Aqua tree file"),
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
            Arg::new("keys-file")
                .short('k')
                .long("keys-file")
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
            Arg::new("trust")
                .long("trust")
                .action(ArgAction::Set)
                .num_args(2)
                .value_names(["DID", "LEVEL"])
                .help("Populate the trust store with a DID at a given trust level (1=marginal, 2=full, 3=ultimate). Used with --forest"),
        )
        .arg(
            Arg::new("simulate")
                .long("simulate")
                .action(ArgAction::SetTrue)
                .help("Run the identity simulation suite — exercises all 12 PlatformIdentityClaim/Attestation WASM states (requires --features simulation)"),
        )
        .arg(
            Arg::new("simulate-personas")
                .long("simulate-personas")
                .action(ArgAction::SetTrue)
                .help("Run the persona-based identity simulation — 5 personas, 15 claim scenarios covering all derived identity templates (requires --features simulation)"),
        )
        .arg(
            Arg::new("keep")
                .long("keep")
                .action(ArgAction::SetTrue)
                .help("Keep simulation tree files on disk for inspection (use with --simulate or --simulate-personas)"),
        )
        .arg(
            Arg::new("daemon")
                .long("daemon")
                .action(ArgAction::Set)
                .num_args(0..=1)
                .default_missing_value("600")
                .value_parser(clap::value_parser!(u64))
                .requires("forest")
                .help("Keep the forest alive as a persistent daemon with idle timeout in seconds (default: 600)"),
        )
        .arg(
            Arg::new("listen")
                .long("listen")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u16))
                .requires("daemon")
                .help("Start an HTTP API on the given port alongside the daemon (requires --daemon)"),
        )
        .arg(
            Arg::new("connect")
                .long("connect")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .help("Connect to a running forest daemon's REPL by its ID (PID)"),
        )
        .arg(
            Arg::new("target")
                .long("target")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .help("Push operation result into a running daemon's forest by its ID (PID)"),
        )
        .group(
            ArgGroup::new("template")
                .args(["template-hash", "template-name"])
        )
        .group(
            ArgGroup::new("operation")
                .args(["authenticate", "sign", "witness", "file", "delete", "link", "info", "create-object", "list-templates", "forest", "simulate", "simulate-personas", "connect"])
                .required(false),
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
        .get_one::<String>("keys-file")
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
    let simulate_personas = matches.get_flag("simulate-personas");
    let keep = matches.get_flag("keep");
    let daemon = matches.get_one::<u64>("daemon").copied();
    let listen = matches.get_one::<u16>("listen").copied();
    let connect = matches.get_one::<u64>("connect").copied();
    let target = matches.get_one::<u64>("target").copied();
    let trust = matches.get_many::<String>("trust").map(|mut vals| {
        let did = vals.next().unwrap().clone();
        let level_str = vals.next().unwrap();
        let level: u8 = level_str
            .parse()
            .unwrap_or_else(|_| {
                eprintln!("Warning: invalid trust level '{}', using 2 (full)", level_str);
                2
            });
        (did, level)
    });

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
        trust,
        simulate,
        simulate_personas,
        keep,
        daemon,
        connect,
        target,
        listen,
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
            eprintln!(
                "Error: --simulate requires building with `cargo build --features simulation`"
            );
            std::process::exit(1);
        }
    }

    if args.simulate_personas {
        #[cfg(feature = "simulation")]
        {
            simulation::run_personas_simulation(args.verbose, args.keep).await;
            return;
        }
        #[cfg(not(feature = "simulation"))]
        {
            eprintln!(
                "Error: --simulate-personas requires building with `cargo build --features simulation`"
            );
            std::process::exit(1);
        }
    }

    if let Some(id) = args.connect {
        cli_connect_forest(id).await;
        return;
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
        && !args.simulate_personas
    {
        println!("{}", BASE_LONG_ABOUT);
        return;
    }

    let alchemy_key = env::var("alchemy_key").unwrap_or_default();
    let keys_file_env = env::var("keys_file").unwrap_or_default();

    let mut builder = Aquafier::builder();
    if let Some(host) = aqua_rs_sdk::build_default_blockchain_host(&alchemy_key) {
        builder = builder.blockchain_host(host);
    }
    if let Some(host) = aqua_rs_sdk::build_default_web_host() {
        builder = builder.web_host(host);
    }
    let aquafier = builder.build();

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
        cli_create_object(args.clone(), &aquafier, keys_file.clone()).await;
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
            println!("Generating Aqua tree from: {:?}", file_path);
            cli_generate_aqua_chain(args.clone(), &aquafier).await;
        }
        (_, _, _, _, _, _, Some(link_paths), _) => {
            let parent = link_paths[0].clone();
            let children: Vec<PathBuf> = link_paths[1..].to_vec();
            println!(
                "Linking {} child tree(s) into parent {:?}",
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
