// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use aqua_rs_sdk::primitives::log::LogData;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::{
    schema::{AquaTreeWrapper, FileData, SigningCredentials},
    Aquafier,
};
use clap::{Parser, Subcommand};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "aqua-notary",
    about = "Sign and verify files with the Aqua Protocol",
    version
)]
struct Cli {
    /// Path to keys file (overrides AQUA_KEYS env var and ~/.aqua/keys.json default)
    #[arg(short = 'k', long, global = true)]
    key: Option<PathBuf>,

    /// Show detailed output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a file (creates <file>.aqua.json sidecar if it does not exist)
    Sign {
        /// File to sign
        file: PathBuf,
        /// Signing key type: did (Ed25519), cli (mnemonic), p256
        #[arg(long, default_value = "did")]
        sign_type: String,
    },
    /// Verify the integrity and signatures of a signed file
    Verify {
        /// File to verify
        file: PathBuf,
    },
    /// Show the Aqua tree structure for a signed file
    Inspect {
        /// File to inspect
        file: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let aquafier = Aquafier::new();
    let key_path = resolve_key_path(cli.key.as_deref());

    match cli.command {
        Commands::Sign { file, sign_type } => {
            cmd_sign(&aquafier, &file, &sign_type, key_path.as_deref(), cli.verbose).await;
        }
        Commands::Verify { file } => {
            cmd_verify(&aquafier, &file, cli.verbose).await;
        }
        Commands::Inspect { file } => {
            cmd_inspect(&file);
        }
    }
}

// ── Key resolution ────────────────────────────────────────────────────────────

fn resolve_key_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    if let Ok(env_path) = std::env::var("AQUA_KEYS") {
        return Some(PathBuf::from(env_path));
    }
    if let Ok(home) = std::env::var("HOME") {
        let default = PathBuf::from(home).join(".aqua").join("keys.json");
        if default.exists() {
            return Some(default);
        }
    }
    None
}

fn load_credentials(sign_type: &str, key_path: Option<&Path>) -> Result<SigningCredentials, String> {
    let path = key_path.ok_or(
        "No keys file found. Use --key <path>, set AQUA_KEYS, or create ~/.aqua/keys.json",
    )?;
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read keys file {}: {}", path.display(), e))?;
    let val: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid keys file JSON: {}", e))?;

    match sign_type {
        "did" => {
            let key_str = val
                .get("did:key")
                .or_else(|| val.get("signing").and_then(|s| s.get("did_key")))
                .and_then(|v| v.as_str())
                .ok_or("No 'did:key' field found in keys file")?;
            Ok(SigningCredentials::Did { did_key: decode_hex(key_str)? })
        }
        "cli" => {
            let mnemonic = val
                .get("mnemonic")
                .or_else(|| val.get("signing").and_then(|s| s.get("mnemonic")))
                .and_then(|v| v.as_str())
                .ok_or("No 'mnemonic' field found in keys file")?
                .to_string();
            Ok(SigningCredentials::Cli { mnemonic })
        }
        "p256" => {
            let key_str = val
                .get("p256_key")
                .or_else(|| val.get("signing").and_then(|s| s.get("p256_key")))
                .and_then(|v| v.as_str())
                .ok_or("No 'p256_key' field found in keys file")?;
            Ok(SigningCredentials::P256 { p256_key: decode_hex(key_str)? })
        }
        other => Err(format!("Unknown sign type '{}'. Valid options: did, cli, p256", other)),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("Invalid hex key: {}", e))
}

// ── Tree I/O ──────────────────────────────────────────────────────────────────

/// Compute the sidecar path: CLAUDE.md → CLAUDE.aqua.json
fn aqua_path(file: &Path) -> PathBuf {
    file.with_extension("aqua.json")
}

fn read_tree(path: &Path) -> Result<Tree, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("Cannot parse Aqua tree at {}: {}", path.display(), e))
}

fn write_tree(tree: &Tree, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(tree)
        .map_err(|e| format!("Cannot serialize tree: {}", e))?;
    fs::write(path, json).map_err(|e| format!("Cannot write {}: {}", path.display(), e))
}

fn print_logs(logs: &[LogData]) {
    for log in logs {
        println!("   {}", log.display());
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

async fn cmd_sign(
    aquafier: &Aquafier,
    file: &Path,
    sign_type: &str,
    key_path: Option<&Path>,
    verbose: bool,
) {
    let aqua_file = aqua_path(file);

    let credentials = match load_credentials(sign_type, key_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ {}", e);
            return;
        }
    };

    // Load existing tree or create genesis from the file
    let tree = if aqua_file.exists() {
        match read_tree(&aqua_file) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("❌ {}", e);
                return;
            }
        }
    } else {
        let content = match fs::read(file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("❌ Cannot read {}: {}", file.display(), e);
                return;
            }
        };
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("CLAUDE.md")
            .to_string();
        let file_data = FileData::new(name, content, file.to_path_buf());
        match aquafier.create_genesis_revision(file_data, None) {
            Ok(t) => {
                println!("  Created genesis revision for {}", file.display());
                t
            }
            Err(e) => {
                eprintln!("❌ Genesis creation failed: {}", e);
                return;
            }
        }
    };

    let wrapper = AquaTreeWrapper::new(tree, None, None);

    match aquafier.sign_aqua_tree(wrapper, &credentials, None, None).await {
        Ok(op_data) => {
            if verbose {
                print_logs(&op_data.log_data);
            }
            match write_tree(&op_data.aqua_tree, &aqua_file) {
                Ok(_) => println!("✅ Signed  →  {}", aqua_file.display()),
                Err(e) => eprintln!("❌ {}", e),
            }
        }
        Err(e) => eprintln!("❌ Signing failed: {}", e),
    }
}

async fn cmd_verify(aquafier: &Aquafier, file: &Path, verbose: bool) {
    let aqua_file = aqua_path(file);

    if !aqua_file.exists() {
        eprintln!("❌ No aqua file found: {}", aqua_file.display());
        eprintln!("   Run:  aqua-notary sign {}", file.display());
        return;
    }

    let tree = match read_tree(&aqua_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("❌ {}", e);
            return;
        }
    };

    // Build file objects so the SDK can verify content hashes
    let mut file_objects = vec![];
    if let Some(main_name) = tree.get_main_file_name() {
        let content_path = file
            .parent()
            .unwrap_or(Path::new("."))
            .join(&main_name);
        if let Ok(content) = fs::read(&content_path) {
            file_objects.push(FileData::new(main_name, content, content_path));
        }
    }

    let wrapper = AquaTreeWrapper::new(tree, None, None);

    match aquafier.verify_aqua_tree(wrapper, file_objects).await {
        Ok(result) => {
            if result.is_valid {
                println!("✅ {} — Valid", file.display());
            } else {
                println!("❌ {} — Invalid", file.display());
                println!("   {}", result.status);
            }
            if verbose || !result.is_valid {
                print_logs(&result.logs);
            }
        }
        Err(e) => eprintln!("❌ Verification error: {}", e),
    }
}

fn cmd_inspect(file: &Path) {
    let aqua_file = aqua_path(file);

    if !aqua_file.exists() {
        eprintln!("❌ No aqua file found: {}", aqua_file.display());
        eprintln!("   Run:  aqua-notary sign {}", file.display());
        return;
    }

    let tree = match read_tree(&aqua_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("❌ {}", e);
            return;
        }
    };

    println!("File:       {}", file.display());
    println!("Aqua tree:  {}", aqua_file.display());
    println!("Revisions:  {}", tree.revisions.len());
    println!();

    for (i, (hash, revision)) in tree.revisions.iter().enumerate() {
        let rev_val = serde_json::to_value(revision).unwrap_or_default();

        let rev_type = rev_val
            .get("revision_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let timestamp = rev_val
            .get("local_timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Signer DID may appear at the top level (signature revisions) or nested
        let signer = rev_val
            .get("signer_did")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let hash_str = format!("{}", hash);
        let short = &hash_str[..20.min(hash_str.len())];

        print!("  [{}] {:12}  {}...", i + 1, rev_type, short);
        if !timestamp.is_empty() {
            print!("  {}", timestamp);
        }
        println!();
        if !signer.is_empty() {
            println!("       signer: {}", signer);
        }
    }
}
