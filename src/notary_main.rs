// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use aqua_rs_sdk::core::signature::sign_did::DIDSigner;
use aqua_rs_sdk::primitives::log::LogData;
use aqua_rs_sdk::schema::templates::PlatformIdentityClaim;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::{
    schema::{AquaTreeWrapper, FileData, SigningCredentials},
    Aquafier, IdentityCredentials,
};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
};

/// Default GitHub OAuth App client ID for aqua-notary.
/// End users do not need to create their own app — this is shared.
/// Override with --client-id or AQUA_GITHUB_CLIENT_ID for development.
const DEFAULT_GITHUB_CLIENT_ID: &str = "Ov23liDeEGGiAdl6hRzp";

// ── CLI definition ─────────────────────────────────────────────────────────────

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
    /// Generate a new Ed25519 key pair and save to ~/.aqua/keys.json
    Keygen {
        /// Output path (default: ~/.aqua/keys.json)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite existing keys file
        #[arg(long)]
        force: bool,
    },
    /// Sign a file (creates <file>.aqua.json sidecar if it does not exist)
    Sign {
        file: PathBuf,
        /// Signing key type: did (Ed25519), cli (mnemonic), p256
        #[arg(long, default_value = "did")]
        sign_type: String,
    },
    /// Verify the integrity and signatures of a signed file
    Verify { file: PathBuf },
    /// Show the Aqua tree structure for a signed file
    Inspect { file: PathBuf },
    /// Link a GitHub identity to your DID and create a signed identity claim.
    ///
    /// Uses GitHub Device Flow (RFC 8628) — no browser redirect needed.
    /// Creates a public gist on your GitHub account as a verifiable proof,
    /// then saves a signed identity claim to ~/.aqua/identity_github.aqua.json.
    Identity {
        /// Identity provider: github
        #[arg(default_value = "github")]
        provider: String,
        /// Override the OAuth App client ID (developer use only).
        /// Defaults to the built-in aqua-notary app — most users can omit this.
        #[arg(long, env = "AQUA_GITHUB_CLIENT_ID")]
        client_id: Option<String>,
    },
    /// Publish a signed CLAUDE.md to the aqua-notary registry.
    ///
    /// If the file is not yet signed, you will be asked to sign it first.
    /// If --gist is omitted, a public gist is created automatically using
    /// the GitHub token saved by `aqua-notary identity github`.
    Publish {
        /// CLAUDE.md (or other file) to publish
        file: PathBuf,
        /// GitHub gist URL — created automatically if omitted
        #[arg(long)]
        gist: Option<String>,
        /// Registry server URL
        #[arg(
            long,
            env = "AQUA_NOTARY_SERVER",
            default_value = "http://localhost:1984"
        )]
        server: String,
        /// Path to identity claim (default: ~/.aqua/identity_github.aqua.json)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Content type: claude_md or skill
        #[arg(long, default_value = "claude_md")]
        content_type: String,
    },
}

// ── Entry point ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let aquafier = Aquafier::new();
    let key_path = resolve_key_path(cli.key.as_deref());

    match cli.command {
        Commands::Keygen { output, force } => {
            cmd_keygen(output.as_deref(), force);
        }
        Commands::Sign { file, sign_type } => {
            cmd_sign(
                &aquafier,
                &file,
                &sign_type,
                key_path.as_deref(),
                cli.verbose,
            )
            .await;
        }
        Commands::Verify { file } => {
            cmd_verify(&aquafier, &file, cli.verbose).await;
        }
        Commands::Inspect { file } => {
            cmd_inspect(&file);
        }
        Commands::Identity {
            provider,
            client_id,
        } => {
            cmd_identity(
                &aquafier,
                &provider,
                client_id.as_deref(),
                key_path.as_deref(),
            )
            .await;
        }
        Commands::Publish {
            file,
            gist,
            server,
            identity,
            content_type,
        } => {
            cmd_publish(
                &aquafier,
                &file,
                gist.as_deref(),
                &server,
                identity.as_deref(),
                &content_type,
                key_path.as_deref(),
                cli.verbose,
            )
            .await;
        }
    }
}

// ── Interactive helpers ────────────────────────────────────────────────────────

/// Ask a yes/no question.  Defaults to Yes on empty input.
fn confirm(prompt: &str) -> bool {
    print!("{} [Y/n] ", prompt);
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    let t = input.trim().to_lowercase();
    t.is_empty() || t == "y" || t == "yes"
}

/// Print a fenced preview of `text`, truncating long files.
fn print_preview(text: &str, max_lines: usize) {
    println!("  ┌─────────────────────────────────────────────────");
    let lines: Vec<&str> = text.lines().collect();
    for line in lines.iter().take(max_lines) {
        println!("  │ {}", line);
    }
    if lines.len() > max_lines {
        println!("  │ … ({} more lines)", lines.len() - max_lines);
    }
    println!("  └─────────────────────────────────────────────────");
}

// ── Key / credential helpers ───────────────────────────────────────────────────

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

fn load_credentials(
    sign_type: &str,
    key_path: Option<&Path>,
) -> Result<SigningCredentials, String> {
    let path = key_path.ok_or("No keys file found. Run:  aqua-notary keygen")?;
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
            Ok(SigningCredentials::Did {
                did_key: decode_hex(key_str)?,
            })
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
            Ok(SigningCredentials::P256 {
                p256_key: decode_hex(key_str)?,
            })
        }
        other => Err(format!(
            "Unknown sign type '{}'. Valid options: did, cli, p256",
            other
        )),
    }
}

fn load_did_key_bytes(key_path: Option<&Path>) -> Result<Vec<u8>, String> {
    let path = key_path.ok_or("No keys file found. Run:  aqua-notary keygen")?;
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read keys file {}: {}", path.display(), e))?;
    let val: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid keys file JSON: {}", e))?;
    let key_str = val
        .get("did:key")
        .or_else(|| val.get("signing").and_then(|s| s.get("did_key")))
        .and_then(|v| v.as_str())
        .ok_or("No 'did:key' field found in keys file")?;
    decode_hex(key_str)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("Invalid hex key: {}", e))
}

// ── GitHub token helpers ───────────────────────────────────────────────────────

fn github_token_path() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".aqua").join("github_token"))
        .unwrap_or_else(|_| PathBuf::from("github_token"))
}

/// Load GitHub token: GITHUB_TOKEN env → ~/.aqua/github_token → None.
fn load_github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN").ok().or_else(|| {
        fs::read_to_string(github_token_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })
}

/// Save token to ~/.aqua/github_token with owner-only permissions (600).
fn save_github_token(token: &str) -> Result<PathBuf, String> {
    let path = github_token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Cannot create ~/.aqua: {}", e))?;
    }
    fs::write(&path, token).map_err(|e| format!("Cannot write token file: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Cannot set file permissions: {}", e))?;
    }
    Ok(path)
}

/// Create a public GitHub gist with one or more files.  Returns the HTML URL.
///
/// `files` is a slice of `(filename, content)` pairs.
async fn create_github_gist(
    token: &str,
    files: &[(&str, &str)],
    description: &str,
) -> Result<String, String> {
    let mut files_json = serde_json::Map::new();
    for (name, content) in files {
        files_json.insert(name.to_string(), serde_json::json!({ "content": content }));
    }

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.github.com/gists")
        .bearer_auth(token)
        .header("User-Agent", "aqua-notary/0.1")
        .header("Accept", "application/vnd.github+json")
        .json(&serde_json::json!({
            "description": description,
            "public": true,
            "files": files_json,
        }))
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("GitHub API returned {}: {}", status, body));
    }

    let result: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;
    result["html_url"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "GitHub response missing html_url".into())
}

// ── Tree I/O ───────────────────────────────────────────────────────────────────

fn aqua_path(file: &Path) -> PathBuf {
    let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    file.with_file_name(format!("{}.aqua.json", name))
}

fn read_tree(path: &Path) -> Result<Tree, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("Cannot parse Aqua tree at {}: {}", path.display(), e))
}

fn write_tree(tree: &Tree, path: &Path) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(tree).map_err(|e| format!("Cannot serialize tree: {}", e))?;
    fs::write(path, json).map_err(|e| format!("Cannot write {}: {}", path.display(), e))
}

fn tree_tip_hash(tree: &Tree) -> Option<String> {
    tree.revisions.keys().last().map(|k| format!("{}", k))
}

fn print_logs(logs: &[LogData]) {
    for log in logs {
        println!("   {}", log.display());
    }
}

fn identity_claim_path(provider: &str) -> PathBuf {
    std::env::var("HOME")
        .map(|h| {
            PathBuf::from(h)
                .join(".aqua")
                .join(format!("identity_{}.aqua.json", provider))
        })
        .unwrap_or_else(|_| PathBuf::from(format!("identity_{}.aqua.json", provider)))
}

// ── Commands ───────────────────────────────────────────────────────────────────

fn cmd_keygen(output: Option<&Path>, force: bool) {
    let out_path = output
        .map(|p| p.to_path_buf())
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".aqua").join("keys.json"))
        })
        .unwrap_or_else(|| PathBuf::from("keys.json"));

    if out_path.exists() && !force {
        eprintln!("❌ Keys file already exists: {}", out_path.display());
        eprintln!("   Use --force to overwrite, or --output to choose a different path.");
        return;
    }

    let mut key_bytes = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut key_bytes) {
        eprintln!("❌ Failed to generate random bytes: {}", e);
        return;
    }

    let did_string = match DIDSigner::new().derive_did_pkh(&key_bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("❌ Failed to derive DID: {}", e);
            return;
        }
    };

    let keys = serde_json::json!({
        "did:key": format!("0x{}", hex::encode(key_bytes)),
        "did":     did_string,
    });

    if let Some(parent) = out_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("❌ Cannot create directory {}: {}", parent.display(), e);
            return;
        }
    }

    #[cfg(unix)]
    {
        // Write with restricted permissions on Unix
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&out_path)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(serde_json::to_string_pretty(&keys).unwrap().as_bytes())
                {
                    eprintln!("❌ Cannot write {}: {}", out_path.display(), e);
                    return;
                }
            }
            Err(e) => {
                eprintln!("❌ Cannot create {}: {}", out_path.display(), e);
                return;
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = fs::write(&out_path, serde_json::to_string_pretty(&keys).unwrap()) {
            eprintln!("❌ Cannot write {}: {}", out_path.display(), e);
            return;
        }
    }

    println!("✅ Keys generated: {}", out_path.display());
    println!("   DID: {}", did_string);
    println!();
    println!("   Keep this file secret — it contains your private key.");
    println!("   Next step:  aqua-notary identity github");
}

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
        match aquafier
            .create_genesis_revision(FileData::new(name, content, file.to_path_buf()), None)
        {
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

    match aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(tree, None, None),
            &credentials,
            None,
            None,
        )
        .await
    {
        Ok(op) => {
            if verbose {
                print_logs(&op.log_data);
            }
            match write_tree(&op.aqua_tree, &aqua_file) {
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

    let mut file_objects = vec![];
    if let Some(main_name) = tree.get_main_file_name() {
        let content_path = file.parent().unwrap_or(Path::new(".")).join(&main_name);
        if let Ok(content) = fs::read(&content_path) {
            file_objects.push(FileData::new(main_name, content, content_path));
        }
    }

    match aquafier
        .verify_aqua_tree(AquaTreeWrapper::new(tree, None, None), file_objects)
        .await
    {
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

/// Link a GitHub identity to your DID.
///
/// Flow:
///   1. Derive DID from local key
///   2. GitHub Device Flow (user approves in browser)
///   3. Preview proof gist → user confirms → gist created on GitHub
///   4. Save GitHub token to ~/.aqua/github_token for use by `publish`
///   5. Build + sign PlatformIdentityClaim → saved to ~/.aqua/identity_github.aqua.json
async fn cmd_identity(
    aquafier: &Aquafier,
    provider: &str,
    client_id: Option<&str>,
    key_path: Option<&Path>,
) {
    // ── Step 1: derive DID ─────────────────────────────────────────────────────
    let key_bytes = match load_did_key_bytes(key_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("❌ {}", e);
            return;
        }
    };

    let did_string = match DIDSigner::new().derive_did_pkh(&key_bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("❌ Failed to derive DID: {}", e);
            return;
        }
    };

    println!("  DID:  {}", did_string);

    // ── Step 2: build provider ─────────────────────────────────────────────────
    let credentials = match provider {
        "github" => {
            let cid = client_id
                .map(|s| s.to_string())
                .unwrap_or_else(|| DEFAULT_GITHUB_CLIENT_ID.to_string());
            IdentityCredentials::GitHub { client_id: cid }
        }
        other => {
            eprintln!(
                "❌ Unknown provider '{}'. Currently supported: github",
                other
            );
            return;
        }
    };

    let id_provider = match credentials.into_provider() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ Failed to create identity provider: {}", e);
            return;
        }
    };

    // ── Step 3: Device Flow ────────────────────────────────────────────────────
    let session = match id_provider.initiate().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to initiate auth flow: {}", e);
            return;
        }
    };

    println!();
    println!("  Open this URL in your browser:");
    println!("    {}", session.verification_url);
    if let Some(code) = &session.user_code {
        println!();
        println!("  Enter this code when prompted:");
        println!("    {}", code);
    }
    println!();
    print!("  Press Enter once you have approved the request… ");
    let _ = io::stdout().flush();
    let mut _buf = String::new();
    let _ = io::stdin().read_line(&mut _buf);

    // ── Step 4: authenticate ───────────────────────────────────────────────────
    println!("  Authenticating…");
    let identity = match id_provider.authenticate(&session).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("❌ Authentication failed: {}", e);
            return;
        }
    };

    println!(
        "  ✅ Authenticated as {} ({})",
        identity.display_name, identity.provider_id
    );

    let github_username = identity
        .metadata
        .get("github_username")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // ── Step 5: build and sign PlatformIdentityClaim ───────────────────────────
    // Sign BEFORE creating the gist so the gist contains the signed Aqua tree.
    // This makes the proof two-factor: GitHub account control (to create the gist)
    // + DID private key (to produce the Aqua signature inside the gist).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let one_year_secs = 365 * 24 * 60 * 60_u64;

    let claim = PlatformIdentityClaim {
        signer_did: did_string.clone(),
        provider: identity.provider.clone(),
        provider_id: identity.provider_id.clone(),
        display_name: identity.display_name.clone(),
        email: identity.email.clone(),
        proof_url: None, // set after gist creation to avoid circular reference
        valid_from: Some(now),
        valid_until: Some(now + one_year_secs),
        metadata: Some(serde_json::json!({ "github_username": github_username })),
    };

    let claim_tree = match aquafier.create_identity_claim(None, claim, None) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("❌ Failed to create identity claim tree: {}", e);
            return;
        }
    };

    let signing_creds = match load_credentials("did", key_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ {}", e);
            return;
        }
    };

    let signed = match aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(claim_tree, None, None),
            &signing_creds,
            None,
            None,
        )
        .await
    {
        Ok(op) => op.aqua_tree,
        Err(e) => {
            eprintln!("❌ Signing failed: {}", e);
            return;
        }
    };

    let claim_hash = tree_tip_hash(&signed).unwrap_or_default();

    // ── Step 6: preview and confirm gist creation ──────────────────────────────
    println!();
    println!(
        "  A PUBLIC gist will be created on your GitHub account (@{}).",
        github_username
    );
    println!("  File: identity_claim.aqua.json");
    println!("  It contains your signed Aqua identity claim — verifiable by anyone.");
    println!("  Proof: GitHub account control + DID private key signature.");
    println!();
    println!("  Claim:");
    println!("    DID:      {}", did_string);
    println!("    Provider: github (@{})", github_username);
    println!("    Hash:     {}", claim_hash);
    println!();

    if !confirm("  Create proof gist on GitHub?") {
        println!("  Aborted.");
        return;
    }

    // ── Step 7: create gist with signed claim tree ─────────────────────────────
    let proof = match id_provider
        .create_proof(&session, &identity, &did_string)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ Proof creation failed: {}", e);
            return;
        }
    };

    println!("  ✅ Proof gist created: {}", proof.proof_url);

    // ── Step 8: save GitHub token for use by `publish` ─────────────────────────
    if let Some(token) = identity
        .metadata
        .get("access_token")
        .and_then(|v| v.as_str())
    {
        match save_github_token(token) {
            Ok(path) => println!(
                "  ✅ GitHub token saved to {} (used by `publish`)",
                path.display()
            ),
            Err(e) => eprintln!("  ⚠  Could not save GitHub token: {}", e),
        }
    }

    // ── Step 9: save ───────────────────────────────────────────────────────────
    let out_path = identity_claim_path(provider);
    if let Some(parent) = out_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("❌ Cannot create directory: {}", e);
            return;
        }
    }

    match write_tree(&signed, &out_path) {
        Ok(_) => {
            println!();
            println!("✅ Identity claim saved to {}", out_path.display());
            println!(
                "   Provider:   {} (@{})",
                identity.provider, github_username
            );
            println!("   DID:        {}", did_string);
            println!("   Proof gist: {}", proof.proof_url);
            println!("   Claim hash: {}", claim_hash);
            println!();
            println!("  Next step:  aqua-notary publish CLAUDE.md");
        }
        Err(e) => eprintln!("❌ {}", e),
    }
}

/// Publish a CLAUDE.md to the aqua-notary registry.
///
/// Automated steps (each with confirmation if it would write to GitHub):
///   1. Sign the file if not already signed
///   2. Create a public GitHub gist if --gist is not provided
///   3. Submit the signed publish command to the server
async fn cmd_publish(
    aquafier: &Aquafier,
    file: &Path,
    gist_url: Option<&str>,
    server_url: &str,
    identity_path: Option<&Path>,
    content_type: &str,
    key_path: Option<&Path>,
    verbose: bool,
) {
    // ── Step 1: auto-sign if sidecar is missing ────────────────────────────────
    let aqua_file = aqua_path(file);

    if !aqua_file.exists() {
        println!("  No signed sidecar found ({}).", aqua_file.display());
        println!(
            "  This will create a cryptographic record that {} was signed by your DID.",
            file.display()
        );
        println!();
        if !confirm("  Sign the file now?") {
            println!("  Aborted. Run:  aqua-notary sign {}", file.display());
            return;
        }
        cmd_sign(aquafier, file, "did", key_path, verbose).await;
        // Verify sign succeeded
        if !aqua_file.exists() {
            return;
        }
    }

    // ── Step 2: read file content and compute content hash ────────────────────
    let content_bytes = match fs::read(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Cannot read {}: {}", file.display(), e);
            return;
        }
    };
    let content_hash = format!("{:x}", Sha256::digest(&content_bytes));
    let content_str = String::from_utf8_lossy(&content_bytes);

    // Get the Aqua tree tip hash
    let aqua_tree_hash = match read_tree(&aqua_file) {
        Ok(t) => tree_tip_hash(&t),
        Err(e) => {
            eprintln!("❌ {}", e);
            return;
        }
    };

    // ── Step 3: load identity claim ────────────────────────────────────────────
    let id_path = identity_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| identity_claim_path("github"));

    if !id_path.exists() {
        eprintln!("❌ No identity claim found at {}", id_path.display());
        eprintln!("   Run:  aqua-notary identity github");
        return;
    }

    let (identity_claim_hash, identity_claim_tree_val) = match read_tree(&id_path) {
        Ok(t) => (tree_tip_hash(&t), serde_json::to_value(&t).ok()),
        Err(e) => {
            eprintln!("❌ Cannot read identity claim: {}", e);
            return;
        }
    };

    // ── Step 4: resolve gist URL (auto-create if not provided) ────────────────
    let resolved_gist_url = match gist_url {
        Some(url) => url.to_string(),
        None => {
            // Need a GitHub token to create the gist
            let token = match load_github_token() {
                Some(t) => t,
                None => {
                    eprintln!("❌ No GitHub token found and --gist not provided.");
                    eprintln!("   Run:  aqua-notary identity github");
                    eprintln!("   — or set GITHUB_TOKEN env var —");
                    eprintln!("   — or pass --gist <url> with an existing gist —");
                    return;
                }
            };

            let filename = file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("CLAUDE.md");

            println!();
            println!("  No --gist provided. A public gist will be created on GitHub.");
            println!("  File: {}", filename);
            println!();
            print_preview(&content_str, 10);
            println!("  ({} bytes total)", content_bytes.len());
            println!();

            if !confirm("  Create public gist on GitHub?") {
                println!("  Aborted.");
                return;
            }

            // Read the sidecar so the gist is self-contained: file + signature.
            let sidecar_name = format!("{}.aqua.json", filename);
            let sidecar_str = fs::read_to_string(&aqua_file).unwrap_or_else(|_| "{}".to_string());

            let description = format!("{} — published via aqua-notary", filename);
            let gist_files: Vec<(&str, &str)> =
                vec![(filename, &content_str), (&sidecar_name, &sidecar_str)];

            match create_github_gist(&token, &gist_files, &description).await {
                Ok(url) => {
                    println!("  ✅ Gist created: {}", url);
                    url
                }
                Err(e) => {
                    eprintln!("❌ Failed to create gist: {}", e);
                    return;
                }
            }
        }
    };

    // ── Step 5: build and sign command Aqua tree ───────────────────────────────
    let payload = serde_json::json!({
        "command":        "publish",
        "gist_url":       resolved_gist_url,
        "content_hash":   content_hash,
        "content_type":   content_type,
        "aqua_tree_hash": aqua_tree_hash,
    });

    let payload_bytes = serde_json::to_vec_pretty(&payload).unwrap();
    let file_data = FileData::new(
        "command.json".to_string(),
        payload_bytes,
        PathBuf::from("command.json"),
    );

    let cmd_tree = match aquafier.create_genesis_revision(file_data, None) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("❌ Failed to create command tree: {}", e);
            return;
        }
    };

    let signing_creds = match load_credentials("did", key_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ {}", e);
            return;
        }
    };

    let signed_cmd = match aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(cmd_tree, None, None),
            &signing_creds,
            None,
            None,
        )
        .await
    {
        Ok(op) => op.aqua_tree,
        Err(e) => {
            eprintln!("❌ Signing failed: {}", e);
            return;
        }
    };

    // ── Step 6: POST to server ─────────────────────────────────────────────────
    let body = serde_json::json!({
        "aqua_tree":           serde_json::to_value(&signed_cmd).unwrap(),
        "payload":             payload,
        "identity_claim_hash": identity_claim_hash,
        "identity_claim_tree": identity_claim_tree_val,
    });

    let url = format!("{}/v1/commands", server_url.trim_end_matches('/'));
    println!("  Submitting to {}…", url);

    let client = reqwest::Client::new();
    let resp = match client.post(&url).json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("❌ Request failed: {}", e);
            return;
        }
    };

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    if status.is_success() {
        println!();
        println!("✅ Published!");
        if let Some(hash) = body.get("content_hash").and_then(|v| v.as_str()) {
            println!("   Content hash: {}", hash);
        }
        println!("   Gist:         {}", resolved_gist_url);
        println!();
        println!("   ⚠  Do not edit the gist content after publishing.");
        println!("      The registry checks gist hashes hourly. If the content changes,");
        println!("      the entry will be automatically deactivated.");
        println!("      To publish an update, create a new gist and run publish again.");

        if let Some(warnings) = body.get("warnings").and_then(|v| v.as_array()) {
            println!();
            for w in warnings {
                if let Some(text) = w.as_str() {
                    println!("⚠  {}", text);
                }
            }
            println!();
            println!("   To remove an old entry: delete its gist on GitHub.");
            println!("   The registry will detect the deletion and deactivate it automatically.");
        }
    } else {
        let msg = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("❌ Server returned {}: {}", status, msg);
    }
}
