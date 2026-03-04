use std::io::{self, Write};
use std::path::PathBuf;

use aqua_rs_sdk::core::signature::sign_did::DIDSigner;
use aqua_rs_sdk::core::signature::sign_p256::P256Signer;
use aqua_rs_sdk::primitives::{get_wallet, RevisionLink};
use aqua_rs_sdk::schema::{AquaTreeWrapper, SigningCredentials};
use aqua_rs_sdk::Aquafier;

use crate::aqua::target::push_tree_to_daemon;
use crate::aqua::twilio::{
    check_verification_code, send_verification_code, TwilioConfig, VerificationChannel,
};
use crate::models::CliArgs;
use crate::utils::{
    colored_error, colored_success, format_method_error, oprataion_logs_and_dumps,
    read_credentials, save_page_data,
};

extern crate serde_json_path_to_error as serde_json;

/// The kind of identity template that supports Twilio verification.
pub enum IdentityTemplateKind {
    /// EmailClaim — extract `"email"` from payload, verify via email channel.
    Email,
    /// PhoneClaim — extract `"phone_number"` from payload, verify via SMS channel.
    Phone,
}

impl IdentityTemplateKind {
    /// The JSON key to extract the contact value from the payload.
    fn payload_key(&self) -> &'static str {
        match self {
            IdentityTemplateKind::Email => "email",
            IdentityTemplateKind::Phone => "phone_number",
        }
    }

    /// The Twilio verification channel.
    fn channel(&self) -> VerificationChannel {
        match self {
            IdentityTemplateKind::Email => VerificationChannel::Email,
            IdentityTemplateKind::Phone => VerificationChannel::Sms,
        }
    }

    /// Human-readable label for log messages.
    fn label(&self) -> &'static str {
        match self {
            IdentityTemplateKind::Email => "email",
            IdentityTemplateKind::Phone => "phone",
        }
    }
}

const MAX_ATTEMPTS: u32 = 3;

/// Resolve the keys file: use the provided path, or fall back to `keys.json`
/// in the current directory.
fn resolve_keys_file(keys_file: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(kf) = keys_file {
        return Some(kf);
    }
    let default = PathBuf::from("keys.json");
    if default.exists() {
        println!("Using keys.json from current directory");
        Some(default)
    } else {
        None
    }
}

/// Derive the `signer_did` string from signing credentials.
async fn derive_signer_did(creds: &SigningCredentials) -> Result<String, String> {
    match creds {
        SigningCredentials::Cli { mnemonic } => {
            let (address, _addr_str, _pk) = get_wallet(mnemonic)
                .await
                .map_err(|e| format!("Failed to derive wallet from mnemonic: {}", e))?;
            Ok(format!(
                "did:pkh:eip155:1:{}",
                address.to_checksum(None)
            ))
        }
        SigningCredentials::Did { did_key } => {
            let signer = DIDSigner::new();
            signer
                .derive_did_pkh(did_key)
                .map_err(|e| format!("Failed to derive Ed25519 DID: {}", e))
        }
        SigningCredentials::P256 { p256_key } => {
            let signer = P256Signer::new();
            signer
                .derive_did_pkh(p256_key)
                .map_err(|e| format!("Failed to derive P-256 DID: {}", e))
        }
        SigningCredentials::Secp256k1 { secp256k1_key } => {
            let signer = aqua_rs_sdk::Secp256k1Signer::new(secp256k1_key.clone());
            let (did, _addr) = signer
                .derive_did_pkh()
                .map_err(|e| format!("Failed to derive secp256k1 DID: {}", e))?;
            Ok(did)
        }
        SigningCredentials::Metamask { .. } => {
            Err("Cannot derive signer_did from Metamask credentials (interactive)".to_string())
        }
    }
}

/// Run the Twilio verification flow, then create and optionally sign the identity claim.
pub async fn verify_and_create_identity_claim(
    args: &CliArgs,
    aquafier: &Aquafier,
    template_hash: RevisionLink,
    mut payload: serde_json::Value,
    kind: IdentityTemplateKind,
    keys_file: Option<PathBuf>,
) -> Result<(), Vec<String>> {
    // 0. Resolve keys file (explicit arg → ./keys.json fallback)
    let keys_file = resolve_keys_file(keys_file);

    // 1. If signer_did is missing from payload, derive it from keys
    if payload.get("signer_did").and_then(|v| v.as_str()).map_or(true, |s| s.is_empty()) {
        let kf = keys_file.as_ref().ok_or_else(|| {
            vec![colored_error(
                "No keys file found. Provide --keys-file or place keys.json in the current directory \
                 (needed to derive signer_did).",
            )]
        })?;
        let creds = read_credentials(kf).map_err(|e| vec![colored_error(&e)])?;
        let did = derive_signer_did(&creds.signing)
            .await
            .map_err(|e| vec![colored_error(&e)])?;
        payload
            .as_object_mut()
            .ok_or_else(|| vec![colored_error("Payload must be a JSON object")])?
            .insert("signer_did".to_string(), serde_json::Value::String(did.clone()));
        println!("Derived signer_did: {}", did);
    }

    // 2. Load Twilio config
    let config = TwilioConfig::from_env().map_err(|e| {
        vec![colored_error(&format!(
            "Twilio credentials required for {} claim verification: {}",
            kind.label(),
            e
        ))]
    })?;

    // 3. Extract contact from payload
    let contact = payload
        .get(kind.payload_key())
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            vec![colored_error(&format!(
                "Payload missing required field \"{}\"",
                kind.payload_key()
            ))]
        })?
        .to_string();

    // 4. Send verification code
    println!(
        "Sending verification code to {} ({})...",
        contact,
        kind.label()
    );
    send_verification_code(&config, &contact, &kind.channel())
        .await
        .map_err(|e| vec![colored_error(&format!("Failed to send verification code: {}", e))])?;
    println!("{}", colored_success("Verification code sent."));

    // 5. Interactive verification loop
    println!();
    println!("Enter the verification code (or 'resend' to resend, 'quit' to abort):");

    let stdin = io::stdin();
    let mut approved = false;
    let mut attempts = 0u32;

    while attempts < MAX_ATTEMPTS {
        print!("code> ");
        io::stdout().flush().ok();

        let mut input = String::new();
        match stdin.read_line(&mut input) {
            Ok(0) => {
                // EOF
                println!();
                return Err(vec![colored_error("Aborted (EOF).")]);
            }
            Ok(_) => {}
            Err(e) => {
                return Err(vec![colored_error(&format!("Error reading input: {}", e))]);
            }
        }

        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == "quit" || trimmed == "exit" {
            return Err(vec![colored_error("Verification aborted by user.")]);
        }

        if trimmed == "resend" {
            println!("Resending verification code...");
            send_verification_code(&config, &contact, &kind.channel())
                .await
                .map_err(|e| {
                    vec![colored_error(&format!(
                        "Failed to resend verification code: {}",
                        e
                    ))]
                })?;
            println!("{}", colored_success("Verification code resent."));
            // Don't count resend as an attempt
            continue;
        }

        attempts += 1;

        match check_verification_code(&config, &contact, trimmed).await {
            Ok(true) => {
                approved = true;
                println!("{}", colored_success("Code verified successfully."));
                break;
            }
            Ok(false) => {
                let remaining = MAX_ATTEMPTS - attempts;
                if remaining > 0 {
                    eprintln!(
                        "{}",
                        colored_error(&format!(
                            "Invalid code. {} attempt{} remaining.",
                            remaining,
                            if remaining == 1 { "" } else { "s" }
                        ))
                    );
                }
            }
            Err(e) => {
                let remaining = MAX_ATTEMPTS - attempts;
                eprintln!(
                    "{}",
                    colored_error(&format!("Verification check failed: {}", e))
                );
                if remaining == 0 {
                    break;
                }
                eprintln!(
                    "{}",
                    colored_error(&format!(
                        "{} attempt{} remaining.",
                        remaining,
                        if remaining == 1 { "" } else { "s" }
                    ))
                );
            }
        }
    }

    if !approved {
        return Err(vec![colored_error(&format!(
            "Verification failed after {} attempts. Aborting.",
            MAX_ATTEMPTS
        ))]);
    }

    // 6. Create genesis object tree
    let mut logs_data: Vec<String> = Vec::new();

    let tree = aquafier
        .create_object(template_hash, None, payload, None)
        .map_err(|err| {
            let mut errs = vec![colored_error("Error creating object revision")];
            errs.extend(format_method_error(&err));
            errs
        })?;

    logs_data.push(colored_success(&format!(
        "Created {} claim object.",
        kind.label()
    )));

    // 7. Auto-sign if keys_file is available
    if let Some(ref kf) = keys_file {
        let creds = read_credentials(kf).map_err(|e| vec![colored_error(&e)])?;

        let wrapper = AquaTreeWrapper::new(tree.clone(), None, None);
        match aquafier
            .sign_aqua_tree(wrapper, &creds.signing, None, None)
            .await
        {
            Ok(op_data) => {
                let signer_label = match &creds.signing {
                    SigningCredentials::Cli { .. } => "cli".to_string(),
                    SigningCredentials::Did { .. } => "ed25519".to_string(),
                    SigningCredentials::P256 { .. } => "p256".to_string(),
                    SigningCredentials::Metamask { .. } => "metamask".to_string(),
                    SigningCredentials::Secp256k1 { .. } => "secp256k1".to_string(),
                };
                logs_data.push(colored_success(&format!(
                    "Signed claim ({}).",
                    signer_label
                )));

                // Save signed tree
                let save_path = PathBuf::from(format!("{}_claim", kind.label()));
                let e = save_page_data(&op_data.aqua_tree, &save_path, "aqua.json".to_string());
                if let Err(err) = e {
                    logs_data.push(format!("Error saving page data: {}", err));
                }

                // Push to daemon if --target is set
                if let Some(target_id) = args.target {
                    match push_tree_to_daemon(target_id, &op_data.aqua_tree).await {
                        Ok(resp) => {
                            logs_data.push(format!("Pushed to daemon {}: {}", target_id, resp))
                        }
                        Err(e) => logs_data.push(format!("Failed to push to daemon: {}", e)),
                    }
                }
            }
            Err(err) => {
                logs_data.push(colored_error("Error signing claim"));
                logs_data.extend(format_method_error(&err));
            }
        }
    } else {
        // Save unsigned tree
        let save_path = PathBuf::from(format!("{}_claim", kind.label()));
        let e = save_page_data(&tree, &save_path, "aqua.json".to_string());
        if let Err(err) = e {
            logs_data.push(format!("Error saving page data: {}", err));
        }
    }

    oprataion_logs_and_dumps(args.clone(), logs_data);
    Ok(())
}
