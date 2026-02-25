use std::fs;
use std::path::{Path, PathBuf};

use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::templates::{
    AccessGrant, AliasRegistration, Attestation, DomainClaim, EmailClaim, File, MultiSigner,
    NameClaim, PhoneClaim, PluginRegistration, TemplateRegistration, TimestampPayload,
    TrustAssertion, VendorRegistration, WalletIdentification,
};
use aqua_rs_sdk::schema::template::BuiltInTemplate;
use aqua_rs_sdk::Aquafier;

use crate::models::CliArgs;
use crate::utils::{oprataion_logs_and_dumps, save_page_data};

extern crate serde_json_path_to_error as serde_json;

/// Convert a `[u8; 32]` template constant to a `RevisionLink` via hex parsing.
fn template_link_to_revision_link(bytes: &[u8; 32]) -> RevisionLink {
    let hex_str = format!("0x{}", hex::encode(bytes));
    hex_str
        .parse::<RevisionLink>()
        .expect("built-in TEMPLATE_LINK should always produce a valid RevisionLink")
}

/// Map a built-in template CLI name to its `RevisionLink`.
fn resolve_template_name(name: &str) -> Result<RevisionLink, String> {
    match name {
        "file" => Ok(template_link_to_revision_link(&File::TEMPLATE_LINK)),
        "domain" => Ok(template_link_to_revision_link(&DomainClaim::TEMPLATE_LINK)),
        "email" => Ok(template_link_to_revision_link(&EmailClaim::TEMPLATE_LINK)),
        "name" => Ok(template_link_to_revision_link(&NameClaim::TEMPLATE_LINK)),
        "phone" => Ok(template_link_to_revision_link(&PhoneClaim::TEMPLATE_LINK)),
        "attestation" => Ok(template_link_to_revision_link(&Attestation::TEMPLATE_LINK)),
        "timestamp" => Ok(template_link_to_revision_link(&TimestampPayload::TEMPLATE_LINK)),
        "multi-signer" => Ok(template_link_to_revision_link(&MultiSigner::TEMPLATE_LINK)),
        "trust-assertion" => Ok(template_link_to_revision_link(&TrustAssertion::TEMPLATE_LINK)),
        "wallet-identification" => {
            Ok(template_link_to_revision_link(&WalletIdentification::TEMPLATE_LINK))
        }
        "access-grant" => Ok(template_link_to_revision_link(&AccessGrant::TEMPLATE_LINK)),
        "vendor-registration" => {
            Ok(template_link_to_revision_link(&VendorRegistration::TEMPLATE_LINK))
        }
        "template-registration" => {
            Ok(template_link_to_revision_link(&TemplateRegistration::TEMPLATE_LINK))
        }
        "alias-registration" => {
            Ok(template_link_to_revision_link(&AliasRegistration::TEMPLATE_LINK))
        }
        "plugin-registration" => {
            Ok(template_link_to_revision_link(&PluginRegistration::TEMPLATE_LINK))
        }
        _ => Err(format!("Unknown template name: {}", name)),
    }
}

/// CLI handler for `--list-templates`.
/// Prints a formatted table of all 15 built-in template names and their hashes.
pub(crate) fn cli_list_templates() {
    let templates: &[(&str, &[u8; 32])] = &[
        ("file", &File::TEMPLATE_LINK),
        ("domain", &DomainClaim::TEMPLATE_LINK),
        ("email", &EmailClaim::TEMPLATE_LINK),
        ("name", &NameClaim::TEMPLATE_LINK),
        ("phone", &PhoneClaim::TEMPLATE_LINK),
        ("attestation", &Attestation::TEMPLATE_LINK),
        ("timestamp", &TimestampPayload::TEMPLATE_LINK),
        ("multi-signer", &MultiSigner::TEMPLATE_LINK),
        ("trust-assertion", &TrustAssertion::TEMPLATE_LINK),
        ("wallet-identification", &WalletIdentification::TEMPLATE_LINK),
        ("access-grant", &AccessGrant::TEMPLATE_LINK),
        ("vendor-registration", &VendorRegistration::TEMPLATE_LINK),
        ("template-registration", &TemplateRegistration::TEMPLATE_LINK),
        ("alias-registration", &AliasRegistration::TEMPLATE_LINK),
        ("plugin-registration", &PluginRegistration::TEMPLATE_LINK),
    ];

    println!("Built-in Templates:");
    println!("  {:<28} HASH", "NAME");
    for (name, link) in templates {
        let rev = template_link_to_revision_link(link);
        println!("  {:<28} {}", name, rev);
    }
}

/// CLI handler for `--create-object`.
pub(crate) fn cli_create_object(args: CliArgs, aquafier: &Aquafier) {
    let mut logs_data: Vec<String> = Vec::new();

    // 1. Resolve template hash
    let template_hash = if let Some(ref hash_str) = args.template_hash {
        match hash_str.parse::<RevisionLink>() {
            Ok(link) => link,
            Err(e) => {
                eprintln!(
                    "Error: Invalid --template-hash '{}': {}",
                    hash_str, e
                );
                logs_data.push(format!("❌ Invalid template hash: {}", e));
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
        }
    } else if let Some(ref name) = args.template_name {
        match resolve_template_name(name) {
            Ok(link) => link,
            Err(e) => {
                eprintln!("Error: {}", e);
                logs_data.push(format!("❌ {}", e));
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
        }
    } else {
        eprintln!("Error: --create-object requires --template-hash or --template-name");
        logs_data.push("❌ Missing template specification".to_string());
        oprataion_logs_and_dumps(args, logs_data);
        return;
    };

    // 2. Resolve payload
    let payload_str = match &args.payload {
        Some(p) => p.clone(),
        None => {
            eprintln!("Error: --create-object requires --payload");
            logs_data.push("❌ Missing --payload".to_string());
            oprataion_logs_and_dumps(args, logs_data);
            return;
        }
    };

    let (payload, source_path): (serde_json::Value, Option<PathBuf>) = {
        let candidate = Path::new(&payload_str);
        if candidate.exists() && candidate.is_file() {
            // Read JSON from file
            match fs::read_to_string(candidate) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(val) => (val, Some(candidate.to_path_buf())),
                    Err(e) => {
                        eprintln!("Error: Failed to parse JSON from '{}': {}", payload_str, e);
                        logs_data.push(format!("❌ Invalid JSON in file: {}", e));
                        oprataion_logs_and_dumps(args, logs_data);
                        return;
                    }
                },
                Err(e) => {
                    eprintln!("Error: Failed to read file '{}': {}", payload_str, e);
                    logs_data.push(format!("❌ Failed to read payload file: {}", e));
                    oprataion_logs_and_dumps(args, logs_data);
                    return;
                }
            }
        } else {
            // Parse as inline JSON
            match serde_json::from_str(&payload_str) {
                Ok(val) => (val, None),
                Err(e) => {
                    eprintln!(
                        "Error: --payload is neither a valid file path nor valid JSON: {}",
                        e
                    );
                    logs_data.push(format!("❌ Invalid payload: {}", e));
                    oprataion_logs_and_dumps(args, logs_data);
                    return;
                }
            }
        }
    };

    // 3. Call aquafier.create_object (genesis: no previous tree, default method)
    match aquafier.create_object(template_hash, None, payload, None) {
        Ok(tree) => {
            logs_data.push("✅ Successfully created genesis object revision".to_string());

            // 4. Determine output path
            //    For file payloads: data.json → data.aqua.json
            //    For inline JSON:   object → object.aqua.json
            //    Strip .json extension from source path so save_page_data appends
            //    "aqua.json" instead of overwriting the input file.
            let save_path_buf: PathBuf = match source_path {
                Some(ref p) => {
                    if p.extension().map_or(false, |ext| ext == "json") {
                        p.with_extension("")
                    } else {
                        p.clone()
                    }
                }
                None => PathBuf::from("object"),
            };

            let e = save_page_data(&tree, &save_path_buf, "aqua.json".to_string());
            if e.is_err() {
                logs_data.push(format!("Error saving page data: {:#?}", e.err()));
            }
        }
        Err(err) => {
            logs_data.push("❌ Error creating object revision".to_string());
            logs_data.extend(crate::utils::format_method_error(&err));
        }
    }

    oprataion_logs_and_dumps(args, logs_data);
}
