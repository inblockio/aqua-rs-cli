use std::fs;
use std::path::{Path, PathBuf};

use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::template::BuiltInTemplate;
use aqua_rs_sdk::schema::templates::{
    AccessGrant, AliasRegistration, Attestation, DnsClaim, EmailClaim, EvmTimestampPayload, File,
    MultiSigner, NameClaim, PhoneClaim, PlatformIdentityClaim, PluginRegistration,
    TemplateRegistration, TrustAssertion, VendorRegistration, WalletIdentification,
};
use aqua_rs_sdk::Aquafier;

use crate::aqua::identity_verify::{verify_and_create_identity_claim, IdentityTemplateKind};
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
        "attestation" => Ok(template_link_to_revision_link(&Attestation::TEMPLATE_LINK)),
        "platform-identity" => Ok(template_link_to_revision_link(
            &PlatformIdentityClaim::TEMPLATE_LINK,
        )),
        "timestamp" => Ok(template_link_to_revision_link(&EvmTimestampPayload::TEMPLATE_LINK)),
        "multi-signer" => Ok(template_link_to_revision_link(&MultiSigner::TEMPLATE_LINK)),
        "trust-assertion" => Ok(template_link_to_revision_link(&TrustAssertion::TEMPLATE_LINK)),
        "wallet-identification" => Ok(template_link_to_revision_link(
            &WalletIdentification::TEMPLATE_LINK,
        )),
        "access-grant" => Ok(template_link_to_revision_link(&AccessGrant::TEMPLATE_LINK)),
        "vendor-registration" => Ok(template_link_to_revision_link(
            &VendorRegistration::TEMPLATE_LINK,
        )),
        "template-registration" => Ok(template_link_to_revision_link(
            &TemplateRegistration::TEMPLATE_LINK,
        )),
        "alias-registration" => Ok(template_link_to_revision_link(
            &AliasRegistration::TEMPLATE_LINK,
        )),
        "plugin-registration" => Ok(template_link_to_revision_link(
            &PluginRegistration::TEMPLATE_LINK,
        )),
        "email" => Ok(template_link_to_revision_link(&EmailClaim::TEMPLATE_LINK)),
        "phone" => Ok(template_link_to_revision_link(&PhoneClaim::TEMPLATE_LINK)),
        "name" => Ok(template_link_to_revision_link(&NameClaim::TEMPLATE_LINK)),
        "domain" => Ok(template_link_to_revision_link(&DnsClaim::TEMPLATE_LINK)),
        _ => Err(format!("Unknown template name: {}", name)),
    }
}

/// Check whether a resolved template hash corresponds to a verifiable identity
/// template (email or phone). Returns the kind if it does.
fn is_identity_verifiable_template(hash: &RevisionLink) -> Option<IdentityTemplateKind> {
    let email_link = template_link_to_revision_link(&EmailClaim::TEMPLATE_LINK);
    let phone_link = template_link_to_revision_link(&PhoneClaim::TEMPLATE_LINK);

    if *hash == email_link {
        Some(IdentityTemplateKind::Email)
    } else if *hash == phone_link {
        Some(IdentityTemplateKind::Phone)
    } else {
        None
    }
}

/// Extract required and optional field names from a template's JSON schema.
fn extract_template_fields(template_json: &str) -> (Vec<String>, Vec<String>) {
    let val: serde_json::Value = match serde_json::from_str(template_json) {
        Ok(v) => v,
        Err(_) => return (vec![], vec![]),
    };

    let schema = match val.get("schema") {
        Some(s) => s,
        None => return (vec![], vec![]),
    };

    let required: Vec<String> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let all_props: Vec<String> = schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    let optional: Vec<String> = all_props
        .into_iter()
        .filter(|k| !required.contains(k))
        .collect();

    (required, optional)
}

/// CLI handler for `--list-templates`.
/// Prints all built-in template names, hashes, and their required/optional fields.
pub(crate) fn cli_list_templates() {
    let templates: &[(&str, &[u8; 32], &str)] = &[
        ("file", &File::TEMPLATE_LINK, File::TEMPLATE_JSON),
        ("attestation", &Attestation::TEMPLATE_LINK, Attestation::TEMPLATE_JSON),
        ("platform-identity", &PlatformIdentityClaim::TEMPLATE_LINK, PlatformIdentityClaim::TEMPLATE_JSON),
        ("timestamp", &EvmTimestampPayload::TEMPLATE_LINK, EvmTimestampPayload::TEMPLATE_JSON),
        ("multi-signer", &MultiSigner::TEMPLATE_LINK, MultiSigner::TEMPLATE_JSON),
        ("trust-assertion", &TrustAssertion::TEMPLATE_LINK, TrustAssertion::TEMPLATE_JSON),
        ("wallet-identification", &WalletIdentification::TEMPLATE_LINK, WalletIdentification::TEMPLATE_JSON),
        ("access-grant", &AccessGrant::TEMPLATE_LINK, AccessGrant::TEMPLATE_JSON),
        ("vendor-registration", &VendorRegistration::TEMPLATE_LINK, VendorRegistration::TEMPLATE_JSON),
        ("template-registration", &TemplateRegistration::TEMPLATE_LINK, TemplateRegistration::TEMPLATE_JSON),
        ("alias-registration", &AliasRegistration::TEMPLATE_LINK, AliasRegistration::TEMPLATE_JSON),
        ("plugin-registration", &PluginRegistration::TEMPLATE_LINK, PluginRegistration::TEMPLATE_JSON),
        ("email", &EmailClaim::TEMPLATE_LINK, EmailClaim::TEMPLATE_JSON),
        ("phone", &PhoneClaim::TEMPLATE_LINK, PhoneClaim::TEMPLATE_JSON),
        ("name", &NameClaim::TEMPLATE_LINK, NameClaim::TEMPLATE_JSON),
        ("domain", &DnsClaim::TEMPLATE_LINK, DnsClaim::TEMPLATE_JSON),
    ];

    println!("Built-in Templates:\n");
    for (name, link_bytes, json) in templates {
        let rev = template_link_to_revision_link(link_bytes);
        println!("  {} ({})", name, rev);
        let (required, optional) = extract_template_fields(json);
        if !required.is_empty() {
            println!("    Required: {}", required.join(", "));
        }
        if !optional.is_empty() {
            println!("    Optional: {}", optional.join(", "));
        }
        println!();
    }
}

/// CLI handler for `--create-object`.
pub(crate) async fn cli_create_object(
    args: CliArgs,
    aquafier: &Aquafier,
    keys_file: Option<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();

    // 1. Resolve template hash
    let template_hash = if let Some(ref hash_str) = args.template_hash {
        match hash_str.parse::<RevisionLink>() {
            Ok(link) => link,
            Err(e) => {
                eprintln!("Error: Invalid --template-hash '{}': {}", hash_str, e);
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

    // 2b. Check if this is a verifiable identity template (email or phone)
    if let Some(kind) = is_identity_verifiable_template(&template_hash) {
        match verify_and_create_identity_claim(
            &args,
            aquafier,
            template_hash,
            payload,
            kind,
            keys_file,
        )
        .await
        {
            Ok(()) => {}
            Err(err_logs) => {
                logs_data.extend(err_logs);
                oprataion_logs_and_dumps(args, logs_data);
            }
        }
        return;
    }

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
