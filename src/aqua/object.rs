use std::fs;
use std::path::{Path, PathBuf};

use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::template::BuiltInTemplate;
use aqua_rs_sdk::schema::templates::{
    AccessGrant, AliasRegistration, Attestation, File, MultiSigner, PlatformIdentityClaim,
    PluginRegistration, TemplateRegistration, TimestampPayload, TrustAssertion, VendorRegistration,
    WalletIdentification,
};
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
        "platform-identity" => Ok(template_link_to_revision_link(
            &PlatformIdentityClaim::TEMPLATE_LINK,
        )),
        "attestation" => Ok(template_link_to_revision_link(&Attestation::TEMPLATE_LINK)),
        "timestamp" => Ok(template_link_to_revision_link(
            &TimestampPayload::TEMPLATE_LINK,
        )),
        "multi-signer" => Ok(template_link_to_revision_link(&MultiSigner::TEMPLATE_LINK)),
        "trust-assertion" => Ok(template_link_to_revision_link(
            &TrustAssertion::TEMPLATE_LINK,
        )),
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
        _ => Err(format!("Unknown template name: {}", name)),
    }
}

/// Extract mandatory and optional field names from a template JSON string.
/// Returns `(mandatory, optional)` vectors of field names.
fn extract_template_fields(json_str: &str) -> (Vec<String>, Vec<String>) {
    let parsed: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return (vec![], vec![]),
    };

    let schema = match parsed.get("schema") {
        Some(s) => s,
        None => return (vec![], vec![]),
    };

    let properties: Vec<String> = schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    let required: Vec<String> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let mut mandatory = Vec::new();
    let mut optional = Vec::new();
    for field in &properties {
        if required.contains(field) {
            mandatory.push(field.clone());
        } else {
            optional.push(field.clone());
        }
    }
    (mandatory, optional)
}

/// CLI handler for `--list-templates`.
/// Prints all built-in template names, hashes, and their fields.
pub(crate) fn cli_list_templates() {
    let templates: &[(&str, &[u8; 32], &str)] = &[
        ("file", &File::TEMPLATE_LINK, File::TEMPLATE_JSON),
        (
            "platform-identity",
            &PlatformIdentityClaim::TEMPLATE_LINK,
            PlatformIdentityClaim::TEMPLATE_JSON,
        ),
        (
            "attestation",
            &Attestation::TEMPLATE_LINK,
            Attestation::TEMPLATE_JSON,
        ),
        (
            "timestamp",
            &TimestampPayload::TEMPLATE_LINK,
            TimestampPayload::TEMPLATE_JSON,
        ),
        (
            "multi-signer",
            &MultiSigner::TEMPLATE_LINK,
            MultiSigner::TEMPLATE_JSON,
        ),
        (
            "trust-assertion",
            &TrustAssertion::TEMPLATE_LINK,
            TrustAssertion::TEMPLATE_JSON,
        ),
        (
            "wallet-identification",
            &WalletIdentification::TEMPLATE_LINK,
            WalletIdentification::TEMPLATE_JSON,
        ),
        (
            "access-grant",
            &AccessGrant::TEMPLATE_LINK,
            AccessGrant::TEMPLATE_JSON,
        ),
        (
            "vendor-registration",
            &VendorRegistration::TEMPLATE_LINK,
            VendorRegistration::TEMPLATE_JSON,
        ),
        (
            "template-registration",
            &TemplateRegistration::TEMPLATE_LINK,
            TemplateRegistration::TEMPLATE_JSON,
        ),
        (
            "alias-registration",
            &AliasRegistration::TEMPLATE_LINK,
            AliasRegistration::TEMPLATE_JSON,
        ),
        (
            "plugin-registration",
            &PluginRegistration::TEMPLATE_LINK,
            PluginRegistration::TEMPLATE_JSON,
        ),
    ];

    println!("Built-in Templates:\n");
    for (name, link_bytes, json_str) in templates {
        let rev = template_link_to_revision_link(link_bytes);
        println!("  {} ({})", name, rev);

        let (mandatory, optional) = extract_template_fields(json_str);
        if !mandatory.is_empty() {
            println!("    Mandatory fields: {}", mandatory.join(", "));
        }
        if !optional.is_empty() {
            println!("    Optional fields:  {}", optional.join(", "));
        }
        println!();
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
