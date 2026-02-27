// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use std::{fs, path::PathBuf};

use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::{AquaTreeWrapper, SigningCredentials};
use aqua_rs_sdk::Aquafier;

use crate::{
    models::{CliArgs, SignType},
    utils::{
        format_method_error, oprataion_logs_and_dumps, parse_eth_network, read_credentials,
        save_page_data,
    },
};

extern crate serde_json_path_to_error as serde_json;

pub(crate) async fn cli_sign_chain(
    args: CliArgs,
    aquafier: &Aquafier,
    sign_path: PathBuf,
    sign_type: SignType,
    keys_file: Option<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();

    // Build SigningCredentials based on sign_type
    let credentials: SigningCredentials = match &sign_type {
        SignType::Cli => {
            if keys_file.is_none() {
                logs_data.push("❌ CLI signature requires keys file".to_string());
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
            let creds = read_credentials(keys_file.as_ref().unwrap());
            if creds.is_err() {
                logs_data.push(format!("❌ {}", creds.err().unwrap()));
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
            creds.unwrap().signing
        }
        SignType::Did => {
            if keys_file.is_none() {
                logs_data.push("❌ DID signature requires keys file".to_string());
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
            let creds = read_credentials(keys_file.as_ref().unwrap());
            if creds.is_err() {
                logs_data.push(format!("❌ {}", creds.err().unwrap()));
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
            let _cred_file = creds.unwrap();
            // If keys file has a did:key field in legacy format, the signing field
            // may already be Cli. We need to extract did_key from the file directly.
            let key_content =
                fs::read_to_string(keys_file.as_ref().unwrap()).expect("Unable to read keys file");
            let val: serde_json::Value = serde_json::from_str(&key_content).unwrap();
            let did_key_str = val
                .get("did:key")
                .or_else(|| val.get("signing").and_then(|s| s.get("did_key")))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let did_key_bytes = if did_key_str.starts_with("0x") {
                hex::decode(&did_key_str[2..]).unwrap_or_default()
            } else if !did_key_str.is_empty() && did_key_str != "sample" {
                hex::decode(did_key_str).unwrap_or_default()
            } else {
                Vec::new()
            };

            SigningCredentials::Did {
                did_key: did_key_bytes,
            }
        }
        SignType::P256 => {
            if keys_file.is_none() {
                logs_data.push("❌ P256 signature requires keys file".to_string());
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
            let key_content =
                fs::read_to_string(keys_file.as_ref().unwrap()).expect("Unable to read keys file");
            let val: serde_json::Value = serde_json::from_str(&key_content).unwrap();
            let p256_key_str = val
                .get("p256_key")
                .or_else(|| val.get("signing").and_then(|s| s.get("p256_key")))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let p256_key_bytes = if p256_key_str.starts_with("0x") {
                hex::decode(&p256_key_str[2..]).unwrap_or_default()
            } else if !p256_key_str.is_empty() {
                hex::decode(p256_key_str).unwrap_or_default()
            } else {
                Vec::new()
            };

            SigningCredentials::P256 {
                p256_key: p256_key_bytes,
            }
        }
        SignType::Metamask => {
            let network_str = std::env::var("aqua_network").unwrap_or("sepolia".to_string());
            let eth_network = parse_eth_network(&network_str);
            SigningCredentials::Metamask { eth_network }
        }
    };

    // Read the aqua chain file
    match fs::read(&sign_path) {
        Ok(body_bytes) => {
            let file_data = String::from_utf8_lossy(&body_bytes).to_string();
            let res = serde_json::from_str::<Tree>(&file_data);

            if res.is_err() {
                logs_data.push("❌ Error parsing json data (check your aqua chain)".to_string());
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
            let tree = res.unwrap();
            let revision = args.previous_hash.as_ref().map(|h| {
                h.parse::<aqua_rs_sdk::primitives::RevisionLink>()
                    .expect("Invalid revision hash format (expected 0x-prefixed lowercase hex)")
            });
            let wrapper = AquaTreeWrapper::new(tree, None, revision);

            match aquafier
                .sign_aqua_tree(wrapper, &credentials, None, None)
                .await
            {
                Ok(op_data) => {
                    logs_data.push("✅ Successfully signed Aqua chain".to_string());

                    let e = save_page_data(&op_data.aqua_tree, &sign_path, "aqua.json".to_string());

                    if e.is_err() {
                        logs_data.push(format!("Error saving page data: {:#?}", e.err()));
                    }
                }
                Err(err) => {
                    logs_data.push("❌ Error signing Aqua chain".to_string());
                    logs_data.extend(format_method_error(&err));
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read file bytes: {}", e);
            logs_data.push("❌ failed to read file".to_string());
        }
    }

    oprataion_logs_and_dumps(args, logs_data);
}
