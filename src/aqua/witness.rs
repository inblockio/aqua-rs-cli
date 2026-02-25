// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use std::{fs, path::PathBuf};

use aqua_rs_sdk::Aquafier;
use aqua_rs_sdk::schema::{AquaTreeWrapper, TimestampCredentials};
use aqua_rs_sdk::schema::tree::Tree;

use crate::models::{CliArgs, WitnessType};
use crate::utils::{format_method_error, oprataion_logs_and_dumps, parse_eth_network, read_credentials, save_page_data};

extern crate serde_json_path_to_error as serde_json;

pub(crate) async fn cli_winess_chain(
    args: CliArgs,
    aquafier: &Aquafier,
    witness_path: PathBuf,
    witness_type: WitnessType,
    keys_file: Option<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();

    // Build TimestampCredentials based on witness_type
    let credentials: TimestampCredentials = match &witness_type {
        WitnessType::Eth => {
            let alchemy_key = std::env::var("api_key").unwrap_or_default();
            let network_str = std::env::var("aqua_network").unwrap_or("sepolia".to_string());
            let network = parse_eth_network(&network_str);

            if let Some(ref kf) = keys_file {
                let creds = read_credentials(kf);
                if let Ok(_cred_file) = creds {
                    // Check if we have a mnemonic from the keys file
                    let key_content = fs::read_to_string(kf).unwrap_or_default();
                    let val: serde_json::Value = serde_json::from_str(&key_content).unwrap_or(serde_json::Value::Null);
                    let mnemonic = val.get("mnemonic")
                        .or_else(|| val.get("signing").and_then(|s| s.get("mnemonic")))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    if !mnemonic.is_empty() {
                        TimestampCredentials::Cli {
                            mnemonic,
                            alchemy_key,
                            network,
                        }
                    } else {
                        TimestampCredentials::Metamask {
                            alchemy_key,
                            network,
                        }
                    }
                } else {
                    TimestampCredentials::Metamask {
                        alchemy_key,
                        network,
                    }
                }
            } else {
                TimestampCredentials::Metamask {
                    alchemy_key,
                    network,
                }
            }
        }
        WitnessType::Nostr => {
            if let Some(ref kf) = keys_file {
                let key_content = fs::read_to_string(kf).unwrap_or_default();
                let val: serde_json::Value = serde_json::from_str(&key_content).unwrap_or(serde_json::Value::Null);
                let nostr_sk = val.get("nostr_sk")
                    .or_else(|| val.get("timestamp").and_then(|t| t.get("nostr_sk")))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                TimestampCredentials::Nostr { nostr_sk }
            } else {
                logs_data.push("❌ Nostr witness requires keys file with nostr_sk".to_string());
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
        }
        WitnessType::Tsa => {
            let tsa_url = std::env::var("tsa_url")
                .unwrap_or("http://timestamp.digicert.com".to_string());
            TimestampCredentials::TSA { url: tsa_url }
        }
    };

    // Read the aqua chain file
    match fs::read(&witness_path) {
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

            match aquafier.timestamp_aqua_tree(wrapper, &credentials, None, None).await {
                Ok(op_data) => {
                    logs_data.push("✅ Successfully witnessed Aqua chain".to_string());

                    let e = save_page_data(
                        &op_data.aqua_tree,
                        &witness_path,
                        "aqua.json".to_string(),
                    );

                    if e.is_err() {
                        logs_data.push(format!("Error saving page data: {:#?}", e.err()));
                    }
                }
                Err(err) => {
                    logs_data.push("❌ Error witnessing Aqua chain".to_string());
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
