// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use aqua_rs_sdk::primitives::log::{LogData, LogType};
use aqua_rs_sdk::primitives::EvmChain;
use aqua_rs_sdk::schema::credentials::CredentialsFile;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::{SigningCredentials, TimestampCredentials};
use console::Style;
use std::io::Write;
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};

use crate::models::CliArgs;
extern crate serde_json_path_to_error as serde_json;

pub fn save_logs_to_file(logs: &Vec<String>, output_file: PathBuf) -> Result<String, String> {
    // Open the file in append mode, create it if it doesn't exist
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&output_file)
    {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open log file: {}", e)),
    };

    // Write each log entry to the file, adding a newline after each one
    for log in logs {
        if let Err(e) = writeln!(file, "{}", log) {
            return Err(format!("Failed to write to log file: {}", e));
        }
    }

    Ok("Log written successfully".to_string())
}

pub fn read_aqua_data(path: &PathBuf) -> Result<Tree, String> {
    let data = fs::read_to_string(path);
    match data {
        Ok(data) => {
            let res = serde_json::from_str::<Tree>(&data);
            match res {
                Ok(res_data) => Ok(res_data),
                Err(err_data) => {
                    return Err(format!("Error, parsing json {}", err_data));
                }
            }
        }
        Err(e) => {
            return Err(format!("Error , {}", e));
        }
    }
}

pub fn read_credentials(path: &PathBuf) -> Result<CredentialsFile, String> {
    let data = fs::read_to_string(path);
    match data {
        Ok(data) => {
            // Try parsing as CredentialsFile first
            let res = serde_json::from_str::<CredentialsFile>(&data);
            match res {
                Ok(res_data) => Ok(res_data),
                Err(_) => {
                    // Fallback: try parsing legacy format { "mnemonic": "...", "nostr_sk": "...", "did:key": "..." }
                    let legacy: Result<serde_json::Value, _> = serde_json::from_str(&data);
                    match legacy {
                        Ok(val) => {
                            let mnemonic = val
                                .get("mnemonic")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let nostr_sk = val
                                .get("nostr_sk")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let did_key_str = val
                                .get("did:key")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            let _did_key_bytes = if did_key_str.starts_with("0x") {
                                hex::decode(&did_key_str[2..]).unwrap_or_default()
                            } else if !did_key_str.is_empty() && did_key_str != "sample" {
                                hex::decode(&did_key_str).unwrap_or_default()
                            } else {
                                Vec::new()
                            };

                            let signing = SigningCredentials::Cli {
                                mnemonic: mnemonic.clone(),
                            };
                            let timestamp = if !nostr_sk.is_empty() && nostr_sk != "sample" {
                                TimestampCredentials::Nostr { nostr_sk }
                            } else {
                                TimestampCredentials::Nostr { nostr_sk }
                            };

                            Ok(CredentialsFile { signing, timestamp })
                        }
                        Err(err_data) => Err(format!("Error, parsing keys json {}", err_data)),
                    }
                }
            }
        }
        Err(e) => {
            return Err(format!("Error , {}", e));
        }
    }
}

pub fn save_page_data(
    aqua_tree: &Tree,
    original_path: &Path,
    extension: String,
) -> Result<(), String> {
    // Determine the output path based on the file extension
    let output_path: PathBuf = if original_path.extension().map_or(false, |ext| ext == "json") {
        original_path.to_path_buf() // If it's a JSON file, overwrite it
    } else {
        original_path.with_extension(extension) // Otherwise, create a new file with the specified extension
    };

    // Serialize Tree to JSON with revisions ordered from genesis to latest
    let ordered_tree = aqua_rs_sdk::schema::tree::OrderedTree::from_tree(aqua_tree);
    match serde_json::to_string_pretty(&ordered_tree.create_tree()) {
        Ok(json_data) => {
            // Write JSON data to the determined file path
            fs::write(&output_path, json_data).map_err(|e| e.to_string())?;
            println!("Aqua chain data saved to: {:?}", output_path);
            Ok(())
        }
        Err(e) => Err(format!("Error serializing Tree: {}", e)),
    }
}

pub fn is_valid_json_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() && path.extension().unwrap_or_default() == "json" {
        Ok(s.to_string())
    } else {
        Err("Invalid JSON file path".to_string())
    }
}

pub fn is_valid_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() {
        Ok(s.to_string())
    } else {
        Err("Invalid file path".to_string())
    }
}

pub fn is_valid_output_file(s: &str) -> Result<String, String> {
    let lowercase = s.to_lowercase();
    if lowercase.ends_with(".json") || lowercase.ends_with(".html") || lowercase.ends_with(".pdf") {
        Ok(s.to_string())
    } else {
        Err("Output file must be .json, .html, or .pdf".to_string())
    }
}

pub fn string_to_bool(s: String) -> bool {
    match s.to_lowercase().as_str() {
        "true" => true,
        "yes" => true,
        "false" => false,
        "no" => false,
        _ => false,
    }
}

fn style_for_log_type(log_type: &LogType) -> Style {
    match log_type {
        LogType::Success => Style::new().green(),
        LogType::Error | LogType::FinalError => Style::new().red().bold(),
        LogType::Warning => Style::new().yellow(),
        LogType::Info => Style::new().cyan(),
        _ => Style::new(),
    }
}

fn format_log_entry(entry: &LogData) -> String {
    let emoji = entry.log_type.emoji();
    let style = style_for_log_type(&entry.log_type);
    if emoji.is_empty() {
        style.apply_to(&entry.log).to_string()
    } else {
        format!("{} {}", emoji, style.apply_to(&entry.log))
    }
}

pub fn log_with_emoji(logs: Vec<LogData>) -> Vec<String> {
    logs.iter()
        .map(|entry| format!("   {}", format_log_entry(entry)))
        .collect()
}

/// Groups verification logs by revision and renders them as a tree with
/// box-drawing connectors (`├─`, `│`, `└─`) and ANSI colors.
pub fn format_verification_tree(logs: &[LogData]) -> Vec<String> {
    let dim = Style::new().dim();

    // Group logs into revision groups.
    // A revision header is an Info entry whose ident is Some("") (empty string).
    let mut groups: Vec<Vec<&LogData>> = Vec::new();
    for entry in logs {
        let is_header = entry.log_type == LogType::Info
            && entry.ident.as_deref() == Some("");
        if is_header {
            // Start a new group
            groups.push(vec![entry]);
        } else if let Some(last) = groups.last_mut() {
            last.push(entry);
        } else {
            // Orphan entry before any header — start its own group
            groups.push(vec![entry]);
        }
    }

    let mut lines: Vec<String> = Vec::new();
    let total_groups = groups.len();

    for (gi, group) in groups.iter().enumerate() {
        let is_last_group = gi == total_groups - 1;

        for (ei, entry) in group.iter().enumerate() {
            let formatted = format_log_entry(entry);
            let is_header = ei == 0;

            if is_header {
                let connector = if is_last_group { "└─" } else { "├─" };
                lines.push(format!("{} {}", dim.apply_to(connector), formatted));
            } else {
                let prefix = if is_last_group { "   " } else { "│  " };
                lines.push(format!("{} {}", dim.apply_to(prefix), formatted));
            }
        }

        // Add a blank continuation line between groups (not after the last)
        if !is_last_group {
            let pipe = if gi < total_groups - 2 { "│" } else { "│" };
            lines.push(dim.apply_to(pipe).to_string());
        }
    }

    lines
}

/// Build a verification summary string from the log entries.
pub fn format_verification_summary(logs: &[LogData], is_valid: bool) -> String {
    // Count revision headers by parsing "Verifying revision type: <type>"
    let mut anchor_count = 0usize;
    let mut object_count = 0usize;
    let mut signature_count = 0usize;
    let mut witness_count = 0usize;
    let mut other_count = 0usize;
    let mut error_count = 0usize;

    for entry in logs {
        let is_header = entry.log_type == LogType::Info
            && entry.ident.as_deref() == Some("");
        if is_header {
            let msg = entry.log.to_lowercase();
            if msg.contains("anchor") {
                anchor_count += 1;
            } else if msg.contains("object") {
                object_count += 1;
            } else if msg.contains("signature") {
                signature_count += 1;
            } else if msg.contains("witness") || msg.contains("timestamp") {
                witness_count += 1;
            } else {
                other_count += 1;
            }
        }
        if entry.log_type == LogType::Error || entry.log_type == LogType::FinalError {
            error_count += 1;
        }
    }

    let total = anchor_count + object_count + signature_count + witness_count + other_count;
    let mut parts: Vec<String> = Vec::new();
    if anchor_count > 0 {
        parts.push(format!("{} anchor", anchor_count));
    }
    if object_count > 0 {
        parts.push(format!("{} object", object_count));
    }
    if signature_count > 0 {
        parts.push(format!("{} signature", signature_count));
    }
    if witness_count > 0 {
        parts.push(format!("{} witness", witness_count));
    }
    if other_count > 0 {
        parts.push(format!("{} other", other_count));
    }

    let breakdown = if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    };

    if is_valid {
        let success_style = Style::new().green();
        format!(
            "\n{}\n  Summary: {} revisions verified{} — all passed",
            success_style.apply_to("✅ Chain verification passed"),
            total,
            breakdown
        )
    } else {
        let error_style = Style::new().red().bold();
        format!(
            "\n{}\n  Summary: {} revisions checked{} — {} error(s)",
            error_style.apply_to("❌ Verification failed"),
            total,
            breakdown,
            error_count
        )
    }
}

/// Build a compact (non-verbose) summary line.
pub fn format_verification_summary_compact(logs: &[LogData], is_valid: bool) -> String {
    let mut anchor_count = 0usize;
    let mut object_count = 0usize;
    let mut signature_count = 0usize;
    let mut witness_count = 0usize;
    let mut other_count = 0usize;
    let mut error_count = 0usize;

    for entry in logs {
        let is_header = entry.log_type == LogType::Info
            && entry.ident.as_deref() == Some("");
        if is_header {
            let msg = entry.log.to_lowercase();
            if msg.contains("anchor") {
                anchor_count += 1;
            } else if msg.contains("object") {
                object_count += 1;
            } else if msg.contains("signature") {
                signature_count += 1;
            } else if msg.contains("witness") || msg.contains("timestamp") {
                witness_count += 1;
            } else {
                other_count += 1;
            }
        }
        if entry.log_type == LogType::Error || entry.log_type == LogType::FinalError {
            error_count += 1;
        }
    }

    let total = anchor_count + object_count + signature_count + witness_count + other_count;
    let mut parts: Vec<String> = Vec::new();
    if anchor_count > 0 {
        parts.push(format!("{} anchor", anchor_count));
    }
    if object_count > 0 {
        parts.push(format!("{} object", object_count));
    }
    if signature_count > 0 {
        parts.push(format!("{} signature", signature_count));
    }
    if witness_count > 0 {
        parts.push(format!("{} witness", witness_count));
    }
    if other_count > 0 {
        parts.push(format!("{} other", other_count));
    }

    let breakdown = if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    };

    if is_valid {
        let style = Style::new().green();
        format!(
            "{}",
            style.apply_to(format!(
                "✅ Chain verification passed — {} revisions{}",
                total, breakdown
            ))
        )
    } else {
        let style = Style::new().red().bold();
        format!(
            "{}",
            style.apply_to(format!(
                "❌ Verification failed — {} revisions{}, {} error(s)",
                total, breakdown, error_count
            ))
        )
    }
}

/// Color a success header line green.
pub fn colored_success(msg: &str) -> String {
    Style::new().green().apply_to(msg).to_string()
}

/// Color an error header line red bold.
pub fn colored_error(msg: &str) -> String {
    Style::new().red().bold().apply_to(msg).to_string()
}

pub fn oprataion_logs_and_dumps(args: CliArgs, logs_data: Vec<String>) {
    // Print logs based on verbosity setting
    if args.verbose {
        for item in logs_data.clone() {
            println!("{}", item);
        }
    } else {
        println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
    }

    // Save logs to file if output path is specified
    if args.output.is_some() {
        let logs = save_logs_to_file(&logs_data, args.output.unwrap());
        if logs.is_err() {
            eprintln!("Error: saving logs {}", logs.unwrap());
        }
    }
}

pub fn format_method_error(err: &aqua_rs_sdk::primitives::MethodError) -> Vec<String> {
    match err {
        aqua_rs_sdk::primitives::MethodError::WithLogs(logs) => log_with_emoji(logs.clone()),
        other => vec![colored_error(&format!("   {}", other))],
    }
}

pub fn parse_eth_network(network_str: &str) -> EvmChain {
    match network_str.to_lowercase().as_str() {
        "mainnet" => EvmChain::Mainnet,
        "holesky" => EvmChain::Holesky,
        _ => EvmChain::Sepolia,
    }
}
