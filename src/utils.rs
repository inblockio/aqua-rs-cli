use aqua_verifier::model::signature::Credentials;
use aqua_verifier_rs_types::models::{
    chain::AquaChain,
    protocol_logs::{ProtocolLogs, ProtocolLogsType},
};
use std::io::Write;
use std::{
    fs::{self,  OpenOptions},
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

pub fn read_aqua_data(path: &PathBuf) -> Result<AquaChain, String> {
    let data = fs::read_to_string(path);
    match data {
        Ok(data) => {
            let res = serde_json::from_str::<AquaChain>(&data);
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

pub fn read_secreat_keys(path: &PathBuf) -> Result<Credentials, String> {
    let data = fs::read_to_string(path);
    match data {
        Ok(data) => {
            let res = serde_json::from_str::<Credentials>(&data);
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

pub fn save_page_data(
    aqua_page_data: &AquaChain,
    original_path: &Path,
    extension: String,
) -> Result<(), String> {
    // Determine the output path based on the file extension
    let output_path: PathBuf = if original_path.extension().map_or(false, |ext| ext == "json") {
        original_path.to_path_buf() // If it's a JSON file, overwrite it
    } else {
        original_path.with_extension(extension) // Otherwise, create a new file with the specified extension
    };

    // Serialize PageData to JSON
    match serde_json::to_string_pretty(aqua_page_data) {
        Ok(json_data) => {
            // Write JSON data to the determined file path
            fs::write(&output_path, json_data).map_err(|e| e.to_string())?;
            println!("Aqua chain data saved to: {:?}", output_path);
            Ok(())
        }
        Err(e) => Err(format!("Error serializing PageData: {}", e)),
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

pub fn log_with_emoji(logs: Vec<ProtocolLogs>) -> Vec<String> {
    // Vector to store log messages
    let mut logs_data: Vec<String> = Vec::new();

    // Collect logs with indentation
    for ele in logs {
        let log_emoji = match ele.log_type {
            ProtocolLogsType::ERROR => "❌",
            ProtocolLogsType::WARNING => "❗",
            _ => "⭐",
        };

        logs_data.push(format!(
            "\t\t {} {:#?} : {}",
            log_emoji, ele.log_type, ele.log
        ));
    }
    return logs_data;
}

pub fn oprataion_logs_and_dumps(args: CliArgs, logs_data: Vec<String>) {
    // Print logs based on verbosity setting
    // if args.verbose {
        for item in logs_data.clone() {
            println!("{}", item);
        }
    // } else {
    //     println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
    // }

    // Save logs to file if output path is specified
    if args.output.is_some() {
        let logs = save_logs_to_file(&logs_data, args.output.unwrap());
        if logs.is_err() {
            eprintln!("Error: saving logs {}", logs.unwrap());
        }
    }
}
