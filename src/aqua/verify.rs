use std::{fs, path::PathBuf};

use aqua_rs_sdk::Aquafier;
use aqua_rs_sdk::schema::{AquaTreeWrapper, FileData};
use aqua_rs_sdk::schema::tree::Tree;

use crate::{
    models::CliArgs,
    utils::{format_method_error, oprataion_logs_and_dumps},
};

extern crate serde_json_path_to_error as serde_json;

pub async fn cli_verify_chain(args: CliArgs, aquafier: &Aquafier, verify_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();

    match fs::read(&verify_path) {
        Ok(body_bytes) => {
            let file_data = String::from_utf8_lossy(&body_bytes).to_string();
            let res = serde_json::from_str::<Tree>(&file_data);

            if res.is_err() {
                logs_data.push("❌ Error parsing json data (check your aqua chain)".to_string());
                oprataion_logs_and_dumps(args, logs_data);
                return;
            }
            let tree = res.unwrap();

            // Build file objects from the tree's file_index
            let mut file_objects: Vec<FileData> = Vec::new();
            let folder_path = verify_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .to_path_buf();

            if let Some(main_file_name) = tree.get_main_file_name() {
                let file_path = folder_path.join(&main_file_name);
                if let Ok(content) = fs::read(&file_path) {
                    file_objects.push(FileData::new(
                        main_file_name,
                        content,
                        file_path,
                    ));
                }
            }

            let wrapper = AquaTreeWrapper::new(tree, None, None);

            match aquafier.verify_aqua_tree(wrapper, file_objects).await {
                Ok(res) => {
                    if res.is_valid {
                        logs_data.push("✅ Successfully verified Aqua chain".to_string());
                    } else {
                        logs_data.push(format!("❌ Verification failed: {}", res.status));
                    }

                    // Add detailed logs
                    for log_entry in &res.logs {
                        logs_data.push(log_entry.display());
                    }
                }
                Err(err) => {
                    logs_data.push("❌ Error verifying Aqua chain".to_string());
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
