// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use std::fs;
use std::path::PathBuf;

use aqua_rs_sdk::schema::{AquaTreeWrapper, FileData};
use aqua_rs_sdk::Aquafier;

use crate::models::CliArgs;
use crate::utils::{
    format_method_error, oprataion_logs_and_dumps, read_aqua_data, save_logs_to_file,
    save_page_data,
};

/// Removes the last revision from an Aqua chain file.
pub fn cli_remove_revisions_from_aqua_chain(
    args: CliArgs,
    aquafier: &Aquafier,
    aqua_chain_file_path: PathBuf,
) {
    let mut logs_data: Vec<String> = Vec::new();

    println!("Verifying file: {:?}", aqua_chain_file_path);

    let res = read_aqua_data(&aqua_chain_file_path);

    if res.is_err() {
        logs_data.push(res.err().unwrap());

        if args.output.is_some() {
            let logs = save_logs_to_file(&logs_data, args.output.unwrap());
            if logs.is_err() {
                eprintln!("Error: saving logs {}", logs.unwrap());
            }
        }
        return;
    }

    let tree = res.unwrap();
    let wrapper = AquaTreeWrapper::new(tree, None, None);

    match aquafier.delete_last_revision(wrapper) {
        Ok(updated_tree) => {
            logs_data.push("✅ Successfully removed last revision from Aqua chain".to_string());

            let e = save_page_data(
                &updated_tree,
                &aqua_chain_file_path,
                "chain.modified.json".to_string(),
            );

            if e.is_err() {
                logs_data.push(format!("Error saving page data: {:#?}", e.err()));
            }
        }
        Err(err) => {
            logs_data.push("❌ Error removing revision".to_string());
            logs_data.extend(format_method_error(&err));
        }
    }

    oprataion_logs_and_dumps(args, logs_data);
}

/// Generates an Aqua chain (genesis revision) from a given file.
pub fn cli_generate_aqua_chain(args: CliArgs, aquafier: &Aquafier) {
    let mut logs_data: Vec<String> = Vec::new();

    if let Some(file_path) = args.clone().file {
        if let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) {
            match fs::read(&file_path) {
                Ok(file_content) => {
                    let file_data =
                        FileData::new(file_name.to_string(), file_content, file_path.clone());

                    let genesis_result = if args.minimal {
                        aquafier.create_minimal_genesis_revision(file_data, None)
                    } else {
                        aquafier.create_genesis_revision(file_data, None)
                    };
                    match genesis_result {
                        Ok(tree) => {
                            logs_data.push("✅ Successfully generated Aqua chain".to_string());

                            let e = save_page_data(&tree, &file_path, "aqua.json".to_string());

                            if e.is_err() {
                                logs_data.push(format!("Error saving page data: {:#?}", e.err()));
                            }
                        }
                        Err(err) => {
                            logs_data.push("❌ Error generating Aqua chain".to_string());
                            logs_data.extend(format_method_error(&err));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read file bytes: {}", e);
                    logs_data.push("❌ failed to read file".to_string());
                }
            }
        } else {
            eprintln!("Error: Invalid file path provided with -f/--file");
            logs_data.push("❌ Invalid file path provided with -f/--file".to_string());
        }
    } else {
        tracing::error!("Failed to generate Aqua file, check file path");
        logs_data.push("❌ Invalid file, check file path".to_string());
    }

    oprataion_logs_and_dumps(args, logs_data);
}
