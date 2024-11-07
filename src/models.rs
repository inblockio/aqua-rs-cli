// use crate::utils::{check_if_page_data_revision_are_okay, compute_content_hash};
use aqua_verifier_rs_types::models::page_data::HashChain;
use serde::{Deserialize, Serialize};
// use std::fs;
// use std::path::Path;
// extern crate serde_json_path_to_error as serde_json;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PageDataContainer {
    pub pages: Vec<HashChain>,
}

// pub struct FileValidator {
//     file_path: String,
// }

// impl FileValidator {
//     pub fn new(file_path: String) -> Self {
//         Self { file_path }
//     }

//     pub fn validate(&self) -> Result<(bool, Vec<String>), Vec<String>> {
//         let path = Path::new(&self.file_path);
//         let mut log_data: Vec<String> = Vec::new();

//         if !path.exists() {
//             log_data.push("Error: File does not exist".to_string());
//             return Err(log_data);
//         } else {
//             log_data.push("Success: File exists".to_string());
//         }

//         let data_file = fs::read(path);
//         if let Err(e) = data_file {
//             log_data.push(format!("Error: Unable to read file - {}", e));
//             return Err(log_data);
//         } else {
//             log_data.push("Success: File read successfully".to_string());
//         }

//         let data = data_file.unwrap();

//         match serde_json::from_slice::<PageDataContainer<HashChain>>(&data) {
//             Ok(parsed_data) => {
//                 log_data.push("Success: File JSON parsed successfully".to_string());

//                 let mut matches = true;
//                 let mut failure_reason = String::new();
//                 let parsed_data_chain = match parsed_data.pages.get(0) {
//                     Some(chain) => chain,
//                     None => {
//                         log_data.push("Error: No pages found in JSON data".to_string());
//                         return Err(log_data);
//                     }
//                 };
//                 log_data.push("Success: Aqua chain  obtained successfully".to_string());

//                 if parsed_data_chain.revisions.len() == 1 {
//                     log_data.push("Info: chain contains only one revision".to_string());

//                     let result = parsed_data_chain.revisions.first();

//                     if result.is_none() {
//                         log_data.push("Errror : First revision not found".to_string());
//                         return Err(log_data);
//                     } else {
//                         log_data.push("Success : First revision found".to_string());
//                     }

//                     let (_, revision) = result.unwrap();

//                     // Recompute the content hash for the revision
//                     match compute_content_hash(&revision.content) {
//                         Ok(computed_hash) => {
//                             if computed_hash == revision.content.content_hash {
//                                 matches = true;
//                                 log_data.push("Success: Content hash matches".to_string());
//                             } else {
//                                 matches = false;
//                                 failure_reason = format!(
//                                     "Hash mismatch: Expected {:?}, got {:?}",
//                                     revision.content.content_hash, computed_hash
//                                 );
//                                 log_data.push(format!("Error: {}", failure_reason));
//                             }
//                         }
//                         Err(err) => {
//                             log_data
//                                 .push(format!("Error: Recomputing content hash failed - {}", err));
//                             return Err(log_data);
//                         }
//                     }
//                 } else {
//                     log_data.push("Info: Found multiple Revisions.".to_string());

//                     let (rev_matches, reason) = check_if_page_data_revision_are_okay(
//                         parsed_data_chain.revisions.clone(),
//                         &mut log_data,
//                     );
//                     matches = rev_matches;
//                     if matches {
//                         log_data.push("Success: Revisions are valid".to_string());
//                     } else {
//                         failure_reason = reason;
//                         log_data.push(format!("Error: Verification failed - {}", failure_reason));
//                     }
//                 }

//                 log_data.push("Info: Completed revision checks".to_string());

//                 if matches {
//                     log_data.push("Success: AQUA Chain is valid".to_string());
//                     Ok((true, log_data))
//                 } else {
//                     log_data.push("Error: Validation failed".to_string());
//                     Ok((false, log_data))
//                 }
//             }
//             Err(e) => {
//                 log_data.push(format!("Error: Failed to parse JSON - {:?}", e));
//                 Err(log_data)
//             }
//         }
//     }
// }
