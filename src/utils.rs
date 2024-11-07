use std::{fs::{self, OpenOptions}, path::{Path, PathBuf}};
use std::io::Write;
use aqua_verifier_rs_types::models::page_data::PageData;


extern crate serde_json_path_to_error as serde_json;

pub fn save_logs_to_file(logs : &Vec<String>, output_file : PathBuf, ) -> Result<String, String> {


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

pub fn read_aqua_data(path: &PathBuf) -> Result<PageData, String> {
    let data = fs::read_to_string(path);
    match data {
        Ok(data) =>{
            let res= serde_json::from_str::<PageData>(&data);
            match res {
                Ok(res_data)=>{
                    Ok(res_data)
                }
                Err(err_data)=>{
                    return Err(format!("Error, parsing json {}", err_data));
                }
            }
        }
        Err(e)=>{
            return Err(format!("Error , {}", e));
        }
    }
}


// Assuming `PageData` has serde::Serialize trait implemented
pub fn save_page_data(aqua_page_data: &PageData, original_path: &Path, extension : String) -> Result<(), String> {
    // Change the file extension to "_signed.json"
    let output_path = original_path.with_extension(extension);

    // Serialize PageData to JSON
    match serde_json::to_string_pretty(aqua_page_data) {
        Ok(json_data) => {
            // Write JSON data to the new file
            fs::write(&output_path, json_data).map_err(|e| e.to_string())?;
            println!("Page data saved to: {:?}", output_path);
            Ok(())
        }
        Err(e) => Err(format!("Error serializing PageData: {}", e)),
    }
}