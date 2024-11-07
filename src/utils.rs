use std::{fs, path::PathBuf};

use aqua_verifier_rs_types::models::page_data::{HashChain, PageData};


extern crate serde_json_path_to_error as serde_json;

pub fn save_logs_to_file(logs : Vec<String>, output_file : PathBuf, ) -> Result<String, String> {

    return Ok("log written".to_string());
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