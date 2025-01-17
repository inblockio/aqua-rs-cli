use aqua_verifier::model::{signature::SignatureType, witness::WitnessType};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CliArgs {
    pub authenticate: Option<PathBuf>,
    pub sign: Option<PathBuf>,
    pub sign_type: Option<SignatureType>,
    pub witness: Option<PathBuf>,
    pub witness_type: Option<WitnessType>,
    pub file: Option<PathBuf>,
    pub verbose: bool,
    pub output: Option<PathBuf>,
    pub level: Option<String>,
    pub keys_file: Option<PathBuf>,
    pub scalar :  Option<PathBuf>,
    pub link: Option<Vec<PathBuf>>,
    pub delete: Option<PathBuf>,
    pub info: bool
    
}



