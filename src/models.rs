use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CliArgs {
    pub authenticate: Option<PathBuf>,
    pub sign: Option<PathBuf>,
    pub witness: Option<PathBuf>,
    pub file: Option<PathBuf>,
    pub remove: Option<PathBuf>,
    pub remove_count: i32,
    pub verbose: bool,
    pub output: Option<PathBuf>,
    pub level: Option<String>,
    pub keys_file: Option<PathBuf>,
}
