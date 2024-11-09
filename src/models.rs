use std::path::PathBuf;


#[derive(Debug, Clone)]
pub struct CliArgs {
    pub verify: Option<PathBuf>,
    pub sign: Option<PathBuf>,
    pub witness: Option<PathBuf>,
    pub file: Option<PathBuf>,
    pub details: bool,
    pub output: Option<PathBuf>,
    pub level: Option<String>,
    pub alchemy: Option<String>,
}