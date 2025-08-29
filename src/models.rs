use std::path::PathBuf;
use serde::{Deserialize, Serialize};



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecreatKeys {

    pub mnemonic: Option<String>,
    pub nostr_sk: Option<String>,
    #[serde(rename = "did:key")]
    pub did_key: Option<String>,

}
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
    // New v3.2 fields
    pub link: Option<PathBuf>,
    pub target: Option<PathBuf>,
    pub link_type: Option<String>,
    pub identity_form: Option<PathBuf>,
    pub domain_id: Option<String>,
    pub form_type: Option<String>,
    pub validate_v3: Option<PathBuf>,
    pub compliance_level: Option<String>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignPayload {
   pub signature: String,
   pub  public_key: String,
   pub  wallet_address: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WitnessPayload {
   pub tx_hash: String,
   pub  network: String,
   pub  wallet_address: String,
}

#[derive(Debug, Serialize)]
pub struct SignOrWitnessNetwork {
    pub network: String,
    
}

#[derive(Debug, Serialize)]
pub struct SignMessage {
    pub message: String,
    pub nonce: String,
}

#[derive(Debug, Serialize)]
pub struct ResponseMessage {
    pub status: String,
}