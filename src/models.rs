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
    pub verify: Option<PathBuf>,
    pub sign: Option<PathBuf>,
    pub witness: Option<PathBuf>,
    pub file: Option<PathBuf>,
    pub details: bool,
    pub output: Option<PathBuf>,
    pub level: Option<String>,
    pub keys_file: Option<PathBuf>,
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
pub struct SignMessage {
    pub message: String,
    pub nonce: String,
}

#[derive(Debug, Serialize)]
pub struct ResponseMessage {
    pub status: String,
}