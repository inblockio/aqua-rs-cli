use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeys {
    pub mnemonic: Option<String>,
    pub nostr_sk: Option<String>,
    #[serde(rename = "did:key")]
    pub did_key: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub content: Option<String>,
    pub form: Option<String>,
    pub link: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignPayload {
    pub signature: String,
    pub public_key: String,
    pub wallet_address: String,
    pub signature_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WitnessPayload {
    pub tx_hash: String,
    pub network: String,
    pub wallet_address: String,
    pub merkle_proof: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignOrWitnessNetwork {
    pub network: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessage {
    pub message: String,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseMessage {
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileRevision {
    pub previous_verification_hash: String,
    pub local_timestamp: String,
    pub revision_type: String,
    pub content: Option<String>,
    pub file_hash: String,
    pub file_nonce: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContentRevision {
    pub previous_verification_hash: String,
    pub local_timestamp: String,
    pub revision_type: String,
    pub file_hash: String,
    pub file_nonce: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FormRevision {
    pub previous_verification_hash: String,
    pub local_timestamp: String,
    pub revision_type: String,
    pub file_hash: String,
    pub file_nonce: String,
    pub version: String,
    pub forms_type: String,
    pub forms_name: Option<String>,
    pub forms_surname: Option<String>,
    pub forms_email: Option<String>,
    pub forms_date_of_birth: Option<String>,
    pub forms_wallet_address: Option<String>,
    pub leaves: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignatureRevision {
    pub previous_verification_hash: String,
    pub local_timestamp: String,
    pub revision_type: String,
    pub signature: String,
    pub signature_public_key: String,
    pub signature_wallet_address: String,
    pub signature_type: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WitnessRevision {
    pub previous_verification_hash: String,
    pub local_timestamp: String,
    pub revision_type: String,
    pub version: String,
    pub witness_merkle_root: Option<String>,
    pub witness_timestamp: Option<i64>,
    pub witness_network: String,
    pub witness_smart_contract_address: Option<String>,
    pub witness_transaction_hash: Option<String>,
    pub witness_sender_account_address: Option<String>,
    pub witness_merkle_proof: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LinkRevision {
    pub previous_verification_hash: String,
    pub local_timestamp: String,
    pub revision_type: String,
    pub version: String,
    pub link_type: String,
    pub link_verification_hashes: Vec<String>,
    pub link_file_hashes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TreeNode {
    pub hash: String,
    pub children: Vec<TreeNode>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TreeMapping {
    pub paths: HashMap<String, Vec<String>>,
    pub latest_hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AquaTree {
    pub revisions: HashMap<String, serde_json::Value>,
    pub file_index: HashMap<String, String>,
    pub tree_mapping: TreeMapping,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ValidationError {
    InvalidVersion,
    MissingRequiredField(String),
    InvalidFileHash,
    InvalidSignature,
    InvalidWitness,
    InvalidSignatureType,
    InvalidWitnessNetwork,
    InvalidFileIndex,
    InvalidPreviousHash,
    InvalidLinkRevision,
    LoopDetected,
    ForkDetected,
    InvalidTimestampOrder,
}
