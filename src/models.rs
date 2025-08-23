use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// CLI argument structure - updated for v3
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
    // New v3 features
    pub content: bool,
    pub form: Option<PathBuf>,
    pub link: Option<PathBuf>,
    pub revision_type: Option<String>,
}

// Secret keys for wallet operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeys {
    pub mnemonic: Option<String>,
    pub nostr_sk: Option<String>,
    #[serde(rename = "did:key")]
    pub did_key: Option<String>,
}

// Network communication structures
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
    pub merkle_root: Option<String>,
    pub timestamp: Option<i64>,
    pub smart_contract_address: Option<String>,
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
    pub status: String,
}

// Base fields common to all revisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseRevision {
    pub previous_verification_hash: String,
    pub local_timestamp: String,
    pub revision_type: String,
    pub version: String,
}

// File Revision (can include content)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub content: Option<String>,
    pub file_hash: String,
    pub file_nonce: String,
}

// Content Revision (reference only, no embedded content)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub file_hash: String,
    pub file_nonce: String,
}

// Form Revision (for identity and layer 2 applications)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub file_hash: String,
    pub file_nonce: String,
    pub forms_type: String,
    pub forms_name: Option<String>,
    pub forms_surname: Option<String>,
    pub forms_email: Option<String>,
    pub forms_date_of_birth: Option<String>,
    pub forms_wallet_address: Option<String>,
    pub leaves: Option<Vec<String>>, // For tree verification method
}

// Signature Revision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub signature: String,
    pub signature_public_key: String,
    pub signature_wallet_address: String,
    pub signature_type: String, // e.g., "ethereum:eip-191", "did_key"
}

// Witness Revision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub witness_merkle_root: Option<String>,
    pub witness_timestamp: Option<i64>,
    pub witness_network: String, // "mainnet", "sepolia", "nostr", "TSA_RFC3161"
    pub witness_smart_contract_address: Option<String>,
    pub witness_transaction_hash: Option<String>,
    pub witness_sender_account_address: Option<String>,
    pub witness_merkle_proof: Option<Vec<String>>,
}

// Link Revision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub link_type: String, // e.g., "aqua"
    pub link_verification_hashes: Vec<String>,
    pub link_file_hashes: Vec<String>,
}

// Tree structure for hierarchical organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    pub hash: String,
    pub children: Vec<TreeNode>,
}

// Tree mapping for path tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeMapping {
    pub paths: HashMap<String, Vec<String>>,
    #[serde(rename = "latestHash")]
    pub latest_hash: String,
}

// Complete Aqua Tree structure (v3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AquaTree {
    pub revisions: HashMap<String, serde_json::Value>, // Generic storage for different revision types
    pub file_index: HashMap<String, String>,           // Maps revision hashes to filenames
    #[serde(rename = "treeMapping")]
    pub tree_mapping: TreeMapping, // Path tracking and latest hash
}

// Legacy v2 structures for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyPageData {
    pub pages: Vec<serde_json::Value>,
}

// Utility enums for validation
#[derive(Debug, Clone, PartialEq)]
pub enum RevisionType {
    File,
    Content,
    Form,
    Signature,
    Witness,
    Link,
}

impl RevisionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevisionType::File => "file",
            RevisionType::Content => "content",
            RevisionType::Form => "form",
            RevisionType::Signature => "signature",
            RevisionType::Witness => "witness",
            RevisionType::Link => "link",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "file" => Some(RevisionType::File),
            "content" => Some(RevisionType::Content),
            "form" => Some(RevisionType::Form),
            "signature" => Some(RevisionType::Signature),
            "witness" => Some(RevisionType::Witness),
            "link" => Some(RevisionType::Link),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashingMethod {
    Scalar,
    Tree,
}

impl HashingMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashingMethod::Scalar => "scalar",
            HashingMethod::Tree => "tree",
        }
    }
}

// Validation constants
pub const SCHEMA_V3_BASE_URL: &str = "https://aqua-protocol.org/docs/v3/schema_2";
pub const SUPPORTED_SIGNATURE_TYPES: &[&str] = &["ethereum:eip-191", "did_key"];
pub const SUPPORTED_WITNESS_NETWORKS: &[&str] = &["mainnet", "sepolia", "nostr", "TSA_RFC3161"];

// Utility function to create version string
pub fn create_version_string(method: HashingMethod) -> String {
    format!(
        "{} | SHA256 | Method: {}",
        SCHEMA_V3_BASE_URL,
        method.as_str()
    )
}

// Error types for validation
#[derive(Debug, Clone)]
pub enum ValidationError {
    InvalidVersion(String),
    MissingRequiredField(String),
    InvalidFileHash,
    InvalidSignature,
    InvalidWitness,
    InvalidSignatureType(String),
    InvalidWitnessNetwork(String),
    InvalidFileIndex,
    InvalidPreviousHash,
    InvalidLinkRevision,
    LoopDetected,
    ForkDetected,
    InvalidTimestampOrder,
    InvalidRevision(String),
    UnsupportedRevisionType(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidVersion(v) => write!(f, "Invalid version: {}", v),
            ValidationError::MissingRequiredField(field) => {
                write!(f, "Missing required field: {}", field)
            }
            ValidationError::InvalidFileHash => write!(f, "Invalid file hash"),
            ValidationError::InvalidSignature => write!(f, "Invalid signature"),
            ValidationError::InvalidWitness => write!(f, "Invalid witness"),
            ValidationError::InvalidSignatureType(t) => write!(f, "Invalid signature type: {}", t),
            ValidationError::InvalidWitnessNetwork(n) => {
                write!(f, "Invalid witness network: {}", n)
            }
            ValidationError::InvalidFileIndex => write!(f, "Invalid file index"),
            ValidationError::InvalidPreviousHash => write!(f, "Invalid previous hash"),
            ValidationError::InvalidLinkRevision => write!(f, "Invalid link revision"),
            ValidationError::LoopDetected => write!(f, "Loop detected in revision chain"),
            ValidationError::ForkDetected => write!(f, "Fork detected in revision chain"),
            ValidationError::InvalidTimestampOrder => write!(f, "Invalid timestamp order"),
            ValidationError::InvalidRevision(msg) => write!(f, "Invalid revision: {}", msg),
            ValidationError::UnsupportedRevisionType(t) => {
                write!(f, "Unsupported revision type: {}", t)
            }
        }
    }
}

impl std::error::Error for ValidationError {}
