// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Verification helpers for SIM-2 scenarios.
//!
//! Thin wrappers around the SDK verify calls that return structured results
//! compatible with the SIM-2 reporting format.

use std::collections::HashMap;
use std::sync::Arc;

use aqua_rs_sdk::{
    primitives::{Method, MethodError, RevisionLink},
    schema::{
        template::BuiltInTemplate,
        templates,
        tree::Tree,
        AquaTreeWrapper, SigningCredentials,
    },
    Aquafier, DefaultTrustStore,
};

use crate::simulation::builders;
use crate::simulation::keygen;
use crate::simulation::scenarios::extract_state;

// ─────────────────────────────────────────────────────────────────────────────
// Shared attestors (3 institutional identities used across all personas)
// ─────────────────────────────────────────────────────────────────────────────

/// Three institutional attestor identities shared across all SIM-2 personas.
pub struct Attestors {
    /// Government — Ed25519 key, official document attestations
    pub gov_priv: Vec<u8>,
    pub gov_did: String,
    /// inblock.io — P-256 key, platform/tech attestations
    pub inblock_priv: Vec<u8>,
    pub inblock_did: String,
    /// Linux Foundation — secp256k1/EIP-191 key, open-source/community attestations
    pub lf_priv: Vec<u8>,
    pub lf_did: String,
}

impl Attestors {
    /// Generate fresh keys for all 3 attestors.
    pub fn generate() -> Self {
        let (gov_priv, gov_did) = keygen::generate_ed25519();
        let (inblock_priv, inblock_did) = keygen::generate_p256();
        let (lf_priv, lf_did) = keygen::generate_secp256k1();
        Self { gov_priv, gov_did, inblock_priv, inblock_did, lf_priv, lf_did }
    }
}

/// Result of a single SIM-2 scenario.
#[derive(Debug)]
pub struct Sim2Result {
    pub persona: &'static str,
    pub scenario_id: String,
    pub claim_type: &'static str,
    pub description: String,
    pub expected_state: &'static str,
    pub actual_state: Option<String>,
    pub is_sub_condition: bool,
    pub passed: bool,
    pub error: Option<String>,
    pub raw_wasm_outputs: Vec<serde_json::Value>,
    pub trees: Vec<(String, Tree)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Aquafier factories
// ─────────────────────────────────────────────────────────────────────────────

/// Build an `Aquafier` with a single trusted DID at the given level.
pub fn trust_one(did: &str, level: u8) -> Aquafier {
    let mut map = HashMap::new();
    map.insert(did.to_string(), level);
    Aquafier::builder()
        .trust_store(Arc::new(DefaultTrustStore::new(map)))
        .build()
}

/// Build an `Aquafier` with an explicit but empty trust store.
pub fn no_trust() -> Aquafier {
    Aquafier::builder()
        .trust_store(Arc::new(DefaultTrustStore::new(HashMap::new())))
        .build()
}


// ─────────────────────────────────────────────────────────────────────────────
// Claim tree helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a genesis claim tree from a template hash constant and JSON payload.
pub fn build_claim_raw(
    aq: &Aquafier,
    template_hash: [u8; 32],
    payload: serde_json::Value,
) -> Result<Tree, MethodError> {
    let link = RevisionLink::from_bytes(template_hash);
    aq.create_object(link, None, payload, Some(Method::Scalar))
}

/// Normal (tip-appended) Ed25519 signature.
pub async fn self_sign_ed25519(aq: &Aquafier, tree: Tree, priv_key: &[u8]) -> Result<Tree, MethodError> {
    builders::sign_ed25519(aq, tree, priv_key).await
}

/// Normal (tip-appended) P-256 signature.
pub async fn self_sign_p256(aq: &Aquafier, tree: Tree, priv_key: &[u8]) -> Result<Tree, MethodError> {
    builders::sign_p256(aq, tree, priv_key).await
}

/// Normal (tip-appended) secp256k1/EIP-191 signature.
pub async fn self_sign_secp256k1(aq: &Aquafier, tree: Tree, priv_key: &[u8]) -> Result<Tree, MethodError> {
    builders::sign_secp256k1(aq, tree, priv_key).await
}

/// Parallel Ed25519 signature branching off `target`.
pub async fn parallel_sign_ed25519(
    aq: &Aquafier,
    tree: Tree,
    priv_key: &[u8],
    target: RevisionLink,
) -> Result<Tree, MethodError> {
    let wrapper = AquaTreeWrapper::new(tree, None, Some(target));
    let creds = SigningCredentials::Did {
        did_key: priv_key.to_vec(),
    };
    let op = aq.sign_aqua_tree(wrapper, &creds, None, None).await?;
    Ok(op.aqua_tree)
}

/// Parallel P-256 signature branching off `target`.
pub async fn parallel_sign_p256(
    aq: &Aquafier,
    tree: Tree,
    priv_key: &[u8],
    target: RevisionLink,
) -> Result<Tree, MethodError> {
    let wrapper = AquaTreeWrapper::new(tree, None, Some(target));
    let creds = SigningCredentials::P256 {
        p256_key: priv_key.to_vec(),
    };
    let op = aq.sign_aqua_tree(wrapper, &creds, None, None).await?;
    Ok(op.aqua_tree)
}

/// Parallel secp256k1/EIP-191 signature branching off `target`.
pub async fn parallel_sign_secp256k1(
    aq: &Aquafier,
    tree: Tree,
    priv_key: &[u8],
    target: RevisionLink,
) -> Result<Tree, MethodError> {
    let wrapper = AquaTreeWrapper::new(tree, None, Some(target));
    let creds = SigningCredentials::Secp256k1 {
        secp256k1_key: priv_key.to_vec(),
    };
    let op = aq.sign_aqua_tree(wrapper, &creds, None, None).await?;
    Ok(op.aqua_tree)
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a standalone claim tree (IdentityBase WASM).
pub async fn verify_claim(
    aq: &Aquafier,
    tree: Tree,
) -> Result<(Option<String>, Vec<serde_json::Value>), MethodError> {
    let wrapper = AquaTreeWrapper::new(tree, None, None);
    let (result, _) = aq.verify_and_build_state(wrapper, vec![]).await?;
    let state = extract_state(&result);
    let raw = result.wasm_outputs.values().cloned().collect();
    Ok((state, raw))
}

/// Verify an attestation tree with the claim provided as a linked tree (two-tree model).
pub async fn verify_attestation(
    aq: &Aquafier,
    attest_tree: Tree,
    claim_tree: Tree,
) -> Result<(Option<String>, Vec<serde_json::Value>), MethodError> {
    let attest_w = AquaTreeWrapper::new(attest_tree, None, None);
    let claim_w = AquaTreeWrapper::new(claim_tree, None, None);
    let (result, _) = aq
        .verify_and_build_state_with_linked_trees(attest_w, vec![claim_w], vec![])
        .await?;
    let state = extract_state(&result);
    let raw = result.wasm_outputs.values().cloned().collect();
    Ok((state, raw))
}

/// Verify a headless attestation (no linked trees).
pub async fn verify_headless_attestation(
    aq: &Aquafier,
    attest_tree: Tree,
) -> Result<(Option<String>, Vec<serde_json::Value>), MethodError> {
    let wrapper = AquaTreeWrapper::new(attest_tree, None, None);
    let (result, _) = aq
        .verify_and_build_state_with_linked_trees(wrapper, vec![], vec![])
        .await?;
    let state = extract_state(&result);
    let raw = result.wasm_outputs.values().cloned().collect();
    Ok((state, raw))
}

// ─────────────────────────────────────────────────────────────────────────────
// Error constructor
// ─────────────────────────────────────────────────────────────────────────────

pub fn make_err(
    persona: &'static str,
    scenario_id: String,
    claim_type: &'static str,
    description: String,
    expected_state: &'static str,
    is_sub_condition: bool,
    e: impl std::fmt::Display,
) -> Sim2Result {
    Sim2Result {
        persona,
        scenario_id,
        claim_type,
        description,
        expected_state,
        actual_state: None,
        is_sub_condition,
        passed: false,
        error: Some(e.to_string()),
        raw_wasm_outputs: vec![],
        trees: vec![],
    }
}

/// Map claim type name → template tree chain for output.
pub fn template_trees_for_claim_type(claim_type: &str) -> Vec<(String, Tree)> {
    let hash: Option<[u8; 32]> = match claim_type {
        "GitHubClaim" => Some(templates::GitHubClaim::TEMPLATE_LINK),
        "EmailClaim" => Some(templates::EmailClaim::TEMPLATE_LINK),
        "NameClaim" => Some(templates::NameClaim::TEMPLATE_LINK),
        "GoogleClaim" => Some(templates::GoogleClaim::TEMPLATE_LINK),
        "PhoneClaim" => Some(templates::PhoneClaim::TEMPLATE_LINK),
        "AddressClaim" => Some(templates::AddressClaim::TEMPLATE_LINK),
        "DnsClaim" => Some(templates::DnsClaim::TEMPLATE_LINK),
        "PassportClaim" => Some(templates::PassportClaim::TEMPLATE_LINK),
        "BirthdateClaim" => Some(templates::BirthdateClaim::TEMPLATE_LINK),
        "AgeClaim" => Some(templates::AgeClaim::TEMPLATE_LINK),
        "DriversLicenseClaim" => Some(templates::DriversLicenseClaim::TEMPLATE_LINK),
        "NationalIdClaim" => Some(templates::NationalIdClaim::TEMPLATE_LINK),
        "PlatformIdentityClaim" => Some(templates::PlatformIdentityClaim::TEMPLATE_LINK),
        "DocumentClaim" => Some(templates::DocumentClaim::TEMPLATE_LINK),
        "Attestation" => Some(templates::Attestation::TEMPLATE_LINK),
        _ => None,
    };
    match hash {
        Some(h) => builders::template_trees_for(&h),
        None => vec![],
    }
}
