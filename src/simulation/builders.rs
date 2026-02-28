// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Tree builders for the simulation scenarios.

use aqua_rs_sdk::{
    primitives::{Method, MethodError, RevisionLink},
    schema::{
        template::BuiltInTemplate,
        templates::{Attestation, PlatformIdentityClaim, TrustAssertion},
        tree::Tree,
        AquaTreeWrapper, SigningCredentials,
    },
    Aquafier,
};

/// Build a `PlatformIdentityClaim` genesis tree (unsigned).
pub fn build_claim_tree(
    aquafier: &Aquafier,
    claimer_did: &str,
    valid_from: Option<u64>,
    valid_until: Option<u64>,
) -> Result<Tree, MethodError> {
    let claim = PlatformIdentityClaim {
        signer_did: claimer_did.to_string(),
        provider: "email".to_string(),
        provider_id: "sim-12345".to_string(),
        display_name: "sim-user".to_string(),
        email: None,
        proof_url: None,
        valid_from,
        valid_until,
        metadata: None,
    };
    aquafier.create_identity_claim(None, claim, Some(Method::Scalar))
}

/// Sign a tree with an Ed25519 key (`did:pkh:ed25519`).
pub async fn sign_ed25519(
    aquafier: &Aquafier,
    tree: Tree,
    private_key: &[u8],
) -> Result<Tree, MethodError> {
    let wrapper = AquaTreeWrapper::new(tree, None, None);
    let creds = SigningCredentials::Did {
        did_key: private_key.to_vec(),
    };
    let op = aquafier.sign_aqua_tree(wrapper, &creds, None, None).await?;
    Ok(op.aqua_tree)
}

/// Sign a tree with a P-256 key (`did:pkh:p256`).
pub async fn sign_p256(
    aquafier: &Aquafier,
    tree: Tree,
    private_key: &[u8],
) -> Result<Tree, MethodError> {
    let wrapper = AquaTreeWrapper::new(tree, None, None);
    let creds = SigningCredentials::P256 {
        p256_key: private_key.to_vec(),
    };
    let op = aquafier.sign_aqua_tree(wrapper, &creds, None, None).await?;
    Ok(op.aqua_tree)
}

/// Helper: convert a `[u8; 32]` TEMPLATE_LINK constant to a `RevisionLink`.
fn template_to_link(bytes: &[u8; 32]) -> RevisionLink {
    format!("0x{}", hex::encode(bytes))
        .parse()
        .expect("built-in TEMPLATE_LINK is always a valid RevisionLink")
}

/// Build an `Attestation` genesis tree (unsigned).
///
/// Uses `create_object` with the Attestation template hash. The `claim_sig_hash`
/// is stored in the payload context field as an informational reference.
pub fn build_attestation_tree(
    aquafier: &Aquafier,
    attester_did: &str,
    claim_sig_hash: &RevisionLink,
    claim_obj_hash: &str,
    valid_from: Option<u64>,
    valid_until: Option<u64>,
) -> Result<Tree, MethodError> {
    let attest = Attestation {
        context: claim_obj_hash.to_string(),
        signer_did: attester_did.to_string(),
        valid_from,
        valid_until,
    };
    let _ = claim_sig_hash; // structural link via genesis anchor not available in current SDK
    let payload = serde_json::to_value(&attest)?;
    let template_link = template_to_link(&Attestation::TEMPLATE_LINK);
    aquafier.create_object(template_link, None, payload, Some(Method::Scalar))
}

/// Build a "headless" attestation tree (no claim link).
pub fn build_headless_attestation_tree(
    aquafier: &Aquafier,
    attester_did: &str,
) -> Result<Tree, MethodError> {
    let attest = Attestation {
        context: "headless".to_string(),
        signer_did: attester_did.to_string(),
        valid_from: None,
        valid_until: None,
    };
    let payload = serde_json::to_value(&attest)?;
    let template_link = template_to_link(&Attestation::TEMPLATE_LINK);
    aquafier.create_object(template_link, None, payload, Some(Method::Scalar))
}

/// Build a `TrustAssertion` tree asserting `trust_level` for `subject_did`.
pub fn build_trust_assertion_tree(
    aquafier: &Aquafier,
    asserter_did: &str,
    subject_did: &str,
    trust_level: u8,
) -> Result<Tree, MethodError> {
    let _ = asserter_did; // included for doc clarity; assertion is unsigned here
    let ta = TrustAssertion {
        subject_did: subject_did.to_string(),
        trust_level,
        distrust: None,
        domains: None,
        reason: Some("simulation".to_string()),
    };
    let payload = serde_json::to_value(&ta)?;
    let template_link = template_to_link(&TrustAssertion::TEMPLATE_LINK);
    aquafier.create_object(template_link, None, payload, Some(Method::Scalar))
}
