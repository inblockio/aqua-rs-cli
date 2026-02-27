// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Raw tree builders for the simulation scenarios.
//!
//! Deliberately uses the lowest-level public SDK API to surface friction points.
//! Friction points are documented with `// FRICTION:` comments.

use aqua_rs_sdk::{
    schema::{
        template::BuiltInTemplate,
        templates::{Attestation, PlatformIdentityClaim, TrustAssertion},
        Anchor, AnyRevision,
        AquaTreeWrapper, SigningCredentials,
        tree::Tree,
    },
    primitives::{HashType, Method, RevisionLink},
    verification::Linkable,
    Aquafier,
};

/// Parse a `[u8; 32]` template hash into a `RevisionLink`.
///
/// # FRICTION
/// `RevisionLink::new()` is `pub(crate)`.  The only public construction path
/// for external callers is `FromStr` via a hex string.  This incurs a
/// runtime allocation + parse even for compile-time constant hashes.
fn template_link(hash: [u8; 32]) -> RevisionLink {
    format!("0x{}", hex::encode(hash))
        .parse()
        .expect("constant template hash is always valid hex")
}

/// Build a `PlatformIdentityClaim` genesis tree (unsigned).
///
/// # FRICTION
/// No typed convenience API for constructing claim payloads: callers must
/// manually serialize `PlatformIdentityClaim` struct to `serde_json::Value`
/// and pass the raw template hash.  A `Aquafier::create_identity_claim()`
/// helper exists behind `#[cfg(feature = "identity")]` but that feature
/// requires full identity provider infrastructure, not raw key material.
pub fn build_claim_tree(
    aquafier: &Aquafier,
    claimer_did: &str,
    valid_from: Option<u64>,
    valid_until: Option<u64>,
) -> Result<Tree, aqua_rs_sdk::primitives::MethodError> {
    let template_hash = template_link(PlatformIdentityClaim::TEMPLATE_LINK);
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
    let payload = serde_json::to_value(&claim)
        .map_err(|e| aqua_rs_sdk::primitives::MethodError::Simple(e.to_string()))?;
    aquafier.create_object(template_hash, None, payload, Some(Method::Scalar))
}

/// Sign a tree with an Ed25519 key (`did:pkh:ed25519`).
pub async fn sign_ed25519(
    aquafier: &Aquafier,
    tree: Tree,
    private_key: &[u8],
) -> Result<Tree, aqua_rs_sdk::primitives::MethodError> {
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
) -> Result<Tree, aqua_rs_sdk::primitives::MethodError> {
    let wrapper = AquaTreeWrapper::new(tree, None, None);
    let creds = SigningCredentials::P256 {
        p256_key: private_key.to_vec(),
    };
    let op = aquafier.sign_aqua_tree(wrapper, &creds, None, None).await?;
    Ok(op.aqua_tree)
}

/// Build an `Attestation` genesis tree (unsigned, no cross-tree link yet).
///
/// # FRICTION
/// `Attestation` (called `Claim` in attestation.rs) requires a `context` field
/// but the spec doesn't define whether this should be the claim hash or a string.
/// No SDK API documents the expected `context` format for WASM verification.
pub fn build_attestation_tree(
    aquafier: &Aquafier,
    attester_did: &str,
    context: &str,
    valid_from: Option<u64>,
    valid_until: Option<u64>,
) -> Result<Tree, aqua_rs_sdk::primitives::MethodError> {
    let template_hash = template_link(Attestation::TEMPLATE_LINK);
    let attest = Attestation {
        context: context.to_string(),
        signer_did: attester_did.to_string(),
        valid_from,
        valid_until,
    };
    let payload = serde_json::to_value(&attest)
        .map_err(|e| aqua_rs_sdk::primitives::MethodError::Simple(e.to_string()))?;
    aquafier.create_object(template_hash, None, payload, Some(Method::Scalar))
}

/// Link an attestation tree to a claim tree.
///
/// Uses `Aquafier::link_aqua_tree()` to append an Anchor revision in the
/// attestation tree that references the claim tree's latest revision hash.
pub fn link_attestation_to_claim(
    aquafier: &Aquafier,
    attest_tree: Tree,
    claim_tree: Tree,
) -> Result<Tree, aqua_rs_sdk::primitives::MethodError> {
    let attest_wrapper = AquaTreeWrapper::new(attest_tree, None, None);
    let claim_wrapper = AquaTreeWrapper::new(claim_tree, None, None);
    aquafier.link_aqua_tree(attest_wrapper, vec![claim_wrapper], None)
}

/// Build a "headless" attestation tree: an attestation whose anchor links to
/// a nonexistent hash, so the link cannot be resolved (A1 scenario).
///
/// # FRICTION
/// No public SDK API for "creating an anchor that references a hash not in scope."
/// We must drop to `schema::Anchor` + `verification::Linkable` directly and
/// manually mutate `Tree::revisions`.  This exposes internal representation
/// details that ideally should be abstracted by an SDK builder.
pub fn build_headless_attestation_tree(
    aquafier: &Aquafier,
    attester_did: &str,
) -> Result<Tree, aqua_rs_sdk::primitives::MethodError> {
    // 1. Build the attestation object tree normally.
    let attest_tree = build_attestation_tree(aquafier, attester_did, "headless-context", None, None)?;

    // 2. Get the latest (object) revision hash to chain the anchor from.
    let latest = attest_tree
        .get_latest_revision_link()
        .ok_or_else(|| aqua_rs_sdk::primitives::MethodError::Simple("empty attestation tree".into()))?;

    // 3. Create an anchor that links to a nonexistent hash.
    //    The fake hash is 32 zero bytes — guaranteed not to exist in any tree.
    //
    // FRICTION: `RevisionLink::new()` is `pub(crate)`, so we must parse from hex.
    let fake_hash: RevisionLink = format!("0x{}", "00".repeat(32))
        .parse()
        .expect("zero hash is valid hex");

    let headless_anchor = Anchor::new(
        latest,
        Method::Scalar,
        HashType::Sha3_256,
        vec![fake_hash],
    );
    let anchor_hash = headless_anchor.calculate_link()?;
    // populate_leaves is only needed for Method::Tree; skip for Scalar.

    // 4. Append the anchor to the tree.
    let mut revisions = attest_tree.revisions.clone();
    let mut file_index = attest_tree.file_index.clone();
    let anchor_name = format!("anchor_{}", &anchor_hash.to_string()[2..10]);
    revisions.insert(anchor_hash.clone(), AnyRevision::Anchor(headless_anchor));
    file_index.insert(anchor_hash, anchor_name);

    Ok(Tree { revisions, file_index })
}

/// Build a `TrustAssertion` tree asserting `trust_level` for `subject_did`.
pub fn build_trust_assertion_tree(
    aquafier: &Aquafier,
    asserter_did: &str,
    subject_did: &str,
    trust_level: u8,
) -> Result<Tree, aqua_rs_sdk::primitives::MethodError> {
    let _ = asserter_did; // included for doc clarity; assertion is unsigned here
    let template_hash = template_link(TrustAssertion::TEMPLATE_LINK);
    let ta = TrustAssertion {
        subject_did: subject_did.to_string(),
        trust_level,
        distrust: None,
        domains: None,
        reason: Some("simulation".to_string()),
    };
    let payload = serde_json::to_value(&ta)
        .map_err(|e| aqua_rs_sdk::primitives::MethodError::Simple(e.to_string()))?;
    aquafier.create_object(template_hash, None, payload, Some(Method::Scalar))
}
