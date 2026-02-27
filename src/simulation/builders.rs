// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Raw tree builders for the simulation scenarios.
//!
//! Deliberately uses the lowest-level public SDK API to surface friction points.
//! Friction points are documented with `// FRICTION:` comments.

use std::collections::BTreeMap;

use aqua_rs_sdk::{
    schema::{
        template::BuiltInTemplate,
        templates::{Attestation, PlatformIdentityClaim, TrustAssertion},
        Anchor, AnyRevision, Object,
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

/// Build an `Attestation` genesis tree (unsigned, not yet linked to a signer).
///
/// The genesis anchor carries `claim_sig_hash` as its sole
/// `link_verification_hashes` entry — the structural import declaring that
/// this attestation depends on that specific signed claim revision.
///
/// `claim_obj_hash` is recorded in the payload `context` field as an
/// informational string reference to the claim *object* revision (not a
/// structural link).  The object hash identifies *which* claim is being
/// attested; the signature hash (in the anchor) enforces that the claim
/// was already signed before this attestation could be constructed.
///
/// This produces a single-anchor tree:
/// ```text
/// Template (genesis)
/// Genesis Anchor (genesis, link_verification_hashes=[claim_sig_hash])
/// Attestation Object (prev=anchor)
/// ```
pub fn build_attestation_tree(
    _aquafier: &Aquafier,
    attester_did: &str,
    claim_sig_hash: &RevisionLink,
    claim_obj_hash: &str,
    valid_from: Option<u64>,
    valid_until: Option<u64>,
) -> Result<Tree, aqua_rs_sdk::primitives::MethodError> {
    let template_hash = template_link(Attestation::TEMPLATE_LINK);

    // Payload: context = claim object hash (informational ref), signer_did = attester.
    let attest = Attestation {
        context: claim_obj_hash.to_string(),
        signer_did: attester_did.to_string(),
        valid_from,
        valid_until,
    };
    let payload = serde_json::to_value(&attest)
        .map_err(|e| aqua_rs_sdk::primitives::MethodError::Simple(e.to_string()))?;

    let mut revisions: BTreeMap<RevisionLink, AnyRevision> = BTreeMap::new();
    let mut file_index: BTreeMap<RevisionLink, String> = BTreeMap::new();

    // 1. Template revision — self-describing.
    let template = Aquafier::builtin_templates()
        .get(&Attestation::TEMPLATE_LINK)
        .ok_or_else(|| aqua_rs_sdk::primitives::MethodError::Simple(
            "attestation built-in template not found".into(),
        ))?
        .clone();
    revisions.insert(template_hash.clone(), AnyRevision::Template(template));
    file_index.insert(
        template_hash.clone(),
        format!("template_{}", template_hash.to_string().chars().take(8).collect::<String>()),
    );

    // 2. Genesis anchor: structural import of the claim's signature revision.
    //    link_verification_hashes = [claim_sig_hash] — the cross-tree dependency.
    let mut anchor = Anchor::genesis(
        Method::Scalar,
        HashType::Sha3_256,
        vec![claim_sig_hash.clone()],
    );
    let anchor_hash = anchor.calculate_link()?;
    anchor.populate_leaves()?;
    file_index.insert(
        anchor_hash.clone(),
        format!("anchor_{}", anchor_hash.to_string().chars().take(8).collect::<String>()),
    );
    revisions.insert(anchor_hash.clone(), AnyRevision::Anchor(anchor));

    // 3. Attestation object chained from the genesis anchor.
    let mut object = Object::new(
        anchor_hash,
        template_hash,
        Method::Scalar,
        HashType::Sha3_256,
        payload,
    );
    let obj_hash = object.calculate_link()?;
    object.populate_leaves()?;
    file_index.insert(
        obj_hash.clone(),
        format!("object_{}", obj_hash.to_string().chars().take(8).collect::<String>()),
    );
    revisions.insert(obj_hash, AnyRevision::Object(object));

    Ok(Tree { revisions, file_index })
}

/// Build a "headless" attestation tree: genesis anchor links to a nonexistent
/// hash, so the anchor cannot be resolved (A1 scenario).
///
/// Under the correct single-anchor model this is simply `build_attestation_tree`
/// with a zero `claim_sig_hash` — structurally identical to any other
/// attestation, but the anchor target does not exist in any tree.
pub fn build_headless_attestation_tree(
    aquafier: &Aquafier,
    attester_did: &str,
) -> Result<Tree, aqua_rs_sdk::primitives::MethodError> {
    // FRICTION: `RevisionLink::new()` is `pub(crate)`, so we must parse from hex.
    let fake_sig_hash: RevisionLink = format!("0x{}", "00".repeat(32))
        .parse()
        .expect("zero hash is valid hex");
    build_attestation_tree(aquafier, attester_did, &fake_sig_hash, "headless", None, None)
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
