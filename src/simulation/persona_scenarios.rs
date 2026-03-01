// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Persona-based identity claim simulation.
//!
//! 5 real-world-plausible personas, each holding a portfolio of identity claims
//! that cover all 15 derived identity templates (everything under IdentityBase,
//! not the root itself).
//!
//! ## Template coverage
//!
//! Depth 1 (IdentityBase children):
//!   EmailClaim, PhoneClaim, NameClaim, DnsClaim, DocumentClaim,
//!   AddressClaim, AgeClaim, BirthdateClaim, PlatformIdentityClaim, Attestation
//!
//! Depth 2 (PlatformIdentity children):
//!   GitHubClaim, GoogleClaim
//!
//! Depth 2 (DocumentClaim children):
//!   PassportClaim, DriversLicenseClaim, NationalIdClaim
//!
//! ## WASM state architecture
//!
//! All non-Attestation claims inherit IdentityBase WASM and are verified standalone
//! (`verify_and_build_state`). IdentityBase WASM scans all signature branches:
//!
//! - **attested**: claimer self-sig + trusted-org parallel sig (both off the object revision)
//! - **expired**: valid_until in the past + trusted-org parallel sig
//! - **not_yet_valid**: valid_from in the future + trusted-org parallel sig
//! - **untrusted**: claimer self-sig + untrusted-org parallel sig (org not in trust store)
//! - **self_signed**: claimer self-sig only
//! - **unsigned**: no signatures
//!
//! Parallel sigs are added via `AquaTreeWrapper { revision: Some(obj_hash) }`,
//! which causes `sign_aqua_tree` to branch off `obj_hash` rather than the tip.
//!
//! **Attestation (P5-3)** uses the two-tree model:
//!   `verify_and_build_state_with_linked_trees(attestation, [claim], [])`
//!
//! ## Personas
//!
//! | ID  | Persona              | Claims (15 total)                            |
//! |-----|----------------------|----------------------------------------------|
//! | P1  | Alice Chen (dev)     | GitHubClaim, EmailClaim, NameClaim           |
//! | P2  | Bob Martinez (free)  | GoogleClaim, PhoneClaim, AddressClaim        |
//! | P3  | Claire Dubois (jour) | DnsClaim, PassportClaim, BirthdateClaim      |
//! | P4  | David Kim (student)  | AgeClaim, DriversLicenseClaim, NationalIdClaim |
//! | P5  | Eve Okafor (founder) | PlatformIdentityClaim, DocumentClaim, Attestation |

use std::collections::HashMap;
use std::sync::Arc;

use aqua_rs_sdk::{
    primitives::{Method, MethodError, RevisionLink},
    schema::{
        tree::Tree,
        AquaTreeWrapper, SigningCredentials,
    },
    Aquafier, DefaultTrustStore,
};

use crate::simulation::builders;
use crate::simulation::keygen;
use crate::simulation::scenarios::extract_state;

// ─────────────────────────────────────────────────────────────────────────────
// Result type
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a single persona claim scenario.
#[derive(Debug)]
pub struct PersonaResult {
    pub persona: &'static str,
    pub scenario_id: &'static str,
    pub claim_type: &'static str,
    pub description: &'static str,
    pub expected_state: &'static str,
    pub actual_state: Option<String>,
    /// Whether this is an intentional sub-condition (expired, not_yet_valid, untrusted, unsigned).
    pub is_sub_condition: bool,
    pub passed: bool,
    pub error: Option<String>,
    pub raw_wasm_outputs: Vec<serde_json::Value>,
    pub trees: Vec<(String, Tree)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Aquafier factories
// ─────────────────────────────────────────────────────────────────────────────

/// Build an `Aquafier` with a single trusted DID at level 2.
fn trust_one(did: &str) -> Aquafier {
    let mut map = HashMap::new();
    map.insert(did.to_string(), 2u8);
    Aquafier::builder()
        .trust_store(Arc::new(DefaultTrustStore::new(map)))
        .build()
}

/// Build an `Aquafier` with an explicit but empty trust store.
///
/// Trust store presence (even empty) triggers WASM execution.
fn no_trust() -> Aquafier {
    Aquafier::builder()
        .trust_store(Arc::new(DefaultTrustStore::new(HashMap::new())))
        .build()
}

// ─────────────────────────────────────────────────────────────────────────────
// Claim tree helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a genesis claim tree from a raw template hash string and JSON payload.
fn build_claim_raw(
    aq: &Aquafier,
    template_hash: &str,
    payload: serde_json::Value,
) -> Result<Tree, MethodError> {
    let link: RevisionLink = template_hash
        .parse()
        .map_err(|e: <RevisionLink as std::str::FromStr>::Err| {
            MethodError::Simple(format!("invalid template hash: {}", e))
        })?;
    aq.create_object(link, None, payload, Some(Method::Scalar))
}

/// Normal (tip-appended) Ed25519 signature.
async fn self_sign_ed25519(aq: &Aquafier, tree: Tree, priv_key: &[u8]) -> Result<Tree, MethodError> {
    builders::sign_ed25519(aq, tree, priv_key).await
}

/// Normal (tip-appended) P-256 signature.
async fn self_sign_p256(aq: &Aquafier, tree: Tree, priv_key: &[u8]) -> Result<Tree, MethodError> {
    builders::sign_p256(aq, tree, priv_key).await
}

/// Parallel Ed25519 signature branching off `target` (not the current tip).
///
/// Setting `AquaTreeWrapper.revision = Some(target)` causes `sign_aqua_tree` to
/// attach the new signature as a child of `target` rather than the latest revision,
/// creating a fork in the tree that the IdentityBase WASM can detect.
async fn parallel_sign_ed25519(
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
async fn parallel_sign_p256(
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

// ─────────────────────────────────────────────────────────────────────────────
// Verification helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a standalone claim tree (IdentityBase WASM).
async fn verify_claim(
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
async fn verify_attestation(
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

// ─────────────────────────────────────────────────────────────────────────────
// Error constructor
// ─────────────────────────────────────────────────────────────────────────────

fn make_err(
    persona: &'static str,
    scenario_id: &'static str,
    claim_type: &'static str,
    description: &'static str,
    expected_state: &'static str,
    is_sub_condition: bool,
    e: impl std::fmt::Display,
) -> PersonaResult {
    PersonaResult {
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
fn template_trees_for_claim_type(claim_type: &str) -> Vec<(String, Tree)> {
    use aqua_rs_sdk::schema::template::BuiltInTemplate;
    use aqua_rs_sdk::schema::templates;

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

// ─────────────────────────────────────────────────────────────────────────────
// Persona 1: Alice Chen — software developer, San Francisco
// ─────────────────────────────────────────────────────────────────────────────

/// P1: Alice Chen.
///
/// - P1-1 GitHubClaim   → `attested`     (org-attested via parallel trusted sig)
/// - P1-2 EmailClaim    → `self_signed`  (Alice signs only)
/// - P1-3 NameClaim     → `self_signed`  (Alice signs only)
pub async fn persona_alice() -> Vec<PersonaResult> {
    const PERSONA: &str = "P1: Alice Chen (developer, San Francisco)";

    let (alice_priv, alice_did) = keygen::generate_ed25519();
    let (org_priv, org_did) = keygen::generate_ed25519();

    let mut out = Vec::new();

    // --- P1-1: GitHubClaim — attested ---
    {
        const ID: &str = "P1-1";
        const CT: &str = "GitHubClaim";
        const EXP: &str = "attested";
        const DESC: &str = "Alice's GitHub identity — org-attested";

        let aq = trust_one(&org_did);

        let result = match async {
            let tree = build_claim_raw(&aq, "0x44416d64213f54cd25c0d0cb72e2a58a358dab83ee584a74c6a89f33e454aae8", serde_json::json!({
                "signer_did": alice_did,
                "provider": "github",
                "provider_id": "8821034",
                "display_name": "@alice-chen-dev",
                "email": "alice@devmail.com",
                "proof_url": "https://gist.github.com/alice-chen-dev/aqua-proof",
                "profile_url": "https://github.com/alice-chen-dev"
            }))?;
            let obj_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_ed25519(&aq, tree, &alice_priv).await?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: false,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
        };
        out.push(result);
    }

    // --- P1-2: EmailClaim — self_signed ---
    {
        const ID: &str = "P1-2";
        const CT: &str = "EmailClaim";
        const EXP: &str = "self_signed";
        const DESC: &str = "Alice's verified email — self-signed";

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, "0x6489c5a615615128cc0da08e175b6faaaafe64f9692f67cc7c04849451964cfa", serde_json::json!({
                "signer_did": alice_did,
                "email": "alice@devmail.com",
                "display_name": "Alice Chen"
            }))?;
            let tree = self_sign_ed25519(&aq, tree, &alice_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: false,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
        };
        out.push(result);
    }

    // --- P1-3: NameClaim — self_signed ---
    {
        const ID: &str = "P1-3";
        const CT: &str = "NameClaim";
        const EXP: &str = "self_signed";
        const DESC: &str = "Alice's legal name — self-signed";

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, "0xb8aeaca00ee15ddf6037f3ea9b4138edbd517fbf905e40b56cf7a9810fc87706", serde_json::json!({
                "signer_did": alice_did,
                "given_name": "Alice",
                "family_name": "Chen",
                "nickname": "ali",
                "preferred_username": "alice-chen-dev"
            }))?;
            let tree = self_sign_ed25519(&aq, tree, &alice_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: false,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
        };
        out.push(result);
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Persona 2: Bob Martinez — freelance translator, Madrid
// ─────────────────────────────────────────────────────────────────────────────

/// P2: Bob Martinez.
///
/// - P2-1 GoogleClaim   → `attested`       (org-attested)
/// - P2-2 PhoneClaim    → `expired`        (valid_until=1000 + trusted sig) ⚠ sub-condition
/// - P2-3 AddressClaim  → `not_yet_valid`  (valid_from=9999999999 + trusted sig) ⚠ sub-condition
pub async fn persona_bob() -> Vec<PersonaResult> {
    const PERSONA: &str = "P2: Bob Martinez (freelance translator, Madrid)";

    let (bob_priv, bob_did) = keygen::generate_p256();
    let (org_priv, org_did) = keygen::generate_p256();

    let mut out = Vec::new();

    // --- P2-1: GoogleClaim — attested ---
    {
        const ID: &str = "P2-1";
        const CT: &str = "GoogleClaim";
        const EXP: &str = "attested";
        const DESC: &str = "Bob's Google account — org-attested";

        let aq = trust_one(&org_did);

        let result = match async {
            let tree = build_claim_raw(&aq, "0x7d4f2b845f33c819dfdfbc86c0d3304e3f1a387a34742d495b23864308df11fd", serde_json::json!({
                "signer_did": bob_did,
                "provider": "google",
                "provider_id": "109283471823456789",
                "display_name": "Bob Martinez",
                "email": "bobmartinez@gmail.com"
            }))?;
            let obj_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_p256(&aq, tree, &bob_priv).await?;
            let tree = parallel_sign_p256(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: false,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
        };
        out.push(result);
    }

    // --- P2-2: PhoneClaim — expired (sub-condition) ---
    {
        const ID: &str = "P2-2";
        const CT: &str = "PhoneClaim";
        const EXP: &str = "expired";
        const DESC: &str = "Bob's phone number — attestation expired (valid_until=1000)";

        let aq = trust_one(&org_did);

        let result = match async {
            let tree = build_claim_raw(&aq, "0xe0efe33df32f17069d726ced96435f1682d9fa4a006bbecafa738b198578f58f", serde_json::json!({
                "signer_did": bob_did,
                "phone_number": "+34 612 345 678",
                "display_name": "Bob Martinez",
                "valid_until": 1000
            }))?;
            let obj_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_p256(&aq, tree, &bob_priv).await?;
            let tree = parallel_sign_p256(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: true,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, true, e),
        };
        out.push(result);
    }

    // --- P2-3: AddressClaim — not_yet_valid (sub-condition) ---
    {
        const ID: &str = "P2-3";
        const CT: &str = "AddressClaim";
        const EXP: &str = "not_yet_valid";
        const DESC: &str = "Bob's new Madrid address — attestation not yet valid (valid_from far future)";

        let aq = trust_one(&org_did);

        let result = match async {
            let tree = build_claim_raw(&aq, "0x156f536a7b3d92c264eaf87a73c5b013238c843afe3fd48f334be5747b9f944b", serde_json::json!({
                "signer_did": bob_did,
                "street_address": "Calle Gran Vía 42, 3B",
                "locality": "Madrid",
                "country": "ES",
                "region": "Community of Madrid",
                "postal_code": "28013",
                "valid_from": 9_999_999_999u64
            }))?;
            let obj_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_p256(&aq, tree, &bob_priv).await?;
            let tree = parallel_sign_p256(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: true,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, true, e),
        };
        out.push(result);
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Persona 3: Claire Dubois — investigative journalist, Paris
// ─────────────────────────────────────────────────────────────────────────────

/// P3: Claire Dubois.
///
/// - P3-1 DnsClaim        → `attested`   (org-attested)
/// - P3-2 PassportClaim   → `self_signed` (Claire signs only)
/// - P3-3 BirthdateClaim  → `expired`    (valid_until=1000 + trusted sig) ⚠ sub-condition
pub async fn persona_claire() -> Vec<PersonaResult> {
    const PERSONA: &str = "P3: Claire Dubois (investigative journalist, Paris)";

    let (claire_priv, claire_did) = keygen::generate_ed25519();
    let (org_priv, org_did) = keygen::generate_ed25519();

    let mut out = Vec::new();

    // --- P3-1: DnsClaim — attested ---
    {
        const ID: &str = "P3-1";
        const CT: &str = "DnsClaim";
        const EXP: &str = "attested";
        const DESC: &str = "Claire's domain ownership — org-attested";

        let aq = trust_one(&org_did);

        let result = match async {
            let tree = build_claim_raw(&aq, "0x5f2a0876d5192fd3089d2f9bbfeecc1f0c12792deafc1664ecd52cee5db75826", serde_json::json!({
                "signer_did": claire_did,
                "domain_name": "claire-dubois.press",
                "proof_url": "https://claire-dubois.press/.well-known/aqua-proof.txt"
            }))?;
            let obj_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_ed25519(&aq, tree, &claire_priv).await?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: false,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
        };
        out.push(result);
    }

    // --- P3-2: PassportClaim — self_signed ---
    {
        const ID: &str = "P3-2";
        const CT: &str = "PassportClaim";
        const EXP: &str = "self_signed";
        const DESC: &str = "Claire's passport — self-asserted";

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, "0x430053037e3e969a3e67056b991b61a46ff449aa7f6df9aea5310230bfd6f975", serde_json::json!({
                "signer_did": claire_did,
                "document_type": "passport",
                "document_number": "09FG228174",
                "given_name": "Claire",
                "family_name": "Dubois",
                "nationality": "FR",
                "issuing_authority": "Préfecture de Police de Paris",
                "issuing_country": "FR",
                "birth_year": 1985,
                "birthplace": "Lyon, France"
            }))?;
            let tree = self_sign_ed25519(&aq, tree, &claire_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: false,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
        };
        out.push(result);
    }

    // --- P3-3: BirthdateClaim — expired (sub-condition) ---
    {
        const ID: &str = "P3-3";
        const CT: &str = "BirthdateClaim";
        const EXP: &str = "expired";
        const DESC: &str = "Claire's birthdate — trusted attestation expired";

        let aq = trust_one(&org_did);

        let result = match async {
            let tree = build_claim_raw(&aq, "0xfa0fe47cd9eaaae0d244d81548cc6a7816d7ca1be61861fb5d357d53f7a9dc72", serde_json::json!({
                "signer_did": claire_did,
                "birth_year": 1985,
                "birth_month": 3,
                "birth_day": 14,
                "birthplace": "Lyon, France",
                "valid_until": 1000
            }))?;
            let obj_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_ed25519(&aq, tree, &claire_priv).await?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: true,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, true, e),
        };
        out.push(result);
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Persona 4: David Kim — graduate student, Seoul
// ─────────────────────────────────────────────────────────────────────────────

/// P4: David Kim.
///
/// - P4-1 AgeClaim            → `attested`   (org-attested)
/// - P4-2 DriversLicenseClaim → `untrusted`  (parallel sig not in trust store) ⚠ sub-condition
/// - P4-3 NationalIdClaim     → `self_signed` (David signs only)
pub async fn persona_david() -> Vec<PersonaResult> {
    const PERSONA: &str = "P4: David Kim (graduate student, Seoul)";

    let (david_priv, david_did) = keygen::generate_p256();
    let (org_priv, org_did) = keygen::generate_p256();
    // A separate untrusted party for P4-2 (not in trust store)
    let (untrusted_priv, _untrusted_did) = keygen::generate_ed25519();

    let mut out = Vec::new();

    // --- P4-1: AgeClaim — attested ---
    {
        const ID: &str = "P4-1";
        const CT: &str = "AgeClaim";
        const EXP: &str = "attested";
        const DESC: &str = "David is 18+ — university registrar attested";

        let aq = trust_one(&org_did);

        let result = match async {
            let tree = build_claim_raw(&aq, "0x4ee2f1792d3aa3abb322c16acf73e6617b201c1351a109b623716cad351ea57a", serde_json::json!({
                "signer_did": david_did,
                "age_over_18": true,
                "age_over_21": false,
                "age_in_years": 24
            }))?;
            let obj_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_p256(&aq, tree, &david_priv).await?;
            let tree = parallel_sign_p256(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: false,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
        };
        out.push(result);
    }

    // --- P4-2: DriversLicenseClaim — untrusted (sub-condition) ---
    {
        const ID: &str = "P4-2";
        const CT: &str = "DriversLicenseClaim";
        const EXP: &str = "untrusted";
        const DESC: &str = "David's driver's license — co-signed by an unrecognised party";

        // Empty trust store — the co-signer is not trusted
        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, "0x1abae19875ca2f3cee4b3fe65de6a93d62d9d60070339798dd87ff7effc1ae3e", serde_json::json!({
                "signer_did": david_did,
                "document_type": "drivers_license",
                "document_number": "KR-DL-20190834",
                "given_name": "David",
                "family_name": "Kim",
                "nationality": "KR",
                "issuing_authority": "Seoul Metropolitan Police Agency",
                "issuing_country": "KR",
                "birth_year": 2000,
                "height_cm": 175
            }))?;
            let obj_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_p256(&aq, tree, &david_priv).await?;
            // Untrusted co-signer (not in trust store) creates a parallel branch
            let tree = parallel_sign_ed25519(&aq, tree, &untrusted_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: true,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, true, e),
        };
        out.push(result);
    }

    // --- P4-3: NationalIdClaim — self_signed ---
    {
        const ID: &str = "P4-3";
        const CT: &str = "NationalIdClaim";
        const EXP: &str = "self_signed";
        const DESC: &str = "David's national ID — self-asserted";

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, "0xa1eb7b1408027d6f9a7262ef2413374df4d0574117ec656826a4ac936b9448e2", serde_json::json!({
                "signer_did": david_did,
                "document_type": "national_id",
                "document_number": "KR-NID-900210-1234567",
                "given_name": "David",
                "family_name": "Kim",
                "nationality": "KR",
                "issuing_authority": "Ministry of the Interior, Republic of Korea",
                "issuing_country": "KR",
                "birth_year": 2000
            }))?;
            let tree = self_sign_p256(&aq, tree, &david_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: false,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
        };
        out.push(result);
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Persona 5: Eve Okafor — startup founder, Lagos
// ─────────────────────────────────────────────────────────────────────────────

/// P5: Eve Okafor.
///
/// - P5-1 PlatformIdentityClaim → `self_signed` (Eve's platform identity, self-only)
/// - P5-2 DocumentClaim         → `unsigned`    (company reg doc, not yet signed) ⚠ sub-condition
/// - P5-3 Attestation           → `attested`    (attests P5-1 claim, two-tree model)
///
/// P5-1's signed tree is reused as the linked claim in P5-3.
pub async fn persona_eve() -> Vec<PersonaResult> {
    const PERSONA: &str = "P5: Eve Okafor (startup founder, Lagos)";

    let (eve_priv, eve_did) = keygen::generate_p256();
    let (org_priv, org_did) = keygen::generate_ed25519();

    let mut out = Vec::new();

    // --- P5-1: PlatformIdentityClaim — self_signed ---
    // Also captures claim_tree + hashes for P5-3.
    let p5_1_claim_state: Option<(Tree, RevisionLink, RevisionLink)> = {
        const ID: &str = "P5-1";
        const CT: &str = "PlatformIdentityClaim";
        const EXP: &str = "self_signed";
        const DESC: &str = "Eve's LinkedIn-style platform identity — self-signed";

        let aq = no_trust();

        let build_result = async {
            let tree = build_claim_raw(&aq, "0x7cf1c62d746ba3788d9bf9f52f8dad8a1d514d2af3ab4c8b4024363f0f8c2c95", serde_json::json!({
                "signer_did": eve_did,
                "provider": "linkedin",
                "provider_id": "eve-okafor-7b8a2",
                "display_name": "Eve Okafor",
                "email": "eve@okafor.ventures"
            }))?;
            let obj_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_p256(&aq, tree, &eve_priv).await?;
            let sig_hash = tree
                .get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty signed tree".into()))?;
            Ok::<_, MethodError>((tree, obj_hash, sig_hash))
        }
        .await;

        match build_result {
            Ok((tree, obj_hash, sig_hash)) => {
                // Verify P5-1 as self_signed
                let verify_result = verify_claim(&aq, tree.clone()).await;
                let pr = match verify_result {
                    Ok((actual, raw)) => {
                        let passed = actual.as_deref() == Some(EXP);
                        PersonaResult {
                            persona: PERSONA,
                            scenario_id: ID,
                            claim_type: CT,
                            description: DESC,
                            expected_state: EXP,
                            actual_state: actual,
                            is_sub_condition: false,
                            passed,
                            error: None,
                            raw_wasm_outputs: raw,
                            trees: vec![(format!("{}_{}", ID, CT), tree.clone())],
                        }
                    }
                    Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
                };
                out.push(pr);
                Some((tree, obj_hash, sig_hash))
            }
            Err(e) => {
                out.push(make_err(PERSONA, ID, CT, DESC, EXP, false, e));
                None
            }
        }
    };

    // --- P5-2: DocumentClaim — unsigned (sub-condition) ---
    {
        const ID: &str = "P5-2";
        const CT: &str = "DocumentClaim";
        const EXP: &str = "unsigned";
        const DESC: &str = "Eve's company incorporation certificate — not yet signed";

        let aq = no_trust();

        let result = match async {
            // Build but do NOT sign — exercising the `unsigned` state
            let tree = build_claim_raw(&aq, "0x00464537648c598b564a4a9670b0ed4000db5dc532af750680a77883352bd3d0", serde_json::json!({
                "signer_did": eve_did,
                "document_type": "certificate",
                "document_number": "RC-NGR-2024-0183847",
                "nationality": "NG",
                "issuing_authority": "Corporate Affairs Commission Nigeria",
                "issuing_country": "NG"
            }))?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(EXP);
                PersonaResult {
                    persona: PERSONA,
                    scenario_id: ID,
                    claim_type: CT,
                    description: DESC,
                    expected_state: EXP,
                    actual_state: actual,
                    is_sub_condition: true,
                    passed,
                    error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("{}_{}", ID, CT), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, true, e),
        };
        out.push(result);
    }

    // --- P5-3: Attestation — attested (two-tree model using P5-1 claim) ---
    {
        const ID: &str = "P5-3";
        const CT: &str = "Attestation";
        const EXP: &str = "attested";
        const DESC: &str = "Org attests Eve's platform identity (two-tree: attestation + claim)";

        if let Some((claim_tree, claim_obj_hash, claim_sig_hash)) = p5_1_claim_state {
            let aq = trust_one(&org_did);

            let result = match async {
                let attest_tree = builders::build_attestation_tree(
                    &aq,
                    &org_did,
                    &claim_sig_hash,
                    &claim_obj_hash.to_string(),
                    None,
                    None,
                )?;
                let attest_tree = builders::sign_ed25519(&aq, attest_tree, &org_priv).await?;
                let attest_c = attest_tree.clone();
                let claim_c = claim_tree.clone();
                let (actual, raw) = verify_attestation(&aq, attest_tree, claim_tree).await?;
                Ok::<_, MethodError>((actual, raw, attest_c, claim_c))
            }
            .await
            {
                Ok((actual, raw, attest_c, claim_c)) => {
                    let passed = actual.as_deref() == Some(EXP);
                    PersonaResult {
                        persona: PERSONA,
                        scenario_id: ID,
                        claim_type: CT,
                        description: DESC,
                        expected_state: EXP,
                        actual_state: actual,
                        is_sub_condition: false,
                        passed,
                        error: None,
                        raw_wasm_outputs: raw,
                        trees: vec![
                            (format!("{}_P5-1_claim", ID), claim_c),
                            (format!("{}_{}", ID, CT), attest_c),
                        ],
                    }
                }
                Err(e) => make_err(PERSONA, ID, CT, DESC, EXP, false, e),
            };
            out.push(result);
        } else {
            // P5-1 failed to build — skip P5-3
            out.push(make_err(
                PERSONA,
                ID,
                CT,
                DESC,
                EXP,
                false,
                "skipped: P5-1 claim build failed",
            ));
        }
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
        // Attestation (P5-3) also depends on the linked PlatformIdentityClaim
        if r.claim_type == "Attestation" {
            r.trees.extend(template_trees_for_claim_type("PlatformIdentityClaim"));
        }
    }
    out
}
