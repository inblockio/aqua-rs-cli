// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! 12 WASM-state scenario definitions.
//!
//! Each function returns a `ScenarioResult` after building trees, signing,
//! verifying, and comparing the WASM output state against the expected value.
//!
//! ## Verification model
//!
//! **Two-tree model** (C3–C6, A2–A6):
//!   A `PlatformIdentityClaim` reaches trust states (untrusted/attested/expired/not_yet_valid)
//!   only through a paired `Attestation` tree.  Verification is always performed on the
//!   **attestation** (primary tree) with the **claim** as a linked tree:
//!
//!   ```text
//!   Claim tree:       PlatformIdentityClaim object  →  claimer self-signature
//!   Attestation tree: Attestation object  →  attester signature  →  anchor (→ claim sig hash)
//!   Call:             verify_and_build_state_with_linked_trees(attestation, [claim], [])
//!   ```
//!
//!   The attestation WASM (`attestation_verify.wat`) checks:
//!     1. The attestation has a signature from its declared `signer_did`
//!     2. That signer is in the trust store at level ≥ 1
//!     3. Temporal bounds (`valid_from` / `valid_until`) on the attestation payload
//!   The claim's presence is validated structurally (the anchor's target hash must exist
//!   in the linked trees); the claim WASM is not used for trust-level states.
//!
//! **Standalone claim** (C1–C2):
//!   Verified directly with `verify_and_build_state` (no linked trees).
//!   The claim WASM (`platform_identity_verify.wat`) checks for a self-signature from
//!   `signer_did` and produces `unsigned` or `self_signed`.
//!
//! ## Key SDK discoveries
//!
//! 1. **Trust store required for WASM**: `verify_and_build_state` only produces
//!    WASM state output when an explicit trust store is configured on `Aquafier`.
//!    Without `.trust_store(...)` on the builder, `wasm_outputs` is always empty.
//!
//! 2. **Genesis anchor carries claim dependency**: The attestation tree's genesis
//!    anchor holds `link_verification_hashes: [claim_sig_hash]` — the structural
//!    import of the signed claim.  No trailing anchor is appended after signing.
//!    The claim must be built and signed *before* the attestation tree is created,
//!    so the claim signature hash is available for the genesis anchor.
//!
//! 3. **WASM trigger condition**: An empty-but-configured trust store
//!    (`DefaultTrustStore::new(HashMap::new())`) still triggers WASM execution.
//!    Trust store presence, not content, is the trigger.
//!
//! States exercised:
//!  PlatformIdentityClaim: unsigned | self_signed | untrusted | attested | expired | not_yet_valid
//!  Attestation:           headless | unsigned    | untrusted | attested | expired | not_yet_valid

use std::collections::HashMap;
use std::sync::Arc;

use aqua_rs_sdk::{
    primitives::RevisionLink,
    schema::{AquaTreeWrapper, tree::Tree},
    Aquafier, DefaultTrustStore, VerificationResult,
};

use crate::simulation::builders;
use crate::simulation::keygen;

/// Result of a single simulation scenario.
#[derive(Debug)]
pub struct ScenarioResult {
    pub id: &'static str,
    pub description: &'static str,
    pub expected_state: &'static str,
    /// State extracted from `VerificationResult.wasm_outputs`, if any.
    pub actual_state: Option<String>,
    pub passed: bool,
    pub error: Option<String>,
    /// SDK friction / discoveries encountered during this scenario.
    pub friction: Vec<&'static str>,
    /// All WASM output values (for diagnostics).
    pub raw_wasm_outputs: Vec<serde_json::Value>,
    /// Trees built during this scenario, as `(name, tree)` pairs.
    /// Written to disk when `--keep` is passed.
    pub trees: Vec<(String, Tree)>,
}

/// Extract the first WASM state string from a `VerificationResult`.
pub fn extract_state(result: &VerificationResult) -> Option<String> {
    result
        .wasm_outputs
        .values()
        .find_map(|v| v.get("state").and_then(|s| s.as_str()).map(String::from))
}

/// Collect all WASM output values for diagnostics.
fn collect_wasm_outputs(result: &VerificationResult) -> Vec<serde_json::Value> {
    result.wasm_outputs.values().cloned().collect()
}

/// Build an `Aquafier` with the given trust store (DID → level mapping).
fn aquafier_with_trust(levels: HashMap<String, u8>) -> Aquafier {
    let store = DefaultTrustStore::new(levels);
    Aquafier::builder().trust_store(Arc::new(store)).build()
}

/// Build an `Aquafier` with an explicit (but empty) trust store.
///
/// # Discovery
/// An empty trust store still triggers WASM execution — the trigger is trust store
/// *presence*, not trust store *content*. Without any trust store configuration,
/// `wasm_outputs` is always empty regardless of the chain's signature state.
fn aquafier_with_empty_trust() -> Aquafier {
    let store = DefaultTrustStore::new(HashMap::new());
    Aquafier::builder().trust_store(Arc::new(store)).build()
}

// ─────────────────────────────────────────────────────────────────────────────
// PlatformIdentityClaim scenarios (C1–C6)
// ─────────────────────────────────────────────────────────────────────────────

/// C1 — `unsigned`: claim exists but has no signature.
/// Trust store present (empty) so WASM executes.
pub async fn c1_unsigned() -> ScenarioResult {
    let id = "C1";
    let expected = "unsigned";
    let (_, claimer_did) = keygen::generate_ed25519();
    let aq = aquafier_with_empty_trust(); // empty trust store → WASM runs

    let tree = match builders::build_claim_tree(&aq, &claimer_did, None, None) {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — unsigned (no signature)", expected, e),
    };

    let tree_copy = tree.clone();
    let wrapper = AquaTreeWrapper::new(tree, None, None);
    match aq.verify_and_build_state(wrapper, vec![]).await {
        Ok((result, _nodes)) => {
            let actual = extract_state(&result);
            let raw = collect_wasm_outputs(&result);
            let passed = actual.as_deref() == Some(expected);
            ScenarioResult {
                id,
                description: "PlatformIdentityClaim — unsigned (no signature, empty trust store)",
                expected_state: expected, actual_state: actual, passed,
                error: None, friction: vec![
                    "WASM only runs when trust store is configured on Aquafier (even if empty)",
                    "No Aquafier::create_identity_claim() without `identity` feature",
                ],
                raw_wasm_outputs: raw,
                trees: vec![(format!("{}_claim", id), tree_copy)],
            }
        }
        Err(e) => err_result(id, "PlatformIdentityClaim — unsigned (no signature)", expected, e),
    }
}

/// C2 — `self_signed`: claim signed by the claimer key itself.
/// Requires trust store presence for WASM to produce output.
pub async fn c2_self_signed() -> ScenarioResult {
    let id = "C2";
    let expected = "self_signed";
    let (claimer_priv, claimer_did) = keygen::generate_p256();
    // Empty trust store — WASM runs; claimer is not in it so state is "self_signed" (not "attested").
    let aq = aquafier_with_empty_trust();

    let tree = match builders::build_claim_tree(&aq, &claimer_did, None, None) {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — self_signed", expected, e),
    };
    let signed = match builders::sign_p256(&aq, tree, &claimer_priv).await {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — self_signed (sign failed)", expected, e),
    };

    verify_claim(id, "PlatformIdentityClaim — self_signed (claimer signs, empty trust store)", expected, signed, aq, vec![
        "WASM only runs when trust store is configured on Aquafier (even if empty)",
    ]).await
}

/// C3 — `untrusted`: two-tree model — claim (self-signed) + attestation (signed, not trusted).
///
/// The verification is on the ATTESTATION tree, with the claim as a linked tree.
/// The attestation WASM checks its own `signer_did` signature and queries the trust store.
/// Attester is NOT in the trust store → "untrusted".
///
/// Structure:
///   Claim tree:       PlatformIdentityClaim object → claimer self-signature
///   Attestation tree: Attestation object → attester signature → anchor (→ claim sig hash)
///   Verify:           attestation (primary) + [claim] (linked) → attestation WASM
pub async fn c3_untrusted() -> ScenarioResult {
    let id = "C3";
    let expected = "untrusted";
    let (claimer_priv, claimer_did) = keygen::generate_ed25519();
    let (attester_priv, attester_did) = keygen::generate_ed25519();
    // Empty trust store — attester NOT in trust store.
    let aq = aquafier_with_empty_trust();

    let (claim_tree, claim_obj_hash, claim_sig_hash) =
        match build_self_signed_claim(&aq, &claimer_did, &claimer_priv, None, None).await {
            Ok(t) => t,
            Err(e) => return err_result(id, "PlatformIdentityClaim — untrusted (claim build failed)", expected, e),
        };

    let attest_tree = match builders::build_attestation_tree(
        &aq, &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, None,
    ) {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — untrusted (attest build failed)", expected, e),
    };
    let signed = match builders::sign_ed25519(&aq, attest_tree, &attester_priv).await {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — untrusted (attest sign failed)", expected, e),
    };

    verify_attestation(id, "PlatformIdentityClaim — untrusted (two-tree: signed attestation, attester not in trust store)", expected, signed, claim_tree, aq, vec![
        "Claim trust states use the two-tree model: verify attestation with claim as linked tree",
        "Genesis anchor carries claim_sig_hash; no trailing link anchor needed",
    ]).await
}

/// C4 — `attested`: two-tree model — claim (self-signed) + attestation (signed by trusted attester).
///
/// Attester is in the trust store at level 2 → attestation WASM returns "attested".
pub async fn c4_attested() -> ScenarioResult {
    let id = "C4";
    let expected = "attested";
    let (claimer_priv, claimer_did) = keygen::generate_p256();
    let (attester_priv, attester_did) = keygen::generate_p256();

    let mut trust = HashMap::new();
    trust.insert(attester_did.clone(), 2u8);
    let aq = aquafier_with_trust(trust);

    let (claim_tree, claim_obj_hash, claim_sig_hash) =
        match build_self_signed_claim(&aq, &claimer_did, &claimer_priv, None, None).await {
            Ok(t) => t,
            Err(e) => return err_result(id, "PlatformIdentityClaim — attested (claim build failed)", expected, e),
        };

    let attest_tree = match builders::build_attestation_tree(
        &aq, &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, None,
    ) {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — attested (attest build failed)", expected, e),
    };
    let signed = match builders::sign_p256(&aq, attest_tree, &attester_priv).await {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — attested (attest sign failed)", expected, e),
    };

    verify_attestation(id, "PlatformIdentityClaim — attested (two-tree: trusted attestation, level 2)", expected, signed, claim_tree, aq, vec![
        "Claim trust states use the two-tree model: verify attestation with claim as linked tree",
    ]).await
}

/// C5 — `expired`: two-tree model — trusted attestation but `valid_until=1000` (past) on attestation.
pub async fn c5_expired() -> ScenarioResult {
    let id = "C5";
    let expected = "expired";
    let (claimer_priv, claimer_did) = keygen::generate_ed25519();
    let (attester_priv, attester_did) = keygen::generate_ed25519();

    let mut trust = HashMap::new();
    trust.insert(attester_did.clone(), 2u8);
    let aq = aquafier_with_trust(trust);

    let (claim_tree, claim_obj_hash, claim_sig_hash) =
        match build_self_signed_claim(&aq, &claimer_did, &claimer_priv, None, None).await {
            Ok(t) => t,
            Err(e) => return err_result(id, "PlatformIdentityClaim — expired (claim build failed)", expected, e),
        };

    let attest_tree = match builders::build_attestation_tree(
        &aq, &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, Some(1000),
    ) {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — expired (attest build failed)", expected, e),
    };
    let signed = match builders::sign_ed25519(&aq, attest_tree, &attester_priv).await {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — expired (attest sign failed)", expected, e),
    };

    verify_attestation(id, "PlatformIdentityClaim — expired (two-tree: attestation valid_until=1000)", expected, signed, claim_tree, aq, vec![]).await
}

/// C6 — `not_yet_valid`: two-tree model — trusted attestation with `valid_from=9999999999` (future).
pub async fn c6_not_yet_valid() -> ScenarioResult {
    let id = "C6";
    let expected = "not_yet_valid";
    let (claimer_priv, claimer_did) = keygen::generate_p256();
    let (attester_priv, attester_did) = keygen::generate_p256();

    let mut trust = HashMap::new();
    trust.insert(attester_did.clone(), 2u8);
    let aq = aquafier_with_trust(trust);

    let (claim_tree, claim_obj_hash, claim_sig_hash) =
        match build_self_signed_claim(&aq, &claimer_did, &claimer_priv, None, None).await {
            Ok(t) => t,
            Err(e) => return err_result(id, "PlatformIdentityClaim — not_yet_valid (claim build failed)", expected, e),
        };

    let attest_tree = match builders::build_attestation_tree(
        &aq, &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), Some(9_999_999_999), None,
    ) {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — not_yet_valid (attest build failed)", expected, e),
    };
    let signed = match builders::sign_p256(&aq, attest_tree, &attester_priv).await {
        Ok(t) => t,
        Err(e) => return err_result(id, "PlatformIdentityClaim — not_yet_valid (attest sign failed)", expected, e),
    };

    verify_attestation(id, "PlatformIdentityClaim — not_yet_valid (two-tree: attestation valid_from=9999999999)", expected, signed, claim_tree, aq, vec![]).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Attestation scenarios (A1–A6)
// ─────────────────────────────────────────────────────────────────────────────

/// A1 — `headless`: attestation anchor points to a nonexistent hash.
///
/// "headless" is a **structural state**, not a WASM-reported state.
/// `attestation_verify.wat` declares state 0 as "headless" but marks it
/// "unreachable in V1" — the WASM never returns 0 itself.  Instead, when
/// the anchor target cannot be resolved, structural validation fails at
/// Stage 0 (`resolve_anchor_links`) and WASM execution is skipped entirely.
///
/// Pass condition: `result.is_valid == false` with no WASM output.
pub async fn a1_headless() -> ScenarioResult {
    let id = "A1";
    let expected = "headless";
    let (_, attester_did) = keygen::generate_ed25519();
    let aq = aquafier_with_empty_trust();

    let headless_tree = match builders::build_headless_attestation_tree(&aq, &attester_did) {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — headless (anchor → nonexistent hash)", expected, e),
    };

    let tree_copy = headless_tree.clone();
    let wrapper = AquaTreeWrapper::new(headless_tree, None, None);
    match aq.verify_and_build_state_with_linked_trees(wrapper, vec![], vec![]).await {
        Ok((result, _nodes)) => {
            let raw = collect_wasm_outputs(&result);
            // "headless" = structural failure: anchor target not in linked trees,
            // WASM never runs, wasm_outputs is empty, is_valid is false.
            let is_headless = !result.is_valid && raw.is_empty();
            let actual_state = if is_headless { Some("headless".to_string()) } else { extract_state(&result) };
            let passed = actual_state.as_deref() == Some(expected);
            ScenarioResult {
                id, description: "Attestation — headless (anchor → nonexistent hash, structural failure)",
                expected_state: expected, actual_state, passed,
                error: None, friction: vec![
                    "headless is a structural state: WASM never runs, detected via !is_valid + empty wasm_outputs",
                    "attestation_verify.wat declares state 0 = headless but marks it 'unreachable in V1'",
                    "No public API for creating an anchor with arbitrary target hash; \
                     requires schema::Anchor + verification::Linkable + manual Tree mutation",
                ],
                raw_wasm_outputs: raw,
                trees: vec![(format!("{}_attestation_headless", id), tree_copy)],
            }
        }
        Err(e) => err_result(id, "Attestation — headless (anchor → nonexistent hash)", expected, e),
    }
}

/// A2 — `unsigned`: attestation linked to claim but no attester signature.
pub async fn a2_unsigned() -> ScenarioResult {
    let id = "A2";
    let expected = "unsigned";
    let (claimer_priv, claimer_did) = keygen::generate_ed25519();
    let (_, attester_did) = keygen::generate_p256();
    let aq = aquafier_with_empty_trust();

    let (claim_tree, claim_obj_hash, claim_sig_hash) =
        match build_self_signed_claim(&aq, &claimer_did, &claimer_priv, None, None).await {
            Ok(t) => t,
            Err(e) => return err_result(id, "Attestation — unsigned", expected, e),
        };

    let attest_tree = match builders::build_attestation_tree(
        &aq, &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, None,
    ) {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — unsigned (attest build failed)", expected, e),
    };
    // No signing — attestation is unsigned.

    verify_attestation(id, "Attestation — unsigned (genesis anchor → claim sig, no attester sig)", expected, attest_tree, claim_tree, aq, vec![]).await
}

/// A3 — `untrusted`: attester signed but NOT in trust store.
///
/// # Discovery
/// Signing AFTER `link_aqua_tree` produced "unsigned" because the Signature revision
/// trails the Anchor in the tree (Signature → Anchor), but the WASM verifier expects
/// the Signature to be on the attestation object directly.
/// Fix: sign BEFORE linking so the tree is: object → signature → anchor (link to claim).
pub async fn a3_untrusted() -> ScenarioResult {
    let id = "A3";
    let expected = "untrusted";
    let (claimer_priv, claimer_did) = keygen::generate_ed25519();
    let (attester_priv, attester_did) = keygen::generate_ed25519();
    // Empty trust store — attester is not in it.
    let aq = aquafier_with_empty_trust();

    let (claim_tree, claim_obj_hash, claim_sig_hash) =
        match build_self_signed_claim(&aq, &claimer_did, &claimer_priv, None, None).await {
            Ok(t) => t,
            Err(e) => return err_result(id, "Attestation — untrusted", expected, e),
        };

    let attest_tree = match builders::build_attestation_tree(
        &aq, &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, None,
    ) {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — untrusted (attest build failed)", expected, e),
    };
    let signed = match builders::sign_ed25519(&aq, attest_tree, &attester_priv).await {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — untrusted (sign failed)", expected, e),
    };

    verify_attestation(id, "Attestation — untrusted (genesis anchor → claim sig, attester not in trust store)", expected, signed, claim_tree, aq, vec![
        "Genesis anchor carries claim_sig_hash; no trailing anchor needed",
    ]).await
}

/// A4 — `attested`: attester signed AND in trust store at level 2.
/// Signing happens BEFORE linking (sign then link).
pub async fn a4_attested() -> ScenarioResult {
    let id = "A4";
    let expected = "attested";
    let (claimer_priv, claimer_did) = keygen::generate_ed25519();
    let (attester_priv, attester_did) = keygen::generate_p256();

    let mut trust = HashMap::new();
    trust.insert(attester_did.clone(), 2u8);
    let aq = aquafier_with_trust(trust);

    let (claim_tree, claim_obj_hash, claim_sig_hash) =
        match build_self_signed_claim(&aq, &claimer_did, &claimer_priv, None, None).await {
            Ok(t) => t,
            Err(e) => return err_result(id, "Attestation — attested", expected, e),
        };

    let attest_tree = match builders::build_attestation_tree(
        &aq, &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, None,
    ) {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — attested (attest build failed)", expected, e),
    };
    let signed = match builders::sign_p256(&aq, attest_tree, &attester_priv).await {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — attested (sign failed)", expected, e),
    };

    verify_attestation(id, "Attestation — attested (genesis anchor → claim sig, attester in trust store level 2)", expected, signed, claim_tree, aq, vec![
        "Aquafier is immutable after build; separate instances required for different trust stores",
    ]).await
}

/// A5 — `expired`: attested (sign before link) but attestation `valid_until` is in the past.
pub async fn a5_expired() -> ScenarioResult {
    let id = "A5";
    let expected = "expired";
    let (claimer_priv, claimer_did) = keygen::generate_ed25519();
    let (attester_priv, attester_did) = keygen::generate_ed25519();

    let mut trust = HashMap::new();
    trust.insert(attester_did.clone(), 2u8);
    let aq = aquafier_with_trust(trust);

    let (claim_tree, claim_obj_hash, claim_sig_hash) =
        match build_self_signed_claim(&aq, &claimer_did, &claimer_priv, None, None).await {
            Ok(t) => t,
            Err(e) => return err_result(id, "Attestation — expired", expected, e),
        };

    let attest_tree = match builders::build_attestation_tree(
        &aq, &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, Some(1000),
    ) {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — expired (attest build failed)", expected, e),
    };
    let signed = match builders::sign_ed25519(&aq, attest_tree, &attester_priv).await {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — expired (sign failed)", expected, e),
    };

    verify_attestation(id, "Attestation — expired (genesis anchor → claim sig, valid_until=1000)", expected, signed, claim_tree, aq, vec![]).await
}

/// A6 — `not_yet_valid`: attested (sign before link) but valid_from is far in the future.
pub async fn a6_not_yet_valid() -> ScenarioResult {
    let id = "A6";
    let expected = "not_yet_valid";
    let (claimer_priv, claimer_did) = keygen::generate_ed25519();
    let (attester_priv, attester_did) = keygen::generate_p256();

    let mut trust = HashMap::new();
    trust.insert(attester_did.clone(), 2u8);
    let aq = aquafier_with_trust(trust);

    let (claim_tree, claim_obj_hash, claim_sig_hash) =
        match build_self_signed_claim(&aq, &claimer_did, &claimer_priv, None, None).await {
            Ok(t) => t,
            Err(e) => return err_result(id, "Attestation — not_yet_valid", expected, e),
        };

    let attest_tree = match builders::build_attestation_tree(
        &aq, &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), Some(9_999_999_999), None,
    ) {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — not_yet_valid (attest build failed)", expected, e),
    };
    let signed = match builders::sign_p256(&aq, attest_tree, &attester_priv).await {
        Ok(t) => t,
        Err(e) => return err_result(id, "Attestation — not_yet_valid (sign failed)", expected, e),
    };

    verify_attestation(id, "Attestation — not_yet_valid (genesis anchor → claim sig, valid_from=9999999999)", expected, signed, claim_tree, aq, vec![]).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

fn err_result(
    id: &'static str,
    description: &'static str,
    expected_state: &'static str,
    e: aqua_rs_sdk::primitives::MethodError,
) -> ScenarioResult {
    ScenarioResult {
        id, description, expected_state,
        actual_state: None, passed: false,
        error: Some(e.to_string()), friction: vec![],
        raw_wasm_outputs: vec![],
        trees: vec![],
    }
}

/// Build a self-signed claim tree and return `(signed_tree, obj_hash, sig_hash)`.
///
/// `obj_hash` is the claim object revision hash (captured before signing) — used
/// as the informational string reference in the attestation payload's `context`.
/// `sig_hash` is the claim signature revision hash — used as the genesis anchor
/// link in the paired attestation tree (structural cross-tree dependency).
async fn build_self_signed_claim(
    aq: &Aquafier,
    claimer_did: &str,
    claimer_priv: &[u8],
    valid_from: Option<u64>,
    valid_until: Option<u64>,
) -> Result<(Tree, RevisionLink, RevisionLink), aqua_rs_sdk::primitives::MethodError> {
    let unsigned = builders::build_claim_tree(aq, claimer_did, valid_from, valid_until)?;
    let obj_hash = unsigned
        .get_latest_revision_link()
        .ok_or_else(|| aqua_rs_sdk::primitives::MethodError::Simple("empty claim tree".into()))?;
    // Always sign with Ed25519 for simplicity (WASM checks the attestation's
    // signature, not the claim's, for trust-level states C3-C6, A2-A6).
    let signed = builders::sign_ed25519(aq, unsigned, claimer_priv).await?;
    let sig_hash = signed
        .get_latest_revision_link()
        .ok_or_else(|| aqua_rs_sdk::primitives::MethodError::Simple("empty signed claim tree".into()))?;
    Ok((signed, obj_hash, sig_hash))
}

/// Verify a claim tree and build a `ScenarioResult`.
async fn verify_claim(
    id: &'static str,
    description: &'static str,
    expected: &'static str,
    tree: Tree,
    aq: Aquafier,
    friction: Vec<&'static str>,
) -> ScenarioResult {
    let tree_copy = tree.clone();
    let wrapper = AquaTreeWrapper::new(tree, None, None);
    let trees = vec![(format!("{}_claim", id), tree_copy)];
    match aq.verify_and_build_state(wrapper, vec![]).await {
        Ok((result, _nodes)) => {
            let actual = extract_state(&result);
            let raw = collect_wasm_outputs(&result);
            let passed = actual.as_deref() == Some(expected);
            ScenarioResult {
                id, description, expected_state: expected, actual_state: actual,
                passed, error: None, friction,
                raw_wasm_outputs: raw, trees,
            }
        }
        Err(e) => ScenarioResult {
            id, description, expected_state: expected, actual_state: None,
            passed: false, error: Some(format!("verify: {e}")), friction,
            raw_wasm_outputs: vec![], trees,
        },
    }
}

/// Verify an attestation tree (with claim as linked tree) and build a `ScenarioResult`.
async fn verify_attestation(
    id: &'static str,
    description: &'static str,
    expected: &'static str,
    attest_tree: Tree,
    claim_tree: Tree,
    aq: Aquafier,
    friction: Vec<&'static str>,
) -> ScenarioResult {
    let attest_copy = attest_tree.clone();
    let claim_copy = claim_tree.clone();
    let trees = vec![
        (format!("{}_claim", id), claim_copy),
        (format!("{}_attestation", id), attest_copy),
    ];
    let attest_wrapper = AquaTreeWrapper::new(attest_tree, None, None);
    let claim_wrapper = AquaTreeWrapper::new(claim_tree, None, None);
    match aq
        .verify_and_build_state_with_linked_trees(attest_wrapper, vec![claim_wrapper], vec![])
        .await
    {
        Ok((result, _nodes)) => {
            let actual = extract_state(&result);
            let raw = collect_wasm_outputs(&result);
            let passed = actual.as_deref() == Some(expected);
            ScenarioResult {
                id, description, expected_state: expected, actual_state: actual,
                passed, error: None, friction,
                raw_wasm_outputs: raw, trees,
            }
        }
        Err(e) => ScenarioResult {
            id, description, expected_state: expected, actual_state: None,
            passed: false, error: Some(format!("verify: {e}")), friction,
            raw_wasm_outputs: vec![], trees,
        },
    }
}
