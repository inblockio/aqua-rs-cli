// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! SIM-2 persona definitions: 5 personas with 25 total claims.
//!
//! Each persona has a cohesive backstory and exercises specific WASM states
//! across the three verification modules (identity_claim_verify,
//! platform_identity_verify, attestation_verify).
//!
//! ## Attestors (3 shared institutional identities)
//!
//! | Attestor          | Key type  | Role                              |
//! |-------------------|-----------|-----------------------------------|
//! | Government        | Ed25519   | Official document attestations    |
//! | inblock.io        | P-256     | Platform/tech attestations        |
//! | Linux Foundation  | secp256k1 | Open-source/community attestations|
//!
//! ## Personas
//!
//! | # | Name            | Location   | Claims | Key type  | Attestor(s)        |
//! |---|-----------------|------------|--------|-----------|--------------------|
//! | 1 | Amara Osei      | Accra      | 7      | secp256k1 | Government         |
//! | 2 | Kenji Tanaka    | Tokyo      | 5      | Ed25519   | Linux Foundation   |
//! | 3 | Sofia Reyes     | Mexico City| 4      | P-256     | inblock.io         |
//! | 4 | Lars Eriksson   | Stockholm  | 3      | Ed25519   | Government, Linux Foundation |
//! | 5 | Priya Sharma    | Mumbai     | 6      | secp256k1 | Government, Linux Foundation |

use aqua_rs_sdk::{
    primitives::{MethodError, RevisionLink},
    schema::{
        template::BuiltInTemplate,
        templates,
        tree::Tree,
    },
};

use crate::simulation::builders;
use crate::simulation::keygen;

use super::verify::*;

// ─────────────────────────────────────────────────────────────────────────────
// Persona 1: Amara Osei — Healthcare Administrator, Accra (7 claims)
// ─────────────────────────────────────────────────────────────────────────────

/// S1: Amara Osei — healthcare administrator, Accra.
///
/// - S1-1 EmailClaim              → `self_signed`     (identity_claim: code 1)
/// - S1-2 NameClaim               → `attested`        (identity_claim: code 1 self + trusted parallel)
/// - S1-3 PhoneClaim              → `expired`         (identity_claim: code 2, valid_until=1000)
/// - S1-4 NationalIdClaim         → `self_signed`     (identity_claim: code 1)
/// - S1-5 AddressClaim            → `not_yet_valid`   (identity_claim: code 3, valid_from far future)
/// - S1-6 PlatformIdentityClaim   → `attested`        (platform_identity: code 3, parallel trusted sig)
/// - S1-7 Attestation             → `attested`        (attestation: code 3, two-tree model)
pub async fn persona_amara(att: &Attestors) -> Vec<Sim2Result> {
    const PERSONA: &str = "S1: Amara Osei (healthcare administrator, Accra)";

    let (amara_priv, amara_did) = keygen::generate_secp256k1();
    // Government attestor (Ed25519) — official healthcare compliance
    let org_priv = &att.gov_priv;
    let org_did = &att.gov_did;

    let mut out = Vec::new();

    // --- S1-1: EmailClaim — self_signed ---
    {
        let id = "S1-1".to_string();
        let ct: &str = "EmailClaim";
        let exp: &str = "self_signed";
        let desc = "Amara's work email — self-signed".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::EmailClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": amara_did,
                "email": "amara.osei@korle-bu.edu.gh",
                "display_name": "Amara Osei"
            }))?;
            let tree = self_sign_secp256k1(&aq, tree, &amara_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: false, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("amara_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
        };
        out.push(result);
    }

    // --- S1-2: NameClaim — attested (org-trusted parallel sig) ---
    {
        let id = "S1-2".to_string();
        let ct: &str = "NameClaim";
        let exp: &str = "attested";
        let desc = "Amara's legal name — Government attested".to_string();

        let aq = trust_one(&org_did, 2);

        let result = match async {
            let tree = build_claim_raw(&aq, templates::NameClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": amara_did,
                "given_name": "Amara",
                "family_name": "Osei",
                "preferred_username": "amara-osei"
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_secp256k1(&aq, tree, &amara_priv).await?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: false, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("amara_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
        };
        out.push(result);
    }

    // --- S1-3: PhoneClaim — expired (self-signed, valid_until=1000) ---
    {
        let id = "S1-3".to_string();
        let ct: &str = "PhoneClaim";
        let exp: &str = "expired";
        let desc = "Amara's phone — self-signed, expired (valid_until=1000)".to_string();

        let aq = trust_one(&org_did, 2);

        let result = match async {
            let tree = build_claim_raw(&aq, templates::PhoneClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": amara_did,
                "phone_number": "+233302123456",
                "display_name": "Amara Osei",
                "valid_until": 1000
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_secp256k1(&aq, tree, &amara_priv).await?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: true, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("amara_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
        };
        out.push(result);
    }

    // --- S1-4: NationalIdClaim — self_signed ---
    {
        let id = "S1-4".to_string();
        let ct: &str = "NationalIdClaim";
        let exp: &str = "self_signed";
        let desc = "Amara's Ghana Card — self-asserted".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::NationalIdClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": amara_did,
                "document_type": "national_id",
                "document_number": "GHA-029384756-2",
                "given_name": "Amara",
                "family_name": "Osei",
                "nationality": "GH",
                "issuing_authority": "National Identification Authority",
                "issuing_country": "GH",
                "birth_year": 1988
            }))?;
            let tree = self_sign_secp256k1(&aq, tree, &amara_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: false, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("amara_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
        };
        out.push(result);
    }

    // --- S1-5: AddressClaim — not_yet_valid (valid_from far future) ---
    {
        let id = "S1-5".to_string();
        let ct: &str = "AddressClaim";
        let exp: &str = "not_yet_valid";
        let desc = "Amara's new address — pending address change (valid_from far future)".to_string();

        let aq = trust_one(&org_did, 2);

        let result = match async {
            let tree = build_claim_raw(&aq, templates::AddressClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": amara_did,
                "street_address": "14 Independence Avenue",
                "locality": "Accra",
                "country": "GH",
                "region": "Greater Accra",
                "postal_code": "GA-123",
                "valid_from": 9_999_999_999u64
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_secp256k1(&aq, tree, &amara_priv).await?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: true, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("amara_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
        };
        out.push(result);
    }

    // --- S1-6: PlatformIdentityClaim — attested (parallel trusted org sig) ---
    // Also captures claim_tree + hashes for S1-7 attestation.
    let s1_6_claim_state: Option<(Tree, RevisionLink, RevisionLink)> = {
        let id = "S1-6".to_string();
        let ct: &str = "PlatformIdentityClaim";
        let exp: &str = "attested";
        let desc = "Amara's hospital portal identity — Government attested".to_string();

        let aq = trust_one(&org_did, 2);

        let build_result = async {
            let tree = build_claim_raw(&aq, templates::PlatformIdentityClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": amara_did,
                "provider": "hospital-portal",
                "provider_id": "amara-osei-kb",
                "display_name": "Amara Osei",
                "email": "amara.osei@korle-bu.edu.gh"
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_secp256k1(&aq, tree, &amara_priv).await?;
            let sig_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty signed tree".into()))?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash.clone()).await?;
            Ok::<_, MethodError>((tree, obj_hash, sig_hash))
        }
        .await;

        match build_result {
            Ok((tree, obj_hash, sig_hash)) => {
                let verify_result = verify_claim(&aq, tree.clone()).await;
                let pr = match verify_result {
                    Ok((actual, raw)) => {
                        let passed = actual.as_deref() == Some(exp);
                        Sim2Result {
                            persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                            description: desc.clone(), expected_state: exp, actual_state: actual,
                            is_sub_condition: false, passed, error: None,
                            raw_wasm_outputs: raw,
                            trees: vec![(format!("amara_{}", ct.to_lowercase()), tree.clone())],
                        }
                    }
                    Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
                };
                out.push(pr);
                Some((tree, obj_hash, sig_hash))
            }
            Err(e) => {
                out.push(make_err(PERSONA, id, ct, desc, exp, false, e));
                None
            }
        }
    };

    // --- S1-7: Attestation — attested (hospital attests Amara's platform identity) ---
    {
        let id = "S1-7".to_string();
        let ct: &str = "Attestation";
        let exp: &str = "attested";
        let desc = "Government attests Amara's platform identity (two-tree model)".to_string();

        if let Some((claim_tree, claim_obj_hash, claim_sig_hash)) = s1_6_claim_state {
            let aq = trust_one(&org_did, 2);

            let result = match async {
                let attest_tree = builders::build_attestation_tree(
                    &aq, &org_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, None,
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
                    let passed = actual.as_deref() == Some(exp);
                    Sim2Result {
                        persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                        description: desc.clone(), expected_state: exp, actual_state: actual,
                        is_sub_condition: false, passed, error: None,
                        raw_wasm_outputs: raw,
                        trees: vec![
                            ("amara_s1-6_claim".to_string(), claim_c),
                            ("amara_attestation".to_string(), attest_c),
                        ],
                    }
                }
                Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
            };
            out.push(result);
        } else {
            out.push(make_err(PERSONA, id, ct, desc, exp, false, "skipped: S1-6 claim build failed"));
        }
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Persona 2: Kenji Tanaka — Freelance Photographer, Tokyo (5 claims)
// ─────────────────────────────────────────────────────────────────────────────

/// S2: Kenji Tanaka — freelance photographer, Tokyo.
///
/// - S2-1 GitHubClaim    → `self_signed`  (platform_identity: code 1)
/// - S2-2 PassportClaim  → `unsigned`     (identity_claim: code 0, never signed)
/// - S2-3 DnsClaim       → `untrusted`    (identity_claim: self + 3rd party not in trust)
/// - S2-4 BirthdateClaim → `self_signed`  (identity_claim: code 1)
/// - S2-5 Attestation    → `headless`     (attestation: code 0, zero-hash sentinel)
pub async fn persona_kenji(att: &Attestors) -> Vec<Sim2Result> {
    const PERSONA: &str = "S2: Kenji Tanaka (freelance photographer, Tokyo)";

    let (kenji_priv, kenji_did) = keygen::generate_ed25519();
    // Linux Foundation attestor (secp256k1) — untrusted 3rd party for DNS co-sign
    let third_priv = &att.lf_priv;

    let mut out = Vec::new();

    // --- S2-1: GitHubClaim — self_signed ---
    {
        let id = "S2-1".to_string();
        let ct: &str = "GitHubClaim";
        let exp: &str = "self_signed";
        let desc = "Kenji's GitHub — no org endorsement".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::GitHubClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": kenji_did,
                "provider": "github",
                "provider_id": "5532901",
                "display_name": "@kenji-tanaka-photo",
                "profile_url": "https://github.com/kenji-tanaka-photo"
            }))?;
            let tree = self_sign_ed25519(&aq, tree, &kenji_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: false, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("kenji_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
        };
        out.push(result);
    }

    // --- S2-2: PassportClaim — unsigned (draft, never signed) ---
    {
        let id = "S2-2".to_string();
        let ct: &str = "PassportClaim";
        let exp: &str = "unsigned";
        let desc = "Kenji's passport — created but never signed (draft state)".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::PassportClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": kenji_did,
                "document_type": "passport",
                "document_number": "TK2839471",
                "given_name": "Kenji",
                "family_name": "Tanaka",
                "nationality": "JP",
                "issuing_authority": "Ministry of Foreign Affairs",
                "issuing_country": "JP",
                "birth_year": 1992
            }))?;
            // No signing — unsigned state
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: true, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("kenji_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
        };
        out.push(result);
    }

    // --- S2-3: DnsClaim — untrusted (self + 3rd party not in trust store) ---
    {
        let id = "S2-3".to_string();
        let ct: &str = "DnsClaim";
        let exp: &str = "untrusted";
        let desc = "Kenji's domain — self-signed + Linux Foundation co-sign (untrusted)".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::DnsClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": kenji_did,
                "domain_name": "kenji-tanaka.photography",
                "proof_url": "https://kenji-tanaka.photography/.well-known/aqua-proof.txt"
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_ed25519(&aq, tree, &kenji_priv).await?;
            let tree = parallel_sign_secp256k1(&aq, tree, third_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: true, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("kenji_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
        };
        out.push(result);
    }

    // --- S2-4: BirthdateClaim — self_signed ---
    {
        let id = "S2-4".to_string();
        let ct: &str = "BirthdateClaim";
        let exp: &str = "self_signed";
        let desc = "Kenji's birthdate — self-asserted".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::BirthdateClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": kenji_did,
                "birth_year": 1992,
                "birth_month": 7,
                "birth_day": 15,
                "birthplace": "Shibuya, Tokyo"
            }))?;
            let tree = self_sign_ed25519(&aq, tree, &kenji_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: false, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("kenji_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
        };
        out.push(result);
    }

    // --- S2-5: Attestation — headless (zero-hash sentinel) ---
    {
        let id = "S2-5".to_string();
        let ct: &str = "Attestation";
        let exp: &str = "headless";
        let desc = "Kenji's attestation — headless (no linked claim, zero-hash sentinel)".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = builders::build_headless_attestation_tree(&aq, &kenji_did)?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_headless_attestation(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: true, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("kenji_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
        };
        out.push(result);
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Persona 3: Sofia Reyes — University Professor, Mexico City (4 claims)
// ─────────────────────────────────────────────────────────────────────────────

/// S3: Sofia Reyes — university professor, Mexico City.
///
/// - S3-1 GoogleClaim    → `attested`     (platform_identity: code 3, university attests)
/// - S3-2 EmailClaim     → `expired`      (identity_claim: code 2, expired university email)
/// - S3-3 DocumentClaim  → `self_signed`  (identity_claim: code 1, faculty cert)
/// - S3-4 Attestation    → `unsigned`     (attestation: code 1, linked but not signed)
pub async fn persona_sofia(att: &Attestors) -> Vec<Sim2Result> {
    const PERSONA: &str = "S3: Sofia Reyes (university professor, Mexico City)";

    let (sofia_priv, sofia_did) = keygen::generate_p256();
    // inblock.io attestor (P-256) — platform/academic attestations
    let org_priv = &att.inblock_priv;
    let org_did = &att.inblock_did;

    let mut out = Vec::new();

    // --- S3-1: GoogleClaim — attested ---
    let s3_1_claim_state: Option<(Tree, RevisionLink, RevisionLink)> = {
        let id = "S3-1".to_string();
        let ct: &str = "GoogleClaim";
        let exp: &str = "attested";
        let desc = "Sofia's Google identity — inblock.io attested".to_string();

        let aq = trust_one(&org_did, 2);

        let build_result = async {
            let tree = build_claim_raw(&aq, templates::GoogleClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": sofia_did,
                "provider": "google",
                "provider_id": "118293746582019384",
                "display_name": "Sofia Reyes",
                "email": "sofia.reyes@unam.mx"
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_p256(&aq, tree, &sofia_priv).await?;
            let sig_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty signed tree".into()))?;
            let tree = parallel_sign_p256(&aq, tree, &org_priv, obj_hash.clone()).await?;
            Ok::<_, MethodError>((tree, obj_hash, sig_hash))
        }
        .await;

        match build_result {
            Ok((tree, obj_hash, sig_hash)) => {
                let aq = trust_one(&org_did, 2);
                let verify_result = verify_claim(&aq, tree.clone()).await;
                let pr = match verify_result {
                    Ok((actual, raw)) => {
                        let passed = actual.as_deref() == Some(exp);
                        Sim2Result {
                            persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                            description: desc.clone(), expected_state: exp, actual_state: actual,
                            is_sub_condition: false, passed, error: None,
                            raw_wasm_outputs: raw,
                            trees: vec![(format!("sofia_{}", ct.to_lowercase()), tree.clone())],
                        }
                    }
                    Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
                };
                out.push(pr);
                Some((tree, obj_hash, sig_hash))
            }
            Err(e) => {
                out.push(make_err(PERSONA, id, ct, desc, exp, false, e));
                None
            }
        }
    };

    // --- S3-2: EmailClaim — expired (valid_until=1000) ---
    {
        let id = "S3-2".to_string();
        let ct: &str = "EmailClaim";
        let exp: &str = "expired";
        let desc = "Sofia's expired university email (valid_until=1000)".to_string();

        let aq = trust_one(&org_did, 2);

        let result = match async {
            let tree = build_claim_raw(&aq, templates::EmailClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": sofia_did,
                "email": "sofia.reyes-old@unam.mx",
                "display_name": "Sofia Reyes",
                "valid_until": 1000
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_p256(&aq, tree, &sofia_priv).await?;
            let tree = parallel_sign_p256(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: true, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("sofia_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
        };
        out.push(result);
    }

    // --- S3-3: DocumentClaim — self_signed (faculty certificate) ---
    {
        let id = "S3-3".to_string();
        let ct: &str = "DocumentClaim";
        let exp: &str = "self_signed";
        let desc = "Sofia's faculty certificate — self-asserted".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::DocumentClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": sofia_did,
                "document_type": "certificate",
                "document_number": "UNAM-FAC-2019-8472",
                "nationality": "MX",
                "issuing_authority": "UNAM Faculty of Sciences",
                "issuing_country": "MX"
            }))?;
            let tree = self_sign_p256(&aq, tree, &sofia_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: false, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("sofia_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
        };
        out.push(result);
    }

    // --- S3-4: Attestation — unsigned (linked to claim but attester hasn't signed) ---
    {
        let id = "S3-4".to_string();
        let ct: &str = "Attestation";
        let exp: &str = "unsigned";
        let desc = "Attestation for Sofia's Google identity — linked but not signed by inblock.io".to_string();

        if let Some((claim_tree, claim_obj_hash, claim_sig_hash)) = s3_1_claim_state {
            let aq = no_trust();

            let result = match async {
                let attest_tree = builders::build_attestation_tree(
                    &aq, &org_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, None,
                )?;
                // No signing — attestation is unsigned
                let attest_c = attest_tree.clone();
                let claim_c = claim_tree.clone();
                let (actual, raw) = verify_attestation(&aq, attest_tree, claim_tree).await?;
                Ok::<_, MethodError>((actual, raw, attest_c, claim_c))
            }
            .await
            {
                Ok((actual, raw, attest_c, claim_c)) => {
                    let passed = actual.as_deref() == Some(exp);
                    Sim2Result {
                        persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                        description: desc.clone(), expected_state: exp, actual_state: actual,
                        is_sub_condition: true, passed, error: None,
                        raw_wasm_outputs: raw,
                        trees: vec![
                            ("sofia_s3-1_claim".to_string(), claim_c),
                            ("sofia_attestation_unsigned".to_string(), attest_c),
                        ],
                    }
                }
                Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
            };
            out.push(result);
        } else {
            out.push(make_err(PERSONA, id, ct, desc, exp, true, "skipped: S3-1 claim build failed"));
        }
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Persona 4: Lars Eriksson — Cybersecurity Consultant, Stockholm (3 claims)
// ─────────────────────────────────────────────────────────────────────────────

/// S4: Lars Eriksson — cybersecurity consultant, Stockholm.
///
/// - S4-1 AgeClaim            → `attested`       (identity_claim: org-attested for compliance)
/// - S4-2 DriversLicenseClaim → `not_yet_valid`  (identity_claim: code 3, valid_from far future)
/// - S4-3 Attestation         → `untrusted`      (attestation: code 2, attester not trusted)
pub async fn persona_lars(att: &Attestors) -> Vec<Sim2Result> {
    const PERSONA: &str = "S4: Lars Eriksson (cybersecurity consultant, Stockholm)";

    let (lars_priv, lars_did) = keygen::generate_ed25519();
    // Government attestor (Ed25519) — compliance attestations
    let org_priv = &att.gov_priv;
    let org_did = &att.gov_did;
    // Linux Foundation attestor (secp256k1) — used as untrusted attester for S4-3
    let untrusted_priv = &att.lf_priv;
    let untrusted_did = &att.lf_did;

    let mut out = Vec::new();

    // --- S4-1: AgeClaim — attested ---
    let s4_1_claim_state: Option<(Tree, RevisionLink, RevisionLink)> = {
        let id = "S4-1".to_string();
        let ct: &str = "AgeClaim";
        let exp: &str = "attested";
        let desc = "Lars is 18+ — Government compliance-verified".to_string();

        let aq = trust_one(&org_did, 2);

        let build_result = async {
            let tree = build_claim_raw(&aq, templates::AgeClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": lars_did,
                "age_over_18": true,
                "age_over_21": true,
                "age_in_years": 38
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_ed25519(&aq, tree, &lars_priv).await?;
            let sig_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty signed tree".into()))?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash.clone()).await?;
            Ok::<_, MethodError>((tree, obj_hash, sig_hash))
        }
        .await;

        match build_result {
            Ok((tree, obj_hash, sig_hash)) => {
                let verify_result = verify_claim(&trust_one(&org_did, 2), tree.clone()).await;
                let pr = match verify_result {
                    Ok((actual, raw)) => {
                        let passed = actual.as_deref() == Some(exp);
                        Sim2Result {
                            persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                            description: desc.clone(), expected_state: exp, actual_state: actual,
                            is_sub_condition: false, passed, error: None,
                            raw_wasm_outputs: raw,
                            trees: vec![(format!("lars_{}", ct.to_lowercase()), tree.clone())],
                        }
                    }
                    Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
                };
                out.push(pr);
                Some((tree, obj_hash, sig_hash))
            }
            Err(e) => {
                out.push(make_err(PERSONA, id, ct, desc, exp, false, e));
                None
            }
        }
    };

    // --- S4-2: DriversLicenseClaim — not_yet_valid (valid_from far future) ---
    {
        let id = "S4-2".to_string();
        let ct: &str = "DriversLicenseClaim";
        let exp: &str = "not_yet_valid";
        let desc = "Lars's driver's license renewal — not yet valid (valid_from far future)".to_string();

        let aq = trust_one(&org_did, 2);

        let result = match async {
            let tree = build_claim_raw(&aq, templates::DriversLicenseClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": lars_did,
                "document_type": "drivers_license",
                "document_number": "SE-DL-20250901-ERIK",
                "given_name": "Lars",
                "family_name": "Eriksson",
                "nationality": "SE",
                "issuing_authority": "Transportstyrelsen",
                "issuing_country": "SE",
                "birth_year": 1987,
                "valid_from": 9_999_999_999u64
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_ed25519(&aq, tree, &lars_priv).await?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: true, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("lars_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
        };
        out.push(result);
    }

    // --- S4-3: Attestation — untrusted (attester signed but not in trust store) ---
    {
        let id = "S4-3".to_string();
        let ct: &str = "Attestation";
        let exp: &str = "untrusted";
        let desc = "Attestation for Lars's age — Linux Foundation signed but not trusted".to_string();

        if let Some((claim_tree, claim_obj_hash, claim_sig_hash)) = s4_1_claim_state {
            // Empty trust store — attester is not trusted
            let aq = no_trust();

            let result = match async {
                let attest_tree = builders::build_attestation_tree(
                    &aq, untrusted_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, None,
                )?;
                let attest_tree = builders::sign_secp256k1(&aq, attest_tree, untrusted_priv).await?;
                let attest_c = attest_tree.clone();
                let claim_c = claim_tree.clone();
                let (actual, raw) = verify_attestation(&aq, attest_tree, claim_tree).await?;
                Ok::<_, MethodError>((actual, raw, attest_c, claim_c))
            }
            .await
            {
                Ok((actual, raw, attest_c, claim_c)) => {
                    let passed = actual.as_deref() == Some(exp);
                    Sim2Result {
                        persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                        description: desc.clone(), expected_state: exp, actual_state: actual,
                        is_sub_condition: true, passed, error: None,
                        raw_wasm_outputs: raw,
                        trees: vec![
                            ("lars_s4-1_claim".to_string(), claim_c),
                            ("lars_attestation_untrusted".to_string(), attest_c),
                        ],
                    }
                }
                Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
            };
            out.push(result);
        } else {
            out.push(make_err(PERSONA, id, ct, desc, exp, true, "skipped: S4-1 claim build failed"));
        }
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Persona 5: Priya Sharma — FinTech Startup Founder, Mumbai (6 claims)
// ─────────────────────────────────────────────────────────────────────────────

/// S5: Priya Sharma — FinTech startup founder, Mumbai.
///
/// - S5-1 PlatformIdentityClaim → `unsigned`      (platform_identity: code 0, fresh claim)
/// - S5-2 NameClaim             → `self_signed`   (identity_claim: code 1)
/// - S5-3 PhoneClaim            → `attested`      (identity_claim: trusted org sig)
/// - S5-4 NationalIdClaim       → `untrusted`     (identity_claim: 3rd party not in trust)
/// - S5-5 Attestation           → `expired`       (attestation: code 4, valid_until=1000)
/// - S5-6 Attestation           → `not_yet_valid` (attestation: code 5, valid_from far future)
pub async fn persona_priya(att: &Attestors) -> Vec<Sim2Result> {
    const PERSONA: &str = "S5: Priya Sharma (FinTech startup founder, Mumbai)";

    let (priya_priv, priya_did) = keygen::generate_secp256k1();
    // Government attestor (Ed25519) — regulatory compliance attestations
    let org_priv = &att.gov_priv;
    let org_did = &att.gov_did;
    // Linux Foundation attestor (secp256k1) — untrusted 3rd party for S5-4
    let untrusted_priv = &att.lf_priv;

    let mut out = Vec::new();

    // Build a signed claim for attestation scenarios (S5-5, S5-6).
    // We need a base claim to link attestations to.
    let base_claim_state: Option<(Tree, RevisionLink, RevisionLink)> = {
        let aq = no_trust();
        let build_result = async {
            let tree = build_claim_raw(&aq, templates::PlatformIdentityClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": priya_did,
                "provider": "fintech-portal",
                "provider_id": "priya-sharma-ft",
                "display_name": "Priya Sharma"
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_secp256k1(&aq, tree, &priya_priv).await?;
            let sig_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty signed tree".into()))?;
            Ok::<_, MethodError>((tree, obj_hash, sig_hash))
        }
        .await;
        build_result.ok()
    };

    // --- S5-1: PlatformIdentityClaim — unsigned (fresh claim, not yet signed) ---
    {
        let id = "S5-1".to_string();
        let ct: &str = "PlatformIdentityClaim";
        let exp: &str = "unsigned";
        let desc = "Priya's platform identity — created, not yet signed".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::PlatformIdentityClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": priya_did,
                "provider": "fintech-portal",
                "provider_id": "priya-sharma-ft-2",
                "display_name": "Priya Sharma",
                "email": "priya@sharma.ventures"
            }))?;
            // No signing — unsigned state
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: true, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("priya_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
        };
        out.push(result);
    }

    // --- S5-2: NameClaim — self_signed ---
    {
        let id = "S5-2".to_string();
        let ct: &str = "NameClaim";
        let exp: &str = "self_signed";
        let desc = "Priya's legal name — self-asserted".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::NameClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": priya_did,
                "given_name": "Priya",
                "family_name": "Sharma",
                "preferred_username": "priya-sharma"
            }))?;
            let tree = self_sign_secp256k1(&aq, tree, &priya_priv).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: false, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("priya_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
        };
        out.push(result);
    }

    // --- S5-3: PhoneClaim — attested (org-trusted parallel sig) ---
    {
        let id = "S5-3".to_string();
        let ct: &str = "PhoneClaim";
        let exp: &str = "attested";
        let desc = "Priya's phone — Government regulatory verification".to_string();

        let aq = trust_one(&org_did, 2);

        let result = match async {
            let tree = build_claim_raw(&aq, templates::PhoneClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": priya_did,
                "phone_number": "+919876543210",
                "display_name": "Priya Sharma"
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_secp256k1(&aq, tree, &priya_priv).await?;
            let tree = parallel_sign_ed25519(&aq, tree, &org_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: false, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("priya_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, false, e),
        };
        out.push(result);
    }

    // --- S5-4: NationalIdClaim — untrusted (self + 3rd party not in trust) ---
    {
        let id = "S5-4".to_string();
        let ct: &str = "NationalIdClaim";
        let exp: &str = "untrusted";
        let desc = "Priya's Aadhaar — co-signed by Linux Foundation (untrusted)".to_string();

        let aq = no_trust();

        let result = match async {
            let tree = build_claim_raw(&aq, templates::NationalIdClaim::TEMPLATE_LINK, serde_json::json!({
                "signer_did": priya_did,
                "document_type": "national_id",
                "document_number": "AADHAAR-9283-7461-5029",
                "given_name": "Priya",
                "family_name": "Sharma",
                "nationality": "IN",
                "issuing_authority": "UIDAI",
                "issuing_country": "IN",
                "birth_year": 1990
            }))?;
            let obj_hash = tree.get_latest_revision_link()
                .ok_or_else(|| MethodError::Simple("empty tree".into()))?;
            let tree = self_sign_secp256k1(&aq, tree, &priya_priv).await?;
            let tree = parallel_sign_secp256k1(&aq, tree, untrusted_priv, obj_hash).await?;
            let tree_c = tree.clone();
            let (actual, raw) = verify_claim(&aq, tree).await?;
            Ok::<_, MethodError>((actual, raw, tree_c))
        }
        .await
        {
            Ok((actual, raw, tree_c)) => {
                let passed = actual.as_deref() == Some(exp);
                Sim2Result {
                    persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                    description: desc.clone(), expected_state: exp, actual_state: actual,
                    is_sub_condition: true, passed, error: None,
                    raw_wasm_outputs: raw,
                    trees: vec![(format!("priya_{}", ct.to_lowercase()), tree_c)],
                }
            }
            Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
        };
        out.push(result);
    }

    // --- S5-5: Attestation — expired (attested, valid_until=1000) ---
    {
        let id = "S5-5".to_string();
        let ct: &str = "Attestation";
        let exp: &str = "expired";
        let desc = "Priya's attestation — Government attested but expired (valid_until=1000)".to_string();

        if let Some((ref claim_tree, ref claim_obj_hash, ref claim_sig_hash)) = base_claim_state {
            let aq = trust_one(&org_did, 2);

            let result = match async {
                let attest_tree = builders::build_attestation_tree(
                    &aq, &org_did, claim_sig_hash, &claim_obj_hash.to_string(),
                    None, Some(1000),
                )?;
                let attest_tree = builders::sign_ed25519(&aq, attest_tree, &org_priv).await?;
                let attest_c = attest_tree.clone();
                let claim_c = claim_tree.clone();
                let (actual, raw) = verify_attestation(&aq, attest_tree, claim_tree.clone()).await?;
                Ok::<_, MethodError>((actual, raw, attest_c, claim_c))
            }
            .await
            {
                Ok((actual, raw, attest_c, claim_c)) => {
                    let passed = actual.as_deref() == Some(exp);
                    Sim2Result {
                        persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                        description: desc.clone(), expected_state: exp, actual_state: actual,
                        is_sub_condition: true, passed, error: None,
                        raw_wasm_outputs: raw,
                        trees: vec![
                            ("priya_base_claim".to_string(), claim_c),
                            ("priya_attestation_expired".to_string(), attest_c),
                        ],
                    }
                }
                Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
            };
            out.push(result);
        } else {
            out.push(make_err(PERSONA, id, ct, desc, exp, true, "skipped: base claim build failed"));
        }
    }

    // --- S5-6: Attestation — not_yet_valid (attested, valid_from far future) ---
    {
        let id = "S5-6".to_string();
        let ct: &str = "Attestation";
        let exp: &str = "not_yet_valid";
        let desc = "Priya's attestation — Government attested but not yet valid (valid_from far future)".to_string();

        if let Some((ref claim_tree, ref claim_obj_hash, ref claim_sig_hash)) = base_claim_state {
            let aq = trust_one(&org_did, 2);

            let result = match async {
                let attest_tree = builders::build_attestation_tree(
                    &aq, &org_did, claim_sig_hash, &claim_obj_hash.to_string(),
                    Some(9_999_999_999), None,
                )?;
                let attest_tree = builders::sign_ed25519(&aq, attest_tree, &org_priv).await?;
                let attest_c = attest_tree.clone();
                let claim_c = claim_tree.clone();
                let (actual, raw) = verify_attestation(&aq, attest_tree, claim_tree.clone()).await?;
                Ok::<_, MethodError>((actual, raw, attest_c, claim_c))
            }
            .await
            {
                Ok((actual, raw, attest_c, claim_c)) => {
                    let passed = actual.as_deref() == Some(exp);
                    Sim2Result {
                        persona: PERSONA, scenario_id: id.clone(), claim_type: ct,
                        description: desc.clone(), expected_state: exp, actual_state: actual,
                        is_sub_condition: true, passed, error: None,
                        raw_wasm_outputs: raw,
                        trees: vec![
                            ("priya_base_claim_2".to_string(), claim_c),
                            ("priya_attestation_not_yet_valid".to_string(), attest_c),
                        ],
                    }
                }
                Err(e) => make_err(PERSONA, id, ct, desc, exp, true, e),
            };
            out.push(result);
        } else {
            out.push(make_err(PERSONA, id, ct, desc, exp, true, "skipped: base claim build failed"));
        }
    }

    for r in &mut out {
        r.trees.extend(template_trees_for_claim_type(r.claim_type));
    }
    out
}
