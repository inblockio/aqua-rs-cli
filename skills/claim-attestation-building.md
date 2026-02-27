# Building Claims and Attestations

How to correctly construct `PlatformIdentityClaim` and `Attestation` trees using
the aqua-rs-sdk, based on working simulation code in `src/simulation/`.

---

## Claim Tree

A claim is self-contained. Build it with `Aquafier::create_object` (which handles
template + genesis anchor + object automatically), then sign with the claimer's key.

```rust
// 1. Build unsigned claim
let unsigned = aquafier.create_object(
    template_link(PlatformIdentityClaim::TEMPLATE_LINK),
    None,                // no previous tree
    serde_json::to_value(&PlatformIdentityClaim {
        signer_did: claimer_did.to_string(),
        provider: "email".to_string(),
        provider_id: "alice@example.com".to_string(),
        display_name: "Alice".to_string(),
        ..Default::default()
    })?,
    Some(Method::Scalar),
)?;

// Capture object hash BEFORE signing (needed as reference in paired attestation).
let claim_obj_hash = unsigned.get_latest_revision_link().unwrap();

// 2. Sign — produces the claim signature revision (fork topology: sig is a branch).
let signed_claim = sign_ed25519(&aquafier, unsigned, &claimer_priv_bytes).await?;

// Capture signature hash AFTER signing (needed as genesis anchor link in attestation).
let claim_sig_hash = signed_claim.get_latest_revision_link().unwrap();
```

**Resulting structure (4 revisions):**
```
Template      (genesis)
Anchor        (genesis, link_verification_hashes=[template_hash])
Object        (prev=anchor)   payloads: { signer_did, provider, ... }
Signature     (prev=object)   signer: claimer_did
```

**Standalone verification (C1/C2 states):**
```rust
let wrapper = AquaTreeWrapper::new(signed_claim, None, None);
let (result, _) = aquafier.verify_and_build_state(wrapper, vec![]).await?;
// wasm_outputs → { "state": "self_signed" }
```

---

## Attestation Tree

The claim **must be signed first**. The attestation genesis anchor carries the
claim signature hash — the structural import declaring that a signed claim must
exist before this attestation can be verified.

**Do NOT use `Aquafier::create_object` for attestations.** Its genesis anchor
always links to the template hash, not the claim. Build the tree manually.

```rust
use std::collections::BTreeMap;
use aqua_rs_sdk::{
    schema::{Anchor, AnyRevision, Object, tree::Tree},
    primitives::{HashType, Method, RevisionLink},
    verification::Linkable,
    Aquafier,
};

fn build_attestation_tree(
    attester_did: &str,
    claim_sig_hash: &RevisionLink,   // genesis anchor target — structural import
    claim_obj_hash: &str,            // payload context — informational reference
    valid_from: Option<u64>,
    valid_until: Option<u64>,
) -> Result<Tree, MethodError> {
    let template_hash: RevisionLink = /* template_link(Attestation::TEMPLATE_LINK) */;

    let payload = serde_json::to_value(&Attestation {
        context: claim_obj_hash.to_string(), // which claim object is being attested
        signer_did: attester_did.to_string(),
        valid_from,
        valid_until,
    })?;

    let mut revisions: BTreeMap<RevisionLink, AnyRevision> = BTreeMap::new();
    let mut file_index: BTreeMap<RevisionLink, String> = BTreeMap::new();

    // 1. Template revision (self-describing).
    let template = Aquafier::builtin_templates()
        .get(&Attestation::TEMPLATE_LINK)
        .unwrap()
        .clone();
    revisions.insert(template_hash.clone(), AnyRevision::Template(template));

    // 2. Genesis anchor: structural import of the claim's signature revision.
    let mut anchor = Anchor::genesis(
        Method::Scalar, HashType::Sha3_256,
        vec![claim_sig_hash.clone()],      // ← claim_sig_hash, NOT template hash
    );
    let anchor_hash = anchor.calculate_link()?;
    anchor.populate_leaves()?;
    revisions.insert(anchor_hash.clone(), AnyRevision::Anchor(anchor));

    // 3. Attestation object chained from the genesis anchor.
    let mut object = Object::new(
        anchor_hash, template_hash, Method::Scalar, HashType::Sha3_256, payload,
    );
    let obj_hash = object.calculate_link()?;
    object.populate_leaves()?;
    revisions.insert(obj_hash, AnyRevision::Object(object));

    Ok(Tree { revisions, file_index })
}
```

**Then sign the attestation:**
```rust
let attest_tree = build_attestation_tree(
    &attester_did, &claim_sig_hash, &claim_obj_hash.to_string(), None, None,
)?;
let signed_attest = sign_p256(&aquafier, attest_tree, &attester_priv_bytes).await?;
```

**Resulting structure (4 revisions):**
```
Template      (genesis)
Anchor        (genesis, link_verification_hashes=[claim_sig_hash])  ← NOT template_hash
Object        (prev=anchor)   payloads: { signer_did: attester, context: claim_obj_hash }
Signature     (prev=object)   signer: attester_did
```

---

## Two-Tree Verification

Pass the **attestation** as the primary tree; pass the **claim** as a linked tree.
The verifier resolves the genesis anchor by finding `claim_sig_hash` in the linked trees.
The attestation WASM then evaluates attester signature + trust store + temporal bounds.

```rust
let attest_wrapper = AquaTreeWrapper::new(signed_attest, None, None);
let claim_wrapper  = AquaTreeWrapper::new(signed_claim, None, None);

let (result, _) = aquafier
    .verify_and_build_state_with_linked_trees(attest_wrapper, vec![claim_wrapper], vec![])
    .await?;
// wasm_outputs → { "state": "attested" | "untrusted" | "unsigned" | "expired" | "not_yet_valid" }
```

**Trust store controls the state:**
```rust
// "attested" — attester in trust store at level ≥ 1
let mut levels = HashMap::new();
levels.insert(attester_did.clone(), 2u8);
let aquafier = Aquafier::builder().trust_store(Arc::new(DefaultTrustStore::new(levels))).build();

// "untrusted" — trust store present but attester not in it
let aquafier = Aquafier::builder().trust_store(Arc::new(DefaultTrustStore::new(HashMap::new()))).build();

// No trust store at all → wasm_outputs is always empty (no state produced).
```

---

## Headless Attestation (A1)

Structurally identical to a normal attestation, but the genesis anchor links to
a hash that does not exist in any tree. The verifier cannot resolve the anchor →
structural failure → `is_valid = false`, `wasm_outputs` empty.

```rust
let fake_sig_hash: RevisionLink = format!("0x{}", "00".repeat(32)).parse().unwrap();
let headless = build_attestation_tree(&attester_did, &fake_sig_hash, "headless", None, None)?;
// Detection: !result.is_valid && result.wasm_outputs.is_empty()
```

---

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| `create_object` for attestation genesis | Two anchors; genesis → template, not claim | Build tree manually (see above) |
| `link_aqua_tree` to attach claim | Trailing anchor after sig; claim dep declared retroactively | Use genesis anchor with `claim_sig_hash` instead |
| Sign attestation AFTER `link_aqua_tree` (old model) | State = `unsigned` (sig trails anchor, WASM misses it) | No longer relevant — no trailing anchor |
| No trust store on `Aquafier` | `wasm_outputs` always empty | Always call `.trust_store(...)` on the builder |
| Pass attestation as linked tree | WASM runs on claim, not attestation | Primary = attestation, linked = `[claim]` |

---

## Reference

- Simulation source: `src/simulation/builders.rs`, `src/simulation/scenarios.rs`
- SDK skill: `../aqua-rs-sdk/skills/identity-layer.md`
- Normative spec: `../aqua-rs-sdk/spec-identity.md` §3–§4
