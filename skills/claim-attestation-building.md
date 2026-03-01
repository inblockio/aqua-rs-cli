# Building Claims and Attestations

How to correctly construct `PlatformIdentityClaim` and `Attestation` trees using
the aqua-rs-sdk, based on working simulation code in `src/simulation/`.

---

## Claim Tree

Build an unsigned claim with `Aquafier::identity().claim()`, then sign:

```rust
let claim = PlatformIdentityClaim {
    signer_did: claimer_did.to_string(),
    provider: "email".to_string(),
    provider_id: "alice@example.com".to_string(),
    display_name: "Alice".to_string(),
    email: None,
    proof_url: None,
    profile_url: None,
    avatar_url: None,
    valid_from: None,
    valid_until: None,
    metadata: None,
};

// 1. Build unsigned claim (genesis anchor + object — template is NOT embedded)
let unsigned = aquafier.identity().claim(claim, Some(Method::Scalar))?;

// Capture object hash BEFORE signing (used as informational context in paired attestation).
let claim_obj_hash = unsigned.get_latest_revision_link().unwrap();

// 2. Sign — produces the claim signature revision.
let signed_claim = sign_ed25519(&aquafier, unsigned, &claimer_priv_bytes).await?;

// Capture signature hash AFTER signing (structural anchor link in attestation).
let claim_sig_hash = signed_claim.get_latest_revision_link().unwrap();
```

**Resulting structure (3 revisions):**
```
Anchor        (genesis, link_verification_hashes=[template_hash])
Object        (prev=anchor)   payloads: { signer_did, provider, ... }
Signature     (prev=object)   signer: claimer_did
```

Templates are **separate trees**, not embedded. The anchor's `link_verification_hashes`
references the template hash, which is resolved from the built-in cache during verification.

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

```rust
let attest = Attestation {
    context: claim_obj_hash.to_string(), // informational ref to which claim is attested
    signer_did: attester_did.to_string(),
    valid_from: None,
    valid_until: None,
};

// Build unsigned attestation (genesis anchor → claim_sig_hash, not template hash)
let attest_tree = aquafier
    .identity()
    .attestation(attest, &claim_sig_hash, Some(Method::Scalar))?;

// Sign
let signed_attest = sign_p256(&aquafier, attest_tree, &attester_priv_bytes).await?;
```

**Resulting structure (3 revisions):**
```
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
let aquafier = Aquafier::builder()
    .trust_store(Arc::new(DefaultTrustStore::new(levels)))
    .build();

// "untrusted" — trust store present but attester not in it
let aquafier = Aquafier::builder()
    .trust_store(Arc::new(DefaultTrustStore::new(HashMap::new())))
    .build();

// No trust store at all → wasm_outputs is always empty (no state produced).
```

---

## Headless Attestation (A1)

The genesis anchor links to `RevisionLink::zero()` — a 32-byte zero sentinel.
Structural validation recognises this sentinel and passes (with an Info log).
WASM then runs, calls `ctx_linked_tree_count()` → 0, and returns state 0
("headless"). The chain is structurally valid (`is_valid = true`); "headless"
is a semantic state, not a structural failure.

```rust
let attest = Attestation {
    context: "headless".to_string(),
    signer_did: attester_did.to_string(),
    valid_from: None,
    valid_until: None,
};
let headless = aquafier.identity().headless_attestation(attest, Some(Method::Scalar))?;

// Verify — no linked trees
let wrapper = AquaTreeWrapper::new(headless, None, None);
let (result, _) = aquafier
    .verify_and_build_state_with_linked_trees(wrapper, vec![], vec![])
    .await?;
// result.is_valid == true (chain intact)
// wasm_outputs → { "state": "headless", "state_index": 0 }
```

---

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Expecting template in object tree | Template revision not found | Templates are separate trees; resolved from built-in cache |
| `create_object` for attestation genesis | Genesis anchor → template hash, not claim sig | Use `identity().attestation(attest, &claim_sig_hash, method)` |
| `link_aqua_tree` to attach claim | Trailing anchor after sig; claim dep declared retroactively | Use genesis anchor with `claim_sig_hash` instead |
| No trust store on `Aquafier` | `wasm_outputs` always empty | Call `.with_trust_store(...)` on the Aquafier |
| Pass attestation as linked tree | WASM runs on claim, not attestation | Primary = attestation, linked = `[claim]` |

---

## Reference

- Simulation source: `src/simulation/builders.rs`, `src/simulation/scenarios.rs`
- SDK skill: `../aqua-rs-sdk/skills/identity-layer.md`
- Normative spec: `../aqua-rs-sdk/spec-identity.md` §3–§4
