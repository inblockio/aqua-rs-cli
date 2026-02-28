# Template-Based Tree Structure

How Aqua trees are structured when objects are built on templates.
Every object lives inside a tree that carries its own template — making it
**self-describing** and structurally verifiable.

---

## Core Principle

Every genesis object tree has **3 revisions minimum**:

```
Template  →  (genesis, embedded)       the template revision itself
Anchor    →  (genesis, links=[…])      declares structural dependencies
Object    →  (prev=anchor)             the payload, chained to the anchor
```

After signing: `Template → Anchor → Object → Signature` (4 revisions).

The **anchor** is always the genesis revision (first in topological order).
The **object** chains to the anchor via `previous_revision`.
The **template** is embedded in the tree so the tree is self-describing —
any consumer can determine the object's type without external lookups.

---

## L1 vs L2 Templates

### L1 Template (root, e.g. IdentityBase)

A single `AnyRevision::Template` revision. No wrapping anchor.

```
[template_hash] → Template { revision_type: "template", schema: {…}, verification: {…} }
```

### L2 Template (derived, e.g. GitHubClaim extends PlatformIdentity)

A two-node structure: the **mother template** (L1) stands alone, and a
**template anchor** links the child template to its parent:

```
[mother_hash]      → Template(IdentityBase)          ← L1, standalone
[tpl_anchor_hash]  → Anchor(links: [child_hash, mother_hash])
[child_hash]       → Template(GitHubClaim)            ← L2, derived
```

The anchor declares the inheritance edge. During WASM verification the
engine walks the ancestry chain (`collect_ancestor_verifications`) to find
and execute all ancestor WASMs in order (parent first, child overrides).

---

## Genesis Object Structure

### Standard claim (L1 template)

```
Template(PlatformIdentityClaim)                    ← self-describing
Anchor(genesis, links: [template_hash])            ← dependency: this template
Object(prev: anchor, revision_type: template_hash) ← the claim payload
Signature(prev: object)                            ← optional
```

**SDK call:**
```rust
let tree = aquafier.identity().claim(claim, Some(Method::Scalar))?;
```

Internally this calls `create_object()` which builds all 3 revisions.

### Standard claim (L2 template, e.g. GitHubClaim)

Same structure but the template resolution may embed the parent:

```
Template(IdentityBase)                             ← L1 mother (if L2 hierarchy)
Anchor(genesis, links: [template_hash])            ← links to the leaf template
Template(GitHubClaim)                              ← L2 child
Object(prev: anchor, revision_type: template_hash)
Signature(prev: object)
```

**SDK call (via raw template hash):**
```rust
let tree = aquafier.create_object(github_template_link, None, payload, Some(Method::Scalar))?;
```

### Attestation (with structural claim link)

The genesis anchor links to `[claim_sig_hash]` instead of `[template_hash]`.
This declares a **cross-tree structural dependency**: the signed claim must
exist (in linked trees) for the anchor to resolve during verification.

```
Template(Attestation)
Anchor(genesis, links: [claim_sig_hash])           ← NOT template_hash
Object(prev: anchor, context: claim_obj_hash)
Signature(prev: object)
```

**SDK call:**
```rust
let tree = aquafier
    .identity()
    .attestation(attest, &claim_sig_hash, Some(Method::Scalar))?;
```

Internally this calls `create_object_with_anchor_links([claim_sig_hash])`.

### Headless attestation (no linked claim)

The genesis anchor links to `[RevisionLink::zero()]` — a 0x000…000 sentinel.
Structural validation recognises this sentinel and passes. WASM then runs,
calls `ctx_linked_tree_count()` → 0, and returns state 0 ("headless").

```
Template(Attestation)
Anchor(genesis, links: [0x0000…0000])              ← zero sentinel
Object(prev: anchor, context: "headless")
```

**SDK call:**
```rust
let tree = aquafier
    .identity()
    .headless_attestation(attest, Some(Method::Scalar))?;
```

---

## Chained Objects (non-genesis)

When appending a second object to an existing tree, **no new anchor or
template** is added. The new object's `previous_revision` points to the
current tip:

```
Template → Anchor → Object₁ → Signature₁ → Object₂
```

Only genesis triggers anchor + template insertion.

---

## Verification: Anchor Resolution

During structural verification (`resolve_anchor_links`):

1. For each `link_verification_hash` in every Anchor:
   - **Intra-tree**: does the hash exist as a revision in this tree? (e.g. template hash)
   - **Cross-tree**: does the hash match the latest revision of any linked tree? (e.g. claim_sig_hash)
   - **Zero sentinel**: `0x000…000` is recognised as a sentinel — passes with Info log
2. If any link is unresolved → anchor rejected → `is_valid = false`

This is how the two-tree model works:
```rust
// Attestation anchor links to claim_sig_hash
// → resolved by finding it as latest revision of the linked claim tree
aquafier.verify_and_build_state_with_linked_trees(
    attest_wrapper,          // primary: attestation
    vec![claim_wrapper],     // linked:  signed claim
    vec![],
).await?;
```

---

## Trust Store & WASM Execution

WASM only runs when a trust store is configured on the Aquafier — even an
empty trust store triggers WASM execution. Without it, `wasm_outputs` is
always empty regardless of signatures.

```rust
// Minimal: empty trust store (WASM runs, nobody is trusted)
let aq = Aquafier::builder()
    .trust_store(Arc::new(DefaultTrustStore::new(HashMap::new())))
    .build();

// With trusted attester (needed for "attested" state)
let mut levels = HashMap::new();
levels.insert(attester_did.clone(), 2u8);
let aq = Aquafier::builder()
    .trust_store(Arc::new(DefaultTrustStore::new(levels)))
    .build();
```

---

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| `create_object()` for attestation genesis | Anchor links to template, not claim sig | Use `identity().attestation(attest, &claim_sig_hash, method)` |
| Bare object (no template/anchor) | Verification can't determine type; WASM skipped | Ensure SDK `create_object` produces 3 revisions |
| Discarding `claim_sig_hash` | Attestation has no structural link to claim | Pass it to `identity().attestation()` |
| No trust store | `wasm_outputs` always empty | Call `.trust_store(...)` on builder |
| Attestation as linked tree | WASM runs on claim, not attestation | Primary = attestation, linked = [claim] |

---

## SDK API Reference

| Method | Creates | Anchor links |
|---|---|---|
| `identity().claim(claim, method)` | Template + Anchor + Object | `[template_hash]` |
| `identity().attestation(attest, &sig_hash, method)` | Template + Anchor + Object | `[claim_sig_hash]` |
| `identity().headless_attestation(attest, method)` | Template + Anchor + Object | `[zero_hash]` |
| `identity().trust_assertion(ta, method)` | Template + Anchor + Object | `[template_hash]` |
| `create_object(tpl, None, payload, method)` | Template + Anchor + Object | `[template_hash]` |
| `create_object_with_anchor_links(tpl, links, payload, method)` | Template + Anchor + Object | `links` (custom) |

---

## Source Files

- SDK: `../aqua-rs-sdk/src/core/object.rs` — `create_object_internal` (genesis anchor logic)
- SDK: `../aqua-rs-sdk/src/core/identity/builders.rs` — `IdentityTreeBuilder`
- CLI: `src/simulation/builders.rs` — wrapper functions
- CLI: `src/simulation/scenarios.rs` — 12-scenario simulation
- CLI: `src/simulation/persona_scenarios.rs` — 15-persona simulation
