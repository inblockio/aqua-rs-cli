# Template-Based Tree Structure

How Aqua trees are structured. **Templates are separate Aqua-Trees** —
object trees no longer embed their template. Templates exist as standalone
reference trees in a three-layer hierarchy.

---

## Three-Layer Model

```
L1: Root template tree       (IdentityBase — 1 revision: Template)
     ↑ ancestry via derives_from
L2: Derived template tree    (GitHubClaim — 1 revision: Template)
     ↑ referenced by anchor
L3: Object tree              (Alice's claim — Anchor + Object + Sig(s))
```

**Templates are NOT embedded** in object trees. They are resolved at
verification time from:
1. Built-in template cache (constant-time hash lookup)
2. Linked trees (cross-referenced via anchor links)

---

## Template Trees

### All templates (root AND derived)

Every template tree is a **single `Template` revision**. No Anchor.

```
[template_hash] → Template { revision_type: "template", schema: {…}, ... }
```

The hierarchy between templates is expressed through `derives_from` and
`ancestry` fields baked into the Template JSON itself — NOT through
Anchor revisions. Adding an Anchor would require `previous_revision`
on the Template, which changes its SHA3-256 hash and breaks the
`TEMPLATE_LINK` identity that object trees reference.

During WASM verification the engine walks the ancestry chain
(`collect_ancestor_verifications`) to find and execute all ancestor WASMs
in order (parent first, child overrides).

### Cross-Tree Dependency Visibility

**Important:** Template `derives_from` hashes are implicit cross-tree
dependencies. Generic tooling (forest L3 scan, DAG renderers, state-viewer)
discovers cross-tree edges by reading `StateNode.link_verification_hashes`.
Anchors populate this field automatically. Templates must do so explicitly.

The policy `build_state_nodes()` function maps template `derives_from` into
`StateNode.link_verification_hashes` (with `link_type: "derives_from"`),
making template-to-template edges visible through the **same pathway** as
anchor cross-tree links. This ensures:

1. Forest L3 scan discovers and auto-loads parent template chains
2. DAG renderers draw template→parent edges without special-casing
3. The state-viewer shows the full derivation graph

Without this, derived template trees would appear as disconnected islands in
the forest because nothing in their structure references the parent template
through the standard link pathway.

### SDK API for Template Trees

```rust
// Get a single template as a properly structured tree
let tree: Option<Tree> = Aquafier::builtin_template_tree(&hash);

// Get the full chain (root first, self last)
// For GitHubClaim: [IdentityBase, PlatformIdentityClaim, GitHubClaim]
let chain: Vec<Tree> = Aquafier::builtin_template_tree_chain(&hash);

// Resolve template hash to human-readable name
let name: Option<&str> = Aquafier::builtin_template_name(&hash);
```

---

## Genesis Object Structure

### Standard claim

A genesis object tree has **2 revisions minimum** (Anchor + Object):

```
Anchor    (genesis, links=[template_hash])    declares which template
Object    (prev=anchor)                       the claim payload
```

After signing: `Anchor → Object → Signature` (3 revisions).

With forked signatures (parallel sigs branch off Object, not linear):
```
Anchor → Object → Signature₁ (claimer self-sig)
                ↘ Signature₂ (org parallel-sig, also prev=object)
```

**SDK call:**
```rust
let tree = aquafier.identity().claim(claim, Some(Method::Scalar))?;
// or for raw template hash:
let tree = aquafier.create_object(template_link, None, payload, Some(Method::Scalar))?;
```

### Attestation (with structural claim link)

The genesis anchor links to `[claim_sig_hash]` instead of `[template_hash]`.
This declares a **cross-tree structural dependency**: the signed claim must
exist (in linked trees) for the anchor to resolve during verification.

```
Anchor    (genesis, links=[claim_sig_hash])   NOT template_hash
Object    (prev=anchor, context: claim_obj_hash)
Signature (prev=object)
```

**SDK call:**
```rust
let tree = aquafier
    .identity()
    .attestation(attest, &claim_sig_hash, Some(Method::Scalar))?;
```

### Headless attestation (no linked claim)

The genesis anchor links to `[RevisionLink::zero()]` — a 0x000…000 sentinel.
Structural validation recognises this sentinel and passes. WASM then runs,
calls `ctx_linked_tree_count()` → 0, and returns state 0 ("headless").

```
Anchor    (genesis, links=[0x0000…0000])     zero sentinel
Object    (prev=anchor, context: "headless")
```

**SDK call:**
```rust
let tree = aquafier
    .identity()
    .headless_attestation(attest, Some(Method::Scalar))?;
```

---

## Verification: Anchor Resolution

During structural verification (`resolve_anchor_links`):

1. For each `link_verification_hash` in every Anchor:
   - **Built-in template**: hash matches a known built-in template → resolved
   - **Intra-tree**: hash exists as a revision in this tree
   - **Cross-tree**: hash matches the latest revision of any linked tree
   - **Zero sentinel**: `0x000…000` passes with Info log
2. If any link is unresolved → anchor rejected → `is_valid = false`

Two verification entry points:
```rust
// Standalone (no linked trees)
aquafier.verify_and_build_state(wrapper, vec![]).await?;

// With linked trees (e.g. attestation + claim)
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
| Expecting Template in object tree | Template revision not found | Templates are separate trees; resolved via built-in cache |
| `create_object()` for attestation genesis | Anchor links to template, not claim sig | Use `identity().attestation(attest, &claim_sig_hash, method)` |
| Discarding `claim_sig_hash` | Attestation has no structural link to claim | Pass it to `identity().attestation()` |
| No trust store | `wasm_outputs` always empty | Call `.trust_store(...)` on builder |
| Attestation as linked tree | WASM runs on claim, not attestation | Primary = attestation, linked = [claim] |

---

## SDK API Reference

| Method | Creates | Anchor links |
|---|---|---|
| `identity().claim(claim, method)` | Anchor + Object | `[template_hash]` |
| `identity().attestation(attest, &sig_hash, method)` | Anchor + Object | `[claim_sig_hash]` |
| `identity().headless_attestation(attest, method)` | Anchor + Object | `[zero_hash]` |
| `identity().trust_assertion(ta, method)` | Anchor + Object | `[template_hash]` |
| `create_object(tpl, None, payload, method)` | Anchor + Object | `[template_hash]` |
| `create_object_with_anchor_links(tpl, links, payload, method)` | Anchor + Object | `links` (custom) |
| `builtin_template_tree(&hash)` | Single Template revision | (template tree) |
| `builtin_template_tree_chain(&hash)` | Vec of template trees (root first) | (template chain) |
| `builtin_template_name(&hash)` | Human-readable name | — |
| `resolve_dependency_trees(&tree)` | Vec of dependency template trees | (from genesis anchor links) |

---

## Source Files

- SDK: `../aqua-rs-sdk/src/core/verify_stages.rs` — template resolution + tree construction
- SDK: `../aqua-rs-sdk/src/core/object.rs` — `create_object_internal` (genesis anchor logic)
- SDK: `../aqua-rs-sdk/src/core/identity/builders.rs` — `IdentityTreeBuilder`
- CLI: `src/simulation/builders.rs` — wrapper functions + `template_trees_for()`
- CLI: `src/simulation/scenarios.rs` — 12-scenario simulation
- CLI: `src/simulation/persona_scenarios.rs` — 15-persona simulation
