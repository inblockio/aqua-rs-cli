# Forest & Cross-Tree Verification

How `--forest` and `--authenticate` resolve cross-tree dependencies
(attestation→claim, template hierarchies) and how `--trust` enables
WASM compute verification.

---

## `--forest`: Ephemeral Forest with L3 Resolution

`src/aqua/forest.rs` uses the SDK's `daemon::Forest` (backed by `NullStorage`)
instead of manual HashMap indexing. This provides structured state management,
built-in template loading, and L3 dependency tracking.

### Algorithm (4 phases)

**Phase 1 — Load all trees:**
Parse all `.aqua.json` files and build a `rev_hash → tree_index` map
(`HashMap<String, usize>`) for O(1) cross-tree lookup.

**Phase 2 — Verify with pre-resolved linked trees, insert into Forest:**
For each tree:
1. Extract `link_verification_hashes` from anchor revisions (skip zero-sentinels)
2. Resolve each link via the rev_hash map → find containing tree → collect as `AquaTreeWrapper`
3. Call `verify_and_build_state_with_linked_trees(wrapper, linked, vec![])`
4. Insert `StateNode`s into `Forest` in topological order
5. For each anchor node's links:
   - `forest.load_builtin_template(&lh)` — auto-loads built-in template chains
   - `forest.register_l3_pending(owner, lh)` — tracks genuinely unresolved deps

**Phase 3 — Post-insert L3 resolution:**
After all trees are inserted, sweep `pending_dependencies()` and resolve
any entries where the awaited hash is now in the forest.

**Phase 4 — Report:**
Uses Forest API: `summary()`, `genesis_hashes()`, `tips()`,
`pending_dependencies()`, `branches()`.

### Key SDK imports

```rust
use aqua_rs_sdk::daemon::{topological_order, Forest, NullStorage};
use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::{Aquafier, DefaultTrustStore};
```

---

## `--authenticate`: Directory-Scan Resolution

`src/aqua/verify.rs` resolves cross-tree links by scanning the parent
directory for co-located `.aqua.json` files (instead of the old broken
`file_index` lookup which never contained external revision hashes).

### How it works

1. Collect `link_verification_hashes` from anchor revisions (skip zero-sentinels)
2. If no links → verify standalone (no linked trees needed)
3. If links exist:
   a. Scan the parent directory for all `.aqua.json` files (skip self)
   b. Parse each into a `Tree`
   c. Build `rev_hash → Tree` map
   d. For each link hash → look up in map → collect as `AquaTreeWrapper`
   e. Call `verify_aqua_tree_with_linked_trees(wrapper, linked, file_objects)`

This makes `--authenticate` self-sufficient for co-located trees
(the common case: simulation output, manually placed chains).

---

## `--trust`: Trust Store for WASM Execution

WASM compute verification only runs when a trust store is configured on
the Aquafier (even an empty one). The `--trust` parameter provides this
for the `--forest` command.

### Usage

```bash
# Empty trust store (WASM runs, nobody trusted → states like "untrusted", "self_signed")
aqua-cli --forest *.aqua.json

# Trusted attester at level 2 (full trust → "attested" states)
aqua-cli --forest *.aqua.json --trust did:pkh:p256:0x02... 2

# Trust levels: 1=marginal, 2=full, 3=ultimate
```

### How it works

`cli_ephemeral_forest` always creates a local Aquafier with a trust store:
- Without `--trust`: empty `DefaultTrustStore` (still triggers WASM)
- With `--trust <DID> <LEVEL>`: `DefaultTrustStore` populated with the DID

```rust
let aquafier = if let Some((ref did, level)) = args.trust {
    let mut levels = HashMap::new();
    levels.insert(did.clone(), level);
    aquafier.with_trust_store(Arc::new(DefaultTrustStore::new(levels)))
} else {
    aquafier.with_trust_store(Arc::new(DefaultTrustStore::new(HashMap::new())))
};
```

The `--trust` param is stored as `trust: Option<(String, u8)>` in `CliArgs`.

---

## End-to-End Example

```bash
# 1. Generate simulation trees
cargo run --bin aqua-cli --features simulation -- --simulate --keep -v
# Output: /tmp/aqua-sim-XXXXXX/ with 24 .aqua.json files

# 2. Forest verification (all trees, with trusted attester)
cargo run --bin aqua-cli -- \
  --forest /tmp/aqua-sim-XXXXXX/*.aqua.json \
  --trust did:pkh:p256:0x02... 2

# Expected output:
#   Per-file verification: all OK
#   Forest: 63 nodes, 24 geneses, 0 pending deps
#   "Forest built successfully."

# 3. Single-file attestation verification (auto-finds claim in same dir)
cargo run --bin aqua-cli -- -a /tmp/aqua-sim-XXXXXX/A4_attestation.aqua.json
```

---

## Source Files

- `src/aqua/forest.rs` — `cli_ephemeral_forest()`, 4-phase algorithm
- `src/aqua/verify.rs` — `cli_verify_chain()`, directory-scan resolution
- `src/main.rs` — `--forest`, `--trust` arg parsing
- `src/models.rs` — `CliArgs.trust: Option<(String, u8)>`
