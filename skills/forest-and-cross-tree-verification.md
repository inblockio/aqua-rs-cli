# Forest & Cross-Tree Verification

How `--forest` and `--authenticate` resolve cross-tree dependencies
(attestation→claim, template hierarchies), how `--trust` enables
WASM compute verification, and how `--daemon` keeps the forest alive
with Unix socket IPC (`--connect`, `--target`).

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

## `--daemon`: Persistent Forest with Unix Socket IPC

When `--daemon` is appended to a `--forest` command, the forest stays alive
after initial ingestion. A REPL is available on stdin and a Unix socket
at `/tmp/aqua-forest-<PID>.sock` accepts connections from `--connect` and
`--target`.

### CLI params

| Param | Type | Description |
|-------|------|-------------|
| `--daemon [SECONDS]` | Optional u64, default 600 | Keep forest alive with idle timeout. Requires `--forest`. |
| `--connect <ID>` | u64 | Connect to a running daemon's REPL (standalone operation). |
| `--target <ID>` | u64 | Push operation result into a running daemon. Modifier for `-a`, `-s`, `-w`, `-f`. |

### Daemon startup flow

1. Run existing 4-phase forest algorithm (unchanged)
2. Use PID as the ephemeral ID
3. Create Unix socket at `/tmp/aqua-forest-<PID>.sock`
4. Print startup banner with ID, timeout, and socket path
5. `tokio::select!` on stdin REPL / socket accept / idle timeout / Ctrl+C
6. On exit: remove socket file, print shutdown message

### Concurrency model

- `Arc<tokio::sync::Mutex<DaemonState>>` for shared state
- `DaemonState` holds: `Forest`, `Aquafier`, `rev_to_tree` index, idle tracking
- `touch()` called on every command from any source (stdin, socket, `--target`)
- Per socket connection: spawned task, locks state per command

### Socket protocol

Line-based text:
- Client sends: `<command>\n`
- Server responds: multi-line response terminated by `\0\n` sentinel
- `ingest` command: Tree JSON on single line (no newlines in JSON)

### REPL command grammar

**Read commands:**

| Command | SDK method | Output |
|---------|-----------|--------|
| `status` | `summary()` + `remaining()` | Node/genesis/pending counts + idle time remaining |
| `geneses` | `genesis_hashes()` | List all genesis hashes |
| `tips` | `tips()` | List all tip (leaf) hashes |
| `pending` | `pending_dependencies()` | List unresolved L3 deps with owner counts |
| `inspect <hash>` | `get_state_node(hash)` | Full state node details |
| `branches <hash>` | `branches(hash)` | Direct children of a node |
| `tree <hash>` | recursive walk | Indented subtree |
| `count` | `node_count()` | Live node count |

**Write commands:**

| Command | SDK method | Semantics |
|---------|-----------|-----------|
| `add <file> [file...]` | verify + `insert_node` | Ingest new .aqua.json files |
| `evict <genesis_hash>` | `evict_node(hash)` | Remove genesis + cascade entire subtree |
| `remove <hash>` | `remove_node(hash)` | Surgical remove single node (no cascade) |

**Session commands:** `help`, `quit` / `exit`

**Hash prefix matching:** All `<hash>` arguments accept prefix matching
(minimum 8 hex chars after `0x`). Ambiguous prefixes return an error
listing all matches.

**Hidden `ingest` command:** Used by `--target` to push a serialized
Tree JSON into the forest. Not intended for interactive use.

### `--target` integration

When `-a`, `-s`, `-w`, or `-f` is invoked with `--target <ID>`,
the result tree is serialized to JSON and sent to the daemon via the
`ingest` command on the Unix socket. The daemon verifies and inserts
the tree, then returns a status line.

Implemented in `src/aqua/target.rs` (`push_tree_to_daemon()`), called
from `verify.rs`, `sign.rs`, `witness.rs`, and `revisions.rs`.

### Key structs

```rust
// src/aqua/forest.rs
struct DaemonState {
    forest: Forest,
    aquafier: Aquafier,
    rev_to_tree: HashMap<String, (String, Tree)>,
    last_accessed: Instant,
    idle_timeout: Duration,
    id: u64,
    verbose: bool,
}
```

---

## End-to-End Example

```bash
# 1. Generate simulation trees
cargo run --bin aqua-cli --features simulation -- --simulate --keep -v
# Output: /tmp/aqua-sim-XXXXXX/ with 24 .aqua.json files

# 2. Ephemeral forest verification (exits immediately)
cargo run --bin aqua-cli -- \
  --forest /tmp/aqua-sim-XXXXXX/*.aqua.json \
  --trust did:pkh:p256:0x02... 2

# 3. Persistent daemon (stays alive for 600s)
cargo run --bin aqua-cli -- \
  --forest /tmp/aqua-sim-XXXXXX/*.aqua.json --daemon
# forest> status
# forest> geneses
# forest> inspect 0xabcdef12
# forest> add /path/to/new.aqua.json
# forest> evict 0xabcdef12
# forest> quit

# 4. Connect from another terminal
cargo run --bin aqua-cli -- --connect <PID>
# forest> tips
# forest> tree 0xabcdef12

# 5. Push verification into running daemon
cargo run --bin aqua-cli -- -a newfile.aqua.json --target <PID>

# 6. Single-file attestation verification (auto-finds claim in same dir)
cargo run --bin aqua-cli -- -a /tmp/aqua-sim-XXXXXX/A4_attestation.aqua.json
```

---

## Source Files

- `src/aqua/forest.rs` — `cli_ephemeral_forest()`, 4-phase algorithm, `DaemonState`, `run_daemon()`, `execute_command()`, `handle_socket_client()`
- `src/aqua/connect.rs` — `cli_connect_forest()`, client REPL for `--connect`
- `src/aqua/target.rs` — `push_tree_to_daemon()`, helper for `--target`
- `src/aqua/verify.rs` — `cli_verify_chain()`, directory-scan resolution, `--target` push
- `src/aqua/sign.rs` — `cli_sign_chain()`, `--target` push after signing
- `src/aqua/witness.rs` — `cli_winess_chain()`, `--target` push after witnessing
- `src/aqua/revisions.rs` — `cli_generate_aqua_chain()`, `--target` push after genesis
- `src/main.rs` — `--forest`, `--daemon`, `--connect`, `--target`, `--trust` arg parsing
- `src/models.rs` — `CliArgs.daemon: Option<u64>`, `.connect: Option<u64>`, `.target: Option<u64>`, `.trust: Option<(String, u8)>`
