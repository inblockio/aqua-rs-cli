# Identity Simulation, Forest & State Viewer Guide

## 1. Create an Identity Simulation (CLI)

### Quick run (12 base scenarios)

```bash
cargo build --features simulation
./target/debug/aqua-cli --simulate -v
```

This runs 12 scenarios across two categories:

| ID | Scenario | Expected State |
|----|----------|---------------|
| C1 | Unsigned claim, empty trust store | `unsigned` |
| C2 | Self-signed claim, not in trust store | `self_signed` |
| C3 | Two-tree: untrusted attester | `untrusted` |
| C4 | Two-tree: trusted attester (level 2) | `attested` |
| C5 | Two-tree: trusted but expired | `expired` |
| C6 | Two-tree: trusted but not yet valid | `not_yet_valid` |
| A1-A6 | Same states but on Attestation trees | (mirrors above) |

### Persona simulation (15 scenarios across 5 personas)

```bash
./target/debug/aqua-cli --simulate-personas -v
```

Runs 5 real-world personas (Alice, Bob, Claire, David, Eve) with 3 scenarios each, covering all 15 identity templates (GitHubClaim, EmailClaim, PassportClaim, etc.).

### Keep the trees for inspection

```bash
./target/debug/aqua-cli --simulate --keep -v
./target/debug/aqua-cli --simulate-personas --keep -v
```

`--keep` writes all `.aqua.json` trees to a temp directory (`aqua-sim-*`) and prints the paths so you can inspect them with `jq` or load them into the state viewer.

---

## 2. View the Forest in the State Viewer

### Start the state viewer

```bash
cd ../aqua-state-viewer
cargo run
```

This launches a 3D DAG visualizer on **http://localhost:8080** using Three.js + force-directed graphs.

### Load simulation trees into the viewer

**Option A — Drag and drop** the `.aqua.json` files from the `--keep` output directory into the browser.

**Option B — CLI upload** via the API:

```bash
# Create a session
curl -X POST http://localhost:8080/api/sessions

# Upload a file (replace SESSION_ID and path)
curl -X POST http://localhost:8080/api/sessions/<SESSION_ID>/load-file \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/aqua-sim-XXXX/C4_claim.aqua.json"}'
```

**Option C — Use the CLI forest daemon + viewer together:**

```bash
# Start a persistent forest daemon with simulation trees
./target/debug/aqua-cli --forest /tmp/aqua-sim-*/*.aqua.json --daemon -v
```

### Viewer features

- **Node colors** indicate revision types (genesis, signature, anchor, etc.)
- **Edge colors**: white=chain, orange=branch, pink=L3 anchor (cross-tree), violet=L3 template
- **Click a node** to see full details (signer, payloads, WASM output, timestamps)
- **Time scrubber** for temporal navigation

---

## 3. Add/Remove Items from the Forest

### Start a persistent forest daemon

```bash
# Load initial trees and keep daemon running (600s idle timeout)
./target/debug/aqua-cli --forest *.aqua.json --daemon -v

# Or with trust store for WASM state evaluation
./target/debug/aqua-cli --forest *.aqua.json --trust did:pkh:ed25519:0xABC 2 --daemon
```

The daemon prints its **PID** on startup and opens a REPL prompt `forest>`.

### Add items

**From the REPL:**

```
forest> add /path/to/new-tree.aqua.json
forest> add file1.aqua.json file2.aqua.json file3.aqua.json
```

**From another terminal (via `--target`):**

```bash
# Sign a tree and push the result into the running daemon
./target/debug/aqua-cli -s tree.aqua.json --sign-type cli -k keys.json --target <PID>

# Verify a tree and push into the daemon
./target/debug/aqua-cli -a tree.aqua.json --target <PID>

# Generate a new tree and push it
./target/debug/aqua-cli -f document.pdf --target <PID>
```

**Programmatic ingest (raw JSON):**

```
forest> ingest {"revisions": {...}, ...}
```

### Remove items

**Evict a full tree** (genesis node + all descendants):

```
forest> evict 0x1234567890abcdef...
```

Only works on genesis nodes. Cascades removal to all child revisions.

**Remove a single node** (surgical, no cascade):

```
forest> remove 0x1234567890abcdef...
```

Cannot remove genesis roots (use `evict` for those).

### Inspect the forest

```
forest> status          # node count, pending deps, idle timeout
forest> geneses         # list all genesis (root) hashes
forest> tips            # list all tip (leaf) hashes
forest> pending         # unresolved cross-tree dependencies
forest> count           # total node count
forest> inspect 0x12... # full node details (supports prefix matching, min 8 hex chars)
forest> tree 0x12...    # indented subtree visualization
forest> branches 0x12.. # direct children of a node
```

### Connect from another terminal

```bash
./target/debug/aqua-cli --connect <PID>
```

This opens a remote REPL over Unix socket (`/tmp/aqua-forest-<PID>.sock`) with the same commands available.

---

## End-to-end example

```bash
# 1. Run simulation, keep trees
./target/debug/aqua-cli --simulate --keep -v
# Note the output directory, e.g. /tmp/aqua-sim-abc123/

# 2. Start state viewer in one terminal
cd ../aqua-state-viewer && cargo run

# 3. Start forest daemon with simulation trees in another terminal
./target/debug/aqua-cli --forest /tmp/aqua-sim-abc123/*.aqua.json --daemon -v

# 4. In the REPL, inspect what's loaded
forest> status
forest> geneses
forest> tree 0x<pick-a-genesis-hash>

# 5. Add a new tree
forest> add /path/to/another.aqua.json

# 6. Evict a tree
forest> evict 0x<genesis-hash>

# 7. From yet another terminal, push into the daemon
./target/debug/aqua-cli -f newfile.txt --target <PID>
```
