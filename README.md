## AQUA VERIFIER RS
CLI tools to validate aqua chain.

This project depends on [aqua-rs-sdk](https://github.com/inblockio/aqua-rs-sdk) v4.

## Simulation Suites

Three simulation modes are available (require `--features simulation`):

| Flag | Scenarios | Coverage |
|------|-----------|----------|
| `--simulate` | 12 | Core WASM states: 6 claim + 6 attestation |
| `--simulate-personas` | 15 | 5 personas covering all 15 derived identity templates |
| `--simulate-2` | 29 | Comprehensive: 5 personas (25 claims) + 4 error scenarios covering all 17 WASM return values |

### Running simulations

```bash
# Core 12-scenario suite
cargo run --features simulation --bin aqua-cli -- --simulate -v

# 15-persona template coverage suite
cargo run --features simulation --bin aqua-cli -- --simulate-personas -v

# SIM-2: comprehensive identity simulation (29 scenarios)
cargo run --features simulation --bin aqua-cli -- --simulate-2 -v
```

### Persisting simulation trees

Add `--keep` to write `.aqua.json` files to a temporary directory for inspection or loading into the state-viewer:

```bash
cargo run --features simulation --bin aqua-cli -- --simulate-2 -v --keep
# Output: /tmp/aqua-sim-XXXXXX/ with persona-named .aqua.json files
```

### SIM-2 with state-viewer (invalidation demo)

SIM-2 integrates with the forest daemon for real-time state-viewer invalidation:

```bash
# 1. Generate and persist the dataset
cargo run --features simulation --bin aqua-cli -- --simulate-2 --keep

# 2. Load into a forest daemon (HTTP API for state-viewer)
cargo run --bin aqua-cli -- --forest /tmp/aqua-sim-*/*.aqua.json --daemon

# 3. In the daemon REPL, remove signature nodes to demonstrate invalidation
forest> invalidate amara-attestation
# State-viewer detects removal via GET /removed → attested → unsigned
```

The `invalidate` REPL command matches ingested tree names by substring, finds all signature nodes in the matching tree, and removes them from the forest. The state-viewer polls `GET /removed` to detect and reflect the change in real time.

### SIM-2 personas

| # | Persona | Location | Claims | Key type | WASM states covered |
|---|---------|----------|--------|----------|---------------------|
| S1 | Amara Osei | Accra | 7 | secp256k1/EIP-191 | self_signed, attested, expired, not_yet_valid (claim + platform + attestation) |
| S2 | Kenji Tanaka | Tokyo | 5 | Ed25519 | self_signed, unsigned, untrusted, headless |
| S3 | Sofia Reyes | Mexico City | 4 | P-256 | attested, expired, self_signed, unsigned (attestation) |
| S4 | Lars Eriksson | Stockholm | 3 | Ed25519 | attested, not_yet_valid, untrusted (attestation) |
| S5 | Priya Sharma | Mumbai | 6 | secp256k1/EIP-191 | unsigned, self_signed, attested, untrusted, expired, not_yet_valid (attestation) |

Error scenarios E1–E4 cover structural rejection (-1), headless edge cases, and self-attestation.

in your environment set the following variables.<br/>

If you use eth-timestamping you'll need to set a verification_platform="alchemy" or "infura" api_key=  the alchemy key or infura api key (optional)<br/>
  6. keys_file = path to json file with similar contents as thos in keys.sample.json use a wallet without metemask<br/>
<br/>
Notes : if a keys file is speciefied in the commands it will take precendence over the environment  valriables specified keys file

## Commands

| Flag | Description |
|------|-------------|
| `-a`, `--authenticate` | Verify an aqua json file |
| `-s`, `--sign` | Sign an aqua json file (requires `--sign-type`) |
| `--sign-type` | Signing method: `cli`, `metamask`, `did`, or `p256` |
| `-w`, `--witness` | Witness an aqua json file (requires a witness type flag) |
| `--witness-eth` | Witness to Ethereum on-chain |
| `--witness-nostr` | Witness to Nostr network |
| `--witness-tsa` | Witness to TSA DigiCert |
| `-f`, `--file` | Generate an aqua json file from a source file |
| `--link` | Link two aqua chain files (requires two paths) |
| `-d`, `--delete` | Remove the last revision from an aqua json file |
| `-k`, `--keys_file` | Path to keys file (can also be set via env) |
| `-o`, `--output` | Save output to a file (json, html, or pdf) |
| `-l`, `--level` | Validation strictness: `1` (strict) or `2` (standard, default) |
| `-v`, `--verbose` | Show detailed logs |
| `-i`, `--info` | Show CLI version and help |
| `--previous-hash` | Target a specific revision by hash instead of the latest (see below) |
| `--create-object` | Create a genesis object revision with a custom template and JSON payload |
| `--template-name` | Built-in template name for `--create-object` (see `--list-templates`) |
| `--template-hash` | Custom template hash (`0x`-prefixed) for `--create-object` |
| `--payload` | JSON payload: a file path or inline JSON string for `--create-object` |
| `--list-templates` | List all available built-in templates with their hashes |
| `--forest <FILES...>` | Ingest `.aqua.json` files into an ephemeral in-memory forest |
| `--daemon [SECONDS]` | Keep forest alive as persistent daemon (default: 600s idle timeout). Starts HTTP API on port 8800 by default |
| `--listen <PORT>` | Override daemon HTTP API port (default: 8800, requires `--daemon`) |
| `--no-listen` | Disable the HTTP API in daemon mode (Unix socket only) |
| `--connect <ID>` | Connect to a running forest daemon's REPL by its PID |
| `--target <ID>` | Push operation results into a running daemon's forest by its PID |
| `--trust <DID> <LEVEL>` | Populate trust store (1=marginal, 2=full, 3=ultimate). Used with `--forest` |
| `--simulate` | Run the 12-scenario WASM state simulation (requires `--features simulation`) |
| `--simulate-personas` | Run the 15-scenario persona simulation (requires `--features simulation`) |
| `--simulate-2` | Run the 29-scenario comprehensive identity simulation (requires `--features simulation`) |
| `--invalidate <NAME>` | Remove attester signature for state-viewer invalidation demo (use with `--simulate-2`) |
| `--keep` | Keep simulation tree files on disk for inspection |
| `--cleanup [all]` | Remove orphaned daemon sockets; with `all`, also kill live daemons |

### `--previous-hash` option

By default, sign, witness, and link operations append to the **latest** revision in the chain, producing a strictly linear history. The `--previous-hash` option lets you target any existing revision by its hash, enabling **tree/DAG structures** — e.g., creating two branches from the same genesis revision.

The value must be a `0x`-prefixed lowercase hex hash that appears in the aqua chain file.

```bash
# Create a genesis revision
aqua-cli -f document.pdf

# Sign it (default — targets latest revision)
aqua-cli -s aqua.json --sign-type cli -k keys.json

# Sign again, but branch from genesis instead of the tip
aqua-cli -s aqua.json --sign-type cli -k keys.json --previous-hash 0x<genesis_hash>

# Witness targeting a specific revision
aqua-cli -w aqua.json --witness-tsa --previous-hash 0x<revision_hash>
```

### `--create-object` option

The `--create-object` flag creates a **genesis object revision** — a new aqua chain whose first revision is populated from a structured template and a JSON payload, rather than from a file hash.

It requires:
- **`--template-name <NAME>`** (a built-in template) **or** **`--template-hash <HASH>`** (a custom `0x`-prefixed hash)
- **`--payload <PATH_OR_JSON>`** — either a path to a JSON file or an inline JSON string

The output is saved as `<source>.aqua.json` (for file payloads) or `object.aqua.json` (for inline JSON).

```bash
# Create object using a built-in template name and a JSON file:
aqua-cli --create-object --template-name domain --payload domain_data.json

# Create object with inline JSON:
aqua-cli --create-object --template-name name --payload '{"name": "Alice Smith", "wallet_address": "0x1234567890abcdef1234567890abcdef12345678"}'

# Create object with a custom template hash:
aqua-cli --create-object --template-hash 0x<hash> --payload data.json

# Example: create a domain claim object using the template hash and a JSON file:
aqua-cli --create-object \
  --template-hash 0xce6751a5591dfe428c19c8352cbdd1ec7b030dfbb139ab5a00f60aa1ec305532 \
  --payload domain_sample.json
```

**Example `domain_sample.json`:**

```json
{
    "domain": "inblock.io",
    "wallet_address": "0x1234567890abcdef1234567890abcdef12345678"
}
```

### `--list-templates` option

Prints all 15 built-in template names, their corresponding hashes, and the required/optional payload fields for each template. Useful for discovering the available `--template-name` values, obtaining a hash for `--template-hash`, and understanding what payload fields each template expects.

```bash
aqua-cli --list-templates
```

### `--cleanup` option

Scans `/tmp` for `aqua-forest-{PID}.sock` files left behind by daemon processes. Orphaned sockets (whose owning process is no longer running) are removed automatically. With the `all` argument, live daemons are also terminated (via `SIGTERM`) and their sockets removed.

```bash
# Remove only orphaned sockets (live daemons are left untouched)
aqua-cli --cleanup

# Kill all running daemons and remove all sockets
aqua-cli --cleanup all
```

## Local use
1. `cargo build ` you can optionally use the `--release` if you want to use te cli tool.
2. cd `target/debug` or `target/release` run aqua-cli binary .
3. to get start run `./aqua-cli --help`


## Licensing

This project is dual-licensed:
- **Open source**: GNU Affero General Public License v3.0 (AGPLv3) – see [LICENSE](LICENSE)
- **Commercial**: Available under a proprietary commercial license from inblock.io assets GmbH for use cases that require closed-source integration, no source disclosure, or additional warranties/support.

All contributions are governed by our [Contributor License Agreement](CLA.md).
By submitting code you agree to the CLA, which assigns all economic rights to inblock.io assets GmbH, enabling this dual model.

## Testing using the `test_aqua_cli` script

1. Give the file some permissions

```bash
chmod +x test_aqua_cli.sh
```

2. Run the script

```bash
./test_aqua_cli.sh
```
