## AQUA VERIFIER RS
CLI tools to validate aqua chain.

This project depends on [aqua-rs-sdk](https://github.com/inblockio/aqua-rs-sdk) v4.

## optional

### Auditing simulation trees
Run once to persist the files:
cargo run --features simulation --bin aqua-cli -- --simulate --keep
The directory path is printed — e.g. /tmp/aqua-sim-6MSEts.

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
