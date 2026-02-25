## AQUA VERIFIER RS
CLI tools to validate aqua chain.

## Versioning
Ensure to use the same version as the Aqua protocol version you are using for example use version 1.2.XX to verify  1.2.0 Aqua chain Json file.

## optional
in your environment set the following variables.<br/>
  1. aqua_domain="random_alphanumeric" (if none is specified one is genrated)<br/>
  2. aqua_network="sepolia" or  "holesky" or "mainnet" (default is sepolia)<br/>
  3. verification_platform="alchemy" or "infura" or  "self" or "none" for witnessing . self scraps the etherscan.io (avoid if possible) (optional) default is none <br/>
  4. chain="sepolia" or "mainnet" or "holesky" for witnessing  (optional) default is none<br/>
  5. api_key=  the alchemy key or infura api key (optional)<br/>
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

## Local use
1. `cargo build ` you can optionally use the `--release` if you want to use te cli tool.
2. cd `target/debug` or `target/release` run aqua-cli binary .
3. to get start run `./aqua-cli --help`


## Testing using the `test_aqua_cli` script

1. Give the file some permissions

```bash
chmod +x test_aqua_cli.sh
```

2. Run the script

```bash
./test_aqua_cli.sh
```