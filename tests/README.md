# Sharness Tests for aqua-cli

Shell-based integration tests using the [sharness](https://github.com/felipec/sharness) test framework.

## Setup

```bash
# Build the binary
cargo build

# Install sharness (downloads v1.2.0 into tests/sharness/)
bash tests/install-sharness.sh
```

## Running Tests

```bash
# Run all tests
cd tests && make test

# Run a single test with verbose output
./tests/test-genesis.sh -v

# Run with custom options
cd tests && make test TEST_OPTS="--verbose"
```

## Test Files

| File | Description |
|------|-------------|
| `test-genesis.sh` | Genesis chain generation, revision structure, file_index |
| `test-verify.sh` | Chain verification, verbose output, tamper detection |
| `test-signing.sh` | CLI, DID, and P256 signing; missing keys error |
| `test-delete.sh` | Revision deletion, sign-delete-verify cycle |
| `test-linking.sh` | Chain linking, verify linked chains |
| `test-witness.sh` | TSA and Nostr witnessing (graceful network degradation) |
| `test-object-creation.sh` | Object creation with templates and payloads |
| `test-forest.sh` | Ephemeral forest ingestion |

## Fixtures

Located in `tests/fixtures/`:
- `sample.txt` / `sample2.txt` — Sample text files
- `keys.json` — Test signing and witnessing keys
- `payload.json` — Sample payload for object creation

## Notes

- Tests run in isolated trash directories (created by sharness)
- Network-dependent tests (TSA, Nostr witnessing) degrade gracefully
- The binary is expected at `target/debug/aqua-cli` (run `cargo build` first)
