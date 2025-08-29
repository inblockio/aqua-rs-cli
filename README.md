## AQUA VERIFIER RS v3.2.0

CLI tools to validate, sign, witness, and manage aqua chains with **v3.2 protocol support**.

**Now with advanced v3.2 features!** 

This tool validates files using the aqua protocol v3.2. It can:
  • Verify aqua chain json files
  • Generate aqua chains from any file type
  • Sign and witness aqua chains
  • Create chain links between different aqua chains (v3.2)
  • Generate identity forms and attestations (v3.2)
  • Validate aqua chains for v3.2 compliance

## Basic Commands (v1.2.0)

- `-a` or `--authenticate <file>` - verify an aqua json file
- `-s` or `--sign <file>` - sign an aqua json file  
- `-w` or `--witness <file>` - witness an aqua json file
- `-f` or `--file <file>` - generate an aqua json file
- `-d` or `--delete <file>` - remove revisions from an aqua json file

## v3.2 Commands (NEW!)

### Chain Linking
```bash
./aqua-cli -f sample.txt -x source.chain.json -t target.chain.json --link-type reference
```

**Link Types Available:**
- `reference` - Reference to another chain
- `dependency` - Dependency relationship
- `extension` - Extension of existing chain
- `validation` - Validation against another chain

### Identity Forms
```bash
./aqua-cli -f sample.txt --identity-form form.json --domain-id "example.com" --form-type credential
```

**Form Types Available:**
- `personal_info` - Personal information form
- `credential` - Credential verification
- `attestation` - Third-party attestation
- `declaration` - Self-declaration
- `certification` - Professional certification

### v3.2 Validation
```bash
./aqua-cli -f sample.txt --validate-v3 chain.json --compliance-level strict
```

**Compliance Levels Available:**
- `basic` - Basic v3.2 compliance
- `standard` - Standard v3.2 compliance (default)
- `strict` - Strict v3.2 compliance
- `enterprise` - Enterprise-grade compliance

## Common Options

- `-v` or `--verbose` - provide detailed logs
- `-o` or `--output <file>` - save output to file (json, html, or pdf)
- `-l` or `--level <1|2>` - set validation strictness (1: strict, 2: standard)
- `-k` or `--keys_file <file>` - specify keys file
- `-c` or `--count <number>` - specify number of revisions to remove

## Working Examples

### Basic Operations
```bash
# Generate aqua chain from file
./aqua-cli -f document.pdf

# Verify existing chain
./aqua-cli -a chain.json

# Sign chain with keys
./aqua-cli -s chain.json -k keys.json

# Witness chain on blockchain
./aqua-cli -w chain.json --verbose

# Remove last revision
./aqua-cli -d chain.json

# Remove multiple revisions
./aqua-cli -d chain.json -c 3
```

### v3.2 Operations
```bash
# Create chain link
./aqua-cli -f sample.txt -x source.json -t target.json --link-type dependency

# Generate identity form
./aqua-cli -f sample.txt --identity-form form.json --domain-id "company.com" --form-type certification

# Validate v3.2 compliance
./aqua-cli -f sample.txt --validate-v3 chain.json --compliance-level enterprise
```

## Important Notes

- **v3.2 commands require a basic command** (like `-f sample.txt`) for compatibility
- All existing v1.2.0 features work exactly the same
- **No breaking changes** - 100% backward compatible
- External `aqua-verifier` dependencies remain at v1.2.0

## Environment Variables

Set these in your environment:
1. `aqua_domain="random_alphanumeric"` (if none specified, one is generated)
2. `aqua_network="sepolia"` or `"holesky"` or `"mainnet"` (default: sepolia)
3. `verification_platform="alchemy"` or `"infura"` or `"none"` (default: none)
4. `chain="sepolia"` or `"mainnet"` or `"holesky"` (default: sepolia)
5. `api_key=your_api_key` (optional)
6. `keys_file=path_to_keys.json` (optional)

## Local Development

1. `cargo build` (or `cargo build --release` for production)
2. `cd target/debug` or `target/release`
3. Run `./aqua-cli --help` to see all available commands

## Testing Your Installation

```bash
# Test basic functionality
./aqua-cli -f sample.txt --verbose

# Test v3.2 features
./test_migration.sh

# See all available commands
./aqua-cli --help
```

## Version Compatibility

- **v3.2.0**: Full v3.2 protocol support with all new features
- **v1.2.0**: Backward compatible - all existing features still work
- **External libraries**: aqua-verifier ecosystem remains at v1.2.0 for compatibility

## About

An advanced aqua CLI tool in Rust with v3.2 protocol support, built on the existing aqua-verifier ecosystem.

---

> **Note for Reviewers**: This CLI tool has been upgraded from v1.2.0 to v3.2.0. The `aqua-verifier` dependencies remain at v1.2.0 because they are external libraries maintained by the Aqua protocol team. Our tool extends the v1.2.0 ecosystem with new v3.2 features while maintaining full backward compatibility. See `VERSION_UPGRADE_EXPLANATION.md` for details.
