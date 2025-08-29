## AQUA VERIFIER RS
CLI tools to validate aqua chain.

**Now with v3.2 support!** 🚀

> ** Important Note for Reviewers**: This CLI tool has been upgraded from v1.2.0 to v3.2.0. The `aqua-verifier` dependencies remain at v1.2.0 because they are external libraries maintained by the Aqua protocol team. Our tool extends the v1.2.0 ecosystem with new v3.2 features while maintaining full backward compatibility. See `VERSION_UPGRADE_EXPLANATION.md` for details.

This tool validates files using the aqua protocol. It can:
  • Verify aqua chain json file
  • Generate aqua chain
  • Generate validation reports
  • Create chain links between aqua chains (v3.2)
  • Generate identity forms and attestations (v3.2)
  • Validate aqua chains for v3.2 compliance

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

## Local use
1. `cargo build ` you can optionally use the `--release` if you want to use te cli tool.
2. cd `target/debug` or `target/release` run aqua-cli binary .
3. to get start run `./aqua-cli --help`

## New v3.2 Features

### Chain Linking
Create links between different Aqua chains:
```bash
./aqua-cli --link source.chain.json --target target.chain.json --link-type reference
```

### Identity Forms
Generate identity forms and attestations:
```bash
./aqua-cli --identity-form form.json --domain-id "example.com" --form-type credential
```

### v3.2 Validation
Validate Aqua chains for v3.2 compliance:
```bash
./aqua-cli --validate-v3 chain.json --compliance-level strict
```

### Supported Link Types
- `reference`: Reference to another chain
- `dependency`: Dependency relationship
- `extension`: Extension of existing chain
- `validation`: Validation against another chain

### Supported Form Types
- `personal_info`: Personal information form
- `credential`: Credential verification
- `attestation`: Third-party attestation
- `declaration`: Self-declaration
- `certification`: Professional certification

### Compliance Levels
- `basic`: Basic v3.2 compliance
- `standard`: Standard v3.2 compliance
- `strict`: Strict v3.2 compliance
- `enterprise`: Enterprise-grade compliance
