# aqua-rs-cli — Claude Code Context

CLI tool for the Aqua Protocol: verify, sign, witness, link, delete aqua chains.
Binary: `aqua-cli` | Entry: `src/main.rs` | SDK: `../aqua-rs-sdk` (path dep)

---

## Build & Run

```bash
cargo build
cargo build --features simulation     # include --simulate suite
cargo run --bin aqua-cli -- --help
cargo run --bin aqua-cli --features simulation -- --simulate -v
```

---

## Skills

| Skill | Topic |
|---|---|
| `skills/claim-attestation-building.md` | Correct way to build `PlatformIdentityClaim` + `Attestation` trees |
| `skills/template-tree-structure.md` | Template-based tree structure: genesis anchor model, L1/L2 hierarchy |

---

## Key Source Files

| File | Purpose |
|---|---|
| `src/main.rs` | CLI arg parsing (clap), main dispatch |
| `src/aqua/verify.rs` | Verification |
| `src/aqua/sign.rs` | Signing (cli, did, p256, metamask) |
| `src/aqua/witness.rs` | Witnessing (eth, nostr, tsa) |
| `src/aqua/revisions.rs` | Genesis generation, delete revision |
| `src/aqua/link.rs` | Chain linking |
| `src/aqua/forest.rs` | `--forest` ephemeral forest |
| `src/simulation/` | `--simulate` identity state suite (12 scenarios) |

---

## SDK Reference

See `../aqua-rs-sdk/CLAUDE.md` for full SDK context, build commands, and skills.
