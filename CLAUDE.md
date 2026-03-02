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
cargo run --bin aqua-cli -- --forest *.aqua.json                     # ephemeral forest
cargo run --bin aqua-cli -- --forest *.aqua.json --trust <DID> 2     # with trust store
cargo run --bin aqua-cli -- --forest *.aqua.json --daemon            # persistent daemon (600s idle)
cargo run --bin aqua-cli -- --forest *.aqua.json --daemon 300        # custom timeout
cargo run --bin aqua-cli -- --connect <PID>                          # connect to running daemon
cargo run --bin aqua-cli -- -a file.aqua.json --target <PID>         # push into daemon
cargo run --bin aqua-cli -- -a attestation.aqua.json                 # verify (dir-scan for linked trees)
```

---

## Skills

| Skill | Topic |
|---|---|
| `skills/claim-attestation-building.md` | Correct way to build `PlatformIdentityClaim` + `Attestation` trees |
| `skills/template-tree-structure.md` | Template-based tree structure: genesis anchor model, L1/L2 hierarchy |
| `skills/forest-and-cross-tree-verification.md` | `--forest` daemon Forest, `--daemon` persistent mode, `--connect`/`--target` IPC, `--authenticate` directory-scan, `--trust` param |

---

## Key Source Files

| File | Purpose |
|---|---|
| `src/main.rs` | CLI arg parsing (clap), main dispatch |
| `src/aqua/verify.rs` | Verification (`--authenticate`); directory-scan cross-tree resolution |
| `src/aqua/sign.rs` | Signing (cli, did, p256, metamask) |
| `src/aqua/witness.rs` | Witnessing (eth, nostr, tsa) |
| `src/aqua/revisions.rs` | Genesis generation, delete revision |
| `src/aqua/link.rs` | Chain linking |
| `src/aqua/forest.rs` | `--forest` ephemeral forest + `--daemon` persistent mode with REPL and Unix socket IPC |
| `src/aqua/connect.rs` | `--connect <ID>` client REPL — connects to running daemon via Unix socket |
| `src/aqua/target.rs` | `--target <ID>` helper — pushes Tree into running daemon via `ingest` command |
| `src/simulation/` | `--simulate` identity state suite (12 scenarios) |

---

## SDK Reference

See `../aqua-rs-sdk/CLAUDE.md` for full SDK context, build commands, and skills.
