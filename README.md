## AQUA VERIFIER RS
CLI tools to validate aqua chain.

## Versioning
Ensure to use the same version as the Aqua protocol version you are using for example use version 1.2.XX to verify  1.2.0 Aqua chain Json file.

## optional
in your environment set the following variables.
    1. aqua_domain="random_alphanumeric"
    2. aqua_network="sepolia" or  "holesky" or "mainnet" (default is sepolia)
    3. alchemy_key="alchemy_key" for witnessing
    4. aqua_alchemy_look_up=  false or true

## Local use
1. `cargo build ` you can optionally use the `--release` if you want to use te cli tool.
2. cd `target/debug` or `target/release` run aqua-cli binary .
3. to get start run `./aqua-cli --help`
