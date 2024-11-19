## AQUA VERIFIER RS
CLI tools to validate aqua chain.

## Versioning
Ensure to use the same version as the Aqua protocol version you are using for example use version 1.2.XX to verify  1.2.0 Aqua chain Json file.

## optional
in your environment set the following variables.
    1. aqua_domain="random_alphanumeric" (if none is specified one is genrated)
    2. aqua_network="sepolia" or  "holesky" or "mainnet" (default is sepolia)
    3. verification_platform="alchemy" or "infura" or "none" for witnessing  (optional) default is none
    4. verification_platform_chain="sepolia" or "mainnet" or "holesky" for witnessing  (optional) default is none
    5. api_key=  the alchemy key or infura api key (optional)
    6. keys_file = pathe to json file with similar contents as thos in keys.sample.json use a wallet without metemask

Notes : if a keys fileis speciefied in the commands it will take precendence over the environment  valriables specified keys file

## Local use
1. `cargo build ` you can optionally use the `--release` if you want to use te cli tool.
2. cd `target/debug` or `target/release` run aqua-cli binary .
3. to get start run `./aqua-cli --help`
