pub mod models;
pub mod utils;

use clap::{Command, Arg, ArgGroup, ArgAction};
use std::path::PathBuf;
use std::fs;

const LONG_ABOUT: &str = r#"🔐 Aqua CLI TOOL

========================================================

This tool validates files using a aqua protocol. It can:
  • Verify aqua chain json file
  • Generate aqua chain.
  • Generate validation reports

COMMANDS: 
   • -v  or --verify  to verify an aqua json file.
   • -s or --sign to sign an aqua json file.
   • -w or --witness to witness an aqua json file.
   • -f or --file to generate an aqua json file.
   • -d or --details to provide logs about the  process when using  -v,-s,-w or -f command (verbose option).
   • -o or --output to save the output to a file (json, html or pdf).
   • -l  or --level  define how strict the validation should be 1 or 2
        1: Strict validation
        2: Standard validation 
   • -h or --help to show usage, about aqua-cli.
   • -i or --info to show the cli version.
   • -a or --alchemy to specify the achemy paskey for strict validation (this is optional)

EXAMPLES:
    aqua-cli -v chain.json
    aqua-cli -s chain.json --output report.json
    aqua-cli -w chain.json --output report.json

    aqua-cli -f document.pdf
    aqua-cli --file image.png --details
    aqua-cli -f document.json --output report.json


SUMMARY
   aquq-cli expects ateast parameter -s,-v,-w or -f.

For more information, visit: https://github.com/inblockio/aqua-verifier-cli"#;

#[derive(Debug)]
pub struct CliArgs {
    pub verify: Option<PathBuf>,
    pub sign: Option<PathBuf>,
    pub witness: Option<PathBuf>,
    pub file: Option<PathBuf>,
    pub details: bool,
    pub output: Option<PathBuf>,
    pub level: Option<String>,
    pub alchemy: Option<String>,
}

pub fn parse_args() -> Result<CliArgs, String> {
    let matches = Command::new("aqua-cli")
    .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .long_about(LONG_ABOUT)
        .about("🔐 Aqua CLI Tool - Validates, Verifies, Signs , Witness aqua chain file and genreates aqua chain files  using aqua protocol")
        .arg(Arg::new("verify")
            .short('v')
            .long("verify")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Verify an aqua json file"))
        .arg(Arg::new("sign")
            .short('s')
            .long("sign")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Sign an aqua json file"))
        .arg(Arg::new("witness")
            .short('w')
            .long("witness")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Witness an aqua json file"))
        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_file))
            .help("Generate an aqua json file")
            .conflicts_with_all(["verify", "sign", "witness"]))
        .arg(Arg::new("details")
            .short('d')
            .long("details")
            .action(ArgAction::SetTrue)
            .help("Provide additional details")
            .long_help("to provide logs about the  process when using  -v,-s,-w or -f command (verbose option)"))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_output_file))
            .help("Save the output to a file (json, html or pdf)"))
        .arg(Arg::new("level")
            .short('l')
            .long("level")
            .help("Define how strict the validation should be")
            .long_help("Define how strict the validation should be:\n 1: Strict validation\n 2: Standard validation")
            .value_parser(["1", "2"])
            .default_value("2")
            .action(ArgAction::Set))
        .arg(Arg::new("alchemy")
            .short('a')
            .long("alchemy")
            .action(ArgAction::Set)
            .help("Specify the alchemy passkey for strict validation"))
        .group(ArgGroup::new("operation")
            .args(["verify", "sign", "witness", "file"])
            .required(true))
        .get_matches();

    let verify = matches.get_one::<String>("verify").map(|p| PathBuf::from(p));
    let sign = matches.get_one::<String>("sign").map(|p| PathBuf::from(p));
    let witness = matches.get_one::<String>("witness").map(|p| PathBuf::from(p));
    let file = matches.get_one::<String>("file").map(|p| PathBuf::from(p));
    let details = matches.get_flag("details");
    let output = matches.get_one::<String>("output").map(|o| PathBuf::from(o));
    let level = matches.get_one::<String>("level").cloned();
    let alchemy = matches.get_one::<String>("alchemy").cloned();

    Ok(CliArgs {
        verify,
        sign,
        witness,
        file,
        details,
        output,
        level,
        alchemy,
    })
}

fn is_valid_json_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() && path.extension().unwrap_or_default() == "json" {
        Ok(s.to_string())
    } else {
        Err("Invalid JSON file path".to_string())
    }
}

fn is_valid_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() {
        Ok(s.to_string())
    } else {
        Err("Invalid file path".to_string())
    }
}

fn is_valid_output_file(s: &str) -> Result<String, String> {
    let lowercase = s.to_lowercase();
    if lowercase.ends_with(".json") || lowercase.ends_with(".html") || lowercase.ends_with(".pdf") {
        Ok(s.to_string())
    } else {
        Err("Output file must be .json, .html, or .pdf".to_string())
    }
}

// Example usage in main function
fn main() {
    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });

    // Example validation of combined flags
    if args.verify.is_some() || args.sign.is_some() || args.witness.is_some() {
        if args.file.is_some() {
            eprintln!("Error: -f/--file cannot be used with -v, -s, or -w");
            std::process::exit(1);
        }
    }

    // Process the arguments based on the combination
    match (args.verify, args.sign, args.witness, args.file.is_some()) {
        (Some(verify_path), _, _, _) => {
            println!("Verifying file: {:?}", verify_path);
            // Verify the file
        },
        (_, Some(sign_path), _, _) => {
            println!("Signing file: {:?}", sign_path);
            // Sign the file
        },
        (_, _, Some(witness_path), _) => {
            println!("Witnessing file: {:?}", witness_path);
            // Witness the file
        },
        (_, _, _, true) => {
            if let Some(file_path) = args.file {
                println!("Generating aqua file from: {:?}", file_path);
                // Generate the aqua file
            }
        },
        _ => unreachable!("Clap ensures at least one operation is selected"),
    }
}