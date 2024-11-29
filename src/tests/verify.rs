#[cfg(test)]
pub mod tests {
    use std::{fs, path::{Path, PathBuf}};
    use tempfile::tempdir;
    // use tempfile::tempdir;
    // use super::*; // Import parent module's structs and functions
    use verifier::aqua_verifier::{AquaVerifier, VerificationOptions};
    use aqua_verifier_rs_types::models::page_data::PageData;

    use crate::{aqua::verify::cli_verify_chain, models::CliArgs};

    #[test]
    fn test_verify_chain() {
        // Create a temporary directory for our test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Create a test aqua data file
        // let verify_path = create_test_aqua_data_file(temp_dir.path());

        let path = Path::new("src/test/data/logo.chain.json").to_path_buf();

        print!("Path is {}", path.display());

        // let res: Result<PageData, String> = read_aqua_data(&path.to_path_buf());

        // if res.is_err(){
        //     panic!("Cannot read json");

        // }

        // Prepare CLI arguments for testing
        let cli_args = CliArgs {
            authenticate: None,
            sign: None,
            witness: None,
            file: Some(path),
            remove: None,
            remove_count: 0,
            verbose: true, // Set to true to see detailed logs during test
            output: Some(temp_dir.path().join("test_output_logs.txt")),
            level: Some("2".to_string()), // Adjust as needed
            keys_file: None,
        };

       
    let option = VerificationOptions {
        version: 1.2,
        strict: false,
        allow_null: false,
        verification_platform: "none".to_string(),
        chain: "sepolia".to_string(),
        api_key: "".to_string(),
    };

    let aqua_verifier = AquaVerifier::new(Some(option));


        // Call the function being tested
        // This is a no-panic test to ensure the function runs without crashing
        cli_verify_chain(
            cli_args.clone(), 
            aqua_verifier, 
            cli_args.file.unwrap()
        );

        // Optional: Add assertions to verify expected behavior
        // 1. Check if output file was created
        assert!(cli_args.output.as_ref().unwrap().exists(), 
            "Output log file should have been created");

        // 2. Read and optionally check the contents of the output log
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        // Add more specific assertions based on your expected verification results
        // For example:
        assert!(!log_contents.is_empty(), "Log file should not be empty");
        // You might want to add more specific checks based on your verification logic
    }

    
    #[test]
    fn test_verify_chain_with_invalid_file() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Create an intentionally invalid file path
        // let invalid_path = temp_dir.path().join("non_existent_file.json");

        let path = Path::new("src/test/data/non_existent_file.json").to_path_buf();

        print!("Path is {}", path.display());

    

        // Prepare CLI arguments for testing
        let cli_args = CliArgs {
            authenticate: None,
            sign: None,
            witness: None,
            file: Some(path),
            remove: None,
            remove_count: 0,
            verbose: true, // Set to true to see detailed logs during test
            output: Some(temp_dir.path().join("test_output_logs.txt")),
            level: Some("2".to_string()), // Adjust as needed
            keys_file: None,
        };


        let option = VerificationOptions {
            version: 1.2,
            strict: false,
            allow_null: false,
            verification_platform: "none".to_string(),
            chain: "sepolia".to_string(),
            api_key: "".to_string(),
        };
    
        let aqua_verifier = AquaVerifier::new(Some(option));
        

        // This test ensures graceful handling of non-existent files
        cli_verify_chain(
            cli_args.clone(), 
            aqua_verifier, 
            cli_args.file.unwrap()
        );

        // Verify error handling
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        assert!(log_contents.contains("Error"), 
            "Log should contain an error message for invalid file");
    }
}