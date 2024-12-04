use bip32::{Mnemonic, Language, ExtendedPrivateKey, DerivationPath};
use k256::{
    SecretKey,
    ecdsa::{SigningKey, Signature, signature::Signer},
    elliptic_curve::sec1::ToEncodedPoint,
};
use tiny_keccak::{Keccak, Hasher};
use std::str::FromStr;
use eyre::Result;
use sha3::{Keccak256, Digest};

fn generate_mnemonic() -> Result<String> {
    // Generate a new random mnemonic (24 words)
    let mnemonic = Mnemonic::random(&mut rand::thread_rng(), Language::English);
    
    // Return the mnemonic as a string
    Ok(mnemonic.phrase().to_string())
}

pub(crate) fn get_wallet(mnemonic_str: &str, on_fail_gen_mnemonic : bool) -> Result<(String, String, String)> {
    // Parse mnemonic
    let mnemonic = match Mnemonic::new(mnemonic_str.trim(), Language::English) {
        Ok(m) => m,
        Err(_) => {
            if on_fail_gen_mnemonic{
                // If parsing fails, generate a new mnemonic
            let new_mnemonic = generate_mnemonic()?;
            println!("=============================================");
            println!(" \n\n Generated new mnemonic: {} \n\n", new_mnemonic);
            println!("=============================================");
            Mnemonic::new(new_mnemonic.trim(), Language::English)?
            }else{
                panic!("Unable to parse mnemonic , set to generate mnemonic by changing level")
            }
        }
    };
    
    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("");
    
    // Derive Ethereum private key (m/44'/60'/0'/0/0)
    let path = DerivationPath::from_str("m/44'/60'/0'/0/0")?;
    let key = ExtendedPrivateKey::<SecretKey>::derive_from_path(&seed, &path)?;
    let private_key = key.private_key();
    
    // Generate public key
    let public_key = private_key.public_key();
    let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
    let public_key_string = hex::encode(&public_key_bytes);
    let public_key_hex = format!("0x{}", public_key_string);

    
    // Generate Ethereum address (last 20 bytes of keccak256 of public key)
    let mut hasher = Keccak::v256();
    hasher.update(&public_key_bytes[1..]); // Skip the first byte (0x04 prefix)
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let address = format!("0x{}", hex::encode(&hash[12..])); // Take last 20 bytes
    
    // Get private key as hex
    let private_key_hex = hex::encode(private_key.to_bytes());
    
    Ok((address.to_lowercase(), public_key_hex, private_key_hex))
}




pub(crate) fn create_ethereum_signature(private_key_hex: &str, verification_hash: &str) -> Result<String> {
    // Convert private key from hex to bytes
        let private_key_bytes = hex::decode(private_key_hex)?;
        
        // Create SecretKey from bytes slice
        let secret_key = SecretKey::from_slice(&private_key_bytes)?;
        let signing_key = SigningKey::from(secret_key);
    
        // Create the message in the same format as the JS version
        let message = format!(
            "I sign the following page verification_hash: [0x{}]",
            verification_hash
        );
    
        // Create Ethereum specific message prefix
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let prefixed_message = [prefix.as_bytes(), message.as_bytes()].concat();
    
        // Hash the prefixed message with Keccak256
        let mut hasher = Keccak256::new();
        hasher.update(&prefixed_message);
        let message_hash = hasher.finalize();
    
        // Sign the hash
        let signature: Signature = signing_key.sign(&message_hash);
    
        // Convert to bytes and add recovery ID
        let mut sig_bytes = signature.to_bytes().to_vec();
        
        // Add recovery ID (27 or 28) at the end
        sig_bytes.push(27);
    
        // Convert to hex
        Ok(format!("0x{}", hex::encode(sig_bytes)))
}
