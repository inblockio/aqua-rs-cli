use aqua_verifier_rs_types::models::{content::RevisionContent, base64::Base64};
use aqua_verifier_rs_types::models::hash::Hash;
use aqua_verifier_rs_types::models::revision::Revision;
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine as _};
use sha3::{Digest, Sha3_512};
use std::{collections::BTreeMap, fmt::format};
use verifier::verification::content_hash;

pub fn check_if_page_data_revision_are_okay(
    revisions: Vec<(Hash, Revision)>,
    log_data: &mut Vec<String>,
) -> (bool, String) {
    let mut is_valid = (true, "".to_string());
    let has_valid_genessis = revsions_has_valid_genesis(revisions.clone(), log_data);

    if has_valid_genessis.is_none() {
        return (
            false,
            "revisions do not contain a valid genesis".to_string(),
        );
    }

    // check if the revision > metadata > previous_verification_hash is among the hash in revsions par
    // if more that one is none return false
    // there is a broken revision chain
    let mut all_hashes: Vec<Hash> = Vec::new();
    revisions
        .iter()
        .for_each(|(hash, revision)| all_hashes.push(hash.clone()));

    let genesis_hash_str = format!("{:#?}", has_valid_genessis.unwrap());

    for (index, (current_hash, current_revision)) in revisions.iter().enumerate() {
        let current_hash_str = format!("{:#?}", current_hash);

        // check hash if match the newly generated one
        let recomputed_content_hash = compute_content_hash(&current_revision.content);

        match recomputed_content_hash {
            Ok(data) => {
                if data == *current_hash {
                    log_data
                        .push("Info : hashes match the generetaed one continue ...".to_string());
                } else {
                    log_data.push(format!("Error : hashes do not match revision has {:#?} \n vs generated hash {:#?} \n",data,current_hash ));
                    is_valid = (false, format!("a hash is not valid : {:#?}", current_hash));

                    break;
                }
            }
            Err(error) => {
                log_data.push(format!("Error : an error occured  {}", error));
                is_valid = (false, "error generating a hash ".to_string());
                break;
            }
        }

        if current_hash_str == genesis_hash_str {
            log_data.push(format!(
                "Info : ignoring genessis hash is {:#?}",
                genesis_hash_str
            ));
        } else {
            let contains = all_hashes.contains(current_hash);

            if contains == false {
                log_data.push(format!("cannot find hash is {:#?}", current_hash_str));
                is_valid = (false, "Hash chain is invalid ".to_string());
                break;
            }
        }
    }

    return is_valid;
}

pub fn revsions_has_valid_genesis(
    revisions: Vec<(Hash, Revision)>,
    log_data: &mut Vec<String>,
) -> Option<Hash> {
    if revisions.len() <= 1 {
        log_data.push("Info : The has chain only has one revision".to_string());

        return None;
    }

    let mut revision_genesis: Vec<&Revision> = Vec::new();

    for (index, (hash, revision)) in revisions.iter().enumerate() {
        match revision.metadata.previous_verification_hash {
            Some(_) => {
                // log_data.push(format!("Info : The previous hash is {:#?}", data));
            }
            None => {
                log_data.push(format!(
                    "Info : found a genesis revision, its hash is {:#?}",
                    revision.metadata.verification_hash
                ));
                revision_genesis.push(revision)
            }
        }
    }

    if revision_genesis.len() > 1 {
        log_data.push(format!(
            "Found more than one revision genesis {}",
            revision_genesis.len()
        ));

        return None;
    }

    let res = revision_genesis.first();
    if res.is_none() {
        log_data.push("Error : No genesis hash (Vec is empty)".to_string());
        return None;
    }

    // we use unwrapp becasue we are guaranteed the res has value due to the if check above
    return Some(res.unwrap().metadata.verification_hash);
}

pub fn compute_content_hash(content_par: &RevisionContent) -> Result<Hash, String> {
    let b64 = content_par
    .file
    .clone()
    .ok_or_else(|| "Missing file data".to_string())?
    .data;

    // Use the new generate_hash_from_base64 function
    let file_hash_current = generate_hash_from_base64(&b64)?;

    // Create the content map with file hash
    let mut content_current = BTreeMap::new();
    content_current.insert("file_hash".to_owned(), file_hash_current.to_string());

    // Get final content hash
    let content_hash_current = content_hash(&content_current);
    Ok(content_hash_current)



}
// Equivalent to the TypeScript generateHashFromBase64 function
// Modified to accept the Base64 type
fn generate_hash_from_base64(b64: &Base64) -> Result<Hash, String> {
    // Convert Base64 to string
    let b64_str = b64.to_string();

    // Decode base64 to bytes
    let decoded_bytes = base64_engine
        .decode(b64_str)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    // Create hasher and generate hash
    let mut hasher = Sha3_512::new();
    hasher.update(&decoded_bytes);
    Ok(Hash::from(hasher.finalize()))
}





pub fn make_empty_hash() -> Hash {
    let mut hasher = sha3::Sha3_512::default();
    hasher.update("");
    let empty_hash = Hash::from(hasher.finalize());
    empty_hash
}
