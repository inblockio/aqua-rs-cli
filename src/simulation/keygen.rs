// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Key generation for simulation scenarios.
//!
//! Generates fresh Ed25519 and P-256 private keys + derives the corresponding
//! `did:pkh:*` DID, matching the format used by `sign_did.rs` and `sign_p256.rs`
//! in the SDK so that the derived DID matches what `sign_aqua_tree` embeds.

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::rngs::OsRng;

/// Generate a fresh Ed25519 private key.
///
/// Returns `(private_key_bytes, did)` where:
/// - `private_key_bytes` is 32 bytes suitable for `SigningCredentials::Did { did_key }`
/// - `did` is `did:pkh:ed25519:0x<pubkey_hex>` matching SDK format
pub fn generate_ed25519() -> (Vec<u8>, String) {
    let signing_key = Ed25519SigningKey::generate(&mut OsRng);
    let priv_bytes = signing_key.to_bytes().to_vec();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let did = format!("did:pkh:ed25519:0x{}", hex::encode(pub_bytes));
    (priv_bytes, did)
}

/// Generate a fresh P-256 private key.
///
/// Returns `(private_key_bytes, did)` where:
/// - `private_key_bytes` is 32 bytes suitable for `SigningCredentials::P256 { p256_key }`
/// - `did` is `did:pkh:p256:0x<compressed_pubkey_hex>` matching SDK format
pub fn generate_p256() -> (Vec<u8>, String) {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let priv_bytes = signing_key.to_bytes().to_vec();
    let compressed = signing_key.verifying_key().to_encoded_point(true);
    let did = format!("did:pkh:p256:0x{}", hex::encode(compressed.as_bytes()));
    (priv_bytes, did)
}
