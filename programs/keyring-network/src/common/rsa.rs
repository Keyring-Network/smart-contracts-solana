use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash;

use crypto_bigint::{NonZero, U1024};

pub fn verify_rsa_signature(
    modulus: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
) -> Result<bool> {
    let modulus = NonZero::new(U1024::from_be_slice(&modulus)).unwrap();
    let signature = NonZero::new(U1024::from_be_slice(&signature)).unwrap();

    let message_hash = hash::hash(message.as_slice());

    // Pad the message hash as per PKCS#1 v1.5 for SHA-256
    let mut padded = Vec::new();
    // 0x00 0x01
    padded.push(0x00);
    padded.push(0x01);
    // 0xFF 0xFF
    padded.push(0xFF);
    padded.push(0xFF);
    // 18 times 0xFF 0xFF 0xFF 0xFF
    for _ in 0..18 {
        padded.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    }
    // ASN.1 DER encoding for SHA-256
    padded.extend_from_slice(&[
        0x00, 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20,
    ]);
    // Append the message hash
    padded.extend_from_slice(message_hash.as_ref());

    let padded = U1024::from_be_slice(&padded);

    let result = signature.mul_mod_vartime(&signature.mul_mod_vartime(&signature, &modulus), &modulus);

    Ok(result == padded)
}