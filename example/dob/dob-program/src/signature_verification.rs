// A program to verify an attestation's signature

use crate::Attest;
use ethers_core::abi::Token;
use ethers_core::types::{RecoveryMessage, Signature, H160, H256};
use ethers_core::utils::keccak256;

// Hashes the attestation message according to EIP712 standard
fn hash_message(domain_separator: &H256, message: &Attest) -> H256 {
    let message_typehash = keccak256(
        b"Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)"
    );

    // Encode message parameters according to EIP712
    let encoded_message = ethers_core::abi::encode(&[
        Token::FixedBytes(message_typehash.to_vec()),
        Token::Uint(message.version.into()),
        Token::FixedBytes(message.schema.as_bytes().to_vec()),
        Token::Address(message.recipient),
        Token::Uint(message.time.into()),
        Token::Uint(message.expiration_time.into()),
        Token::Bool(message.revocable),
        Token::FixedBytes(message.ref_uid.as_bytes().to_vec()),
        Token::FixedBytes(keccak256(&message.data).to_vec()),
        Token::FixedBytes(message.salt.as_bytes().to_vec()),
    ]);

    // Create EIP712 digest with domain separator
    keccak256(
        &[0x19, 0x01]  // EIP712 prefix
            .iter()
            .chain(domain_separator.as_bytes())
            .chain(&keccak256(&encoded_message))
            .cloned()
            .collect::<Vec<u8>>(),
    )
    .into()
}

// Verifies ECDSA signature against the attestation message
pub fn verify_signature(
    signer_address: H160,
    signature: Signature,
    message: &Attest,
    domain_separator: &H256,
) -> Result<(), &'static str> {
    // Calculate message digest
    let calculated_digest = hash_message(domain_separator, message);
    
    // Recover signer address from signature
    let recovered_address = signature
        .recover(RecoveryMessage::Hash(calculated_digest))
        .map_err(|_| "Signature recovery failed")?;

    // Verify recovered address matches expected signer
    if signer_address != recovered_address {
        return Err("Invalid signature");
    }
    Ok(())
}
