// A program to verify age threshold, and output relevant data.

#![no_main]
sp1_zkvm::entrypoint!(main);

mod signature_verification;
use signature_verification::verify_signature;

use alloy_sol_types::SolType;
use dob_lib::PublicValuesStruct;
use ethers_core::abi::{decode, ParamType};
use ethers_core::types::{Address,Signature, H160, H256};

use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
struct Attest {
    version: u16,                 // Version of the attestation
    schema: H256,                 // Schema identifier
    recipient: Address,           // Address of the recipient
    time: u64,                    // Timestamp of attestation creation
    expiration_time: u64,         // Expiration timestamp
    revocable: bool,              // Whether attestation is revocable
    ref_uid: H256,                // Reference UID
    data: Vec<u8>,                // Encoded data (contains date of birth)
    salt: H256,                   // Random salt for uniqueness
}
// Decodes date of birth from the attestation data
pub fn decode_date_of_birth(data: &Vec<u8>) -> u64 {
    // Define expected parameter type (uint256)
    let param_types = vec![ParamType::Uint(256)];
    
    // Decode the data using Ethereum ABI decoding
    let decoded: Vec<ethers_core::abi::Token> =
        decode(&param_types, data).expect("Failed to decode data");
    
    // Extract and convert the date of birth value
    let dob = decoded[0].clone().into_uint().expect("Failed to parse dob");
    return dob.as_u64();
}

pub fn main() {
    // Read inputs from the zkVM environment
    let signer_address: H160 = sp1_zkvm::io::read();        // Address of the signer
    let signature: Signature = sp1_zkvm::io::read();        // ECDSA signature
    let threshold_age: u64 = sp1_zkvm::io::read();          // Minimum required age
    let current_timestamp: u64 = sp1_zkvm::io::read();      // Current timestamp
    let message: Attest = sp1_zkvm::io::read();             // Attestation message
    let domain_separator: H256 = sp1_zkvm::io::read();      // EIP712 domain separator

    // Verify the ECDSA signature
    if let Err(e) = verify_signature(signer_address, signature, &message, &domain_separator) {
        panic!("{}", e);
    }

    // Calculate age in seconds
    let age_in_seconds = current_timestamp - decode_date_of_birth(&message.data);
    
    // Convert addresses and domain separator to byte arrays
    let signer_address_bytes: [u8; 20] = signer_address.into();
    let recipient_address_bytes: [u8; 20] = message.recipient.into();
    let domain_separator_bytes: [u8; 32] = domain_separator.into();

    // Check if age meets the threshold
    if age_in_seconds < threshold_age {
        panic!("Age is below threshold");
    } else {
        // Prepare public values for commitment
        let public_values = PublicValuesStruct {
            signer_address: signer_address_bytes.into(),
            threshold_age,
            current_timestamp,
            attest_time: message.time,
            receipent_address: recipient_address_bytes.into(),
            domain_seperator: domain_separator_bytes.into(),
        };
        
        // Commit the public values to the zkVM
        sp1_zkvm::io::commit_slice(&PublicValuesStruct::abi_encode(&public_values));
    }
}