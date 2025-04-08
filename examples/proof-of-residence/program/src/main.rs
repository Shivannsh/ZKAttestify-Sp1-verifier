//! A program to verify an attestation's signature, age threshold, and output relevant data.

#![no_main]
sp1_zkvm::entrypoint!(main);

mod signature_verification;

use alloy_sol_types::SolType;
use ethers_core::abi::{decode, ParamType};
use ethers_core::types::{Address, Signature, H160, H256};
use proof_residence_lib::PublicValuesStruct;
use serde::{Deserialize, Serialize};
use signature_verification::verify_signature;

/// The list of valid countries for the resident country.
const VALID_COUNTRIES: &[&str] = &["india", "usa", "canada", "germany", "france"];

#[derive(Debug, Serialize, Deserialize)]
struct Attest {
    version: u16,
    schema: H256,
    recipient: Address,
    time: u64,
    expiration_time: u64,
    revocable: bool,
    ref_uid: H256,
    data: Vec<u8>,
    salt: H256,
}

pub fn decode_resident_country(data: &Vec<u8>) -> String {
    let param_types = vec![
        ParamType::String,
        ParamType::String,
        ParamType::Uint(32),
        ParamType::String,
    ];
    let decoded: Vec<ethers_core::abi::Token> =
        decode(&param_types, data).expect("Failed to decode data"); // Decode the data
    println!("Decoded data: {:?}", decoded);
    let resident_country = decoded[3]
        .clone()
        .into_string()
        .expect("Failed to parse resident country");
    return resident_country;
}

pub fn main() {
    // Read inputs from the zkVM environment.
    let signer_address: H160 = sp1_zkvm::io::read();
    let signature: Signature = sp1_zkvm::io::read();
    let current_timestamp: u64 = sp1_zkvm::io::read();
    let message: Attest = sp1_zkvm::io::read();
    let domain_separator: H256 = sp1_zkvm::io::read();

    // Verify the ECDSA signature
    if let Err(e) = verify_signature(signer_address, signature, &message, &domain_separator) {
        panic!("{}", e);
    }

    let signer_address_bytes: [u8; 20] = signer_address.into();
    let recipient_address_bytes: [u8; 20] = message.recipient.into();
    let domain_separator_bytes: [u8; 32] = domain_separator.into();

    let recovered_resident_country = decode_resident_country(&message.data);
    if !VALID_COUNTRIES.contains(&recovered_resident_country.as_str().to_lowercase().as_str()) {  //lowercase so that it is case insensitive
        panic!("Resident country is not valid");
    } else {
        let public_values = PublicValuesStruct {
            signer_address: signer_address_bytes.into(),
            current_timestamp,
            resident_country: recovered_resident_country.to_string(),
            attest_time: message.time,
            receipent_address: recipient_address_bytes.into(),
            domain_seperator: domain_separator_bytes.into(),
        };
        sp1_zkvm::io::commit_slice(&PublicValuesStruct::abi_encode(&public_values));
    }
}
