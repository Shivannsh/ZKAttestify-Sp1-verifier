//! A program to verify an attestation's signature, age threshold, and output relevant data.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use fibonacci_lib::PublicValuesStruct;
use ethers_core::types::{RecoveryMessage, Signature, H160, H256, Address};
use ethers_core::abi::{decode, ParamType, Token};
use ethers_core::utils::keccak256;
use serde::{Deserialize, Serialize};
use regex::Regex;

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


fn hash_message(domain_separator: &H256, message: &Attest) -> H256 {
    let message_typehash = keccak256(
        b"Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)"
    );

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

    keccak256(&[0x19, 0x01].iter().chain(domain_separator.as_bytes()).chain(&keccak256(&encoded_message)).cloned().collect::<Vec<u8>>()).into()
}


pub fn decode_resident_country(data: &Vec<u8>) -> String {
    let param_types = vec![ParamType::String,ParamType::String,ParamType::Uint(32),ParamType::String];
    let decoded: Vec<ethers_core::abi::Token> = decode(&param_types, data).expect("Failed to decode data");  // Decode the data
    println!("Decoded data: {:?}", decoded);
    let resident_country = decoded[3].clone().into_string().expect("Failed to parse resident country");
    return resident_country;
}

pub fn is_valid_atcud(text: &Vec<u8>) -> Option<String> {

    let param_types = vec![ParamType::String];
    let decoded: Vec<ethers_core::abi::Token> = decode(&param_types, text).expect("Failed to decode data");  // Decode the data
    let atcud: String = decoded[1].clone().into_string().expect("Failed to parse ATCUD");
    // ATCUD format: XXXXXXXX-Y+
    // where X is an 8-character series and Y is one or more digits
    let re = Regex::new(r"([A-Z0-9]{8}-\d+)").unwrap();
    
    // Find all matches and return the first valid one
    let valid_atcud = re.find_iter(&atcud)
        .map(|m| m.as_str().to_string())
        .find(|atcud| {
            // Additional validation can be added here if needed
            let parts: Vec<&str> = atcud.split('-').collect();
            if parts.len() != 2 {
                return false;
            }
            
            let series = parts[0];
            let sequence = parts[1];
            
            // Verify series is exactly 8 characters
            series.len() == 8 && 
            // Verify sequence has at least 1 digit and all characters are digits
            !sequence.is_empty() && sequence.chars().all(|c| c.is_digit(10))
        });

        // TODO: validate from the government's API that the ATCUD is valid
        valid_atcud
}


pub fn main() {
    // Read inputs from the zkVM environment.
    let signer_address: H160 = sp1_zkvm::io::read();
    let signature: Signature = sp1_zkvm::io::read();
    let resident_country: String = sp1_zkvm::io::read();    
    let current_timestamp: u64 = sp1_zkvm::io::read();
    let message: Attest = sp1_zkvm::io::read();
    let domain_separator: H256 = sp1_zkvm::io::read();

    let calculated_digest = hash_message(&domain_separator, &message);
    let recovered_address = signature.recover(RecoveryMessage::Hash(calculated_digest)).expect("Signature recovery failed");

    
    let signer_address_bytes: [u8; 20] = signer_address.into();
    let recipient_address_bytes: [u8; 20] = message.recipient.into();
    let domain_separator_bytes: [u8; 32] = domain_separator.into();


    let recovered_resident_country = decode_resident_country(&message.data);
    if signer_address != recovered_address {
        panic!("Invalid signature");
    } else if resident_country != recovered_resident_country  && is_valid_atcud(&message.data).is_none() {
        panic!("Resident country is not India");
    } else {
        let public_values = PublicValuesStruct {
            signer_address: signer_address_bytes.into(),
            current_timestamp,
            resident_country: resident_country.to_string(),
            attest_time: message.time,
            receipent_address: recipient_address_bytes.into(),
            domain_seperator: domain_separator_bytes.into(),
        };
        sp1_zkvm::io::commit_slice(&PublicValuesStruct::abi_encode(&public_values));
    }
}
