//! A program to verify an attestation's signature, age threshold, and output relevant data.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use dob_lib::PublicValuesStruct;
use ethers_core::types::{RecoveryMessage, Signature, H160, H256, Address};
use ethers_core::abi::{decode, ParamType, Token};
use ethers_core::utils::keccak256;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize)]
struct DateOfBirth {
    unix_timestamp: u128,
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

pub fn decode_date_of_birth(data: &Vec<u8>) -> u64 {
    let param_types = vec![ParamType::Uint(256)];
    let decoded: Vec<ethers_core::abi::Token> =decode(&param_types, data).expect("Failed to decode data");  // Decode the data
    let dob = decoded[0].clone().into_uint().expect("Failed to parse dob");
    return dob.as_u64();
}

pub fn main() {
    // Read inputs from the zkVM environment.
    let signer_address: H160 = sp1_zkvm::io::read();
    let signature: Signature = sp1_zkvm::io::read();
    let threshold_age: u64 = sp1_zkvm::io::read();
    let current_timestamp: u64 = sp1_zkvm::io::read();
    let message: Attest = sp1_zkvm::io::read();
    let domain_separator: H256 = sp1_zkvm::io::read();

    let calculated_digest = hash_message(&domain_separator, &message);
    let recovered_address = signature.recover(RecoveryMessage::Hash(calculated_digest)).expect("Signature recovery failed");

    let age_in_seconds = current_timestamp - decode_date_of_birth(&message.data);
    let signer_address_bytes: [u8; 20] = signer_address.into();
    let recipient_address_bytes: [u8; 20] = message.recipient.into();
    let domain_separator_bytes: [u8; 32] = domain_separator.into();


    if signer_address != recovered_address {
        panic!("Invalid signature");
    } else if age_in_seconds < threshold_age {
        panic!("Age is below threshold");
    } else {
        let public_values = PublicValuesStruct {
            signer_address: signer_address_bytes.into(),
            threshold_age,
            current_timestamp,
            attest_time: message.time,
            receipent_address: recipient_address_bytes.into(),
            domain_seperator: domain_separator_bytes.into(),
        };
        sp1_zkvm::io::commit_slice(&PublicValuesStruct::abi_encode(&public_values));
    }
}
