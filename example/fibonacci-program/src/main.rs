//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use fibonacci_lib::PublicValuesStruct;
use serde::{Deserialize, Serialize};
use ethers_core::types::{RecoveryMessage, Signature, H160, H256 , Address};
use ethers_core::utils::keccak256;
use ethers_core::abi::decode; // Add this line to import the decode function
use ethers_core::abi::ParamType;


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
    let message_typehash: H256 = keccak256(
        b"Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)"
    ).into();

    let encoded_message = ethers_core::abi::encode(&[
        ethers_core::abi::Token::FixedBytes(message_typehash.as_bytes().to_vec()),
        ethers_core::abi::Token::Uint(ethers_core::types::U256::from(message.version)),
        ethers_core::abi::Token::FixedBytes(message.schema.as_bytes().to_vec()),
        ethers_core::abi::Token::Address(message.recipient),
        ethers_core::abi::Token::Uint(ethers_core::types::U256::from(message.time)),
        ethers_core::abi::Token::Uint(ethers_core::types::U256::from(message.expiration_time)),
        ethers_core::abi::Token::Bool(message.revocable),
        ethers_core::abi::Token::FixedBytes(message.ref_uid.as_bytes().to_vec()),
        ethers_core::abi::Token::FixedBytes(keccak256(&message.data).to_vec()),
        ethers_core::abi::Token::FixedBytes(message.salt.as_bytes().to_vec()),
    ]);

    let hashed_message = keccak256(&encoded_message);

    let mut combined = Vec::new();
    combined.extend_from_slice(&[0x19, 0x01]);
    combined.extend_from_slice(domain_separator.as_bytes());
    combined.extend_from_slice(&hashed_message);

    keccak256(&combined).into()
}

pub fn decode_date_of_birth(data: &Vec<u8>) -> u64 {
    let param_types = vec![ParamType::Uint(256)];

    // Decode the data
    let decoded: Vec<ethers_core::abi::Token> =
        decode(&param_types, data).expect("Failed to decode data");

    let dob = decoded[0].clone().into_uint().expect("Failed to parse dob");
    return dob.as_u64();
}


pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let signer_address = sp1_zkvm::io::read::<H160>();
    let signature = sp1_zkvm::io::read::<Signature>();
    let threshold_age = sp1_zkvm::io::read::<u64>();
    let current_timestamp = sp1_zkvm::io::read::<u64>();
    let message = sp1_zkvm::io::read::<Attest>();
    let domain_separator = sp1_zkvm::io::read::<H256>();

    println!("Domain Separator: {:?}", domain_separator);

    let calculated_digest = hash_message(&domain_separator, &message);

    let recovery_message = RecoveryMessage::Hash(calculated_digest);
    let recovered_address = signature.recover(recovery_message).unwrap();

    // Age calculation in seconds
    let current_age = decode_date_of_birth(&message.data) as u64;
    let age_in_seconds = current_timestamp - current_age;

    let signer_address_bytes: [u8; 20] = signer_address.into();
    let recipient_address_bytes: [u8; 20] = message.recipient.into();
    let domain_separator_bytes: [u8; 32] = domain_separator.into();

    if signer_address != recovered_address {
        panic!("Invalid signature");
    } else if age_in_seconds < threshold_age {
        panic!("Age is below threshold");
    } else {
        let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { 
            signer_address:signer_address_bytes.into() , // Convert H160 to Address
            threshold_age, 
            current_timestamp, 
            attest_time: message.time, 
            receipent_address: recipient_address_bytes.into(), // Convert H160 to Address
            domain_seperator: domain_separator_bytes.into()
        });   
        sp1_zkvm::io::commit_slice(&bytes);
    }
}
