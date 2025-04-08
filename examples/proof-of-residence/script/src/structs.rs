// src/structs.rs
use ethers_core::types::{Address, H256};
use serde::{Deserialize, Serialize};

// Struct for the message
#[derive(Debug, Serialize, Deserialize , Clone)]
pub struct Attest {
    pub version: u16,
    pub schema: H256,
    pub recipient: Address,
    pub time: u64,
    pub expiration_time: u64,
    pub revocable: bool,
    pub ref_uid: H256,
    pub data: Vec<u8>,
    pub salt: H256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DateOfBirth {
    pub unix_timestamp: u128,
}

// Structs for deserializing JSON input
#[derive(Debug, Deserialize)]
pub struct InputData {
    pub sig: SignatureData,
    pub signer: String,
}

#[derive(Debug, Deserialize)]
pub struct SignatureData {
    pub domain: DomainData,
    pub signature: SignatureDetails,
    pub message: MessageData,
}

#[derive(Debug, Deserialize)]
pub struct DomainData {
    pub name: String,
    pub version: String,
    #[serde(rename = "chainId")]
    pub chain_id: String,
    #[serde(rename = "verifyingContract")]
    pub verifying_contract: String,
}

#[derive(Debug, Deserialize)]
pub struct SignatureDetails {
    pub r: String,
    pub s: String,
    pub v: u8,
}

#[derive(Debug, Deserialize)]
pub struct MessageData {
    pub version: u16,
    pub schema: String,
    pub recipient: String,
    pub time: String,
    #[serde(rename = "expirationTime")]
    pub expiration_time: String,
    pub revocable: bool,
    #[serde(rename = "refUID")]
    pub ref_uid: String,
    pub data: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProofData {
    pub proof: String,         // hex string
    pub public_inputs: String, // hex string
    pub vkey_hash: String,     // vk.bytes32()
    pub mode: String,
}

