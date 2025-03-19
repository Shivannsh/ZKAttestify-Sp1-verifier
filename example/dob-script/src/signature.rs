use ethers_core::types::{ H256, Signature};
use ethers_core::abi::Token;
use ethers_core::types::transaction::eip712::EIP712Domain;
use ethers_core::utils::keccak256;
use crate::structs::{Attest, InputData};

// Generates EIP712 domain separator hash
pub fn domain_separator(domain: &EIP712Domain, type_hash: H256) -> H256 {
    let encoded = ethers_core::abi::encode(&[
        Token::FixedBytes(type_hash.as_bytes().to_vec()),
        Token::FixedBytes(keccak256(domain.name.as_ref().unwrap().as_bytes()).to_vec()),
        Token::FixedBytes(keccak256(domain.version.as_ref().unwrap().as_bytes()).to_vec()),
        Token::Uint(domain.chain_id.unwrap()),
        Token::Address(domain.verifying_contract.unwrap()),
    ]);
    keccak256(&encoded).into()
}

// Creates domain separator from input data
pub fn create_domain_separator(input_data: &InputData) -> H256 {
    let domain = ethers_core::types::transaction::eip712::EIP712Domain {
        name: Some(input_data.sig.domain.name.clone()),
        version: Some(input_data.sig.domain.version.clone()),
        chain_id: Some(ethers_core::types::U256::from_dec_str(&input_data.sig.domain.chain_id).unwrap()),
        verifying_contract: Some(input_data.sig.domain.verifying_contract.parse().unwrap()),
        salt: None,
    };
    domain_separator(
        &domain,
        ethers_core::utils::keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)").into(),
    )
}

// Builds attestation message from input data
pub fn build_message(input_data: &InputData) -> Attest {
    Attest {
        version: input_data.sig.message.version.clone(),
        schema: input_data.sig.message.schema.parse().unwrap(),
        recipient: input_data.sig.message.recipient.parse().unwrap(),
        time: input_data.sig.message.time.parse().unwrap(),
        expiration_time: input_data.sig.message.expiration_time.parse().unwrap(),
        revocable: input_data.sig.message.revocable,
        ref_uid: input_data.sig.message.ref_uid.parse().unwrap(),
        data: ethers_core::utils::hex::decode(&input_data.sig.message.data[2..]).unwrap(),
        salt: input_data.sig.message.salt.parse().unwrap(),
    }
}

// Parses ECDSA signature from input data
pub fn parse_signature(input_data: &InputData) -> Signature {
    Signature {
        r: input_data.sig.signature.r.parse().unwrap(),
        s: input_data.sig.signature.s.parse().unwrap(),
        v: input_data.sig.signature.v.into(),
    }
}
