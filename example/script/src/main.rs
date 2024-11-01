mod structs;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_sdk::{utils, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use ethers_core::types::{H160, Signature, H256};
use ethers_core::abi::Token;
use ethers_core::types::transaction::eip712::EIP712Domain;
use ethers_core::utils::keccak256;
use std::fs;
use structs::{Attest, InputData};

/// ELF file for the Succinct RISC-V zkVM.
pub const ADDRESS_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");
const YEAR_IN_SECONDS: u64 = 365 * 24 * 60 * 60;
const THRESHOLD_AGE: u64 = 18 * YEAR_IN_SECONDS;

#[derive(Serialize, Deserialize)]
struct ProofData {
    proof: String,         // hex string
    public_inputs: String, // hex string
    vkey_hash: String,     // vk.bytes32()
    mode: String,
}

#[derive(Parser)]
#[command(name = "zkVM Proof Generator")]
struct Cli {
    #[arg(long, default_value_t = false, help = "Generate or use pregenerated proof")]
    prove: bool,
    #[arg(long, default_value = "plonk", help = "Proof mode (e.g., groth16, plonk)")]
    mode: String,
}

fn parse_input_data(file_path: &str) -> InputData {
    let json_str = fs::read_to_string(file_path).expect("Failed to read input file");
    serde_json::from_str(&json_str).expect("Failed to parse JSON input")
}

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

fn create_domain_separator(input_data: &InputData) -> H256 {
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

fn build_message(input_data: &InputData) -> Attest {
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

fn parse_signature(input_data: &InputData) -> Signature {
    Signature {
        r: input_data.sig.signature.r.parse().unwrap(),
        s: input_data.sig.signature.s.parse().unwrap(),
        v: input_data.sig.signature.v.into(),
    }
}

fn main() {
    utils::setup_logger();
    let args = Cli::parse();
    let input_data = parse_input_data("./input.json");

    let signer_address: H160 = input_data.signer.parse().unwrap();
    let message = build_message(&input_data);
    let domain_separator = create_domain_separator(&input_data);
    let signature = parse_signature(&input_data);

    let mut stdin = SP1Stdin::new();
    stdin.write(&signer_address);
    stdin.write(&signature);
    stdin.write(&(THRESHOLD_AGE));  // threshold age in seconds
    stdin.write(&(chrono::Utc::now().timestamp() as u64));
    stdin.write(&message);
    stdin.write(&domain_separator);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ADDRESS_ELF);
    let proof_path = format!("../binaries/DOB-Attestaion_{}_proof.bin", args.mode);
    let json_path = format!("../json/DOB-Attestaion_{}_proof.json", args.mode);

    if args.prove {
        let proof = match args.mode.as_str() {
            "groth16" => client.prove(&pk, stdin).groth16().run().expect("Groth16 proof generation failed"),
            "plonk" => client.prove(&pk, stdin).plonk().run().expect("Plonk proof generation failed"),
            _ => panic!("Invalid proof mode"),
        };
        proof.save(&proof_path).expect("Failed to save proof");
    }

    let proof = SP1ProofWithPublicValues::load(&proof_path).expect("Failed to load proof");
    let fixture = ProofData {
        proof: hex::encode(proof.raw_with_checksum()),
        public_inputs: hex::encode(proof.public_values),
        vkey_hash: vk.bytes32(),
        mode: args.mode.clone(),
    };

    fs::write(&json_path, serde_json::to_string(&fixture).expect("Failed to serialize proof"))
        .expect("Failed to write JSON proof");
    println!("Successfully generated JSON proof for the program!");
}
