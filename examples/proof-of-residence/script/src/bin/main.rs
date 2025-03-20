mod structs;
mod signature;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, utils, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use ethers_core::types::{H160, Signature, H256};
use ethers_core::abi::Token;
use ethers_core::types::transaction::eip712::EIP712Domain;
use ethers_core::utils::keccak256;
use std::fs;
use structs::{Attest, InputData};
use signature::{create_domain_separator, build_message, parse_signature};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");
const RESIDENT_COUNTRY: &str = "India";

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



fn main() {
    utils::setup_logger();
    let args = Cli::parse();   
    let input_data = parse_input_data("/home/gautam/Desktop/verifier/ZKAttestify-Sp1-verifier/example/proof-of-residence/script/src/bin/input.json");

    let signer_address: H160 = input_data.signer.parse().unwrap();
    let message = build_message(&input_data);
    let domain_separator = create_domain_separator(&input_data);
    let signature = parse_signature(&input_data);


    let mut stdin = SP1Stdin::new();
    stdin.write(&signer_address);
    stdin.write(&signature);
    stdin.write(&RESIDENT_COUNTRY.to_string());  
    stdin.write(&(chrono::Utc::now().timestamp() as u64));
    stdin.write(&message);
    stdin.write(&domain_separator);

    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);
    let proof_path = format!("/home/gautam/Desktop/verifier/ZKAttestify-Sp1-verifier/example/proof-of-residence/binaries/POR-Attestaion_{}_proof.bin", args.mode);
    let json_path = format!("/home/gautam/Desktop/verifier/ZKAttestify-Sp1-verifier/example/proof-of-residence/json/POR-Attestaion_{}_proof.json", args.mode);

    if args.prove {
        let proof = match args.mode.as_str() {
            "groth16" => client.prove(&pk, &stdin).groth16().run().expect("Groth16 proof generation failed"),
            "plonk" => client.prove(&pk, &stdin).plonk().run().expect("Plonk proof generation failed"),
            _ => panic!("Invalid proof mode"),
        };
        proof.save(&proof_path).expect("Failed to save proof");
    }

    let proof = SP1ProofWithPublicValues::load(&proof_path).expect("Failed to load proof");
    let fixture = ProofData {
        proof: hex::encode(proof.bytes()),
        public_inputs: hex::encode(proof.public_values),
        vkey_hash: vk.bytes32(),
        mode: args.mode.clone(),
    };

    // Create directories if they don't exist
    std::fs::create_dir_all("../binaries").expect("Failed to create binaries directory");
    std::fs::create_dir_all("../json").expect("Failed to create json directory");

    fs::write(&json_path, serde_json::to_string(&fixture).expect("Failed to serialize proof"))
        .expect("Failed to write JSON proof");
    println!("Successfully generated JSON proof for the program!");
}