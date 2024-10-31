//! A simple script to generate proofs for the fibonacci program, and serialize them to JSON.
mod structs;
mod helper;

use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, utils, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use alloy_sol_types::SolType;
use fibonacci_lib::PublicValuesStruct;

use std::fs;
use structs::{Attest, InputData};
use ethers_core::types::{H160 , Signature , H256};
use helper::domain_separator;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ADDRESS_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");
#[derive(Serialize, Deserialize)]
struct ProofData {
    proof: String,         // hex string
    public_inputs: String, // hex string
    vkey_hash: String,     // vk.bytes32()
    mode: String,
}

#[derive(clap::Parser)]
#[command(name = "zkVM Proof Generator")]
struct Cli {
    #[arg(
        long,
        value_name = "prove",
        default_value_t = false,
        help = "Whether to generate a proof or use the pregenerated proof"
    )]
    prove: bool,

    #[arg(
        long,
        value_name = "mode",
        default_value = "plonk",
        help = "Specifies the proof mode to use (e.g., groth16, plonk)"
    )]
    mode: String,
}

fn main() {
    // Setup logging for the application
    utils::setup_logger();

    // Parse command line arguments
    let args = Cli::parse();

// ========================================= Main logic =========================================

let json_str = fs::read_to_string("/Users/shivanshgupta/example-sp1-wasm-verifier/example/script/src/input.json").unwrap();
    let input_data: InputData = serde_json::from_str(&json_str).unwrap();

    let domain = ethers_core::types::transaction::eip712::EIP712Domain {
        name: Some(input_data.sig.domain.name),
        version: Some(input_data.sig.domain.version),
        chain_id: Some(ethers_core::types::U256::from_dec_str(
            &input_data.sig.domain.chain_id,
        ).unwrap()),
        verifying_contract: Some(input_data.sig.domain.verifying_contract.parse().unwrap()),
        salt: None,
    };

    let signer_address: H160 = input_data.signer.parse().unwrap();

    let message = Attest {
        version: input_data.sig.message.version,
        schema: input_data.sig.message.schema.parse().unwrap(),
        recipient: input_data.sig.message.recipient.parse().unwrap(),
        time: input_data.sig.message.time.parse().unwrap(),
        expiration_time: input_data.sig.message.expiration_time.parse().unwrap(),
        revocable: input_data.sig.message.revocable,
        ref_uid: input_data.sig.message.ref_uid.parse().unwrap(),
        data: ethers_core::utils::hex::decode(&input_data.sig.message.data[2..]).unwrap(),
        salt: input_data.sig.message.salt.parse().unwrap(),
    };

    // Calculate the current timestamp and the threshold age
    let current_timestamp = chrono::Utc::now().timestamp() as u64;
    let threshold_age: u64 = 18 * 365 * 24 * 60 * 60; // 18 years in seconds

    // Calculate the domain separator and the message hash
    let domain_separator = domain_separator(
        &domain,
        ethers_core::utils::keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .into(),
    );

    // Parse the signature
    let signature = ethers_core::types::Signature {
        r: input_data.sig.signature.r.parse().unwrap(),
        s: input_data.sig.signature.s.parse().unwrap(),
        v: input_data.sig.signature.v.into(),
    };

    // ========================================== Logic Ends ==========================================

    let mut stdin = SP1Stdin::new();
    stdin.write(&signer_address);
    stdin.write(&signature);
    stdin.write(&threshold_age);
    stdin.write(&current_timestamp);
    stdin.write(&message);
    stdin.write(&domain_separator);

    // Initialize the prover client.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ADDRESS_ELF);

    // These are the output paths.
    let proof_path = format!("../binaries/DOB-Attestaion_{}_proof.bin", args.mode);
    let json_path = format!("../json/DOB-Attestaion_{}_proof.json", args.mode);

    if args.prove {
        // Generate a proof for the specified program
        let proof = match args.mode.as_str() {
            "groth16" => client
                .prove(&pk, stdin)
                .groth16()
                .run()
                .expect("Groth16 proof generation failed"),
            "plonk" => client
                .prove(&pk, stdin)
                .plonk()
                .run()
                .expect("Plonk proof generation failed"),
            _ => panic!("Invalid proof mode. Use 'groth16' or 'plonk'."),
        };
        proof.save(&proof_path).expect("Failed to save proof");
    }
    // Load the proof, extract the proof and public inputs, and serialize the appropriate fields.
    let proof = SP1ProofWithPublicValues::load(&proof_path).expect("Failed to load proof");
    let fixture = ProofData {
        proof: hex::encode(proof.raw_with_checksum()),
        public_inputs: hex::encode(proof.public_values),
        vkey_hash: vk.bytes32(),
        mode: args.mode,
    };

    // Serialize the proof data to a JSON file.
    let json_proof = serde_json::to_string(&fixture).expect("Failed to serialize proof");
    std::fs::write(json_path, json_proof).expect("Failed to write JSON proof");

    println!("Successfully generated json proof for the program!")
}
