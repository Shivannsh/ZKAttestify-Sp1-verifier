mod signature;
mod structs;
use clap::Parser;
use ethers_core::types::H160;
use signature::{build_message, create_domain_separator, parse_signature};
use sp1_sdk::{
    include_elf, utils, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey,
    SP1ProofWithPublicValues, SP1Stdin,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use structs::{InputData, ProofData};
mod onchain_verify;
use onchain_verify::verify_contract;

/// ELF file for the Succinct RISC-V zkVM.
pub const ADDRESS_ELF: Elf = include_elf!("dob-program");
const YEAR_IN_SECONDS: u64 = 365 * 24 * 60 * 60;
const THRESHOLD_AGE: u64 = 18 * YEAR_IN_SECONDS;

#[derive(Parser)]
#[command(name = "zkVM Proof Generator")]
struct Cli {
    #[arg(
        long,
        default_value_t = false,
        help = "Generate or use pregenerated proof"
    )]
    prove: bool,
    #[arg(
        long,
        default_value = "plonk",
        help = "Proof mode (e.g., groth16, plonk)"
    )]
    mode: String,
}

fn parse_input_data(path: impl AsRef<Path>) -> InputData {
    let json_str = fs::read_to_string(path.as_ref()).expect("Failed to read input file");
    serde_json::from_str(&json_str).expect("Failed to parse JSON input")
}

fn script_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// `examples/dob` (parent of this crate).
fn example_dir() -> PathBuf {
    script_dir()
        .parent()
        .expect("dob-script should live under examples/dob")
        .to_path_buf()
}

// Main function for generating zkVM proofs
#[tokio::main]
async fn main() {
    utils::setup_logger();
    let start = Instant::now();
    let args = Cli::parse();
    let input_path = script_dir().join("src/input.json");
    let input_data = parse_input_data(&input_path);

    // Prepare inputs for zkVM
    let signer_address: H160 = input_data.signer.parse().unwrap();
    let message = build_message(&input_data);
    let domain_separator = create_domain_separator(&input_data);
    let signature = parse_signature(&input_data);

    // Write inputs to zkVM stdin
    let mut stdin = SP1Stdin::new();
    stdin.write(&signer_address);
    stdin.write(&signature);
    stdin.write(&(THRESHOLD_AGE)); // threshold age in seconds
    stdin.write(&(chrono::Utc::now().timestamp() as u64));
    stdin.write(&message);
    stdin.write(&domain_separator);

    // Setup prover and generate proof
    let client = ProverClient::from_env().await;
    let pk = client.setup(ADDRESS_ELF).await.unwrap();
    let proof_path = example_dir()
        .join("binaries")
        .join(format!("DOB-Attestaion_{}_proof.bin", args.mode));
    let json_path = example_dir()
        .join("json")
        .join(format!("DOB-Attestaion_{}_proof.json", args.mode));

    fs::create_dir_all(example_dir().join("binaries")).expect("Failed to create binaries directory");
    fs::create_dir_all(example_dir().join("json")).expect("Failed to create json directory");

    if args.prove {
        let proof = match args.mode.as_str() {
            "groth16" => client
                .prove(&pk, stdin.clone())
                .groth16()
                .await
                .expect("Groth16 proof generation failed"),
            "plonk" => client
                .prove(&pk, stdin.clone())
                .plonk()
                .await
                .expect("Plonk proof generation failed"),
            _ => panic!("Invalid proof mode"),
        };
        proof.save(&proof_path).expect("Failed to save proof");
    }

    // Create proof data and save as JSON
    let proof = SP1ProofWithPublicValues::load(&proof_path).expect("Failed to load proof");
    let fixture = ProofData {
        proof: hex::encode(proof.bytes()),
        public_inputs: hex::encode(proof.public_values.as_slice()),
        vkey_hash: pk.verifying_key().bytes32().to_string(),
        mode: args.mode.clone(),
    };

    fs::write(
        &json_path,
        serde_json::to_string(&fixture).expect("Failed to serialize proof"),
    )
    .expect("Failed to write JSON proof");
    let duration = start.elapsed();
    println!("Time elapsed in generating proof is: {:?}", duration);
    println!("Successfully generated JSON proof for the program!");

    // Call the contract verification function
    verify_contract(fixture)
        .await
        .expect("Contract verification failed");
}
