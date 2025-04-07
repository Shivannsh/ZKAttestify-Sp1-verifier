mod signature;
mod structs;
use clap::Parser;
use dotenv::dotenv;
use ethers::{
    middleware::SignerMiddleware,
    prelude::*,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer}
};
use ethers_contract::abigen;
use ethers_core::types::H160;
use eyre::Result;
use serde::{Deserialize, Serialize};
use signature::{build_message, create_domain_separator, parse_signature};
use sp1_sdk::{
    include_elf, utils::setup_logger, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin,
};
use std::convert::TryFrom;
use std::fs;
use std::time::Instant;
use structs::InputData;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const PROOF_ADDRESS_ELF: &[u8] = include_elf!("proof-of-residence-program");
const RESIDENT_COUNTRY: &str = "India";

abigen!(POR_Groth16_Verifier, "../contracts/abi/POR_Groth16_Verifier.json",methods{verifyAndAttest(bytes,bytes) as VerifyAndAttest});

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

fn parse_input_data(file_path: &str) -> InputData {
    let json_str = fs::read_to_string(file_path).expect("Failed to read input file");
    serde_json::from_str(&json_str).expect("Failed to parse JSON input")
}
#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();
    dotenv().ok();
    let start = Instant::now();
    let args = Cli::parse();
    let input_data = parse_input_data("src/input.json");

    let signer_address: H160 = input_data.signer.parse().unwrap();
    let message = build_message(&input_data);
    let domain_separator = create_domain_separator(&input_data);
    let signature = parse_signature(&input_data);

    println!("Domain separator: 0x{}", hex::encode(domain_separator));

    let mut stdin = SP1Stdin::new();
    stdin.write(&signer_address);
    stdin.write(&signature);
    stdin.write(&RESIDENT_COUNTRY.to_string());
    stdin.write(&(chrono::Utc::now().timestamp() as u64));
    stdin.write(&message);
    stdin.write(&domain_separator);

    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(PROOF_ADDRESS_ELF);
    let proof_path = format!("../binaries/POR-Attestaion_{}_proof.bin", args.mode);
    let json_path = format!("../json/POR-Attestaion_{}_proof.json", args.mode);

    if args.prove {
        let proof = match args.mode.as_str() {
            "groth16" => client
                .prove(&pk, &stdin)
                .groth16()
                .run()
                .expect("Groth16 proof generation failed"),
            "plonk" => client
                .prove(&pk, &stdin)
                .plonk()
                .run()
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
        vkey_hash: vk.bytes32().to_string(),
        mode: args.mode.clone(),
    };
    // Get the public values as bytes.
    let public_values = proof.public_values.as_slice();
    println!("public values: {:?}", (public_values));
    println!("Proof: {:?}", (proof.bytes()));

    // Create directories if they don't exist
    std::fs::create_dir_all("../binaries").expect("Failed to create binaries directory");
    std::fs::create_dir_all("../json").expect("Failed to create json directory");

    fs::write(
        &json_path,
        serde_json::to_string(&fixture).expect("Failed to serialize proof"),
    )
    .expect("Failed to write JSON proof");
    let duration = start.elapsed();
    println!("Time elapsed in generating proof is: {:?}", duration);
    println!("Successfully generated JSON proof for the program!");

    // connect to the network
    let provider = Provider::<Http>::try_from(std::env::var("RPC_URL").expect("SET RPC URL"))?;

    let chain_id = provider.get_chainid().await?;
    // define the signer
    // for simplicity replace the private key (without 0x), ofc it always recommended to load it from an .env file or external vault
    let wallet: LocalWallet = std::env::var("PRIVATE_KEY")
        .expect("Please SET PRIVATE KEY")
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id.as_u64());

    let contract_address = std::env::var("CONTRACT_ADDRESS")
        .expect("Please SET CONTRACT ADDRESS")
        .parse::<H160>()
        .expect("Invalid contract address format");

    println!("Wallet Sender: {:?}", wallet.address());

    let signer = SignerMiddleware::new(provider.clone(), wallet.clone());

    let por_groth16_verifier = POR_Groth16_Verifier::new(contract_address, signer.into());

    let proof_bytes = Bytes::from(hex::decode(&fixture.proof)?);
    let public_inputs_bytes = Bytes::from(hex::decode(&fixture.public_inputs)?);

    let receipt = por_groth16_verifier
        .VerifyAndAttest(public_inputs_bytes, proof_bytes)
        .send()
        .await?
        .await?;

    println!("Receipt: {:?}", receipt);
    Ok(())
}
