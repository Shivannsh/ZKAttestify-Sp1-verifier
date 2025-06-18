use ethers::{
    middleware::SignerMiddleware,
    prelude::*,
    providers::{Http, Provider},
    signers::LocalWallet,
};
use ethers_contract::abigen;
use ethers_core::types::H160;
use eyre::Result;
use crate::structs::ProofData;

abigen!(Groth16_Verifier, "examples/solidity-verifier/abi/Groth16_Verifier.json",methods{verifyAndAttest(bytes32,bytes,bytes) as VerifyAndAttest});

pub async fn verify_contract(fixture: ProofData) -> Result<()> {
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

    let groth16_verifier = Groth16_Verifier::new(contract_address, signer.into());

    let proof_bytes = Bytes::from(hex::decode(&fixture.proof)?);
    let public_inputs_bytes = Bytes::from(hex::decode(&fixture.public_inputs)?);
    
    let vkey_hash = fixture.vkey_hash.trim_start_matches("0x");
    let vkey_hash_bytes = hex::decode(vkey_hash)?
        .try_into()
        .expect("vkey_hash must be 32 bytes");
    println!("Vkey Hash: {:?}", &vkey_hash_bytes);
    
    // Get current gas price
    let gas_price = provider.get_gas_price().await?;
    
    
    let receipt = groth16_verifier
        .VerifyAndAttest(vkey_hash_bytes, public_inputs_bytes, proof_bytes)
        .gas(5000000) // Set a reasonable gas limit
        .gas_price(gas_price)
        .send()
        .await?
        .await?;

    println!("Receipt: {:?}", receipt);
    Ok(())
}