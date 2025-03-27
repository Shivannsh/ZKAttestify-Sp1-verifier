# SP1 Wasm verification example

This repo demonstrates how to verify Groth16 and Plonk proofs in browser. We wrap the [`sp1-verifier`](https://github.com/succinctlabs/sp1) crate in wasm bindings, and invoke it from javascript.

## Prerequisites

- Rust (install via https://rustup.rs/)
- SP1 ( `curl -L https://sp1up.succinct.xyz | bash` )
## Repo overview

- `verifier`: The rust sp1 verifier crate with wasm bindings.
- `example/proof-of-residence/program`: A SP1 program to verify country using offchain attestation .
- `example/proof-of-residence/script`: A simple script to generate proofs in a json format.
- `example/wasm_example`: A short javascript example that verifies proofs in wasm.

## Usage

### Wasm Bindings

First, generate the wasm library for the verifier. From the `verifier` directory, run

```bash
wasm-pack build --target nodejs --dev 
```

### Generate proofs

Next, run the script to generate `POR-Attestaion_groth16_proof.json` and `POR-Attestaion_plonk_proof.json`. From the `example/proof-of-residence/script` directory, run:

```bash
cargo run --release -- --mode groth16
cargo run --release -- --mode plonk
```

By default, this will *not* generate fresh proofs from the program in `example/proof-of-residence/program`. To generate fresh proofs, from the `example/proof-of-residence/script` directory, run:

```bash
SP1_PROVER=network NETWORK_PRIVATE_KEY=$SP1_PRIVATE_KEY cargo run --release -- --mode groth16 --prove
SP1_PROVER=network NETWORK_PRIVATE_KEY=$SP1_PRIVATE_KEY cargo run --release -- --mode plonk --prove
```
We used SP1 prover network in our example . You can also run it locally using the commands:
```bash
cargo run --release -- --mode groth16 --prove
cargo run --release -- --mode plonk --prove
```

### Verify proofs in wasm

To verify proofs in wasm, run the following command from the `example/wasm_verifier` directory:

```bash
pnpm install
pnpm run test
```

### **How Zero-Knowledge Proof Generation is happening**
1. The system employs **Succinct ZKVM** to validate the attestation's integrity without exposing the actual data.
2. The ZKVM re-generates the **EIP712 signature** by calculating:
   - **DomainHash**
   - **MessageHash**  
   This confirms the attestation is untampered.
3. Checks the Country and Generate a ZKP of the same