# SP1 Wasm verification example

This repo demonstrates how to verify Groth16 and Plonk proofs in browser. We wrap the [`sp1-verifier`](https://github.com/succinctlabs/sp1) crate in wasm bindings, and invoke it from javascript.

## Prerequisites

- Rust (install via https://rustup.rs/)
- SP1 ( `curl -L https://sp1up.succinct.xyz | bash` )

## Schemas Used in Examples

- `Proof of Age (DOB)` : [Click here](https://sepolia.easscan.org/schema/view/0xe102b6f4e9491f87a8ca24a7bb9ccab0bdbc57cc2d58dacc38295c349f17542e)
- `Proof of residence` : [Click here](https://sepolia.easscan.org/schema/view/0x0cc24a3c3f7839c54a809826938052e8c9d8c0f3b3b73d1a69f3126f01887991)

## Repo overview

- `verifier`: The rust sp1 verifier crate with wasm bindings.
- `example/dob/dob-program`: A SP1 program to verify date of birth offchain attestation .
- `example/dob/dob-script`: A simple script to generate proofs in a json format.
- `example/wasm_example`: A short javascript example that verifies proofs in wasm.
- `example/solidity-verifier`: A solidity contract that verifies proof onchain.


## Usage

### Wasm Bindings

First, generate the wasm library for the verifier. From the `verifier` directory, run

```bash
wasm-pack build --target nodejs --dev
```

### Generate proofs

Next, run the script to generate `DOB-Attestaion_groth16_proof.json` and `DOB-Attestaion_plonk_proof.json`. From the `examples/dob/dob-script` directory, run:

```bash
cargo run --release -- --mode groth16
cargo run --release -- --mode plonk
```

By default, this will _not_ generate fresh proofs from the program in `examples/dob/dob-program`. To generate fresh proofs, from the `examples/dob/dob-script` directory, run:

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
pnpm run dob
```

### **How Zero-Knowledge Proof Generation is happening**

1. The system employs **Succinct ZKVM** to validate the attestation's integrity without exposing the actual data.
2. The ZKVM re-generates the **EIP712 signature** by calculating:
   - **DomainHash**
   - **MessageHash**  
     This confirms the attestation is untampered.
3. It checks specific conditions, such as verifying if the individual's date of birth shows they are above 18.
4. This proof can be used anywhere where you want to prove that you are 18+ without actually revealing your actual Date of Birth.
