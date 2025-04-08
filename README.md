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

## Solidity Verifier Contract (`Groth16_Verifier.sol`)
   ### Contract Details
- **Deployed Address**: `0xC68Df23Aa3629e52a85f95B2f2D2be5b697C63F4` (Base Sepolia)
- **Schema UID**: `0xe48ca74f3e32cc5fcb3a3b504baeda647d8a870f23fb3d9f6a97d138102a2367` (Base Sepolia)

### Core Functionality

#### Key Components:

1. **SP1 Verifier Integration**

   - Uses `ISP1Verifier` interface for proof verification
   - Supports both direct verifier contracts and gateway routing

2. **Ethereum Attestation Service (EAS)**
   - Stores immutable reference to EAS contract
   - Uses predefined schema for attestations

### Core Functions

#### 1. Constructor

```solidity
constructor(address _verifier, IEAS eas)
```

- Initializes contract with:
  - `_verifier`: Address of SP1 verifier contract/gateway
  - `eas`: Ethereum Attestation Service contract address
- Security checks:
  - Reverts with `InvalidEAS` if zero address provided
  - Stores verifier address for proof validation

#### 2. verifyAndAttest

```solidity
function verifyAndAttest(
    bytes32 _ProgramVKey,
    bytes calldata _publicValues,
    bytes calldata _proofBytes
) external returns (bytes32)
```

- Verification Flow:
  1. Calls SP1 verifier with:
     - `_ProgramVKey`: Verification key hash
     - `_publicValues`: Public inputs from zkVM
     - `_proofBytes`: Serialized Groth16 proof
  2. Creates EAS attestation with:
     - Fixed schema identifier
     - Encoded proof data
     - No expiration time
     - Revocable attestation

### Integration Points

- Uses generated ABI for cross-chain verification
- Handles proof serialization/deserialization
- Manages Ethereum transaction signing
- Supports both local and network proof generation

### Security Features

- **Immutable EAS Reference**: Set once during construction
- **Verifier Whitelisting**: Only pre-approved verifier addresses
- **Input Validation**: Automatic checks through SP1 verifier
- **Non-expiring Attestations**: Uses `NO_EXPIRATION_TIME` constant

For full ABI details see [Groth16_Verifier.json](examples/solidity-verifier/abi/Groth16_Verifier.json)

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
pnpm run test
```

### **How Zero-Knowledge Proof Generation is happening**

1. The system employs **Succinct ZKVM** to validate the attestation's integrity without exposing the actual data.
2. The ZKVM re-generates the **EIP712 signature** by calculating:
   - **DomainHash**
   - **MessageHash**  
     This confirms the attestation is untampered.
3. It checks specific conditions, such as verifying if the individual's date of birth shows they are above 18.
4. This proof can be used anywhere where you want to prove that you are 18+ without actually revealing your actual Date of Birth.
