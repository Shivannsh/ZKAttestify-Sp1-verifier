## Solidity Verifier Contract (`Groth16_Verifier.sol`)
   ### Contract Details
- **Deployed Address**: `0x752f944c84000185e752913689cee3a00feea3fc` (Base Sepolia)
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


