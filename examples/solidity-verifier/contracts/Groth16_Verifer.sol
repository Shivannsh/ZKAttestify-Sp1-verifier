// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1Verifier.sol";
import {IEAS, AttestationRequest, AttestationRequestData} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {NO_EXPIRATION_TIME, EMPTY_UID} from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";

/// @title Groth16_Verifer.
/// @author Succinct Labs And EAS
/// @notice This contract implements a simple example of verifying proof of any type and attesting it onchain.

contract Groth16_Verifier {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://docs.succinct.xyz/onchain-verification/contract-addresses
    address public verifier;

    bytes32 internal constant schema =
        bytes32(
            0xe48ca74f3e32cc5fcb3a3b504baeda647d8a870f23fb3d9f6a97d138102a2367
        );

    error InvalidEAS();

    // The address of the global EAS contract.
    IEAS private immutable _eas;

    /// @notice Creates a new ExampleAttester instance.
    /// @param eas The address of the global EAS contract.
    /// @param _verifier The address of the SP1 verifier contract.
   
    constructor(
        address _verifier,
        IEAS eas
    ) {
        if (address(eas) == address(0)) {
            revert InvalidEAS();
        }
        verifier = _verifier;
        _eas = eas;
    }
    /// @notice The entrypoint for verifying the proof of residence and attesting it onchain.
    /// @param _proofBytes The encoded proof.
    /// @param _publicValues The encoded public values.
    function verifyAndAttest(
        bytes32 _ProgramVKey,
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) external returns (bytes32) {
        // Verify the proof first
        ISP1Verifier(verifier).verifyProof(
            _ProgramVKey,
            _publicValues,
            _proofBytes
        );

        // Create the attestation with the original inputs
        return
            _eas.attest(
                AttestationRequest({
                    schema: schema,
                    data: AttestationRequestData({
                        recipient: address(0),
                        expirationTime: NO_EXPIRATION_TIME,
                        revocable: true,
                        refUID: EMPTY_UID,
                        data: abi.encode(_publicValues, _proofBytes),
                        value: 0
                    })
                })
            );
    }
}
