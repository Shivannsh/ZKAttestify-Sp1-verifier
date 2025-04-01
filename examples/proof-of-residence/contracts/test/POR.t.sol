// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/POR.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

contract PORTest is Test {
    POR public por;
    address mockVerifier = address(0x397A5f7f3dBd538f23DE225B51f532c34448dA9B);
    bytes32 vkey = 0x0019fca50a530cbb17875efdaf7c72ca636ccf3708ce628c9ec9f2e0408f928a;
    
    function setUp() public {
        por = new POR(mockVerifier, vkey);
    }

    function testVerifyProof() public {
        // Setup test data
        address testSigner = address(0x1702B23f07DfCf70bb91C3316CDBC812E1f5C6c0);
        string memory testCountry = "India";
        uint64 testTimestamp = 1700000000;
        uint64 testAttestTime = 1742483986;
        address testRecipient = address(0x0000000000000000000000000000000000000000);
        bytes32 testDomainSeparator = keccak256("domain-separator");

        // Encode public values to match contract expectations
        bytes memory publicValues = abi.encode(
            testSigner,
            testCountry, 
            testTimestamp,
            testAttestTime,
            testRecipient,
            testDomainSeparator
        );

        // Execute and verify
        (
            address signer,
            string memory country,
            uint64 timestamp,
            uint64 attestTime,
            address recipient,
            bytes32 domainSeparator
        ) = por.verifyFibonacciProof(publicValues, "dummy-proof");

        assertEq(signer, testSigner);
        assertEq(country, testCountry);
        assertEq(timestamp, testTimestamp);
        assertEq(attestTime, testAttestTime);
        assertEq(recipient, testRecipient);
        assertEq(domainSeparator, testDomainSeparator);
    }

    function testVerifyProofRevertsOnInvalidVerifier() public {
        vm.expectRevert();
        por.verifyFibonacciProof(
            abi.encode(address(0), "", 0, 0, address(0), bytes32(0)), 
            "bad-proof"
        );
    }
} 