/**
 * This script verifies the proofs generated by the script in `example/script`.
 *
 * It loads json files in `example/json` and verifies them using the wasm bindings
 * in `example/verifier/pkg/sp1_wasm_verifier.js`.
 */

import * as wasm from "../../verifier/pkg/sp1_wasm_verifier.js"
import fs from 'node:fs'
import path from 'node:path'
import assert from 'node:assert'

// Convert a hexadecimal string to a Uint8Array
export const fromHexString = (hexString) =>
    Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

const files = fs.readdirSync("../json");

// Iterate through each file in the data directory
for (const file of files) {
    try {
        // Read and parse the JSON content of the file
        const fileContent = fs.readFileSync(path.join("../json", file), 'utf8');
        const proof_json = JSON.parse(fileContent);

        // Determine the ZKP type (Groth16 or Plonk) based on the filename
        const zkpType = file.toLowerCase().includes('groth16') ? 'groth16' : 'plonk';
        const proof = fromHexString(proof_json.proof);
        const public_inputs = fromHexString(proof_json.public_inputs);
        const vkey_hash = proof_json.vkey_hash;

        // console.log(public_inputs);

        // Decode the public values
        const decodedValues = decodePublicValuesStruct(proof_json.public_inputs);
        console.log('Decoded Public Values:', {
            'Signer Address': decodedValues.signerAddress,
            'Current Timestamp': Number(decodedValues.currentTimestamp),
            'Threshold Age': Number(decodedValues.thresholdAge),
            'Attest Time': Number(decodedValues.attestTime),
            'Recipient Address': decodedValues.recipientAddress,
            'Domain Separator': decodedValues.domainSeparator
        });

        // Select the appropriate verification function and verification key based on ZKP type
        const verifyFunction = zkpType === 'groth16' ? wasm.verify_groth16 : wasm.verify_plonk;

        assert(verifyFunction(proof, public_inputs, vkey_hash));
        console.log(`Proof in ${file} is valid.`);
    } catch (error) {
        console.error(`Error processing ${file}: ${error.message}`);
    }
}

// Function to decode the public values struct from the proof's public inputs
function decodePublicValuesStruct(publicInputsHex) {
    // Remove '0x' prefix if present and convert to Uint8Array
    const publicInputs = fromHexString(publicInputsHex.replace('0x', ''));
    
    // Create a DataView to read values
    const view = new DataView(publicInputs.buffer);
    
    // Read addresses - skip the padding and only take the last 20 bytes for each address
    // signer_address: last 20 bytes of first 32 bytes
    const signerAddress = '0x' + Buffer.from(publicInputs.slice(12, 32)).toString('hex');
    
    // recipient_address: last 20 bytes of bytes 128-160
    const recipientAddress = '0x' + Buffer.from(publicInputs.slice(140, 160)).toString('hex');
    
    // Read timestamps using getBigUint64 from the end of their respective 32-byte slots
    // threshold_age: bytes 32-64
    const thresholdAge = view.getBigUint64(56, false);
    
    // current_timestamp: bytes 64-96
    const currentTimestamp = view.getBigUint64(88, false);
    
    // attest_time: bytes 96-128
    const attestTime = view.getBigUint64(120, false);
    
    // domain_separator: bytes 160-192 (full 32 bytes)
    const domainSeparator = '0x' + Buffer.from(publicInputs.slice(160, 192)).toString('hex');
    
    return {
        signerAddress,
        thresholdAge,
        currentTimestamp,
        attestTime,
        recipientAddress,
        domainSeparator
    };
}