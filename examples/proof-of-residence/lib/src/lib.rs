use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        address signer_address;
        string resident_country;
        uint64 current_timestamp;
        uint64 attest_time;
        address receipent_address;
        bytes32 domain_seperator;
    }
}



