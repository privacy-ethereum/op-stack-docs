pragma circom 2.1.6;

include "./bitify.circom";
include "./poseidon.circom";

include "./Slice20Bytes.circom";

// This circuit generates an unspendable address from secret, random, and nonce inputs
template UnspendableAddress(DOMAIN_TAG) {
    // ------------------------------------------------------
    // Private Inputs
    // ------------------------------------------------------
    // Input secret signal
    signal input secret;
    // Input random signal
    signal input random;
    // Input nonce signal
    signal input nonce;

    // ------------------------------------------------------
    // Public Inputs
    // ------------------------------------------------------
    // Input preimage hash signal of secret, random, and nonce
    signal input preimageHash;

    // Output unspendable address signal
    signal output address;
    
    // Hash the inputs using Poseidon
    component addressHash = Poseidon(3);
    addressHash.inputs[0] <== secret;
    addressHash.inputs[1] <== random;
    addressHash.inputs[2] <== nonce + DOMAIN_TAG;

    // Slice the lower 20 bytes from the hash to get the unspendable address
    component slice = Slice20Bytes();
    slice.hash <== addressHash.out;

    // Ensure the computed unspendable address hash matches the provided preimage hash
    component commitmentHash = Poseidon(2);
    commitmentHash.inputs[0] <== slice.out;
    commitmentHash.inputs[1] <== secret;

    // Enforce that the provided preimageHash matches the computed commitment hash
    preimageHash === commitmentHash.out;

    // Output the unspendable address
    address <== slice.out;
}
