pragma circom 2.1.6;

include "./bitify.circom";
include "./poseidon.circom";

include "./Slice20Bytes.circom";

/*
 * UnspendableAddress circuit derives a deterministic, unspendable address from
 * a secret, randomness, and nonce, domain-separated by DOMAIN_TAG.
 *
 * The circuit binds the derived address to a public preimage hash, allowing
 * external verifiers to reference the address without learning the underlying
 * secret inputs.
 *
 * The circuit performs the following checks:
 * 1. Computes a Poseidon hash over (secret, random, nonce + DOMAIN_TAG) to derive
 *    an address preimage.
 * 2. Slices the lower 20 bytes of the hash output to obtain an Ethereum-style
 *    unspendable address.
 * 3. Computes a secondary commitment hash over (address, secret).
 * 4. Enforces that the computed commitment hash matches the provided public
 *    preimage hash, binding the address to the secret.
 *
 * Inputs:
 * -------
 * Private Inputs:
 *  - secret        : Secret value used to derive and bind the address.
 *  - random        : Randomness used in address derivation.
 *  - nonce         : Nonce used to ensure address uniqueness.
 *
 * Public Inputs:
 *  - preimageHash  : Commitment hash binding the derived address to the secret.
 *
 * Outputs:
 * --------
 *  - address       : Derived unspendable address (lower 20 bytes of the hash).
 *
 * Subcomponents:
 * ---------------
 * 1. Poseidon       : Hash function used for address and commitment derivation.
 * 2. Slice20Bytes   : Extracts the lower 20 bytes from the hash output.
 *
 * @param DOMAIN_TAG - Domain separator added to the nonce to prevent cross-protocol collisions.
 */
template UnspendableAddress(DOMAIN_TAG) {
    // ------------------------------------------------------
    // Private Inputs
    // ------------------------------------------------------
    // Secret value used to derive and bind the address
    signal input secret;
    // Randomness used in address derivation
    signal input random;
    // Nonce used to ensure address uniqueness
    signal input nonce;

    // ------------------------------------------------------
    // Public Inputs
    // ------------------------------------------------------
    // Commitment hash binding the derived address to the secret
    signal input preimageHash;

    // Derived unspendable address (lower 20 bytes of the hash)
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
