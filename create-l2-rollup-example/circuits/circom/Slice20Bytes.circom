pragma circom 2.1.6;

include "./bitify.circom";

/*
 * Slice20Bytes circuit extracts the lower 20 bytes (160 bits) from a field
 * element, typically the output of a Poseidon hash.
 *
 * This circuit is commonly used to derive Ethereum-style addresses from hash
 * outputs by selecting the least-significant 160 bits.
 *
 * The circuit performs the following steps:
 * 1. Converts the input hash into its binary representation.
 * 2. Selects the lower 160 bits of the binary representation.
 * 3. Reconstructs a field element from the selected bits.
 *
 * Inputs:
 * -------
 * Private Inputs:
 *  - hash : Field element representing a hash value (e.g. Poseidon output).
 *
 * Outputs:
 * --------
 *  - out  : Field element representing the lower 160 bits of the input hash.
 *
 * Subcomponents:
 * ---------------
 * 1. Num2Bits  : Converts a field element into a fixed-length bit array.
 * 2. Bits2Num : Reconstructs a field element from a bit array.
 *
 * Constants:
 * ----------
 *  - BITS_SIZE     : Total number of bits in the input hash (254 bits).
 *  - SELECTED_BITS : Number of bits extracted (160 bits / 20 bytes).
 *
 * Security Notes:
 * ---------------
 * - The circuit assumes the input hash fits within BITS_SIZE bits.
 * - No cryptographic security is added by slicing; security depends on the properties of the upstream hash function.
 */
template Slice20Bytes() {
    // Total number of bits in the input hash (254 bits)
    var BITS_SIZE = 254;
    // Number of bits extracted (160 bits / 20 bytes)
    var SELECTED_BITS = 160;

    // Field element representing a hash value (e.g. Poseidon output)
    signal input hash;
    // Field element representing the lower 160 bits of the input hash
    signal output out;

    // Convert the hash to bits
    component n2b = Num2Bits(BITS_SIZE);
    n2b.in <== hash;

    // Reconstruct the lower 160 bits
    component b2n = Bits2Num(SELECTED_BITS);

    for (var i = 0; i < SELECTED_BITS; i++) {
        b2n.in[i] <== n2b.out[i];
    }

    // Output the lower 160 bits sum
    out <== b2n.out;
}
