pragma circom 2.1.6;

include "./bitify.circom";

// This circuit slices the lower 20 bytes (160 bits) from a given hash input
template Slice20Bytes() {
    // Total bits in the input hash (254 bits for Poseidon)
    var BITS_SIZE = 254;
    // Number of bits to select for the address slice (20 bytes)
    var SELECTED_BITS = 160;

    // Input hash signal
    signal input hash;
    // Output sliced address signal
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
