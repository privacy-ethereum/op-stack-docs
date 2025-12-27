pragma circom 2.1.6;

include "./babyjub.circom";
include "./bitify.circom";
include "./escalarmulfix.circom";

/**
 * PedersenCommitment Circuit
 *
 * This circuit implements a Pedersen commitment on the Baby Jubjub elliptic curve.
 * A Pedersen commitment is a cryptographic commitment scheme of the form:
 *    C = message * G + random * H
 * where:
 *    - message is the message (secret)
 *    - random is a random blinding factor
 *    - G and H are fixed points on the curve
 *    - C is the resulting commitment (output)
 *
 * The commitment is perfectly hiding (does not reveal message) and computationally binding
 * (cannot find a different message', random' that maps to the same C without breaking discrete log).
 */
template PedersenCommitment() {
    // ------------------------------------------------------
    // Private Inputs
    // ------------------------------------------------------
    // The secret message to commit
    signal input message;
    // The random blinding factor
    signal input random;

    // ------------------------------------------------------
    // Public Inputs
    // ------------------------------------------------------
    // Expected commitment point [x, y] for verification
    signal input commitment[2];
    
    // Output commitment point [x, y]
    signal output out[2];

    // Base generator
    var G[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // Secondary generator (discrete log known if secret is known)
    var H[2] = [
        8161729262802821074953933772769868423242630511238094437756788308176542630231,
        17477144202559280327772048374561482684555254494412313979603280050466695949333
    ];

    // Convert message and random numbers to 254-bit arrays for scalar multiplication
    var messageBits[254] = Num2Bits(254)(message);
    var randomBits[254] = Num2Bits(254)(random);

    // Compute message * G and random * H using fixed-base scalar multiplication
    var messagePoint[2] = EscalarMulFix(254, G)(messageBits);
    var randomPoint[2] = EscalarMulFix(254, H)(randomBits);

    // Compute the Pedersen commitment C = message * G + random * H
    component addPoint = BabyAdd();
    addPoint.x1 <== messagePoint[0];
    addPoint.y1 <== messagePoint[1];
    addPoint.x2 <== randomPoint[0];
    addPoint.y2 <== randomPoint[1];

    // Enforce the computed commitment equals the input commitment
    addPoint.xout === commitment[0];
    addPoint.yout === commitment[1];

    // Set output
    out <== [addPoint.xout, addPoint.yout];
}
