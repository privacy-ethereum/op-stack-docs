pragma circom 2.1.6;

include "./babyjub.circom";
include "./bitify.circom";
include "./escalarmulfix.circom";

/*
 * PedersenCommitment circuit implements a Pedersen commitment scheme over the
 * Baby Jubjub elliptic curve.
 *
 * A Pedersen commitment has the form:
 *
 *   C = message * G + random * H
 *
 * where:
 *  - message is the committed secret value
 *  - random is a blinding factor
 *  - G and H are fixed, independent generators on the curve
 *  - C is the resulting elliptic curve point commitment
 *
 * This construction is perfectly hiding and computationally binding under the
 * discrete logarithm assumption on Baby Jubjub.
 *
 * The circuit performs the following checks:
 * 1. Converts the secret message and blinding factor into fixed-length bit
 *    representations.
 * 2. Computes message * G and random * H using fixed-base scalar multiplication.
 * 3. Adds the resulting points to obtain the Pedersen commitment.
 * 4. Enforces that the computed commitment matches the provided public
 *    commitment point.
 *
 * Inputs:
 * -------
 * Private Inputs:
 *  - message : Secret value being committed.
 *  - random  : Blinding factor providing hiding.
 *
 * Public Inputs:
 *  - commitment : Expected Pedersen commitment point [x, y].
 *
 * Outputs:
 * --------
 *  - out : The computed Pedersen commitment point [x, y].
 *
 * Subcomponents:
 * ---------------
 * 1. Num2Bits        : Converts scalars to fixed-length bit arrays.
 * 2. EscalarMulFix  : Fixed-base scalar multiplication on Baby Jubjub.
 * 3. BabyAdd        : Elliptic curve point addition.
 *
 * Constants:
 * ----------
 *  - G : Primary generator point on Baby Jubjub.
 *  - H : Secondary generator point, independent from G.
 *
 * Security Notes:
 * ---------------
 * - H must be chosen such that its discrete logarithm relative to G is unknown.
 * - Binding relies on the hardness of the discrete logarithm problem.
 * - Hiding relies on the secrecy and uniformity of the blinding factor.
 */
template PedersenCommitment() {
    // ------------------------------------------------------
    // Private Inputs
    // ------------------------------------------------------
    // Secret value being committed
    signal input message;
    // Blinding factor providing hiding
    signal input random;

    // ------------------------------------------------------
    // Public Inputs
    // ------------------------------------------------------
    // Expected Pedersen commitment point [x, y]
    signal input commitment[2];
    
    // The computed Pedersen commitment point [x, y]
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
