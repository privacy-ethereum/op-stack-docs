pragma circom 2.1.6;

include "./bitify.circom";
include "./comparators.circom";
include "./PedersenCommitment.circom";

/*
 * TransactionRangeCheck circuit allows a prover to demonstrate that a secret
 * transaction amount does not exceed a secret balance, while proving that both
 * values are correctly committed using Pedersen commitments.
 *
 * The circuit ensures consistency between the committed values and their
 * corresponding secrets, without revealing the amount or balance.
 *
 * The circuit performs the following checks:
 * 1. Enforces that the secret transaction amount is less than or equal to the
 *    secret balance.
 * 2. Recomputes the Pedersen commitment to the transaction amount using a
 *    blinding factor and verifies it matches the public amount commitment.
 * 3. Recomputes the Pedersen commitment to the balance using a blinding factor
 *    and verifies it matches the public balance commitment.
 *
 * Inputs:
 * -------
 * Private Inputs:
 *  - amount          : Secret transaction amount.
 *  - amountRandom    : Blinding factor for the amount Pedersen commitment.
 *  - balance         : Secret balance.
 *  - balanceRandom   : Blinding factor for the balance Pedersen commitment.
 *
 * Public Inputs:
 *  - amountCommitment  : Pedersen commitment to the transaction amount.
 *  - balanceCommitment : Pedersen commitment to the balance.
 *
 * Subcomponents:
 * ---------------
 * 1. LessEqThan          : Comparator enforcing amount <= balance.
 * 2. PedersenCommitment : Commitment scheme used to bind values with blinding.
 *
 * Security Notes:
 * ---------------
 * - Correctness relies on the binding property of Pedersen commitments.
 * - Privacy relies on the hiding property of Pedersen commitments and the
 *   secrecy of the blinding factors.
 */
template TransactionRangeCheck() {
    // ------------------------------------------------------
    // Private Inputs
    // ------------------------------------------------------
    // Secret transaction amount
    signal input amount;
    // Blinding factor for the amount Pedersen commitment
    signal input amountRandom;
    // Secret balance
    signal input balance;
    // Blinding factor for the balance Pedersen commitment
    signal input balanceRandom;

    // ------------------------------------------------------
    // Public Inputs
    // ------------------------------------------------------
    // Pedersen commitment to the transaction amount
    signal input amountCommitment[2];
    // Pedersen commitment to the balance
    signal input balanceCommitment[2];

    // Enforce the amount <= balance
    signal isLess <== LessEqThan(252)([amount, balance]);
    isLess === 1;

    // Compute the Pedersen commitment for transaction amount
    component amountPedersenCommitment = PedersenCommitment();
    amountPedersenCommitment.message <== amount;
    amountPedersenCommitment.random <== amountRandom;
    amountPedersenCommitment.commitment <== amountCommitment;

    // Enforce the computed commitment equals the input commitment
    amountPedersenCommitment.out === amountCommitment;

    // Compute the Pedersen commitment for balance
    component balancePedersenCommitment = PedersenCommitment();
    balancePedersenCommitment.message <== balance;
    balancePedersenCommitment.random <== balanceRandom;
    balancePedersenCommitment.commitment <== balanceCommitment;

    // Enforce the computed commitment equals the input commitment
    balancePedersenCommitment.out === balanceCommitment;
}
