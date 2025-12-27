pragma circom 2.1.6;

include "./bitify.circom";
include "./comparators.circom";
include "./PedersenCommitment.circom";

/**
 * TransactionRangeCheck Circuit
 *
 * This circuit enforces that a secret transaction amount is less than or equal
 * to a secret balance, and that both values are correctly committed using
 * Pedersen commitments.
 */
template TransactionRangeCheck() {
    // ------------------------------------------------------
    // Private Inputs
    // ------------------------------------------------------
    // The secret amount to commit
    signal input amount;
    // The amount random blinding factor
    signal input amountRandom;
    // The secret balance to commit
    signal input balance;
    // The balance random blinding factor
    signal input balanceRandom;

    // ------------------------------------------------------
    // Public Inputs
    // ------------------------------------------------------
    // Expected amount commitment point [x, y] for verification
    signal input amountCommitment[2];
    // Expected balance commitment point [x, y] for verification
    signal input balanceCommitment[2];

    // Enforce the amount <= balance
    var isLess = LessEqThan(252)([amount, balance]);
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
