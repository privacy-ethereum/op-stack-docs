pragma circom 2.1.6;

include "./comparators.circom";
include "./TransactionRangeCheck.circom";
include "./UnspendableAddress.circom";
include "./Withdrawal.circom";

/*
 * ProofOfBurn circuit allows a user to prove that they have irreversibly burned
 * a specified amount of value by sending it to an unspendable address, while
 * simultaneously performing a valid withdrawal update from a Merkle-tree-based
 * commitment.
 *
 * The circuit proves correctness of the burn and withdrawal without revealing
 * sensitive inputs such as secrets, balances, salts, or Merkle paths.
 *
 * The circuit performs the following checks:
 * 1. Recomputes an unspendable address from a secret, randomness, and nonce,
 *    domain-separated by DOMAIN_TAG, and verifies it matches the provided address.
 * 2. Verifies correctness of the amount and balance commitments using blinding
 *    factors, and ensures the burned amount does not exceed the committed balance.
 * 3. Enforces that the burn amount is less than or equal to the remaining balance.
 * 4. Verifies Merkle inclusion of the existing withdrawal commitment against the
 *    public Merkle root.
 * 5. Computes and verifies a nullifier derived from the withdrawal secret to
 *    prevent double withdrawals.
 * 6. Computes a new withdrawal commitment reflecting the updated balance after
 *    the burn and verifies it matches the public new commitment.
 *
 * Inputs:
 * -------
 * Private Inputs:
 *  - secret              : Secret used to derive the unspendable address.
 *  - random              : Randomness used in unspendable address derivation.
 *  - nonce               : Nonce used in unspendable address derivation.
 *  - address             : Derived unspendable address (kept private).
 *  - amount              : Amount to mint.
 *  - amountRandom        : Blinding factor for the amount commitment.
 *  - balance             : Balance encoded in the original commitment.
 *  - balanceRandom       : Blinding factor for the balance commitment.
 *  - siblings            : Merkle proof sibling nodes for inclusion verification.
 *  - index               : Index of the commitment leaf in the Merkle tree.
 *  - withdrawalKey       : Secret key used for withdrawal commitment and nullifier.
 *  - withdrawalSalt      : Salt used to generate the original withdrawal commitment.
 *  - newWithdrawalKey    : Secret key for the new withdrawal commitment.
 *  - newWithdrawalSalt   : Salt used to generate the new withdrawal commitment.
 *
 * Public Inputs:
 *  - preimageHash        : Hash of (secret, random, nonce) used to bind the address.
 *  - amountCommitment    : Commitment to the mint amount.
 *  - balanceCommitment   : Commitment to the original balance.
 *  - root                : Merkle root of the withdrawal commitment tree.
 *  - nullifier           : Nullifier derived from the withdrawal secret.
 *  - commitment          : Original withdrawal commitment stored in the tree.
 *  - newCommitment       : New withdrawal commitment after the mint.
 *  - depth               : Depth of the Merkle tree used in the proof.
 *
 * Subcomponents:
 * ---------------
 * 1. UnspendableAddress      : Derives and verifies an unspendable address.
 * 2. TransactionRangeCheck   : Verifies amount and balance commitments and their correctness.
 * 3. LessEqThan              : Comparator enforcing amount <= balance.
 * 4. Withdrawal              : Verifies withdrawal validity, nullifier correctness, Merkle inclusion, and new commitment generation.
 *
 * @param DOMAIN_TAG - Domain separator used for unspendable address derivation.
 * @param DEPTH      - Maximum supported depth of the Merkle tree.
 */
template ProofOfBurn(DOMAIN_TAG, DEPTH) {
    // ------------------------------------------------------
    // Private Inputs
    // ------------------------------------------------------
    // Secret used to derive the unspendable address
    signal input secret;
    // Randomness used in unspendable address derivation
    signal input random;
    // Nonce used in unspendable address derivation
    signal input nonce;
    // Derived unspendable address
    signal input address;
    // Amount to mint
    signal input amount;
    // Blinding factor for the amount commitment
    signal input amountRandom;
    // Balance encoded in the original commitment
    signal input balance;
    // Blinding factor for the balance commitment
    signal input balanceRandom;
    // Merkle proof sibling nodes for inclusion verification
    signal input siblings[DEPTH];
    // Index of the commitment leaf in the Merkle tree
    signal input index;
    // Secret key used for withdrawal commitment and nullifier
    signal input withdrawalKey;
    // Salt used to generate the original withdrawal commitment
    signal input withdrawalSalt;
    // Secret key for the new withdrawal commitment
    signal input newWithdrawalKey;
    // Salt used to generate the new withdrawal commitment
    signal input newWithdrawalSalt;

    // ------------------------------------------------------
    // Public Inputs
    // ------------------------------------------------------
    // Hash of (secret, random, nonce) used to bind the address
    signal input preimageHash;
    // Commitment to the mint amount
    signal input amountCommitment[2];
    // Commitment to the current balance
    signal input balanceCommitment[2];
    // Merkle root of the withdrawal commitment tree
    signal input root;
    // Nullifier derived from the withdrawal key secret
    signal input nullifier;
    // Original withdrawal commitment stored in the tree
    signal input commitment;
    // New withdrawal commitment after the mint
    signal input newCommitment;
    // Depth of the Merkle tree used in the proof (must be <= DEPTH)
    signal input depth;

    // Compute the unspendable address
    component unspendableAddress = UnspendableAddress(DOMAIN_TAG);
    unspendableAddress.secret <== secret;
    unspendableAddress.random <== random;
    unspendableAddress.nonce <== nonce;
    unspendableAddress.preimageHash <== preimageHash;

    // Enforce the computed address equals the input address
    unspendableAddress.address === address;

    // Enforce transaction amount does not exceed remaining balance
    component transactionRangeCheck = TransactionRangeCheck();
    transactionRangeCheck.amount <== amount;
    transactionRangeCheck.amountRandom <== amountRandom;
    transactionRangeCheck.amountCommitment <== amountCommitment;
    transactionRangeCheck.balance <== balance;
    transactionRangeCheck.balanceRandom <== balanceRandom;
    transactionRangeCheck.balanceCommitment <== balanceCommitment;

    // Enforce the amount <= balance
    signal isLess <== LessEqThan(8)([depth, DEPTH]);
    isLess === 1;

    // Enforce withdrawal constraints
    component withdrawal = Withdrawal(DEPTH);
    withdrawal.siblings <== siblings;
    withdrawal.index <== index;
    withdrawal.secret <== withdrawalKey;
    withdrawal.salt <== withdrawalSalt;
    withdrawal.newSecret <== newWithdrawalKey;
    withdrawal.newSalt <== newWithdrawalSalt;
    withdrawal.amount <== amount;
    withdrawal.balance <== balance;
    withdrawal.root <== root;
    withdrawal.nullifier <== nullifier;
    withdrawal.commitment <== commitment;
    withdrawal.newCommitment <== newCommitment;
    withdrawal.depth <== depth;
}
