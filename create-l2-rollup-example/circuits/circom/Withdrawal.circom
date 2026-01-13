pragma circom 2.1.6;

include "./binary-merkle-root.circom";
include "./comparators.circom";
include "./poseidon.circom";

/*
 * Withdrawal circuit allows a user to prove that they are withdrawing a valid amount
 * from a Merkle-tree-based commitment, without revealing secret inputs such as the
 * secret, balance, salts, or Merkle path.
 *
 * The circuit performs the following checks:
 * 1. Recomputes the commitment from the secret, balance, and salt, and verifies it
 *    matches the public commitment.
 * 2. Computes a nullifier from the secret and verifies it matches the public nullifier,
 *    preventing double withdrawals.
 * 3. Verifies Merkle inclusion of the commitment by recomputing the Merkle root and
 *    matching it against the public root.
 * 4. Ensures that the withdrawal amount does not exceed the committed balance.
 * 5. Computes a new commitment with an updated balance after withdrawal and verifies
 *    it matches the public new commitment.
 *
 * Inputs:
 * -------
 * Private Inputs:
 *  - secret        : Secret used to generate the original commitment.
 *  - salt          : Salt used to generate the original commitment.
 *  - balance       : Balance encoded in the original commitment.
 *  - siblings      : Merkle proof sibling nodes for inclusion verification.
 *  - index         : Index of the commitment leaf in the Merkle tree.
 *  - depth         : Depth of the Merkle tree used in the proof.
 *  - amount        : Amount to withdraw (must be <= balance).
 *  - newSecret     : Secret used to generate the new commitment after withdrawal.
 *  - newSalt       : Salt used to generate the new commitment after withdrawal.
 *
 * Public Inputs:
 *  - root          : Merkle root of the commitment tree.
 *  - commitment    : Original commitment stored in the Merkle tree.
 *  - nullifier     : Nullifier derived from the secret to prevent double spending.
 *  - newCommitment : Commitment representing the updated balance after withdrawal.
 *
 * Subcomponents:
 * ---------------
 * 1. BinaryMerkleRoot : Verifies inclusion of a leaf in a Merkle tree.
 * 2. Poseidon        : Hash function used for commitments and nullifier derivation.
 * 3. LessEqThan      : Comparator enforcing amount <= balance.
 *
 * @param DEPTH - Depth of the Merkle tree.
 */
template Withdrawal(DEPTH) {
    // ------------------------------------------------------
    // Private Inputs
    // ------------------------------------------------------
    // Sibling nodes for the Merkle inclusion proof
    signal input siblings[DEPTH];
    // Index of the leaf in the Merkle tree
    signal input index;
    // Secret used to generate the original commitment
    signal input secret;
    // Salt used to generate the original commitment
    signal input salt;
    // New secret for the updated commitment
    signal input newSecret;
    // New salt for the updated commitment
    signal input newSalt;
    // Amount to withdraw (must be <= balance)
    signal input amount;
    // Current balance
    signal input balance;

    // ------------------------------------------------------
    // Public Inputs
    // ------------------------------------------------------
    // Merkle tree root
    signal input root;
    // Nullifier to prevent double-spending
    signal input nullifier;
    // Original commitment stored in the Merkle tree
    signal input commitment;
    // New commitment after withdrawal
    signal input newCommitment;
    // Depth used in the Merkle proof (must be <= DEPTH)
    signal input depth;

    // Recompute the leaf commitment from private inputs
    signal leaf <== Poseidon(3)([secret, balance, salt]);
    leaf === commitment;

    // Enforce uniqueness per commitment to prevent double spends
    signal computedNullifier <== Poseidon(1)([secret]);
    computedNullifier === nullifier;

    // Enforce that the computed Merkle root matches the public root
    component binaryMerkleRoot = BinaryMerkleRoot(DEPTH);
    binaryMerkleRoot.leaf <== leaf;
    binaryMerkleRoot.siblings <== siblings;
    binaryMerkleRoot.index <== index;
    binaryMerkleRoot.depth <== depth;
    binaryMerkleRoot.out === root;

    // Enforce the amount <= balance
    signal isLess <== LessEqThan(252)([amount, balance]);
    isLess === 1;

    // Enforce correctness of the new commitment
    signal computedNewCommitment <== Poseidon(3)([newSecret, balance - amount, newSalt]);
    computedNewCommitment === newCommitment;
}
