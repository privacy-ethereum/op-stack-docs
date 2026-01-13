pragma circom 2.1.6;

include "./poseidon.circom";
include "./PedersenCommitment.circom";
include "./UnspendableAddress.circom";

/*
 * BalanceCheck circuit allows a user to prove that user has a valid balance
 * associated with an unspendable address and a withdrawal note, without
 * revealing secret inputs such as the secret, balance, salts, or keys.
 *
 * This circuit is intended to attest to the correctness of a burn-related
 * balance state by binding together an unspendable address, a balance
 * commitment, and a withdrawal commitment.
 *
 * The circuit performs the following checks:
 * 1. Recomputes an unspendable address from a secret, randomness, and nonce,
 *    domain-separated by DOMAIN_TAG, and verifies it matches the provided
 *    private address.
 * 2. Recomputes the Pedersen commitment to the balance using a blinding factor
 *    and verifies it matches the public balance commitment.
 * 3. Computes a nullifier from the secret and verifies it matches the public
 *    nullifier, preventing reuse of the same burn state.
 * 4. Recomputes the withdrawal commitment from the withdrawal key, balance,
 *    and salt, and verifies it matches the public commitment.
 *
 * Inputs:
 * -------
 * Private Inputs:
 *  - secret           : Secret used to derive the unspendable address and nullifier.
 *  - random           : Randomness used in unspendable address derivation.
 *  - nonce            : Nonce used in unspendable address derivation.
 *  - balance          : Balance encoded in the commitment.
 *  - balanceRandom    : Blinding factor for the balance Pedersen commitment.
 *  - address          : Derived unspendable address (kept private).
 *  - withdrawalKey    : Secret key used to generate the withdrawal commitment.
 *  - withdrawalSalt   : Salt used to generate the withdrawal commitment.
 *
 * Public Inputs:
 *  - preimageHash     : Hash of (secret, random, nonce) binding the address.
 *  - balanceCommitment: Pedersen commitment to the balance.
 *  - nullifier        : Nullifier derived from the secret.
 *  - commitment       : Withdrawal commitment encoding the balance.
 *
 * Subcomponents:
 * ---------------
 * 1. UnspendableAddress  : Derives and verifies an unspendable address.
 * 2. PedersenCommitment : Computes a commitment to the balance with blinding.
 * 3. Poseidon           : Hash function used for nullifier and commitment derivation.
 *
 * @param DOMAIN_TAG - Domain separator used for unspendable address derivation.
 */
template BalanceCheck(DOMAIN_TAG) {
    // ------------------------------------------------------
    // Private Inputs
    // ------------------------------------------------------
    // Secret used to derive the unspendable address and nullifier
    signal input secret;
    // Randomness used in unspendable address derivation
    signal input random;
    // Nonce used in unspendable address derivation
    signal input nonce;
    // Balance encoded in the commitment
    signal input balance;
    // Blinding factor for the balance Pedersen commitment
    signal input balanceRandom;
    // Derived unspendable address
    signal input address;
    // Secret key used to generate the withdrawal commitment
    signal input withdrawalKey;
    // Salt used to generate the withdrawal commitment
    signal input withdrawalSalt;

    // ------------------------------------------------------
    // Public Inputs
    // ------------------------------------------------------
    // Hash of (secret, random, nonce) binding the address
    signal input preimageHash;
    // Pedersen commitment to the balance
    signal input balanceCommitment[2];
    // Nullifier derived from the secret
    signal input nullifier;
    // Withdrawal commitment encoding the balance
    signal input commitment;

    // Compute the unspendable address
    component unspendableAddress = UnspendableAddress(DOMAIN_TAG);
    unspendableAddress.secret <== secret;
    unspendableAddress.random <== random;
    unspendableAddress.nonce <== nonce;
    unspendableAddress.preimageHash <== preimageHash;

    // Enforce the computed address equals the input address
    unspendableAddress.address === address;

    // Compute the Pedersen commitment for balance
    component balancePedersenCommitment = PedersenCommitment();
    balancePedersenCommitment.message <== balance;
    balancePedersenCommitment.random <== balanceRandom;
    balancePedersenCommitment.commitment <== balanceCommitment;

     // Enforce the computed commitment equals the input commitment
    balancePedersenCommitment.out === balanceCommitment;

    // Compute and enforce nullifier
    signal computedNullifier <== Poseidon(1)([secret]);
    computedNullifier === nullifier;

    // Compute and enforce commitment
    signal computedCommitment <== Poseidon(3)([withdrawalKey, balance, withdrawalSalt]);
    computedCommitment === commitment;
}
