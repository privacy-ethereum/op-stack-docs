import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon2 } from "poseidon-lite/poseidon2";
import { poseidon3 } from "poseidon-lite/poseidon3";

import { buildBabyjub, type BabyJub } from "circomlibjs";
import type { PedersenCommitment } from "./pedersen";
import type { IMintTokensArgs } from "./types";

import { generateUnspendableAddress } from "./address";
import { generateProof } from "./proof";

/**
 * Builds a Minter helper for generating zero-knowledge minting proofs.
 *
 * OVERVIEW
 * --------
 * The `Minter` orchestrates all cryptographic primitives required to mint
 * tokens inside a zero-knowledge circuit. It:
 *
 *  - Computes Pedersen commitments over BabyJubJub
 *  - Derives Poseidon-based commitments and nullifiers
 *  - Generates unspendable addresses
 *  - Assembles circuit inputs
 *  - Produces a zkSNARK proof
 *
 * SECURITY NOTICE
 * ---------------
 * This helper assumes:
 *
 *  - The provided `PedersenCommitment` instance is secure
 *    (i.e. generators G and H have unknown discrete log relation)
 *  - Poseidon hash functions are collision resistant
 *  - The underlying circuit correctly enforces all constraints
 *
 * This class DOES NOT:
 *  - Validate Merkle roots
 *  - Verify proofs
 *  - Protect against misuse of secrets or randomness
 *
 * All cryptographic security ultimately depends on the correctness of:
 *  - The trusted setup
 *  - The circuit
 *  - The Pedersen commitment parameters
 *
 * @param pedersenCommitment - Initialized Pedersen commitment helper
 * @returns Minter instance
 */
export default async function buildMinter(
  pedersenCommitment: PedersenCommitment
): Promise<Minter> {
  const babyJub = await buildBabyjub();

  return new Minter(pedersenCommitment, babyJub);
}

/**
 * Minter
 *
 * High-level helper for minting tokens via zero-knowledge proofs.
 *
 * This class prepares all cryptographic inputs required by the minting
 * circuit, including:
 *
 *  - Pedersen commitments to amounts and balances
 *  - Poseidon commitments and nullifiers
 *  - Merkle inclusion proofs
 *  - Address derivation
 *
 * It outputs a zkSNARK proof suitable for on-chain or off-chain verification.
 */
export class Minter {
  /**
   * Pedersen commitment helper
   */
  private pedersenCommitment: PedersenCommitment;

  /**
   * BabyJubJub curve instance
   */
  private babyJub: BabyJub;

  /**
   * Creates a new Minter instance.
   *
   * @param pedersenCommitment - Initialized Pedersen commitment helper
   * @param babyJub - Initialized BabyJubJub curve instance
   */
  constructor(pedersenCommitment: PedersenCommitment, babyJub: BabyJub) {
    this.pedersenCommitment = pedersenCommitment;
    this.babyJub = babyJub;
  }

  /**
   * Generates a zero-knowledge proof for minting tokens.
   *
   * Minting logic (high-level):
   *
   *  1. Commit to `amount` and `balance` using Pedersen commitments
   *  2. Derive an unspendable address from secret material
   *  3. Compute:
   *      - Nullifier (prevents double spends)
   *      - Old commitment
   *      - New commitment after mint
   *  4. Assemble all circuit inputs
   *  5. Generate a zkSNARK proof
   *
   * Cryptographic constructions used:
   *
   *  - Pedersen commitments (BabyJubJub)
   *  - Poseidon hash (arity 1, 2, and 3)
   *  - Merkle inclusion proof
   *
   * SECURITY NOTES
   * ---------------
   *  - Secrets and randomness MUST be generated securely
   *  - Reusing salts or randomness can break privacy
   *
   * @param args - Minting arguments and witness data
   *
   * @returns zkSNARK proof and public signals
   */
  async mintTokens({
    amount,
    amountRandom,
    balance,
    balanceRandom,
    withdrawalKey,
    withdrawalSalt,
    newWithdrawalKey,
    newWithdrawalSalt,
    secret,
    random,
    nonce,
    tag,
    depth,
    actualDepth,
    root,
    index,
    siblings,
    zkeyPath,
    wasmPath,
  }: IMintTokensArgs): Promise<ReturnType<typeof generateProof>> {
    if (amount > balance) {
      throw new Error("Amount to mint cannot exceed balance");
    }

    const rawAmountCommitment = this.pedersenCommitment.commit(
      amount,
      amountRandom
    );

    const rawBalanceCommitment = this.pedersenCommitment.commit(
      balance,
      balanceRandom
    );

    const amountCommitment = [
      BigInt(this.babyJub.F.toObject(rawAmountCommitment[0])),
      BigInt(this.babyJub.F.toObject(rawAmountCommitment[1])),
    ];

    const balanceCommitment = [
      BigInt(this.babyJub.F.toObject(rawBalanceCommitment[0])),
      BigInt(this.babyJub.F.toObject(rawBalanceCommitment[1])),
    ];

    const address = generateUnspendableAddress({
      secret,
      random,
      nonce,
      tag,
    });

    const nullifier = poseidon1([withdrawalKey]);
    const commitment = poseidon3([withdrawalKey, balance, withdrawalSalt]);
    const newCommitment = poseidon3([
      newWithdrawalKey,
      balance - amount,
      newWithdrawalSalt,
    ]);

    const siblingNodes = Array.from(
      { length: depth },
      (_, index) => siblings[index] ?? 0n
    );

    const inputs = {
      secret: secret,
      random: random,
      nonce: nonce,
      amount: amount,
      amountRandom: amountRandom,
      balance: balance,
      balanceRandom: balanceRandom,
      withdrawalKey: withdrawalKey,
      withdrawalSalt: withdrawalSalt,
      newWithdrawalKey: newWithdrawalKey,
      newWithdrawalSalt: newWithdrawalSalt,
      siblings: siblingNodes,
      index,
      root,
      address: BigInt(address),
      preimageHash: poseidon2([address, secret]),
      amountCommitment,
      balanceCommitment,
      nullifier,
      commitment,
      newCommitment,
      depth: actualDepth,
    };

    return await generateProof({ inputs, zkeyPath, wasmPath });
  }
}
