import type { BigNumberish } from "ethers";
import type { CircuitSignals, PublicSignals } from "snarkjs";

/**
 * Arguments for generating an unspendable address
 */
export interface IGenerateUnspendableAddressArgs {
  /**
   * Secret
   */
  secret: bigint;

  /**
   * Random
   */
  random: bigint;

  /**
   * Nonce
   */
  nonce: bigint;

  /**
   * Domain separation tag
   */
  tag: bigint;
}

/**
 * Arguments for generating proof function
 */
export interface IGenerateProofOptions {
  /**
   * Circuit inputs
   */
  inputs: CircuitSignals;

  /**
   * The path to the zkey
   */
  zkeyPath: string;

  /**
   * The path to the wasm witness
   */
  wasmPath: string;
}

/**
 * Arguments for exporiting verifying key from prover key
 */
export interface IVerifyingKeyObjectParams {
  /**
   * Identifier of the zkSNARK proving system protocol
   * (e.g. Groth16, PLONK, etc.), encoded as a numeric value.
   */
  protocol: BigNumberish;

  /**
   * Identifier of the elliptic curve used by the proving system
   * (e.g. BN254, BLS12-381), encoded as a numeric value.
   */
  curve: BigNumberish;

  /**
   * Number of public inputs expected by the circuit.
   * This determines the size of the input commitment (IC) array.
   */
  nPublic: BigNumberish;

  /**
   * Alpha element of the verifying key in group G1.
   * Represented as an array of field elements (e.g. [x, y]).
   */
  vk_alpha_1: BigNumberish[];

  /**
   * Beta element of the verifying key in group G2.
   * Represented as a 2D array corresponding to Fp2 coordinates.
   */
  vk_beta_2: BigNumberish[][];

  /**
   * Gamma element of the verifying key in group G2.
   * Used in public input consistency checks.
   */
  vk_gamma_2: BigNumberish[][];

  /**
   * Delta element of the verifying key in group G2.
   * Used in the final pairing equation.
   */
  vk_delta_2: BigNumberish[][];

  /**
   * Precomputed pairing of alpha and beta:
   * e(alpha, beta) ∈ GT.
   * Represented as a 3D array of field elements.
   */
  vk_alphabeta_12: BigNumberish[][][];

  /**
   * Input commitment (IC) points in group G1.
   * Each element corresponds to a coefficient for a public input,
   * with IC[0] being the constant term.
   */
  IC: BigNumberish[][];
}

/**
 * Arguments for preparing transaction data
 */
export interface IPrepareTransactionDataArgs {
  /**
   * Transaction amount to send
   */
  amount: bigint;

  /**
   * Random blinding factor for transaction
   */
  amountRandom: bigint;

  /**
   * Sender's balance
   */
  balance: bigint;

  /**
   * Random blinding factor for sender's balance
   */
  balanceRandom: bigint;

  /**
   * Zkey path
   */
  zkeyPath: string;

  /**
   * Wasm path
   */
  wasmPath: string;
}

/**
 * Return type for preparing transaction data
 */
export interface IPrepareTransactionDataReturn {
  /**
   * Formatted proof
   */
  proof: string[];

  /**
   * Public circuit signals
   */
  publicSignals: PublicSignals;

  /**
   * Pedersen amount commitment
   */
  amountCommitment: [bigint, bigint];

  /**
   * Pedersen balance commitment
   */
  balanceCommitment: [bigint, bigint];

  /**
   * Verifying key
   */
  verifyingKey: IVerifyingKeyObjectParams;
}
