import { buildBabyjub, Point } from "circomlibjs";

import { SECONDARY_GENERATOR } from "./constants";
import { extractVerifyingKey } from "./keys";
import buildPedersenCommitment from "./pedersen";
import {
  formatProofForVerifierContract,
  generateProof,
  verifyProof,
} from "./proof";

import type {
  IPrepareTransactionDataArgs,
  IPrepareTransactionDataReturn,
} from "./types";

/**
 * Prepares zero-knowledge transaction data for on-chain verification.
 *
 * This function:
 * 1. Initializes the BabyJubJub curve and Pedersen commitment scheme
 * 2. Computes Pedersen commitments for `amount` and `balance` using their
 *    respective randomness values
 * 3. Generates a Groth16 proof using the provided WASM and zkey files
 * 4. Verifies the generated proof locally using the extracted verifying key
 * 5. Formats the proof for consumption by a Solidity verifier contract
 *
 * If local verification fails, the function throws and no data is returned.
 *
 * @param args.amount Plaintext transaction amount (private input)
 * @param args.amountRandom Random blinding factor used for the amount commitment
 * @param args.balance Plaintext balance value (private input)
 * @param args.balanceRandom Random blinding factor used for the balance commitment
 * @param args.zkeyPath File path to the Groth16 proving key (.zkey)
 * @param args.wasmPath File path to the compiled circuit WASM
 *
 * @returns An object containing:
 * - `proof`             Groth16 proof formatted for the Solidity verifier
 * - `publicSignals`     Public signals emitted by the circuit
 * - `amountCommitment` Pedersen commitment to `amount`
 * - `balanceCommitment` Pedersen commitment to `balance`
 *
 * @throws Error if the generated proof fails local verification
 */
export async function prepareTransactionData({
  amount,
  amountRandom,
  balance,
  balanceRandom,
  zkeyPath,
  wasmPath,
}: IPrepareTransactionDataArgs): Promise<IPrepareTransactionDataReturn> {
  const babyJub = await buildBabyjub();

  const H = [
    babyJub.F.e(SECONDARY_GENERATOR[0].toString()),
    babyJub.F.e(SECONDARY_GENERATOR[1].toString()),
  ] as Point;

  const pedersenCommitment = await buildPedersenCommitment(H);

  const amountCommitmentPoint = pedersenCommitment.commit(amount, amountRandom);
  const balanceCommitmentPoint = pedersenCommitment.commit(
    balance,
    balanceRandom
  );

  const amountCommitment: [bigint, bigint] = [
    BigInt(babyJub.F.toObject(amountCommitmentPoint[0])),
    BigInt(babyJub.F.toObject(amountCommitmentPoint[1])),
  ];

  const balanceCommitment: [bigint, bigint] = [
    BigInt(babyJub.F.toObject(balanceCommitmentPoint[0])),
    BigInt(babyJub.F.toObject(balanceCommitmentPoint[1])),
  ];

  const { proof, publicSignals } = await generateProof({
    inputs: {
      amount,
      amountRandom,
      amountCommitment,
      balance,
      balanceRandom,
      balanceCommitment,
    },
    zkeyPath,
    wasmPath,
  });

  const verifyingKey = await extractVerifyingKey(zkeyPath);
  const isValid = await verifyProof(publicSignals, proof, verifyingKey);

  if (!isValid) {
    throw new Error("Verification failed");
  }

  return {
    proof: formatProofForVerifierContract(proof),
    publicSignals,
    amountCommitment,
    balanceCommitment,
    verifyingKey,
  };
}
