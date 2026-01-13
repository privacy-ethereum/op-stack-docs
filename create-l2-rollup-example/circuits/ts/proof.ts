import { groth16, Groth16Proof, PublicSignals } from "snarkjs";

import type { IGenerateProofOptions, IVerifyingKeyObjectParams } from "./types";

/**
 * Generate a zk-SNARK proof using snarkjs
 * @param args - arguments for generating proof
 * @returns the zk-SNARK proof and public signals
 */
export async function generateProof({
  inputs,
  zkeyPath,
  wasmPath,
}: IGenerateProofOptions): ReturnType<typeof groth16.fullProve> {
  return groth16.fullProve(inputs, wasmPath, zkeyPath);
}

/**
 * Verify a zk-SNARK proof using snarkjs
 * @param publicInputs - the public inputs to the circuit
 * @param proof - the proof
 * @param verifyingKey - the verification key
 * @returns whether the proof is valid or not
 */
export const verifyProof = async (
  publicInputs: PublicSignals,
  proof: Groth16Proof,
  verifyingKey: IVerifyingKeyObjectParams
): Promise<boolean> => {
  return await groth16.verify(verifyingKey, publicInputs, proof);
};

/**
 * Format a SnarkProof type to an array of strings
 * which can be passed to the Groth16 verifier contract.
 * @param proof the SnarkProof to format
 * @returns an array of strings
 */
export const formatProofForVerifierContract = (
  proof: Groth16Proof
): string[] =>
  [
    proof.pi_a[0],
    proof.pi_a[1],

    proof.pi_b[0][0],
    proof.pi_b[0][1],
    proof.pi_b[1][0],
    proof.pi_b[1][1],

    proof.pi_c[0],
    proof.pi_c[1],
  ].map((x) => x.toString());

/**
 * Parse a formatted proof to Groth16 proof.
 * @param formattedProof the formatted SnarkProof
 * @returns Groth16 proof
 */
export const parseProofFromVerifierContract = (
  formattedProof: readonly string[]
): Groth16Proof => ({
  pi_a: [formattedProof[0], formattedProof[1]],
  pi_b: [
    [formattedProof[2], formattedProof[3]],
    [formattedProof[4], formattedProof[5]],
  ],
  pi_c: [formattedProof[6], formattedProof[7]],
  protocol: "groth16",
  curve: "bn128",
});
