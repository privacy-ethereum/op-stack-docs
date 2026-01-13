import { LeanIMT } from "@zk-kit/lean-imt";
import { Circomkit, type WitnessTester } from "circomkit";
import { poseidon2 } from "poseidon-lite/poseidon2";

import fs from "fs";
import path from "path";

/**
 * Path to circomkit configuration file
 */
const configFilePath = path.resolve(__dirname, "../circomkit.json");

/**
 * Circomkit configuration
 */
const config = JSON.parse(fs.readFileSync(configFilePath, "utf-8"));

/**
 * Circomkit instance
 */
export const circomkit = new Circomkit({
  ...config,
  verbose: false,
});

/**
 * BN254 field modulus
 */
export const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Arguments for getting a signal from the circuit
 */
interface IGetSignalArgs {
  /**
   * Circuit tester
   */
  circuit: WitnessTester;

  /**
   * Witness
   */
  witness: bigint[];

  /**
   * Signal name
   */
  name: string;
}

/**
 * Get a signal from the circuit
 *
 * @param args - get signal arguments
 * @returns the signal value
 */
export const getSignal = async ({
  circuit,
  witness,
  name,
}: IGetSignalArgs): Promise<bigint> => {
  const prefix = "main";
  // E.g. the full name of the signal "root" is "main.root"
  // You can look up the signal names using `circuit.getDecoratedOutput(witness))`
  const signalFullName = `${prefix}.${name}`;

  const out = await circuit.readWitness(witness, [signalFullName]);
  return BigInt(out[signalFullName]);
};

/**
 * Represents the proof data for a leaf in a Merkle tree, providing all necessary
 * information required to verify the leaf's inclusion in the tree.
 */
interface IBinaryMerkleTreeProof {
  /**
   * The leaf value
   */
  leaf: bigint;

  /**
   * The actual depth of the Merkle tree
   */
  depth: number;

  /**
   * The leaf index
   */
  index: number;

  /**
   * Nodes encountered when traversing from the leaf to the root
   */
  siblings: bigint[];

  /**
   * The Merkle root of the tree, calculated from all the leaves
   */
  root: bigint;
}

/**
 * Generates a binary Merkle tree and a proof for a given leaf index.
 * @param maxDepth The maximum depth of the binary Merkle tree.
 * Defaults to 5. This is used to calculate the path indices for the proof.
 * @param leafIndex The index of the leaf for which to generate
 * the proof. Defaults to 0.
 * @param leaves An array of bigint values representing the leaves of the Merkle tree.
 * @returns An object structured to provide the necessary inputs
 * and output for a binary Merkle root proof verification for the
 * `binary-merkle-root` circuit.
 */
export const generateBinaryMerkleRoot = (
  maxDepth = 5,
  leafIndex = 0,
  leaves?: bigint[]
): IBinaryMerkleTreeProof => {
  const tree = new LeanIMT((a, b) => poseidon2([a, b]));

  for (let index = 0; index < 2 ** maxDepth; index += 1) {
    tree.insert(leaves?.[index] || BigInt(index));
  }

  const leaf = tree.leaves[leafIndex];
  const { siblings, index } = tree.generateProof(
    leafIndex % tree.leaves.length
  );

  // For example, if the circuit expects a Merkle tree of depth 20,
  // the input must always include 20 sibling nodes, even if the actual
  // tree depth is smaller (e.g., 3). The unused sibling positions can be
  // filled with 0, as they won't affect the root calculation in the circuit.
  for (let index = 0; index < maxDepth; index += 1) {
    if (siblings[index] === undefined) {
      siblings[index] = 0n;
    }
  }

  return {
    leaf,
    depth: siblings.length,
    index,
    siblings,
    root: tree.root,
  };
};
