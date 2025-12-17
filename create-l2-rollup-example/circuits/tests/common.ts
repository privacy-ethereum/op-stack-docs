import { Circomkit, type WitnessTester } from "circomkit";
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
