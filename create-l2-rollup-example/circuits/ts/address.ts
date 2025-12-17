import { getAddress, toBeHex } from "ethers";
import { poseidon3 } from "poseidon-lite/poseidon3";

import type { IGenerateUnspendableAddressArgs } from "./types";

/**
 * Max address value (2 ** 160)
 */
export const MAX_ADDRESS = 2n ** 160n;

/**
 * Number of bytes in an Ethereum address
 */
export const BYTES = 20;

/**
 * Generates an unspendable address
 *
 * @param args - generate unspendable address arguments
 * @returns Unspendable address in hex format
 */
export const generateUnspendableAddress = ({
  secret,
  random,
  nonce,
  tag,
}: IGenerateUnspendableAddressArgs): string => {
  const hash = poseidon3([secret, random, nonce + tag]);

  return hex(hash);
};

/**
 * Helps to format bigint as hex address
 *
 * @param address - address
 * @returns
 */
export const hex = (address: bigint): string =>
  getAddress(toBeHex(address % MAX_ADDRESS, BYTES));
