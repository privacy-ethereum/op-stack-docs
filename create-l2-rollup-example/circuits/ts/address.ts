import { getAddress, toBeHex } from "ethers";
import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon2 } from "poseidon-lite/poseidon2";
import { poseidon3 } from "poseidon-lite/poseidon3";
import { groth16 } from "snarkjs";

import type {
  IGenerateUnspendableAddressArgs,
  IProveUnspendableAdddressOwnershipArgs,
  IProvideUnspendableAddressWithBalanceOwnershipArgs,
} from "./types";
import { generateProof, verifyProof } from "./proof";
import { extractVerifyingKey } from "./keys";

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
 * @returns Hex address
 */
export const hex = (address: bigint): string =>
  getAddress(toBeHex(address % MAX_ADDRESS, BYTES));

/**
 * Proves ownership of an unspendable address
 *
 * @param args - prove unspendable address ownership arguments
 * @returns Proof data
 */
export const proveUnspendableAdddressOwnership = async ({
  secret,
  random,
  nonce,
  tag,
  zkeyPath,
  wasmPath,
}: IProveUnspendableAdddressOwnershipArgs): ReturnType<
  typeof groth16.fullProve
> => {
  const inputs = {
    secret,
    random,
    nonce,
    preimageHash: poseidon2([
      generateUnspendableAddress({
        secret,
        random,
        nonce,
        tag,
      }),
      secret,
    ]),
  };

  const verifyingKey = await extractVerifyingKey(zkeyPath);

  const data = await generateProof({ inputs, zkeyPath, wasmPath });

  const isValid = await verifyProof(
    data.publicSignals,
    data.proof,
    verifyingKey
  );

  if (!isValid) {
    throw new Error("Invalid proof");
  }

  return data;
};

/**
 *
 *
 * @param args - prove unspendable address with balance ownership arguments
 * @returns Proof data
 */
export const proveUnspendableAdddressWithBalanceOwnership = async ({
  secret,
  random,
  nonce,
  tag,
  balance,
  balanceRandom,
  withdrawalKey,
  withdrawalSalt,
  balanceCommitment,
  zkeyPath,
  wasmPath,
}: IProvideUnspendableAddressWithBalanceOwnershipArgs): ReturnType<
  typeof groth16.fullProve
> => {
  const address = generateUnspendableAddress({
    secret,
    random,
    nonce,
    tag,
  });

  const inputs = {
    secret,
    random,
    nonce,
    address,
    preimageHash: poseidon2([address, secret]),
    balance,
    balanceRandom,
    withdrawalKey,
    withdrawalSalt,
    balanceCommitment,
    commitment: poseidon3([withdrawalKey, balance, withdrawalSalt]),
    nullifier: poseidon1([secret]),
  };

  const verifyingKey = await extractVerifyingKey(zkeyPath);

  const data = await generateProof({ inputs, zkeyPath, wasmPath });

  const isValid = await verifyProof(
    data.publicSignals,
    data.proof,
    verifyingKey
  );

  if (!isValid) {
    throw new Error("Invalid proof");
  }

  return data;
};
