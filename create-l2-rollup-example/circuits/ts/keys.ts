import { zKey } from "snarkjs";
import { IVerifyingKeyObjectParams } from "./types";

/**
 * Extract the Verification Key from a zKey
 * @param zkeyPath - the path to the zKey
 * @param cleanup - whether to cleanup the threads or not
 * @returns the verification key
 */
export const extractVerifyingKey = async (
  zkeyPath: string
): Promise<IVerifyingKeyObjectParams> =>
  zKey
    .exportVerificationKey(zkeyPath)
    .then((verifyingKey) => verifyingKey as IVerifyingKeyObjectParams);
