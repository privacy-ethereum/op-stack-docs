import fc from "fast-check";
import path from "path";

import { prepareTransactionData } from "../ts/encryptedToken";
import {
  parseProofFromVerifierContract,
  formatProofForVerifierContract,
  verifyProof,
} from "../ts/proof";
import { BN254_FR_MODULUS } from "./common";

describe("encryptedToken", () => {
  const MAX_SUPPORTED_VALUE = 2n ** 252n - 1n;
  const zkeyPath = path.resolve(
    __dirname,
    "../build/TransactionRangeCheck/groth16_pkey.zkey"
  );
  const wasmPath = path.resolve(
    __dirname,
    "../build/TransactionRangeCheck/TransactionRangeCheck_js/TransactionRangeCheck.wasm"
  );

  it("should prepare transaction data properly", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async ([amount, balance], amountRandom, balanceRandom) => {
          const { proof, publicSignals, verifyingKey } =
            await prepareTransactionData({
              amount,
              balance,
              amountRandom,
              balanceRandom,
              zkeyPath,
              wasmPath,
            });

          const formattedProof = formatProofForVerifierContract(
            parseProofFromVerifierContract(proof)
          );

          const isValid = await verifyProof(
            publicSignals,
            parseProofFromVerifierContract(proof),
            verifyingKey
          );

          return (
            isValid && proof.every((x, index) => x === formattedProof[index])
          );
        }
      )
    );
  });
});
