import path from "path";
import { exit } from "process";

import { extractVerifyingKey } from "./keys";
import { BigNumberish } from "ethers";
import {
  formatProofForVerifierContract,
  generateProof,
  verifyProof,
} from "./proof";
import { buildBabyjub, Point } from "circomlibjs";
import buildPedersenCommitment from "./pedersen";

if (require.main === module) {
  (async () => {
    const babyJub = await buildBabyjub();

    const H = [
      babyJub.F.e(
        "8161729262802821074953933772769868423242630511238094437756788308176542630231"
      ),
      babyJub.F.e(
        "17477144202559280327772048374561482684555254494412313979603280050466695949333"
      ),
    ] as Point;

    const pedersenCommitment = await buildPedersenCommitment(H);

    const amount = 10n ** 18n / 5n;
    const amountRandom = 9000;
    const balance = 10n ** 18n;
    const balanceRandom = 8000;

    const amountCommitment = pedersenCommitment.commit(amount, amountRandom);
    const balanceCommitment = pedersenCommitment.commit(balance, balanceRandom);

    const { proof, publicSignals } = await generateProof({
      inputs: {
        amount,
        amountRandom,
        amountCommitment: [
          BigInt(babyJub.F.toObject(amountCommitment[0])),
          BigInt(babyJub.F.toObject(amountCommitment[1])),
        ],
        balance,
        balanceRandom,
        balanceCommitment: [
          BigInt(babyJub.F.toObject(balanceCommitment[0])),
          BigInt(babyJub.F.toObject(balanceCommitment[1])),
        ],
      },
      zkeyPath: path.resolve("./build/TransactionRangeCheck/groth16_pkey.zkey"),
      wasmPath: path.resolve(
        "./build/TransactionRangeCheck/TransactionRangeCheck_js/TransactionRangeCheck.wasm"
      ),
    });

    const verifyingKey = await extractVerifyingKey(
      path.resolve("./build/TransactionRangeCheck/groth16_pkey.zkey")
    );

    const isValid = await verifyProof(publicSignals, proof, verifyingKey);

    console.log(isValid, proof, publicSignals);

    exit(0);
  })();
}
