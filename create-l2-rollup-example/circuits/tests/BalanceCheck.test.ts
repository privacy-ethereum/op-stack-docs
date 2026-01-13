import { expect } from "chai";
import { BabyJub, buildBabyjub, Point } from "circomlibjs";
import { WitnessTester } from "circomkit";
import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon2 } from "poseidon-lite/poseidon2";
import { poseidon3 } from "poseidon-lite/poseidon3";
import fc from "fast-check";

import path from "path";

import {
  generateUnspendableAddress,
  proveUnspendableAdddressWithBalanceOwnership,
} from "../ts/address";
import { SECONDARY_GENERATOR } from "../ts/constants";
import { extractVerifyingKey } from "../ts/keys";
import buildPedersenCommitment, { PedersenCommitment } from "../ts/pedersen";
import { verifyProof } from "../ts/proof";
import { BN254_FR_MODULUS, circomkit } from "./common";

describe("BalanceCheck", () => {
  let circuit: WitnessTester<
    [
      "secret",
      "random",
      "nonce",
      "address",
      "preimageHash",
      "balance",
      "balanceRandom",
      "withdrawalKey",
      "withdrawalSalt",
      "balanceCommitment",
      "nullifier",
      "commitment"
    ]
  >;
  let babyJub: BabyJub;
  let pedersenCommitment: PedersenCommitment;

  const DOMAIN_TAG = 123n;

  const common = {
    secret: 2n ** 160n - 1n,
    random: 2n ** 160n - 2n,
    nonce: 0n,
    balance: 100n,
    balanceRandom: 42n,
    withdrawalKey: 1234n,
    withdrawalSalt: 5678n,
  };

  before(async () => {
    circuit = await circomkit.WitnessTester("BalanceCheck", {
      file: "BalanceCheck",
      template: "BalanceCheck",
      params: [DOMAIN_TAG],
    });

    babyJub = await buildBabyjub();

    const H = [
      babyJub.F.e(SECONDARY_GENERATOR[0].toString()),
      babyJub.F.e(SECONDARY_GENERATOR[1].toString()),
    ] as Point;

    pedersenCommitment = await buildPedersenCommitment(H);
  });

  it("should check balance properly", async () => {
    const rawBalanceCommitment = pedersenCommitment.commit(
      common.balance,
      common.balanceRandom
    );

    const balanceCommitment = [
      BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
      BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
    ];

    const address = generateUnspendableAddress({
      secret: common.secret,
      random: common.random,
      nonce: common.nonce,
      tag: DOMAIN_TAG,
    });

    const nullifier = poseidon1([common.secret]);
    const commitment = poseidon3([
      common.withdrawalKey,
      common.balance,
      common.withdrawalSalt,
    ]);

    const inputs = {
      secret: common.secret,
      random: common.random,
      nonce: common.nonce,
      balance: common.balance,
      balanceRandom: common.balanceRandom,
      withdrawalKey: common.withdrawalKey,
      withdrawalSalt: common.withdrawalSalt,
      balanceCommitment,
      address: BigInt(address),
      preimageHash: poseidon2([address, common.secret]),
      nullifier,
      commitment,
    };

    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("should prove unspendable address with balance ownership properly", async () => {
    const zkeyPath = path.resolve(
      __dirname,
      "../build/BalanceCheck/groth16_pkey.zkey"
    );

    const wasmPath = path.resolve(
      __dirname,
      "../build/BalanceCheck/BalanceCheck_js/BalanceCheck.wasm"
    );

    const rawBalanceCommitment = pedersenCommitment.commit(
      common.balance,
      common.balanceRandom
    );

    const balanceCommitment: [bigint, bigint] = [
      BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
      BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
    ];

    const data = await proveUnspendableAdddressWithBalanceOwnership({
      secret: common.secret,
      random: common.random,
      nonce: common.nonce,
      tag: DOMAIN_TAG,
      balance: common.balance,
      balanceRandom: common.balanceRandom,
      withdrawalKey: common.withdrawalKey,
      withdrawalSalt: common.withdrawalSalt,
      balanceCommitment,
      zkeyPath,
      wasmPath,
    });

    const verifyingKey = await extractVerifyingKey(zkeyPath);
    const isValid = await verifyProof(
      data.publicSignals,
      data.proof,
      verifyingKey
    );

    expect(isValid).to.eq(true);
  });

  it("should fuzz balance check properly", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (
          secret,
          random,
          nonce,
          balance,
          balanceRandom,
          withdrawalKey,
          withdrawalSalt
        ) => {
          const rawBalanceCommitment = pedersenCommitment.commit(
            balance,
            balanceRandom
          );

          const balanceCommitment = [
            BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
            BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
          ];

          const address = generateUnspendableAddress({
            secret,
            random,
            nonce,
            tag: DOMAIN_TAG,
          });

          const nullifier = poseidon1([secret]);
          const commitment = poseidon3([
            withdrawalKey,
            balance,
            withdrawalSalt,
          ]);

          const inputs = {
            secret,
            random,
            nonce,
            balance,
            balanceRandom,
            withdrawalKey,
            withdrawalSalt,
            balanceCommitment,
            address: BigInt(address),
            preimageHash: poseidon2([address, secret]),
            nullifier,
            commitment,
          };

          const witness = await circuit.calculateWitness(inputs);

          return circuit
            .expectConstraintPass(witness)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should not pass balance check if address is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (
          secret,
          random,
          nonce,
          balance,
          balanceRandom,
          withdrawalKey,
          withdrawalSalt
        ) => {
          const rawBalanceCommitment = pedersenCommitment.commit(
            balance,
            balanceRandom
          );

          const balanceCommitment = [
            BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
            BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
          ];

          const address = secret + random + nonce + balance + balanceRandom;

          const nullifier = poseidon1([secret]);
          const commitment = poseidon3([
            withdrawalKey,
            balance,
            withdrawalSalt,
          ]);

          const inputs = {
            secret,
            random,
            nonce,
            balance,
            balanceRandom,
            withdrawalKey,
            withdrawalSalt,
            balanceCommitment,
            address: BigInt(address),
            preimageHash: poseidon2([address, secret]),
            nullifier,
            commitment,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should not pass balance check if balance commitment is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (
          secret,
          random,
          nonce,
          balance,
          balanceRandom,
          withdrawalKey,
          withdrawalSalt
        ) => {
          const rawBalanceCommitment = pedersenCommitment.commit(
            balance,
            balanceRandom
          );

          const balanceCommitment = [
            BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
            BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
          ];

          const address = generateUnspendableAddress({
            secret,
            random,
            nonce,
            tag: DOMAIN_TAG,
          });

          const nullifier = poseidon1([secret]);
          const commitment = poseidon3([
            withdrawalKey,
            balance,
            withdrawalSalt,
          ]);

          const inputs = {
            secret,
            random,
            nonce,
            balance,
            balanceRandom,
            withdrawalKey,
            withdrawalSalt,
            balanceCommitment,
            address: BigInt(address),
            preimageHash: poseidon2([address, secret]),
            nullifier,
            commitment,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should not pass balance check if burn commitment is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (
          secret,
          random,
          nonce,
          balance,
          balanceRandom,
          withdrawalKey,
          withdrawalSalt,
          commitment
        ) => {
          const rawBalanceCommitment = pedersenCommitment.commit(
            balance,
            balanceRandom
          );

          const balanceCommitment = [
            BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
            BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
          ];

          const address = generateUnspendableAddress({
            secret,
            random,
            nonce,
            tag: DOMAIN_TAG,
          });

          const nullifier = poseidon1([secret]);

          const inputs = {
            secret,
            random,
            nonce,
            balance,
            balanceRandom,
            withdrawalKey,
            withdrawalSalt,
            balanceCommitment,
            address: BigInt(address),
            preimageHash: poseidon2([address, secret]),
            nullifier,
            commitment,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should not pass balance check if burn nullifier is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (
          secret,
          random,
          nonce,
          balance,
          balanceRandom,
          withdrawalKey,
          withdrawalSalt,
          nullifier
        ) => {
          const rawBalanceCommitment = pedersenCommitment.commit(
            balance,
            balanceRandom
          );

          const balanceCommitment = [
            BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
            BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
          ];

          const address = generateUnspendableAddress({
            secret,
            random,
            nonce,
            tag: DOMAIN_TAG,
          });

          const commitment = poseidon3([
            withdrawalKey,
            balance,
            withdrawalSalt,
          ]);

          const inputs = {
            secret,
            random,
            nonce,
            balance,
            balanceRandom,
            withdrawalKey,
            withdrawalSalt,
            balanceCommitment,
            address: BigInt(address),
            preimageHash: poseidon2([address, secret]),
            nullifier,
            commitment,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });
});
