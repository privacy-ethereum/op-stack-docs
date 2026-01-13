import { expect, use } from "chai";
import chaiAsPromised from "chai-as-promised";

import { BabyJub, buildBabyjub, Point } from "circomlibjs";
import { WitnessTester } from "circomkit";
import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon2 } from "poseidon-lite/poseidon2";
import { poseidon3 } from "poseidon-lite/poseidon3";
import fc from "fast-check";

import path from "path";

import { generateUnspendableAddress } from "../ts/address";
import { SECONDARY_GENERATOR } from "../ts/constants";
import { extractVerifyingKey } from "../ts/keys";
import buildMinter, { Minter } from "../ts/mint";
import buildPedersenCommitment, { PedersenCommitment } from "../ts/pedersen";
import { verifyProof } from "../ts/proof";
import {
  BN254_FR_MODULUS,
  circomkit,
  generateBinaryMerkleRoot,
} from "./common";

use(chaiAsPromised);

describe("ProofOfBurn", () => {
  let circuit: WitnessTester<
    [
      "secret",
      "random",
      "nonce",
      "address",
      "amount",
      "amountRandom",
      "balance",
      "balanceRandom",
      "siblings",
      "index",
      "withdrawalKey",
      "withdrawalSalt",
      "newWithdrawalKey",
      "newWithdrawalSalt",
      "preimageHash",
      "amountCommitment",
      "balanceCommitment",
      "root",
      "nullifier",
      "commitment",
      "newCommitment",
      "depth"
    ]
  >;
  let babyJub: BabyJub;
  let pedersenCommitment: PedersenCommitment;
  let minter: Minter;

  const DOMAIN_TAG = 123n;
  const DEPTH = 5;
  const MAX_SUPPORTED_VALUE = 2n ** 252n - 1n;

  const common = {
    secret: 2n ** 160n - 1n,
    random: 2n ** 160n - 2n,
    nonce: 0n,
    amount: 10n,
    amountRandom: 24n,
    balance: 100n,
    balanceRandom: 42n,
    withdrawalKey: 1234n,
    withdrawalSalt: 5678n,
    newWithdrawalKey: 12345n,
    newWithdrawalSalt: 56789n,
  };

  before(async () => {
    circuit = await circomkit.WitnessTester("ProofOfBurn", {
      file: "ProofOfBurn",
      template: "ProofOfBurn",
      params: [DOMAIN_TAG, DEPTH],
    });

    babyJub = await buildBabyjub();

    const H = [
      babyJub.F.e(SECONDARY_GENERATOR[0].toString()),
      babyJub.F.e(SECONDARY_GENERATOR[1].toString()),
    ] as Point;

    pedersenCommitment = await buildPedersenCommitment(H);

    minter = await buildMinter(pedersenCommitment);
  });

  it("should check proof of burn with common data properly", async () => {
    const rawAmountCommitment = pedersenCommitment.commit(
      common.amount,
      common.amountRandom
    );

    const rawBalanceCommitment = pedersenCommitment.commit(
      common.balance,
      common.balanceRandom
    );

    const amountCommitment = [
      BigInt(babyJub.F.toObject(rawAmountCommitment[0])),
      BigInt(babyJub.F.toObject(rawAmountCommitment[1])),
    ];

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

    const nullifier = poseidon1([common.withdrawalKey]);
    const commitment = poseidon3([
      common.withdrawalKey,
      common.balance,
      common.withdrawalSalt,
    ]);
    const newCommitment = poseidon3([
      common.newWithdrawalKey,
      common.balance - common.amount,
      common.newWithdrawalSalt,
    ]);

    const { siblings, index, root, depth } = generateBinaryMerkleRoot(
      DEPTH,
      0,
      [commitment]
    );

    const inputs = {
      secret: common.secret,
      random: common.random,
      nonce: common.nonce,
      amount: common.amount,
      amountRandom: common.amountRandom,
      balance: common.balance,
      balanceRandom: common.balanceRandom,
      withdrawalKey: common.withdrawalKey,
      withdrawalSalt: common.withdrawalSalt,
      newWithdrawalKey: common.newWithdrawalKey,
      newWithdrawalSalt: common.newWithdrawalSalt,
      siblings,
      index,
      root,
      address: BigInt(address),
      preimageHash: poseidon2([address, common.secret]),
      amountCommitment,
      balanceCommitment,
      nullifier,
      commitment,
      newCommitment,
      depth,
    };

    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("should generate proof of burn properly", async () => {
    const zkeyPath = path.resolve(
      __dirname,
      "../build/ProofOfBurn/groth16_pkey.zkey"
    );

    const wasmPath = path.resolve(
      __dirname,
      "../build/ProofOfBurn/ProofOfBurn_js/ProofOfBurn.wasm"
    );

    const commitment = poseidon3([
      common.withdrawalKey,
      common.balance,
      common.withdrawalSalt,
    ]);

    const { siblings, index, root, depth } = generateBinaryMerkleRoot(
      DEPTH,
      0,
      [commitment]
    );

    const data = await minter.mintTokens({
      secret: common.secret,
      random: common.random,
      nonce: common.nonce,
      tag: DOMAIN_TAG,
      amount: common.amount,
      amountRandom: common.amountRandom,
      balance: common.balance,
      balanceRandom: common.balanceRandom,
      withdrawalKey: common.withdrawalKey,
      withdrawalSalt: common.withdrawalSalt,
      newWithdrawalKey: common.newWithdrawalKey,
      newWithdrawalSalt: common.newWithdrawalSalt,
      siblings,
      index,
      root,
      actualDepth: depth,
      depth: 32,
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

  it("should fail to generate proof of burn when amount exceeds balance", async () => {
    const zkeyPath = path.resolve(
      __dirname,
      "../build/ProofOfBurn/groth16_pkey.zkey"
    );

    const wasmPath = path.resolve(
      __dirname,
      "../build/ProofOfBurn/ProofOfBurn_js/ProofOfBurn.wasm"
    );

    const commitment = poseidon3([
      common.withdrawalKey,
      common.balance,
      common.withdrawalSalt,
    ]);

    const { siblings, index, root, depth } = generateBinaryMerkleRoot(
      DEPTH,
      0,
      [commitment]
    );

    await expect(
      minter.mintTokens({
        secret: common.secret,
        random: common.random,
        nonce: common.nonce,
        tag: DOMAIN_TAG,
        amount: common.balance + 1n,
        amountRandom: common.amountRandom,
        balance: common.balance,
        balanceRandom: common.balanceRandom,
        withdrawalKey: common.withdrawalKey,
        withdrawalSalt: common.withdrawalSalt,
        newWithdrawalKey: common.newWithdrawalKey,
        newWithdrawalSalt: common.newWithdrawalSalt,
        siblings,
        index,
        root,
        actualDepth: depth,
        depth: 32,
        zkeyPath,
        wasmPath,
      })
    ).to.be.rejectedWith("Amount to mint cannot exceed balance");
  });

  it("should fuzz proof of burn properly", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (
          secret,
          random,
          nonce,
          [amount, balance],
          amountRandom,
          balanceRandom,
          withdrawalKey,
          withdrawalSalt,
          newWithdrawalKey,
          newWithdrawalSalt
        ) => {
          const rawAmountCommitment = pedersenCommitment.commit(
            amount,
            amountRandom
          );

          const rawBalanceCommitment = pedersenCommitment.commit(
            balance,
            balanceRandom
          );

          const amountCommitment = [
            BigInt(babyJub.F.toObject(rawAmountCommitment[0])),
            BigInt(babyJub.F.toObject(rawAmountCommitment[1])),
          ];

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

          const nullifier = poseidon1([withdrawalKey]);
          const commitment = poseidon3([
            withdrawalKey,
            balance,
            withdrawalSalt,
          ]);
          const newCommitment = poseidon3([
            newWithdrawalKey,
            balance - amount,
            newWithdrawalSalt,
          ]);

          const { siblings, index, root, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            secret,
            random,
            nonce,
            amount,
            amountRandom,
            balance,
            balanceRandom,
            withdrawalKey,
            withdrawalSalt,
            newWithdrawalKey,
            newWithdrawalSalt,
            siblings,
            index,
            root,
            address: BigInt(address),
            preimageHash: poseidon2([address, secret]),
            amountCommitment,
            balanceCommitment,
            nullifier,
            commitment,
            newCommitment,
            depth,
          };

          return circuit
            .expectPass(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should fail when amount exceeds balance", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        fc.bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE }).chain((balance) =>
          fc
            .bigInt({
              min:
                balance === MAX_SUPPORTED_VALUE
                  ? MAX_SUPPORTED_VALUE
                  : balance + 1n,
              max: MAX_SUPPORTED_VALUE,
            })
            .map((amount) => [amount, balance] as const)
        ),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (
          secret,
          random,
          nonce,
          [amount, balance],
          amountRandom,
          balanceRandom,
          withdrawalKey,
          withdrawalSalt,
          newWithdrawalKey,
          newWithdrawalSalt
        ) => {
          if (amount === balance) {
            return true;
          }

          const rawAmountCommitment = pedersenCommitment.commit(
            amount,
            amountRandom
          );

          const rawBalanceCommitment = pedersenCommitment.commit(
            balance,
            balanceRandom
          );

          const amountCommitment = [
            BigInt(babyJub.F.toObject(rawAmountCommitment[0])),
            BigInt(babyJub.F.toObject(rawAmountCommitment[1])),
          ];

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

          const nullifier = poseidon1([withdrawalKey]);
          const commitment = poseidon3([
            withdrawalKey,
            balance,
            withdrawalSalt,
          ]);
          const newCommitment = poseidon3([
            newWithdrawalKey,
            balance - amount,
            newWithdrawalSalt,
          ]);

          const { siblings, index, root, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            secret,
            random,
            nonce,
            amount,
            amountRandom,
            balance,
            balanceRandom,
            withdrawalKey,
            withdrawalSalt,
            newWithdrawalKey,
            newWithdrawalSalt,
            siblings,
            index,
            root,
            address: BigInt(address),
            preimageHash: poseidon2([address, secret]),
            amountCommitment,
            balanceCommitment,
            nullifier,
            commitment,
            newCommitment,
            depth,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should fail when unspendable address is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (
          secret,
          random,
          nonce,
          [amount, balance],
          amountRandom,
          balanceRandom,
          withdrawalKey,
          withdrawalSalt,
          newWithdrawalKey,
          newWithdrawalSalt,
          address
        ) => {
          const rawAmountCommitment = pedersenCommitment.commit(
            amount,
            amountRandom
          );

          const rawBalanceCommitment = pedersenCommitment.commit(
            balance,
            balanceRandom
          );

          const amountCommitment = [
            BigInt(babyJub.F.toObject(rawAmountCommitment[0])),
            BigInt(babyJub.F.toObject(rawAmountCommitment[1])),
          ];

          const balanceCommitment = [
            BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
            BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
          ];

          const nullifier = poseidon1([withdrawalKey]);
          const commitment = poseidon3([
            withdrawalKey,
            balance,
            withdrawalSalt,
          ]);
          const newCommitment = poseidon3([
            newWithdrawalKey,
            balance - amount,
            newWithdrawalSalt,
          ]);

          const { siblings, index, root, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            secret,
            random,
            nonce,
            amount,
            amountRandom,
            balance,
            balanceRandom,
            withdrawalKey,
            withdrawalSalt,
            newWithdrawalKey,
            newWithdrawalSalt,
            siblings,
            index,
            root,
            address: BigInt(address),
            preimageHash: poseidon2([address, secret]),
            amountCommitment,
            balanceCommitment,
            nullifier,
            commitment,
            newCommitment,
            depth,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should fail when root is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (
          secret,
          random,
          nonce,
          [amount, balance],
          amountRandom,
          balanceRandom,
          withdrawalKey,
          withdrawalSalt,
          newWithdrawalKey,
          newWithdrawalSalt,
          root
        ) => {
          const rawAmountCommitment = pedersenCommitment.commit(
            amount,
            amountRandom
          );

          const rawBalanceCommitment = pedersenCommitment.commit(
            balance,
            balanceRandom
          );

          const amountCommitment = [
            BigInt(babyJub.F.toObject(rawAmountCommitment[0])),
            BigInt(babyJub.F.toObject(rawAmountCommitment[1])),
          ];

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

          const nullifier = poseidon1([withdrawalKey]);
          const commitment = poseidon3([
            withdrawalKey,
            balance,
            withdrawalSalt,
          ]);
          const newCommitment = poseidon3([
            newWithdrawalKey,
            balance - amount,
            newWithdrawalSalt,
          ]);

          const { siblings, index, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            secret,
            random,
            nonce,
            amount,
            amountRandom,
            balance,
            balanceRandom,
            withdrawalKey,
            withdrawalSalt,
            newWithdrawalKey,
            newWithdrawalSalt,
            siblings,
            index,
            root,
            address: BigInt(address),
            preimageHash: poseidon2([address, secret]),
            amountCommitment,
            balanceCommitment,
            nullifier,
            commitment,
            newCommitment,
            depth,
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
