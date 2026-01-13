import { BabyJub, buildBabyjub, Point } from "circomlibjs";
import { WitnessTester } from "circomkit";
import fc from "fast-check";
import path from "path";

import { SECONDARY_GENERATOR } from "../ts/constants";
import buildPedersenCommitment, { PedersenCommitment } from "../ts/pedersen";
import { BN254_FR_MODULUS, circomkit } from "./common";

describe("TransactionRangeCheck", () => {
  let circuit: WitnessTester<
    [
      "amount",
      "amountRandom",
      "amountCommitment",
      "balance",
      "balanceRandom",
      "balanceCommitment"
    ]
  >;
  let babyJub: BabyJub;
  let pedersenCommitment: PedersenCommitment;

  const MAX_SUPPORTED_VALUE = 2n ** 252n - 1n;

  before(async () => {
    circuit = await circomkit.WitnessTester("TransactionRangeCheck", {
      file: "TransactionRangeCheck",
      template: "TransactionRangeCheck",
      params: [],
    });

    babyJub = await buildBabyjub();

    const H = [
      babyJub.F.e(SECONDARY_GENERATOR[0].toString()),
      babyJub.F.e(SECONDARY_GENERATOR[1].toString()),
    ] as Point;

    pedersenCommitment = await buildPedersenCommitment(H);
  });

  it("should check transaction amount range properly", async () => {
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

          const witness = await circuit.calculateWitness({
            amount,
            amountRandom,
            amountCommitment,
            balance,
            balanceRandom,
            balanceCommitment,
          });

          return circuit
            .expectConstraintPass(witness)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should produce proper witness for the same inputs", async () => {
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

          const inputs = {
            amount,
            amountRandom,
            amountCommitment,
            balance,
            balanceRandom,
            balanceCommitment,
          };

          const witness1 = await circuit.calculateWitness(inputs);
          const witness2 = await circuit.calculateWitness(inputs);

          return (
            witness1.length === witness2.length &&
            witness1.every((value, index) => value === witness1[index])
          );
        }
      )
    );
  });

  it("should fail if amount is greater than balance", async () => {
    await fc.assert(
      fc.asyncProperty(
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
        async ([amount, balance], amountRandom, balanceRandom) => {
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

          return circuit
            .expectPass({
              amount,
              amountRandom,
              amountCommitment,
              balance,
              balanceRandom,
              balanceCommitment,
            })
            .then(() => false)
            .catch(() => true);
        }
      )
    );
  });

  it("should pass for amount = 0, balance = 0", async () => {
    const amount = 0n;
    const balance = 0n;

    const amountRandom = 1n;
    const balanceRandom = 2n;

    const rawAmountCommitment = pedersenCommitment.commit(amount, amountRandom);
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

    await circuit.expectPass({
      amount,
      amountRandom,
      amountCommitment,
      balance,
      balanceRandom,
      balanceCommitment,
    });
  });

  it("should pass when amount equals balance", async () => {
    const amount = MAX_SUPPORTED_VALUE;
    const balance = MAX_SUPPORTED_VALUE;

    const amountRandom = 1n;
    const balanceRandom = 2n;

    const rawAmountCommitment = pedersenCommitment.commit(amount, amountRandom);
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

    await circuit.expectPass({
      amount,
      amountRandom,
      amountCommitment,
      balance,
      balanceRandom,
      balanceCommitment,
    });
  });

  it("should fail if amount commitment does not match amount", async () => {
    const amount = 5n;
    const balance = 10n;

    const amountRandom = 3n;
    const balanceRandom = 7n;

    const fakeAmountCommitment = pedersenCommitment.commit(
      amount + 1n,
      amountRandom
    );

    const rawBalanceCommitment = pedersenCommitment.commit(
      balance,
      balanceRandom
    );

    const amountCommitment = [
      BigInt(babyJub.F.toObject(fakeAmountCommitment[0])),
      BigInt(babyJub.F.toObject(fakeAmountCommitment[1])),
    ];
    const balanceCommitment = [
      BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
      BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
    ];

    await circuit
      .expectPass({
        amount,
        amountRandom,
        amountCommitment,
        balance,
        balanceRandom,
        balanceCommitment,
      })
      .then(() => {
        throw new Error("should fail");
      })
      .catch(() => undefined);
  });

  it("should fail if randomness is incorrect", async () => {
    const amount = 5n;
    const balance = 10n;

    const amountRandom = 3n;
    const balanceRandom = 7n;

    const rawAmountCommitment = pedersenCommitment.commit(
      amount,
      amountRandom + 1n
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

    await circuit
      .expectPass({
        amount,
        amountRandom,
        amountCommitment,
        balance,
        balanceRandom,
        balanceCommitment,
      })
      .then(() => {
        throw new Error("should fail");
      })
      .catch(() => undefined);
  });

  it("should fail if amount and balance commitments are swapped", async () => {
    const amount = MAX_SUPPORTED_VALUE;
    const balance = MAX_SUPPORTED_VALUE;

    const amountRandom = 1n;
    const balanceRandom = 2n;

    const rawBalanceCommitment = pedersenCommitment.commit(
      amount,
      amountRandom
    );
    const rawAmountCommitment = pedersenCommitment.commit(
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

    await circuit
      .expectPass({
        amount,
        amountRandom,
        amountCommitment,
        balance,
        balanceRandom,
        balanceCommitment,
      })
      .then(() => {
        throw new Error("should fail");
      })
      .catch(() => undefined);
  });

  it("should fail if amount exceeds 252-bit range", async () => {
    const amount = MAX_SUPPORTED_VALUE + 1n;
    const balance = amount;

    const amountRandom = 1n;
    const balanceRandom = 2n;

    const rawAmountCommitment = pedersenCommitment.commit(amount, amountRandom);
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

    await circuit
      .expectPass({
        amount,
        amountRandom,
        amountCommitment,
        balance,
        balanceRandom,
        balanceCommitment,
      })
      .then(() => {
        throw new Error("should fail");
      })
      .catch(() => undefined);
  });

  it("should fail if public commitment is tampered", async () => {
    const amount = 1;
    const balance = 2;

    const amountRandom = 1n;
    const balanceRandom = 2n;

    const rawBalanceCommitment = pedersenCommitment.commit(
      balance,
      balanceRandom
    );
    const rawAmountCommitment = pedersenCommitment.commit(amount, amountRandom);

    const amountCommitment = [
      BigInt(babyJub.F.toObject(rawAmountCommitment[0])) + 1n,
      BigInt(babyJub.F.toObject(rawAmountCommitment[1])),
    ];
    const balanceCommitment = [
      BigInt(babyJub.F.toObject(rawBalanceCommitment[0])) + 2n,
      BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
    ];

    await circuit
      .expectPass({
        amount,
        amountRandom,
        amountCommitment,
        balance,
        balanceRandom,
        balanceCommitment,
      })
      .then(() => {
        throw new Error("should fail");
      })
      .catch(() => undefined);
  });

  it("should fail if the same commitment is opened with a different amount", async () => {
    const balance = 10n;
    const amount = 5n;

    const amountRandom = 123n;
    const balanceRandom = 456n;

    const rawAmountCommitment = pedersenCommitment.commit(amount, amountRandom);
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

    const fakeAmount = amount + 1n;

    await circuit
      .expectPass({
        amount: fakeAmount,
        amountRandom,
        amountCommitment,
        balance,
        balanceRandom,
        balanceCommitment,
      })
      .then(() => {
        throw new Error("Malicious opening should not pass");
      })
      .catch(() => undefined);
  });

  it("should fail if amount > balance but masked by field overflow", async () => {
    const amount = BN254_FR_MODULUS - 1n;
    const balance = 1n;

    const amountRandom = 111n;
    const balanceRandom = 222n;

    const rawAmountCommitment = pedersenCommitment.commit(amount, amountRandom);
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

    await circuit
      .expectPass({
        amount,
        amountRandom,
        amountCommitment,
        balance,
        balanceRandom,
        balanceCommitment,
      })
      .then(() => {
        throw new Error(
          "Overflow attack succeeded — missing range constraints!"
        );
      })
      .catch(() => undefined);
  });

  it("should pass even if the same randomness is reused", async () => {
    const amount = 5n;
    const balance = 10n;

    const reusedRandom = 999n;

    const rawAmountCommitment = pedersenCommitment.commit(amount, reusedRandom);
    const rawBalanceCommitment = pedersenCommitment.commit(
      balance,
      reusedRandom
    );

    const amountCommitment = [
      BigInt(babyJub.F.toObject(rawAmountCommitment[0])),
      BigInt(babyJub.F.toObject(rawAmountCommitment[1])),
    ];
    const balanceCommitment = [
      BigInt(babyJub.F.toObject(rawBalanceCommitment[0])),
      BigInt(babyJub.F.toObject(rawBalanceCommitment[1])),
    ];

    await circuit.expectPass({
      amount,
      amountRandom: reusedRandom,
      amountCommitment,
      balance,
      balanceRandom: reusedRandom,
      balanceCommitment,
    });
  });
});
