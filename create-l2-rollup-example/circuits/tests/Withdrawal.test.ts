import { WitnessTester } from "circomkit";
import fc from "fast-check";
import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon3 } from "poseidon-lite/poseidon3";

import { circomkit, generateBinaryMerkleRoot } from "./common";

describe("Withdrawal", () => {
  let circuit: WitnessTester<
    [
      "siblings",
      "index",
      "secret",
      "salt",
      "newSecret",
      "newSalt",
      "amount",
      "balance",
      "root",
      "nullifier",
      "commitment",
      "newCommitment",
      "depth"
    ]
  >;

  const DEPTH = 5;
  const MAX_SUPPORTED_VALUE = 2n ** 252n - 1n;

  before(async () => {
    circuit = await circomkit.WitnessTester("Withdrawal", {
      file: "Withdrawal",
      template: "Withdrawal",
      params: [DEPTH],
    });
  });

  it("should prove withdrawal properly", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        async ([amount, balance], secret, salt, newSecret, newSalt) => {
          const nullifier = poseidon1([secret]);
          const commitment = poseidon3([secret, balance, salt]);
          const newCommitment = poseidon3([
            newSecret,
            balance - amount,
            newSalt,
          ]);

          const { siblings, index, root, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            nullifier,
            commitment,
            newCommitment,
            secret,
            salt,
            newSecret,
            newSalt,
            amount,
            balance,
            depth,
            siblings,
            index,
            root,
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

  it("should not prove withdrawal if amount exceeds balance", async () => {
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
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        async ([amount, balance], secret, salt, newSecret, newSalt) => {
          if (amount === balance) {
            return true;
          }

          const nullifier = poseidon1([secret]);
          const commitment = poseidon3([secret, balance, salt]);
          const newCommitment = poseidon3([
            newSecret,
            balance - amount,
            newSalt,
          ]);

          const { siblings, index, root, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            nullifier,
            commitment,
            newCommitment,
            secret,
            salt,
            newSecret,
            newSalt,
            amount,
            balance,
            depth,
            siblings,
            index,
            root,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should not prove withdrawal if commitment is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        async (
          [amount, balance],
          secret,
          salt,
          newSecret,
          newSalt,
          commitment
        ) => {
          const nullifier = poseidon1([secret]);
          const newCommitment = poseidon3([
            newSecret,
            balance - amount,
            newSalt,
          ]);

          const { siblings, index, root, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            nullifier,
            commitment,
            newCommitment,
            secret,
            salt,
            newSecret,
            newSalt,
            amount,
            balance,
            depth,
            siblings,
            index,
            root,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should not prove withdrawal if new commitment is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        async (
          [amount, balance],
          secret,
          salt,
          newSecret,
          newSalt,
          newCommitment
        ) => {
          const nullifier = poseidon1([secret]);
          const commitment = poseidon3([secret, balance, salt]);

          const { siblings, index, root, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            nullifier,
            commitment,
            newCommitment,
            secret,
            salt,
            newSecret,
            newSalt,
            amount,
            balance,
            depth,
            siblings,
            index,
            root,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should not prove withdrawal if nullifier is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        async (
          [amount, balance],
          secret,
          salt,
          newSecret,
          newSalt,
          nullifier
        ) => {
          const commitment = poseidon3([secret, balance, salt]);
          const newCommitment = poseidon3([
            newSecret,
            balance - amount,
            newSalt,
          ]);

          const { siblings, index, root, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            nullifier,
            commitment,
            newCommitment,
            secret,
            salt,
            newSecret,
            newSalt,
            amount,
            balance,
            depth,
            siblings,
            index,
            root,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should not prove withdrawal if root is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        async ([amount, balance], secret, salt, newSecret, newSalt, root) => {
          const nullifier = poseidon1([secret]);
          const commitment = poseidon3([secret, balance, salt]);
          const newCommitment = poseidon3([
            newSecret,
            balance - amount,
            newSalt,
          ]);

          const { siblings, index, depth } = generateBinaryMerkleRoot(
            DEPTH,
            0,
            [commitment]
          );

          const inputs = {
            nullifier,
            commitment,
            newCommitment,
            secret,
            salt,
            newSecret,
            newSalt,
            amount,
            balance,
            depth,
            siblings,
            index,
            root,
          };

          return circuit
            .expectFail(inputs)
            .then(() => true)
            .catch(() => false);
        }
      )
    );
  });

  it("should not prove withdrawal if tree is invalid", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc
          .bigInt({ min: 0n, max: MAX_SUPPORTED_VALUE })
          .chain((balance) =>
            fc
              .bigInt({ min: 0n, max: balance })
              .map((amount) => [amount, balance] as const)
          ),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.nat(),
        async ([amount, balance], secret, salt, newSecret, newSalt, index) => {
          const nullifier = poseidon1([secret]);
          const commitment = poseidon3([secret, balance, salt]);
          const newCommitment = poseidon3([
            newSecret,
            balance - amount,
            newSalt,
          ]);

          const { siblings, root, depth } = generateBinaryMerkleRoot(
            DEPTH,
            index,
            []
          );

          const inputs = {
            nullifier,
            commitment,
            newCommitment,
            secret,
            salt,
            newSecret,
            newSalt,
            amount,
            balance,
            depth,
            siblings,
            index,
            root,
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
