import { buildBabyjub, Point } from "circomlibjs";
import { WitnessTester } from "circomkit";
import { createHash, randomBytes } from "crypto";
import fc from "fast-check";

import { SECONDARY_GENERATOR } from "../ts/constants";
import buildPedersenCommitment from "../ts/pedersen";
import { BN254_FR_MODULUS, circomkit, getSignal } from "./common";

describe("Pedersen", () => {
  let circuit: WitnessTester<["message", "random", "commitment"], ["out"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("PedersenCommitment", {
      file: "PedersenCommitment",
      template: "PedersenCommitment",
      params: [],
    });
  });

  it("should check pedersen commitment", async () => {
    const babyJub = await buildBabyjub();

    const H = [
      babyJub.F.e(SECONDARY_GENERATOR[0].toString()),
      babyJub.F.e(SECONDARY_GENERATOR[1].toString()),
    ] as Point;
    const pedersenCommitment = await buildPedersenCommitment(H);

    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (message, random) => {
          const commitment = pedersenCommitment.commit(message, random);

          const witness = await circuit.calculateWitness({
            message,
            random,
            commitment: [
              BigInt(babyJub.F.toObject(commitment[0])),
              BigInt(babyJub.F.toObject(commitment[1])),
            ],
          });

          await circuit.expectConstraintPass(witness);

          const x = await getSignal({
            circuit,
            witness,
            name: "out[0]",
          });

          const y = await getSignal({
            circuit,
            witness,
            name: "out[1]",
          });

          return (
            x === BigInt(babyJub.F.toObject(commitment[0])) &&
            y === BigInt(babyJub.F.toObject(commitment[1]))
          );
        }
      )
    );
  });

  it("should check homomorphic property", async () => {
    const secret = randomBytes(256);
    const secretHash = BigInt(
      `0x${createHash("sha256").update(secret).digest("hex")}`
    );
    const babyJub = await buildBabyjub();

    // Base generator
    const G = babyJub.Base8;
    // Secondary generator (discrete log known if secretHash is known)
    const H = babyJub.mulPointEscalar(G, secretHash);

    const pedersenCommitment = await buildPedersenCommitment(H);

    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        fc.bigInt({ min: 0n }),
        async (message1, message2, random1, random2) => {
          const commitment1 = pedersenCommitment.commit(message1, random1);
          const commitment2 = pedersenCommitment.commit(message2, random2);

          const sumCommitment = pedersenCommitment.commit(
            message1 + message2,
            random1 + random2
          );
          const directCommitment = babyJub.addPoint(commitment1, commitment2);

          return (
            babyJub.F.eq(sumCommitment[0], directCommitment[0]) &&
            babyJub.F.eq(sumCommitment[1], directCommitment[1])
          );
        }
      )
    );
  });
});
