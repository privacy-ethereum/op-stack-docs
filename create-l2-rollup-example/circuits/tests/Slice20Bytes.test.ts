import { expect } from "chai";
import { WitnessTester } from "circomkit";
import { isAddress } from "ethers";
import fc from "fast-check";

import { hex, MAX_ADDRESS } from "../ts/address";
import { BN254_FR_MODULUS, circomkit, getSignal } from "./common";

describe("Slice20Bytes", () => {
  let circuit: WitnessTester<["hash"], ["out"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("Slice20Bytes", {
      file: "Slice20Bytes",
      template: "Slice20Bytes",
      params: [],
    });
  });

  it("should slice 20 bytes from hash properly", async () => {
    const inputs = {
      hash: 2n ** 160n - 1n,
    };

    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);

    const output = await getSignal({
      circuit,
      witness,
      name: "out",
    });

    expect(hex(output)).to.equal(hex(inputs.hash));
  });

  it("should not fail slicing 20 bytes if hash is greater than or equal to 2^160", async () => {
    const inputs = {
      hash: 2n ** 160n,
    };

    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);

    const output = await getSignal({
      circuit,
      witness,
      name: "out",
    });

    expect(hex(output)).to.equal(hex(inputs.hash));
  });

  it("should highlight collision of the slice", async () => {
    // This test shows the case where slice gives the same address (same for keccak256)
    // hex(hash) === hex(hash % 2n ** 160n)
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (hash) => {
          fc.pre(hash + MAX_ADDRESS < BN254_FR_MODULUS);

          const inputs = {
            hash,
          };

          const shiftedInputs = {
            hash: hash + MAX_ADDRESS,
          };

          await circuit.expectPass(inputs);
          await circuit.expectPass(shiftedInputs);

          const output = await getSignal({
            circuit,
            witness: await circuit.calculateWitness(inputs),
            name: "out",
          });

          const shiftedOutput = await getSignal({
            circuit,
            witness: await circuit.calculateWitness(shiftedInputs),
            name: "out",
          });

          const expectedAddress = hex(hash);
          const actualAddress = hex(output);
          const shiftedOutputAddress = hex(shiftedOutput);

          return (
            isAddress(actualAddress) &&
            expectedAddress === actualAddress &&
            actualAddress === shiftedOutputAddress
          );
        }
      )
    );
  });

  it("should check slice 20 bytes from hash properly", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        async (hash) => {
          const inputs = {
            hash,
          };

          const witness = await circuit.calculateWitness(inputs);
          await circuit.expectConstraintPass(witness);

          const output = await getSignal({
            circuit,
            witness,
            name: "out",
          });

          const expectedAddress = hex(hash);
          const actualAddress = hex(output);

          return isAddress(actualAddress) && expectedAddress === actualAddress;
        }
      )
    );
  });
});
