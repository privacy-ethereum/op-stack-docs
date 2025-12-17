import { expect } from "chai";
import { WitnessTester } from "circomkit";
import { isAddress } from "ethers";
import fc from "fast-check";
import { poseidon2 } from "poseidon-lite/poseidon2";
import { poseidon3 } from "poseidon-lite/poseidon3";

import { generateUnspendableAddress, hex } from "../ts/address";
import { BN254_FR_MODULUS, circomkit, getSignal } from "./common";

describe("UnspendableAddress", () => {
  let circuit: WitnessTester<
    ["secret", "random", "nonce", "preimageHash"],
    ["address"]
  >;

  const DOMAIN_TAG = 123n;

  const common = {
    secret: 2n ** 160n - 1n,
    random: 2n ** 160n - 2n,
    nonce: 0n,
  };

  before(async () => {
    circuit = await circomkit.WitnessTester("UnspendableAddress", {
      file: "UnspendableAddress",
      template: "UnspendableAddress",
      params: [DOMAIN_TAG],
    });
  });

  it("should generate an unspendable address properly", async () => {
    const inputs = {
      secret: common.secret,
      random: common.random,
      nonce: common.nonce,
      preimageHash: poseidon2([
        generateUnspendableAddress({
          secret: common.secret,
          random: common.random,
          nonce: common.nonce,
          tag: DOMAIN_TAG,
        }),
        common.secret,
      ]),
    };

    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);

    const output = await getSignal({
      circuit,
      witness,
      name: "address",
    });

    const circuitAddress = hex(output);
    const offchainAddress = generateUnspendableAddress({
      ...inputs,
      tag: DOMAIN_TAG,
    });

    expect(isAddress(circuitAddress)).to.equal(true);
    expect(circuitAddress).to.equal(offchainAddress);
    expect(circuitAddress).to.equal(
      "0x9c715700C53d715b1c9F3351fc4a7cFBF6c81C5A"
    );
  });

  it("should fail if preimage hash does not match secrets", async () => {
    const inputs = {
      secret: 0n,
      random: 0n,
      nonce: 0n,
      preimageHash: 0n,
    };

    await circuit.expectFail(inputs);
  });

  it("should check slice 20 bytes from hash properly", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - 1n }),
        fc.bigInt({ min: 0n, max: BN254_FR_MODULUS - DOMAIN_TAG - 1n }),
        async (secret, random, nonce) => {
          const inputs = {
            secret,
            random,
            nonce,
            preimageHash: poseidon2([
              generateUnspendableAddress({
                secret,
                random,
                nonce,
                tag: DOMAIN_TAG,
              }),
              secret,
            ]),
          };

          const witness = await circuit.calculateWitness(inputs);
          await circuit.expectConstraintPass(witness);

          const output = await getSignal({
            circuit,
            witness,
            name: "address",
          });

          const circuitAddress = hex(output);
          const offchainAddress = generateUnspendableAddress({
            ...inputs,
            tag: DOMAIN_TAG,
          });

          return (
            isAddress(circuitAddress) && circuitAddress === offchainAddress
          );
        }
      )
    );
  });
});
