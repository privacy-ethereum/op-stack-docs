import { BabyJub, BigNumberish, buildBabyjub, Point } from "circomlibjs";

/**
 * Builds a Pedersen commitment helper over the BabyJubJub curve.
 *
 * SECURITY NOTICE
 * ------------------
 * Pedersen commitments require TWO independent generators G and H
 * such that **no one knows** a scalar `x` with:
 *
 *    H = x * G
 *
 * In this implementation, `H` is derived as:
 *
 *    H = secretHash * G
 *
 * This means:
 *  - The homomorphic property is preserved
 *  - Perfect hiding is preserved
 *  - Binding is NOT preserved if `secretHash` is known
 *
 * This construction is therefore suitable for:
 *  - Testing
 *  - Demonstrations
 *  - Non-adversarial environments
 *
 * DO NOT use this in production unless `secretHash` is generated via a trusted setup or MPC ceremony.
 *
 * @param H - Secondary generator (discrete log known if secret is known)
 * @returns PedersenCommitment instance
 */
export default async function buildPedersenCommitment(
  H: Point
): Promise<PedersenCommitment> {
  const babyJub = await buildBabyjub();

  return new PedersenCommitment(babyJub, H);
}

/**
 * Pedersen commitment over BabyJubJub.
 *
 * Commitment scheme:
 *
 *   C(m, r) = m * G + r * H
 *
 * Properties:
 *  - Perfectly hiding
 *  - Computationally binding (ONLY if discrete log between G and H is unknown)
 *  - Additively homomorphic:
 *
 *    C(m1, r1) + C(m2, r2) = C(m1 + m2, r1 + r2)
 */
export class PedersenCommitment {
  /**
   * Secondary generator (discrete log known if secret is known)
   */
  private H: Point;

  /**
   * BabyJubJub curve instance
   */
  private babyJub: BabyJub;

  /**
   * Creates a new Pedersen commitment instance.
   *
   * @param babyJub - Initialized BabyJubJub curve instance
   * @param secretHash - Scalar used to derive generator H (must be generated via trusted setup or MPC for cryptographic security)
   */
  constructor(babyJub: BabyJub, H: Point) {
    this.babyJub = babyJub;
    this.H = H;
  }

  /**
   * Computes a Pedersen commitment.
   *
   * @param message - Message scalar `message`
   * @param random  - Randomness scalar `random`
   *
   * @returns Commitment point: C = m * G + r * H
   */
  commit(message: BigNumberish, random: BigNumberish): Point {
    // Base generator
    const G = this.babyJub.Base8;

    const messageG = this.babyJub.mulPointEscalar(G, message);
    const randomH = this.babyJub.mulPointEscalar(this.H, random);

    return this.babyJub.addPoint(messageG, randomH);
  }
}
