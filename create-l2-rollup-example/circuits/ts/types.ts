/**
 * Arguments for generating an unspendable address
 */
export interface IGenerateUnspendableAddressArgs {
  /**
   * Secret
   */
  secret: bigint;

  /**
   * Random
   */
  random: bigint;

  /**
   * Nonce
   */
  nonce: bigint;

  /**
   * Domain separation tag
   */
  tag: bigint;
}
