// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {CurveBabyJubJub} from "./crypto/CurveBabyJubJub.sol";

/**
 * @title PedersenCommitment
 * @notice PedersenCommitment implementation for tests (DO NOT USE IN PRODUCTION)
 */
contract PedersenCommitment {
    /**
     * @notice X-coordinate of the generator H.
     * @dev
     * H must be a valid BabyJubjub curve point in the same prime-order
     * subgroup as the base generator G, and its discrete logarithm
     * relative to G must be unknown.
     */
    uint256 public constant HX =
        8161729262802821074953933772769868423242630511238094437756788308176542630231;
    /**
     * @notice Y-coordinate of the generator H.
     * @dev See `HX` for security requirements.
     */
    uint256 public constant HY =
        17477144202559280327772048374561482684555254494412313979603280050466695949333;

    /**
     * @notice Thrown when `message` or `random` inputs are invalid.
     */
    error InvalidInput();

    /**
     * @notice Computes a Pedersen commitment to a message.
     *
     * @dev
     * Computes the elliptic-curve point:
     *
     *   C = message * G + random * H
     *
     * using BabyJubjub curve arithmetic.
     *
     * @param message The value being committed to.
     * @param random A random blinding factor used to hide the message.
     *
     * @return x The x-coordinate of the commitment point.
     * @return y The y-coordinate of the commitment point.
     */
    function commitment(
        uint256 message,
        uint256 random
    ) public view returns (uint256 x, uint256 y) {
        bool isInvalid = message == 0 ||
            random == 0 ||
            message >= CurveBabyJubJub.SUBGROUP_ORDER ||
            random >= CurveBabyJubJub.SUBGROUP_ORDER;

        if (isInvalid) {
            revert InvalidInput();
        }

        (uint256 mGx, uint256 mGy) = CurveBabyJubJub.pointMul(
            CurveBabyJubJub.BASE8_X,
            CurveBabyJubJub.BASE8_Y,
            message
        );
        (uint256 rHx, uint256 rHy) = CurveBabyJubJub.pointMul(HX, HY, random);

        return CurveBabyJubJub.pointAdd(mGx, mGy, rHx, rHy);
    }
}
