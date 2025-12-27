// @note This code was taken from
// https://github.com/yondonfu/sol-baby-jubjub/blob/master/contracts/CurveBabyJubJub.sol
// Thanks to yondonfu for the code
// Implementation cited on baby-jubjub's paper
// https://eips.ethereum.org/EIPS/eip-2494#implementation

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library CurveBabyJubJub {
    // Curve parameters
    // E: 168700x^2 + y^2 = 1 + 168696x^2y^2
    // A = 168700
    uint256 public constant A = 0x292FC;
    // D = 168696
    uint256 public constant D = 0x292F8;
    // Prime Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    uint256 public constant Q =
        0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001;
    // Base point
    uint256 internal constant Base8X =
        5299619240641551281634865583518297030282874472190772894086521144482721001553;
    uint256 internal constant Base8Y =
        16950150798460657717958625567821834550301663161624707787222815936182638968203;
    // Subgroup order
    uint256 internal constant SUBGROUP_ORDER =
        0x30644E72E131A029B85045B68181585D59F76DC1C90770533B94BEE1C9093788;

    /**
     * @dev Add 2 points on baby jubjub curve
     * Formula for adding 2 points on a twisted Edwards curve:
     * x3 = (x1y2 + y1x2) / (1 + dx1x2y1y2)
     * y3 = (y1y2 - ax1x2) / (1 - dx1x2y1y2)
     */
    function pointAdd(
        uint256 _x1,
        uint256 _y1,
        uint256 _x2,
        uint256 _y2
    ) internal view returns (uint256 x3, uint256 y3) {
        if (_x1 == 0 && _y1 == 0) {
            return (_x2, _y2);
        }

        if (_x2 == 0 && _y2 == 0) {
            return (_x1, _y1);
        }

        uint256 x1x2 = mulmod(_x1, _x2, Q);
        uint256 y1y2 = mulmod(_y1, _y2, Q);
        uint256 dx1x2y1y2 = mulmod(D, mulmod(x1x2, y1y2, Q), Q);
        uint256 x3Num = addmod(mulmod(_x1, _y2, Q), mulmod(_y1, _x2, Q), Q);
        uint256 y3Num = submod(y1y2, mulmod(A, x1x2, Q), Q);

        x3 = mulmod(x3Num, inverse(addmod(1, dx1x2y1y2, Q)), Q);
        y3 = mulmod(y3Num, inverse(submod(1, dx1x2y1y2, Q)), Q);
    }

    /**
     * @dev Double a point on baby jubjub curve
     * Doubling can be performed with the same formula as addition
     */
    function pointDouble(
        uint256 _x1,
        uint256 _y1
    ) internal view returns (uint256 x2, uint256 y2) {
        return pointAdd(_x1, _y1, _x1, _y1);
    }

    /**
     * @dev Multiply a point on baby jubjub curve by a scalar
     * Use the double and add algorithm
     */
    function pointMul(
        uint256 _x1,
        uint256 _y1,
        uint256 _d
    ) internal view returns (uint256 x2, uint256 y2) {
        uint256 remaining = _d;

        uint256 px = _x1;
        uint256 py = _y1;
        uint256 ax = 0;
        uint256 ay = 1;

        while (remaining != 0) {
            if ((remaining & 1) != 0) {
                // Binary digit is 1 so add
                (ax, ay) = pointAdd(ax, ay, px, py);
            }

            (px, py) = pointDouble(px, py);

            remaining = remaining / 2;
        }

        x2 = ax;
        y2 = ay;
    }

    /**
     * @dev Check if a given point is on the curve
     * (168700x^2 + y^2) - (1 + 168696x^2y^2) == 0
     */
    function isOnCurve(uint256 _x, uint256 _y) internal pure returns (bool) {
        uint256 xSq = mulmod(_x, _x, Q);
        uint256 ySq = mulmod(_y, _y, Q);
        uint256 lhs = addmod(mulmod(A, xSq, Q), ySq, Q);
        uint256 rhs = addmod(1, mulmod(mulmod(D, xSq, Q), ySq, Q), Q);
        return submod(lhs, rhs, Q) == 0;
    }

    /**
     * @dev Perform modular subtraction
     */
    function submod(
        uint256 _a,
        uint256 _b,
        uint256 _mod
    ) internal pure returns (uint256) {
        if (_mod == 0) {
            return 0;
        }

        return addmod(_a, _mod - (_b % _mod), _mod);
    }

    /**
     * @dev Compute modular inverse of a number
     */
    function inverse(uint256 _a) internal view returns (uint256) {
        // We can use Euler's theorem instead of the extended Euclidean algorithm
        // Since m = Q and Q is prime we have: a^-1 = a^(m - 2) (mod m)
        return expmod(_a, Q - 2, Q);
    }

    /**
     * @dev Helper function to call the bigModExp precompile
     */
    function expmod(
        uint256 _b,
        uint256 _e,
        uint256 _m
    ) internal view returns (uint256 o) {
        assembly {
            let memPtr := mload(0x40)
            mstore(memPtr, 0x20) // Length of base _b
            mstore(add(memPtr, 0x20), 0x20) // Length of exponent _e
            mstore(add(memPtr, 0x40), 0x20) // Length of modulus _m
            mstore(add(memPtr, 0x60), _b) // Base _b
            mstore(add(memPtr, 0x80), _e) // Exponent _e
            mstore(add(memPtr, 0xa0), _m) // Modulus _m

            // The bigModExp precompile is at 0x05
            let success := staticcall(gas(), 0x05, memPtr, 0xc0, memPtr, 0x20)
            switch success
            case 0 {
                revert(0x0, 0x0)
            }
            default {
                o := mload(memPtr)
            }
        }
    }

    /**
     * @notice Packs a BabyJubjub elliptic curve point into a single 256-bit integer.
     * @dev Encodes the y-coordinate in little-endian format and stores the sign of x in the most significant bit.
     *      This format is compatible with standard BabyJubjub point serialization.
     * @param x The x-coordinate of the BabyJubjub point.
     * @param y The y-coordinate of the BabyJubjub point.
     * @return p The packed 256-bit integer representing the BabyJubjub point.
     */
    function packPoint(uint256 x, uint256 y) internal pure returns (uint256 p) {
        p = y & ((1 << 255) - 1);

        if (x > (Q - 1) / 2) {
            p |= 1 << 255;
        }
    }

    /**
     * @notice Unpacks a BabyJubjub elliptic curve point from a 256-bit integer.
     * @dev Extracts y-coordinate and recovers x using the curve equation.
     * @param point The packed BabyJubjub point.
     * @return x The x-coordinate.
     * @return y The y-coordinate.
     */
    function unpackPoint(
        uint256 point
    ) internal view returns (uint256 x, uint256 y) {
        // Extract y (lower 255 bits)
        y = point & ((1 << 255) - 1);

        // Extract sign bit of x
        bool xSign = (point >> 255) == 1;

        // Compute x² = (1 - y²) / (A - D·y²)
        uint256 y2 = mulmod(y, y, Q);

        uint256 numerator = addmod(1, Q - y2, Q);
        uint256 denominator = addmod(A, Q - mulmod(D, y2, Q), Q);

        uint256 invDenominator = inverse(denominator);
        uint256 x2 = mulmod(numerator, invDenominator, Q);

        // Compute square root
        x = modSqrt(x2);

        // Enforce correct sign
        if ((x > (Q - 1) / 2) != xSign) {
            x = Q - x;
        }

        return (x, y);
    }

    function modSqrt(uint256 a) internal view returns (uint256 x) {
        if (a == 0) return 0;

        uint256 p = Q;

        // Check Legendre symbol: a^((p-1)/2) ≡ 1 (mod p)
        if (expmod(a, (p - 1) >> 1, p) != 1) revert();

        // Factor p-1 = q * 2^s with q odd
        uint256 q = p - 1;
        uint256 s = 0;
        while ((q & 1) == 0) {
            q >>= 1;
            s++;
        }

        // Find quadratic non-residue z
        uint256 z = 2;
        while (expmod(z, (p - 1) >> 1, p) != p - 1) {
            z++;
        }

        uint256 c = expmod(z, q, p);
        x = expmod(a, (q + 1) >> 1, p);
        uint256 t = expmod(a, q, p);
        uint256 m = s;

        while (t != 1) {
            uint256 i = 1;
            uint256 t2i = mulmod(t, t, p);
            while (t2i != 1) {
                t2i = mulmod(t2i, t2i, p);
                i++;
            }

            uint256 b = expmod(c, uint256(1) << (m - i - 1), p);
            x = mulmod(x, b, p);
            t = mulmod(t, mulmod(b, b, p), p);
            c = mulmod(b, b, p);
            m = i;
        }
    }

    /**
     * @notice Computes P1 − P2 on the BabyJubJub curve.
     * @dev Implemented as P1 + (−P2), where −(x, y) = (−x mod Q, y).
     *
     * @param x1 The x-coordinate of the first point P1.
     * @param y1 The y-coordinate of the first point P1.
     * @param x2 The x-coordinate of the second point P2.
     * @param y2 The y-coordinate of the second point P2.
     *
     * @return x3 The x-coordinate of the resulting point P3 = P1 − P2.
     * @return y3 The y-coordinate of the resulting point P3 = P1 − P2.
     */
    function pointSub(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) internal view returns (uint256 x3, uint256 y3) {
        return pointAdd(x1, y1, Q - x2, y2);
    }
}
