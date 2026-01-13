// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/src/Test.sol";
import {CurveBabyJubJub} from "../src/crypto/CurveBabyJubJub.sol";

contract CurveBabyJubJubTest is Test {
    function test_PointAddZeroValues() public view {
        (uint256 x1, uint256 y1) = CurveBabyJubJub.pointAdd(0, 0, 1, 1);

        assertEq(x1, 1);
        assertEq(y1, 1);

        (uint256 x2, uint256 y2) = CurveBabyJubJub.pointAdd(2, 2, 0, 0);

        assertEq(x2, 2);
        assertEq(y2, 2);
    }

    function testFuzz_packUnpackPoint(uint256 scalar) public view {
        (uint256 initialX, uint256 initialY) = CurveBabyJubJub.pointMul(
            CurveBabyJubJub.BASE8_X,
            CurveBabyJubJub.BASE8_Y,
            scalar
        );

        uint256 packed = CurveBabyJubJub.packPoint(initialX, initialY);
        (uint256 actualX, uint256 actualY) = CurveBabyJubJub.unpackPoint(
            packed
        );

        assertTrue(CurveBabyJubJub.isOnCurve(initialX, initialY));
        assertTrue(CurveBabyJubJub.isOnCurve(actualX, actualY));
        assertEq(initialX, actualX);
        assertEq(initialY, actualY);
    }

    function testFuzz_pointAddPointDouble(uint256 scalar) public view {
        (uint256 initialX, uint256 initialY) = CurveBabyJubJub.pointMul(
            CurveBabyJubJub.BASE8_X,
            CurveBabyJubJub.BASE8_Y,
            scalar
        );

        (uint256 addX, uint256 addY) = CurveBabyJubJub.pointAdd(
            initialX,
            initialY,
            initialX,
            initialY
        );
        (uint256 doubleX, uint256 doubleY) = CurveBabyJubJub.pointDouble(
            initialX,
            initialY
        );

        assertTrue(CurveBabyJubJub.isOnCurve(initialX, initialY));
        assertTrue(CurveBabyJubJub.isOnCurve(addX, addY));
        assertTrue(CurveBabyJubJub.isOnCurve(doubleX, doubleY));

        assertEq(addX, doubleX);
        assertEq(addY, doubleY);
    }

    function testFuzz_pointAddPointSub(
        uint256 scalar1,
        uint256 scalar2
    ) public view {
        (uint256 initial1X, uint256 initial1Y) = CurveBabyJubJub.pointMul(
            CurveBabyJubJub.BASE8_X,
            CurveBabyJubJub.BASE8_Y,
            scalar1
        );

        (uint256 initial2X, uint256 initial2Y) = CurveBabyJubJub.pointMul(
            CurveBabyJubJub.BASE8_X,
            CurveBabyJubJub.BASE8_Y,
            scalar2
        );

        (uint256 addX, uint256 addY) = CurveBabyJubJub.pointAdd(
            initial1X,
            initial1Y,
            initial2X,
            initial2Y
        );
        (uint256 sub1X, uint256 sub1Y) = CurveBabyJubJub.pointSub(
            addX,
            addY,
            initial2X,
            initial2Y
        );
        (uint256 sub2X, uint256 sub2Y) = CurveBabyJubJub.pointSub(
            addX,
            addY,
            initial1X,
            initial1Y
        );

        assertTrue(CurveBabyJubJub.isOnCurve(initial1X, initial1Y));
        assertTrue(CurveBabyJubJub.isOnCurve(initial2X, initial2Y));
        assertTrue(CurveBabyJubJub.isOnCurve(addX, addY));
        assertTrue(CurveBabyJubJub.isOnCurve(sub1X, sub1Y));
        assertTrue(CurveBabyJubJub.isOnCurve(sub2X, sub2Y));

        assertEq(initial1X, sub1X);
        assertEq(initial1Y, sub1Y);
        assertEq(initial2X, sub2X);
        assertEq(initial2Y, sub2Y);
    }

    function testFuzz_ExpMod(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) public view {
        uint256 result = CurveBabyJubJub.expmod(base, exponent, modulus);

        if (modulus == 0) {
            assertEq(result, 0);
        } else {
            assertLt(result, modulus);
        }
    }

    function testFuzz_Submod(uint256 a, uint256 b, uint256 m) public pure {
        vm.assume(m != 0);

        uint256 result = CurveBabyJubJub.submod(a, b, m);
        uint256 recomposed = addmod(result, b, m);

        
        assertEq(recomposed, a % m);
    }

    function test_Submod_EdgeCase() public pure {
        uint256 result = CurveBabyJubJub.submod(1, 1, 0);

        assertEq(result, 0);
    }

    function testFuzz_Inverse(uint256 a) public view {
        vm.assume(a != 0);
        vm.assume(a < CurveBabyJubJub.Q);

        uint256 inv = CurveBabyJubJub.inverse(a);
        uint256 actual = mulmod(a, inv, CurveBabyJubJub.Q);

        assertEq(actual, 1);
    }

    function test_Inverse_EdgeCases() public view {
        assertEq(CurveBabyJubJub.inverse(1), 1);

        assertEq(
            CurveBabyJubJub.inverse(CurveBabyJubJub.Q - 1),
            CurveBabyJubJub.Q - 1
        );

        assertEq(mulmod(2, CurveBabyJubJub.inverse(2), CurveBabyJubJub.Q), 1);
        assertEq(mulmod(3, CurveBabyJubJub.inverse(3), CurveBabyJubJub.Q), 1);
    }

    function testFuzz_ModSqrt(uint256 x) public view {
        uint256 square = mulmod(x, x, CurveBabyJubJub.Q); // a is guaranteed to be a quadratic residue

        uint256 sqrt = CurveBabyJubJub.modSqrt(square);
        uint256 actual = mulmod(sqrt, sqrt, CurveBabyJubJub.Q);

        assertEq(actual, square);
    }

    function test_ModSqrt_EdgeCases() public view {
        assertEq(CurveBabyJubJub.modSqrt(0), 0);

        uint256 sqrt = CurveBabyJubJub.modSqrt(1);
        uint256 check = mulmod(sqrt, sqrt, CurveBabyJubJub.Q);
        assertEq(check, 1);
    }
}
