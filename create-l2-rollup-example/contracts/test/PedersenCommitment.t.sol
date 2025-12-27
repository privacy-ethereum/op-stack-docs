// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {CurveBabyJubJub} from "../src/crypto/CurveBabyJubJub.sol";
import {PedersenCommitment} from "../src/PedersenCommitment.sol";

contract PedersenCommitmentTest is Test {
    PedersenCommitment public pedersenCommitment;

    function setUp() public {
        pedersenCommitment = new PedersenCommitment();
    }

    function test_generatorOnCurve() public view {
        assertTrue(
            CurveBabyJubJub.isOnCurve(
                CurveBabyJubJub.Base8X,
                CurveBabyJubJub.Base8Y
            )
        );

        assertTrue(
            CurveBabyJubJub.isOnCurve(
                pedersenCommitment.Hx(),
                pedersenCommitment.Hy()
            )
        );
    }

    function test_RevertIf_CommitmentWithZeroMessage() public {
        vm.expectRevert("InvalidInput()");

        pedersenCommitment.commitment(0, 1);
    }

    function test_RevertIf_CommitmentWithZeroRandom() public {
        vm.expectRevert("InvalidInput()");

        pedersenCommitment.commitment(1, 0);
    }

    function test_RevertIf_CommitmentWithMaxMessage() public {
        vm.expectRevert("InvalidInput()");

        pedersenCommitment.commitment(CurveBabyJubJub.SUBGROUP_ORDER, 1);
    }

    function test_RevertIf_CommitmentWithMaxRandom() public {
        vm.expectRevert("InvalidInput()");

        pedersenCommitment.commitment(1, CurveBabyJubJub.SUBGROUP_ORDER);
    }

    function test_PedersenCommitment() public view {
        (uint256 x, uint256 y) = pedersenCommitment.commitment(1, 2);

        assertEq(CurveBabyJubJub.isOnCurve(x, y), true);
    }

    function testFuzz_PedersenCommitment(
        uint256 message,
        uint256 random
    ) public view {
        vm.assume(
            message != 0 &&
                random != 0 &&
                message < CurveBabyJubJub.Q &&
                random < CurveBabyJubJub.Q
        );

        (uint256 x, uint256 y) = pedersenCommitment.commitment(message, random);

        assertEq(CurveBabyJubJub.isOnCurve(x, y), true);
    }
}
