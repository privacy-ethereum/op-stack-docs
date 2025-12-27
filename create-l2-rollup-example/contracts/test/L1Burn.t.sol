// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/src/Test.sol";
import {L1Burn} from "../src/L1Burn.sol";

contract L1BurnTest is Test {
    L1Burn public l1Burn;

    function setUp() public {
        l1Burn = new L1Burn();
    }

    function test_RevertIf_ReportWithNonDepositorCaller() public {
        vm.expectRevert("Unauthorized()");

        l1Burn.report(1, 1);
    }

    function test_Report() public {
        uint256 initialTotal = l1Burn.total();
        uint64 burnAmount = 1;
        vm.prank(l1Burn.DEPOSITOR_ACCOUNT());

        l1Burn.report(1, burnAmount);
        uint256 reportedBurn = l1Burn.reports(1);

        assertEq(initialTotal, 0);
        assertEq(l1Burn.total(), initialTotal + burnAmount);
        assertEq(reportedBurn, reportedBurn);
    }

    function test_RevertIf_ReportSameBlockNumber() public {
        vm.prank(l1Burn.DEPOSITOR_ACCOUNT());
        l1Burn.report(1, 1);

        assertEq(l1Burn.total(), 1);

        vm.prank(l1Burn.DEPOSITOR_ACCOUNT());
        vm.expectRevert("AlreadyReported()");

        l1Burn.report(1, 1);

        assertEq(l1Burn.total(), 1);
    }

    function testFuzz_Report(uint64 blockNumber, uint64 burnAmount) public {
        uint256 initialTotal = l1Burn.total();
        vm.prank(l1Burn.DEPOSITOR_ACCOUNT());

        l1Burn.report(blockNumber, burnAmount);
        uint256 reportedBurn = l1Burn.reports(blockNumber);

        assertEq(l1Burn.total(), initialTotal + burnAmount);
        assertEq(reportedBurn, burnAmount);
    }

    function test_EmptyTally() public view {
        uint256 tally = l1Burn.tally(1);

        assertEq(tally, 0);
    }

    function testFuzz_Tally(uint64 blockNumber, uint64 burnAmount) public {
        vm.prank(l1Burn.DEPOSITOR_ACCOUNT());

        l1Burn.report(blockNumber, burnAmount);

        uint256 total = l1Burn.total();
        uint256 tally = l1Burn.tally(blockNumber);

        assertEq(tally, total - burnAmount);
    }
}
