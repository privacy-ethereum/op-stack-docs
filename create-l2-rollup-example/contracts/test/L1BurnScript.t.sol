// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/src/Test.sol";
import {L1BurnScript} from "../script/L1Burn.s.sol";
import {L1Burn} from "../src/L1Burn.sol";

contract L1BurnScriptTest is Test {
    L1BurnScript public l1BurnScript;

    function setUp() public {
        l1BurnScript = new L1BurnScript();
    }

    function test_ScriptRun() public {
        l1BurnScript.run();

        L1Burn l1Burn = l1BurnScript.l1Burn();

        assertNotEq(address(l1Burn), address(0));
        assertEq(l1Burn.total(), 0);
    }
}
