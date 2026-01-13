// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/src/Script.sol";
import {L1Burn} from "../src/L1Burn.sol";

contract L1BurnScript is Script {
    L1Burn public l1Burn;

    function run() public {
        vm.startBroadcast();

        l1Burn = new L1Burn();

        vm.stopBroadcast();
    }
}
