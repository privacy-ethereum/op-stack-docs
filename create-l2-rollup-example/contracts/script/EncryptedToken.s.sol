// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/src/Script.sol";
import {Groth16Verifier} from "../src/crypto/Groth16Verifier.sol";
import {EncryptedToken} from "../src/EncryptedToken.sol";

contract EncryptedTokenScript is Script {
    EncryptedToken public encryptedToken;

    Groth16Verifier public verifier;

    function run() public {
        vm.startBroadcast();

        verifier = new Groth16Verifier();
        encryptedToken = new EncryptedToken(verifier);

        vm.stopBroadcast();
    }
}
