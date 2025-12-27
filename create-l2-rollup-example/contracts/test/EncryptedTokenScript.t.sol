// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/src/Test.sol";
import {EncryptedTokenScript} from "../script/EncryptedToken.s.sol";
import {Groth16Verifier} from "../src/crypto/Groth16Verifier.sol";
import {EncryptedToken} from "../src/EncryptedToken.sol";

contract EncryptedTokenScriptTest is Test {
    EncryptedTokenScript public encryptedTokenScript;

    function setUp() public {
        encryptedTokenScript = new EncryptedTokenScript();
    }

    function test_ScriptRun() public {
        encryptedTokenScript.run();

        EncryptedToken encryptedToken = encryptedTokenScript.encryptedToken();
        Groth16Verifier verifier = encryptedTokenScript.verifier();

        EncryptedToken.Commitment memory commitment = encryptedToken.balanceOf(
            address(0)
        );

        assertNotEq(address(encryptedToken), address(0));
        assertNotEq(address(verifier), address(0));
        assertEq(commitment.x, 0);
        assertEq(commitment.y, 0);
    }
}
