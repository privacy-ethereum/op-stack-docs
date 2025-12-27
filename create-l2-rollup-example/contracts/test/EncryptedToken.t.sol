// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/src/Test.sol";
import {CurveBabyJubJub} from "../src/crypto/CurveBabyJubJub.sol";
import {Groth16Verifier} from "../src/crypto/Groth16Verifier.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {EncryptedToken} from "../src/EncryptedToken.sol";
import {PedersenCommitment} from "../src/PedersenCommitment.sol";

contract EncryptedTokenTest is Test {
    EncryptedToken public encryptedToken;
    PedersenCommitment public pedersenCommitment;
    Groth16Verifier public verifier;

    uint256 public constant mintedBalance = 10 ** 18;
    uint256 public constant mintedRandom = 8000;
    uint256[8] public mockProof = [
        14808338865819067265902649274357823880518674989205716253974634754141691280315,
        8522144239604611700153609365961599434046829697672866132043985044825857612382,
        18135013614376051614433202674822696109155411418365115648071244478738908007885,
        150661968183963236783091862771295302829277633439434485112022706085798993441,
        13316111415083222894629873997860431048879797881646704380413222044694735495130,
        11273159173786458810459817514273134881333736202839020222871908403089398812718,
        16334731460207694093742061390056507675128611239336714562040441297691264640369,
        13227029188981242576504387657468892366408659107711387069585387519064247462792
    ];

    address sender = address(0x123);
    address receiver = address(0x456);

    function setUp() public {
        vm.startPrank(sender);

        verifier = new Groth16Verifier();
        encryptedToken = new EncryptedToken(verifier);
        pedersenCommitment = new PedersenCommitment();

        (uint256 x, uint256 y) = pedersenCommitment.commitment(
            mintedBalance,
            mintedRandom
        );
        encryptedToken.mint(sender, EncryptedToken.Commitment(x, y));
    }

    function test_InitialBalance() public view {
        EncryptedToken.Commitment memory commitment = encryptedToken.balanceOf(
            sender
        );

        (uint256 initialX, uint256 initialY) = pedersenCommitment.commitment(
            mintedBalance,
            mintedRandom
        );

        assertEq(initialX, commitment.x);
        assertEq(initialY, commitment.y);
    }

    function test_TransferFailWithZeroReceiver() public {
        vm.expectRevert(
            "InvalidReceiver(0x0000000000000000000000000000000000000000)"
        );

        encryptedToken.transfer(
            address(0),
            EncryptedToken.Commitment(0, 0),
            mockProof
        );
    }

    function test_TransferFailWithInvalidProof() public {
        vm.expectRevert("InvalidProof()");
        uint256[8] memory proof = [
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0)
        ];

        encryptedToken.transfer(
            receiver,
            EncryptedToken.Commitment(0, 0),
            proof
        );
    }

    function test_TransferFailWithInsufficientBalance() public {
        (uint256 x, uint256 y) = pedersenCommitment.commitment(
            mintedBalance + 1,
            9000
        );

        vm.expectRevert("InvalidProof()");

        encryptedToken.transfer(
            receiver,
            EncryptedToken.Commitment(x, y),
            mockProof
        );
    }

    function test_TransferFailWithInvalidCommitment() public {
        vm.expectRevert("InvalidProof()");

        encryptedToken.transfer(
            receiver,
            EncryptedToken.Commitment(0, 0),
            mockProof
        );
    }

    function test_Transfer() public {
        vm.expectEmit(true, true, false, true);
        emit EncryptedToken.Transfer(
            sender,
            receiver,
            0x12f67025d97213656faaa4aef5102babf5bbd6ed8c8ff06797326c077a6e9cf3,
            0x2949d14fcd07b5c583d0fbffad196fdbc275755b40c03e49d4cd5ef4786c4154,
            0x181ad7bb9d75f3801d150602f540489a6eaa83fb7744d348474075c40a946a01,
            0x30061c4c52b0468fd63b005c74606a9da8cb175078b87f8622265b99a37b2d74
        );

        uint256 receiverRandom = 9000;

        (uint256 x, uint256 y) = pedersenCommitment.commitment(
            mintedBalance / 5,
            receiverRandom
        );

        encryptedToken.transfer(
            receiver,
            EncryptedToken.Commitment(x, y),
            mockProof
        );

        EncryptedToken.Commitment memory senderBalance = encryptedToken
            .balanceOf(sender);
        EncryptedToken.Commitment memory receiverBalance = encryptedToken
            .balanceOf(receiver);

        uint256 senderRandom = addmod(
            mintedRandom,
            CurveBabyJubJub.SUBGROUP_ORDER - receiverRandom,
            CurveBabyJubJub.SUBGROUP_ORDER
        );

        (uint256 senderX, uint256 senderY) = pedersenCommitment.commitment(
            mintedBalance - mintedBalance / 5,
            senderRandom
        );

        (uint256 receiverX, uint256 receiverY) = pedersenCommitment.commitment(
            mintedBalance / 5,
            receiverRandom
        );

        assertEq(senderX, senderBalance.x);
        assertEq(senderY, senderBalance.y);
        assertEq(receiverX, receiverBalance.x);
        assertEq(receiverY, receiverBalance.y);
    }
}
