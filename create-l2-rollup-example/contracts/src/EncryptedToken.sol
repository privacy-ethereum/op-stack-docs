// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin-contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {CurveBabyJubJub} from "./crypto/CurveBabyJubJub.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";

/**
 * @title EncryptedToken
 * @author 0xmad
 * @notice A token contract where balances are represented as cryptographic commitments on the Baby JubJub elliptic curve.
 * @dev This contract allows minting, transferring, and querying balances using elliptic curve commitments instead of uint256 values.
 */
contract EncryptedToken {
    /**
     * @notice Represents a cryptographic balance as a point on the Baby JubJub curve
     */
    struct Commitment {
        uint256 x;
        uint256 y;
    }

    /**
     * @notice Groth16 Verifier contract
     */
    IVerifier private verifier;

    /**
     * @notice Maps account addresses to their cryptographic balance commitments
     */
    mapping(address => Commitment) private _balances;

    /**
     * @notice Emitted when a transfer of cryptographic commitments occurs between accounts
     * @dev Each balance is represented as a point on the Baby JubJub curve
     * @param from The sender address
     * @param to The recipient address
     * @param senderX The x-coordinate of the sender's commitment after the transfer
     * @param senderY The y-coordinate of the sender's commitment after the transfer
     * @param receiverX The x-coordinate of the recipient's commitment after the transfer
     * @param receiverY The y-coordinate of the recipient's commitment after the transfer
     */
    event Transfer(
        address indexed from,
        address indexed to,
        uint256 senderX,
        uint256 senderY,
        uint256 receiverX,
        uint256 receiverY
    );

    /**
     * @dev Indicates an error related to the current proof verification for transfer.
     */
    error InvalidProof();

    /**
     * @dev Indicates a failure with the token `receiver`. Used in transfers.
     * @param receiver Address to which tokens are being transferred.
     */
    error InvalidReceiver(address receiver);

    /**
     * Initialization for token
     * @param _verifier Groth16 Verifier contract
     */
    constructor(IVerifier _verifier) {
        verifier = _verifier;
    }

    /**
     * @notice Mints tokens by setting the commitment of an account
     * @param account The account to receive the minted tokens
     * @param commitment The cryptographic commitment representing the balance
     */
    function mint(address account, Commitment memory commitment) public {
        // TODO: need to add proof of burn for zk-wormholes integration
        // TODO: integrate with ERC20/native tokens
        _updateBalance(account, commitment.x, commitment.y);
    }

    /**
     * @notice Returns the current cryptographic balance commitment of an account
     * @param account The address to query
     * @return commitment The commitment representing the account's balance
     */
    function balanceOf(
        address account
    ) public view virtual returns (Commitment memory commitment) {
        return _balances[account];
    }

    /**
     * @notice Transfers a cryptographic token commitment to another account
     * @dev Updates both sender and recipient balances using elliptic curve point addition/subtraction
     * @param to The recipient address
     * @param commitment The commitment to transfer
     */
    function transfer(
        address to,
        Commitment calldata commitment,
        uint[8] calldata proof
    ) external {
        if (to == address(0)) {
            revert InvalidReceiver(address(0));
        }

        // verify balance is greater or equal to zero
        Commitment memory previousReceiverCommitment = _balances[to];
        Commitment memory previousSenderCommitment = _balances[msg.sender];

        bool isValid = verifier.verify(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            [
                commitment.x,
                commitment.y,
                previousSenderCommitment.x,
                previousSenderCommitment.y
            ]
        );

        if (!isValid) {
            revert InvalidProof();
        }

        (uint256 newReceiverX, uint256 newReceiverY) = CurveBabyJubJub.pointAdd(
            previousReceiverCommitment.x,
            previousReceiverCommitment.y,
            commitment.x,
            commitment.y
        );
        _updateBalance(to, newReceiverX, newReceiverY);

        (uint256 newSenderX, uint256 newSenderY) = CurveBabyJubJub.pointSub(
            previousSenderCommitment.x,
            previousSenderCommitment.y,
            commitment.x,
            commitment.y
        );
        _updateBalance(msg.sender, newSenderX, newSenderY);

        emit Transfer(
            msg.sender,
            to,
            newSenderX,
            newSenderY,
            newReceiverX,
            newReceiverY
        );
    }

    /**
     * @dev Updates the balance commitment for a given account
     * @param account The account to update
     * @param x The new commitment x-coordinate to set
     * @param y The new commitment x-coordinate to set
     */
    function _updateBalance(address account, uint256 x, uint256 y) private {
        Commitment memory commitment = Commitment(x, y);
        _balances[account] = commitment;
    }
}
