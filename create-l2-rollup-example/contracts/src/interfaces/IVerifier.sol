// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IVerifier
/// @notice an interface for a Groth16 verifier contract
interface IVerifier {
    function verify(
        uint[2] calldata pA,
        uint[2][2] calldata pB,
        uint[2] calldata pC,
        uint[4] calldata pubSignals
    ) external view returns (bool);
}
