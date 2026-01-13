// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "../interfaces/IVerifier.sol";

contract Groth16Verifier is IVerifier {
    // Scalar field size
    uint256 constant r =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant ALPHAX =
        20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant ALPHAY =
        9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant BETAX1 =
        4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant BETAX2 =
        6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant BETAY1 =
        21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant BETAY2 =
        10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant GAMMAX1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant GAMMAX2 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant GAMMAY1 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant GAMMAY2 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant DELTAX1 =
        11300405183057063091390836851838211185795710383741912992316374276486225698479;
    uint256 constant DELTAX2 =
        14996273819475395061889105946695697563114469118261282863561085423002951780040;
    uint256 constant DELTAY1 =
        4530241920287288351322239127843874649604400229061407553124343460056881339229;
    uint256 constant DELTAY2 =
        9749051416559979786530139549965730684360833878095697447606552807281667831088;

    uint256 constant IC0X =
        2742789814675992181170661755665092301231699222952347858672529814979792752642;
    uint256 constant IC0Y =
        9113111010571022005218396134916023666589519766632789911292961930181507075541;

    uint256 constant IC1X =
        18940903541684515578482897011774834247107551670069345278147540587549213378388;
    uint256 constant IC1Y =
        3914048611171287634291558330809562873553356486072505752634055186475393364509;

    uint256 constant IC2X =
        1473706520647333981431445834915145812867520706063767051704404577680101242479;
    uint256 constant IC2Y =
        9675645776882113260983516336925707269946803969181974258543681931726399809411;

    uint256 constant IC3X =
        4948029366178289985532090605134088372776390438363887409295360026682267819276;
    uint256 constant IC3Y =
        12069700458561479723571388493170984678298796197765322299171714245711958232793;

    uint256 constant IC4X =
        19760383193391934735757636960000783372682862777750188587538324459513798002438;
    uint256 constant IC4Y =
        8953730018999226235779854394270840221809211763071731024679265272745461325300;

    // Memory data
    uint16 constant P_VK = 0;
    uint16 constant P_PAIRING = 128;

    uint16 constant P_LAST_MEM = 896;

    function verify(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[4] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, P_PAIRING)
                let _pVk := add(pMem, P_VK)

                mstore(_pVk, IC0X)
                mstore(add(_pVk, 32), IC0Y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1X, IC1Y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2X, IC2Y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3X, IC3Y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4X, IC4Y, calldataload(add(pubSignals, 96)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(
                    add(_pPairing, 32),
                    mod(sub(q, calldataload(add(pA, 32))), q)
                )

                // B
                mstore(add(_pPairing, 64), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 96), calldataload(pB))
                mstore(add(_pPairing, 128), calldataload(add(pB, 96)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 64)))

                // alpha1
                mstore(add(_pPairing, 192), ALPHAX)
                mstore(add(_pPairing, 224), ALPHAY)

                // beta2
                mstore(add(_pPairing, 256), BETAX1)
                mstore(add(_pPairing, 288), BETAX2)
                mstore(add(_pPairing, 320), BETAY1)
                mstore(add(_pPairing, 352), BETAY2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, P_VK)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(P_VK, 32))))

                // gamma2
                mstore(add(_pPairing, 448), GAMMAX1)
                mstore(add(_pPairing, 480), GAMMAX2)
                mstore(add(_pPairing, 512), GAMMAY1)
                mstore(add(_pPairing, 544), GAMMAY2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), DELTAX1)
                mstore(add(_pPairing, 672), DELTAX2)
                mstore(add(_pPairing, 704), DELTAY1)
                mstore(add(_pPairing, 736), DELTAY2)

                let success := staticcall(
                    sub(gas(), 2000),
                    8,
                    _pPairing,
                    768,
                    _pPairing,
                    0x20
                )

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, P_LAST_MEM))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
