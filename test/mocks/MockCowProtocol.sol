// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {ICowSettlement, ICowAuthentication} from "../../../src/CowWrapper.sol";

import {Address} from "openzeppelin-contracts/contracts/utils/Address.sol";

/// @title MockCowAuthentication
/// @notice Mock implementation of CoW Protocol authenticator for unit testing
contract MockCowAuthentication is ICowAuthentication {
    mapping(address => bool) public solvers;

    function setSolver(address solver, bool authorized) external {
        solvers[solver] = authorized;
    }

    function isSolver(address prospectiveSolver) external view override returns (bool) {
        return solvers[prospectiveSolver];
    }
}

/// @title MockCowSettlement
/// @notice Mock implementation of CoW Protocol settlement contract for unit testing
contract MockCowSettlement is ICowSettlement {
    ICowAuthentication public immutable AUTH;
    mapping(bytes => bool) public preSignatures;

    constructor(address _auth) {
        AUTH = ICowAuthentication(_auth);
    }

    function authenticator() external view override returns (ICowAuthentication) {
        return AUTH;
    }

    function vaultRelayer() external pure override returns (address) {
        return address(0x7777);
    }

    function domainSeparator() external pure override returns (bytes32) {
        return keccak256("MockDomainSeparator");
    }

    function setPreSignature(bytes calldata orderUid, bool approved) external override {
        preSignatures[orderUid] = approved;
    }

    function settle(address[] calldata, uint256[] calldata, Trade[] calldata, Interaction[][3] calldata interactions)
        external
        override
    {
        for (uint256 i = 0; i < interactions.length; i++) {
            for (uint256 j = 0; j < interactions[i].length; j++) {
                Address.functionCall(interactions[i][j].target, interactions[i][j].callData);
            }
        }
    }
}
