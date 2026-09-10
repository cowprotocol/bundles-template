// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {IERC1271} from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {IERC165} from "openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
import {ICowAuthWrapper} from "src/CowAuthWrapper.sol";
import {ICowSettlement} from "src/CowWrapper.sol";
import {PreApprovedHashes} from "src/PreApprovedHashes.sol";
import {BasicAuthWrapper, WrapperParams} from "src/examples/BasicAuthWrapper.sol";
import {MockCowAuthentication, MockCowSettlement} from "test/mocks/MockCowProtocol.sol";

/// @notice Fork-free unit tests for the view surface and helpers that the end-to-end fork tests don't
///         exercise: ERC-165 advertisement, the example wrapper's getters/validation, and the
///         `PreApprovedHashes` consume path (currently unused by the auth flow — see the wrapper docs).
contract CowAuthWrapperUnitTest is Test {
    BasicAuthWrapper internal wrapper;

    function setUp() public {
        MockCowAuthentication auth = new MockCowAuthentication();
        MockCowSettlement settlement = new MockCowSettlement(address(auth));
        wrapper = new BasicAuthWrapper(ICowSettlement(address(settlement)));
    }

    // -----------------------------------------------------------------------
    // ERC-165
    // -----------------------------------------------------------------------

    function test_supportsInterface_advertisesAuthWrapperInterfaces() public view {
        assertTrue(wrapper.supportsInterface(type(ICowAuthWrapper).interfaceId), "ICowAuthWrapper");
        assertTrue(wrapper.supportsInterface(type(IERC1271).interfaceId), "IERC1271");
        assertTrue(wrapper.supportsInterface(type(IERC165).interfaceId), "IERC165");
    }

    function test_supportsInterface_rejectsUnknownInterface() public view {
        assertFalse(wrapper.supportsInterface(0xffffffff), "unknown interface must be false");
    }

    // -----------------------------------------------------------------------
    // Example wrapper getters / validation
    // -----------------------------------------------------------------------

    function test_name() public view {
        assertEq(wrapper.name(), "Basic Auth Demo Wrapper");
    }

    function test_validateWrapperData_acceptsWellFormedData() public view {
        WrapperParams memory params = WrapperParams({target: address(0xABCD), amount: 1, label: "ok"});
        // nestedAppData(32) ‖ orderData(384) ‖ signature(65) ‖ abi.encode(params)
        bytes memory data = abi.encodePacked(bytes32("nested"), new bytes(384), new bytes(65), abi.encode(params));
        wrapper.validateWrapperData(data); // must not revert
    }

    function test_validateWrapperData_revertsWhenTooShort() public {
        vm.expectRevert(bytes("wrapperData too short"));
        wrapper.validateWrapperData(new bytes(480)); // < 32 + 384 + 65
    }

    // -----------------------------------------------------------------------
    // PreApprovedHashes._consumePreApprovedHash (via harness)
    // -----------------------------------------------------------------------

    function test_consumePreApprovedHash_consumesApprovedHashOnce() public {
        PreApprovedHashesHarness h = new PreApprovedHashesHarness();
        bytes32 hash = keccak256("op");

        h.setPreApprovedHash(hash, true); // msg.sender == address(this) becomes the owner
        assertTrue(h.isHashPreApproved(address(this), hash));

        vm.expectEmit(true, true, false, false);
        emit PreApprovedHashes.PreApprovedHashConsumed(address(this), hash);
        h.consume(address(this), hash);

        assertFalse(h.isHashPreApproved(address(this), hash), "must be consumed");
    }

    function test_consumePreApprovedHash_revertsIfAlreadyConsumed() public {
        PreApprovedHashesHarness h = new PreApprovedHashesHarness();
        bytes32 hash = keccak256("op");

        h.setPreApprovedHash(hash, true);
        h.consume(address(this), hash);

        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.AlreadyConsumed.selector, address(this), hash));
        h.consume(address(this), hash);
    }

    function test_consumePreApprovedHash_revertsIfNeverApproved() public {
        PreApprovedHashesHarness h = new PreApprovedHashesHarness();
        bytes32 hash = keccak256("never");

        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.HashNotApproved.selector, address(this), hash));
        h.consume(address(this), hash);
    }
}

/// @dev Exposes the internal `_consumePreApprovedHash` for direct testing.
contract PreApprovedHashesHarness is PreApprovedHashes {
    function consume(address owner, bytes32 hash) external {
        _consumePreApprovedHash(owner, hash);
    }
}
