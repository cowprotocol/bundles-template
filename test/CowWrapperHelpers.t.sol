// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapperHelpers} from "../src/CowWrapperHelpers.sol";
import {ICowAuthentication, ICowSettlement} from "../src/CowWrapper.sol";
import {MockCowSettlement, MockCowAuthentication} from "./mocks/MockCowProtocol.sol";

import {EmptyWrapper} from "../src/examples/EmptyWrapper.sol";

contract CowWrapperHelpersTest is Test {
    CowWrapperHelpers helpers;
    MockCowAuthentication wrapperAuth;
    MockCowSettlement mockSettlement;

    EmptyWrapper wrapper1;
    EmptyWrapper wrapper2;
    EmptyWrapper wrapper3;

    uint256 constant TOO_LONG_LENGTH = 65536;

    function setUp() public {
        wrapperAuth = new MockCowAuthentication();
        helpers = new CowWrapperHelpers(ICowAuthentication(address(wrapperAuth)));

        mockSettlement = new MockCowSettlement(address(wrapperAuth));

        // Create mock wrappers
        wrapper1 = new EmptyWrapper(mockSettlement);
        wrapper2 = new EmptyWrapper(mockSettlement);
        wrapper3 = new EmptyWrapper(mockSettlement);

        // Add wrappers as solvers
        wrapperAuth.setSolver(address(wrapper1), true);
        wrapperAuth.setSolver(address(wrapper2), true);
        wrapperAuth.setSolver(address(wrapper3), true);
    }

    function test_verifyAndBuildWrapperData_EmptyArrays() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](0);

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should be empty
        assertEq(result, hex"");
    }

    function test_verifyAndBuildWrapperData_SingleWrapper() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should contain: data[0] only (no settlement appended)
        bytes memory expected = abi.encodePacked(uint16(4), hex"deadbeef");
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_MultipleWrappers() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](3);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({target: address(wrapper2), data: hex"cafebabe12345678"});
        wrapperCalls[2] = CowWrapperHelpers.WrapperCall({target: address(wrapper3), data: hex""});

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should contain: data[0] + target[1] + data[1] + target[2] + data[2] (no settlement)
        bytes memory expected = abi.encodePacked(
            uint16(4),
            hex"deadbeef",
            address(wrapper2),
            uint16(8),
            hex"cafebabe12345678",
            address(wrapper3),
            uint16(0),
            hex""
        );
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperNotAuthorized() public {
        address notAWrapper = makeAddr("notAWrapper");

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: notAWrapper, data: hex""});

        vm.expectRevert(
            abi.encodeWithSelector(
                CowWrapperHelpers.WrapperNotAuthorized.selector, 0, notAWrapper, address(wrapperAuth)
            )
        );
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperNotAuthorized_SecondWrapper() public {
        address notAWrapper = makeAddr("notAWrapper");

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](2);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({target: notAWrapper, data: hex""});

        vm.expectRevert(
            abi.encodeWithSelector(
                CowWrapperHelpers.WrapperNotAuthorized.selector, 1, notAWrapper, address(wrapperAuth)
            )
        );
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperNoCode() public {
        address plainSolver = makeAddr("plain solver");
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: plainSolver, data: hex"deadbeef"});

        wrapperAuth.setSolver(plainSolver, true);

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperHasNoCode.selector, 0, plainSolver));
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataMalformed() public {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});

        bytes memory errorData = hex"feab";
        vm.mockCallRevert(address(wrapper1), abi.encodeWithSelector(wrapper1.validateWrapperData.selector), errorData);

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperDataMalformed.selector, 0, errorData));
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_EmptyWrapperData() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](2);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper3), // Consumes 0 bytes
            data: hex""
        });
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper3), // Consumes 0 bytes
            data: hex""
        });

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should contain: data[0] + target[1] + data[1]
        bytes memory expected = abi.encodePacked(uint16(0), hex"", address(wrapper3), uint16(0), hex"");
        assertEq(result, expected);
    }

    function test_immutableAuthenticator() public view {
        assertEq(address(helpers.WRAPPER_AUTHENTICATOR()), address(wrapperAuth));
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataTooLong_FirstWrapper() public {
        // Create data that's exactly TOO_LONG_LENGTH bytes (exceeds uint16 max of 65535)
        bytes memory tooLongData = new bytes(TOO_LONG_LENGTH);

        // Create a wrapper that consumes all bytes passed to it
        EmptyWrapper largeWrapper = new EmptyWrapper(ICowSettlement(address(mockSettlement)));
        wrapperAuth.setSolver(address(largeWrapper), true);

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(largeWrapper), data: tooLongData});

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperDataTooLong.selector, 0, TOO_LONG_LENGTH));
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataTooLong_SecondWrapper() public {
        // Create data that's exactly TOO_LONG_LENGTH bytes for the second wrapper
        bytes memory tooLongData = new bytes(TOO_LONG_LENGTH);

        // Create a wrapper that consumes all bytes passed to it
        EmptyWrapper largeWrapper = new EmptyWrapper(ICowSettlement(address(mockSettlement)));
        wrapperAuth.setSolver(address(largeWrapper), true);

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](2);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({target: address(largeWrapper), data: tooLongData});

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperDataTooLong.selector, 1, TOO_LONG_LENGTH));
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_SucceedsWithMaxLengthData() public {
        // Create data that's exactly 65535 bytes (max valid uint16)
        bytes memory maxLengthData = new bytes(65535);

        // Create a wrapper that consumes all bytes
        EmptyWrapper largeWrapper = new EmptyWrapper(ICowSettlement(address(mockSettlement)));
        wrapperAuth.setSolver(address(largeWrapper), true);

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(largeWrapper), data: maxLengthData});

        // Should not revert - 65535 is the max valid length
        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Verify the length prefix is correct (first 2 bytes)
        bytes2 lengthPrefix = abi.decode(result, (bytes2));
        assertEq(uint16(lengthPrefix), 65535);
    }
}
