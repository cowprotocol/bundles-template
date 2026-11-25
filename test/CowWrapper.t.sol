// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {CowWrapper, ICowAuthentication, ICowSettlement, ICowWrapper} from "../src/CowWrapper.sol";
import {Test} from "forge-std/Test.sol";

import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";

import {CowWrapperHelpers} from "../src/CowWrapperHelpers.sol";

import {EmptyWrapper} from "../src/examples/EmptyWrapper.sol";

contract CowWrapperTest is Test {
    MockCowAuthentication public authenticator;
    MockCowSettlement public mockSettlement;
    CowWrapperHelpers public helpers;
    address public solver;

    EmptyWrapper private wrapper1;
    EmptyWrapper private wrapper2;
    EmptyWrapper private wrapper3;

    error TestRevert();

    function setUp() public {
        // Deploy mock contracts
        authenticator = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(authenticator));
        helpers = new CowWrapperHelpers(ICowAuthentication(address(authenticator)));

        solver = makeAddr("solver");
        // Add solver to the authenticator
        authenticator.setSolver(solver, true);

        // Create test wrappers
        wrapper1 = new EmptyWrapper(ICowSettlement(address(mockSettlement)));
        wrapper2 = new EmptyWrapper(ICowSettlement(address(mockSettlement)));
        wrapper3 = new EmptyWrapper(ICowSettlement(address(mockSettlement)));

        // Add all wrappers as solvers
        authenticator.setSolver(address(wrapper1), true);
        authenticator.setSolver(address(wrapper2), true);
        authenticator.setSolver(address(wrapper3), true);
    }

    function _emptyInteractions() private pure returns (ICowSettlement.Interaction[][3] memory) {
        return
            [
                new ICowSettlement.Interaction[](0),
                new ICowSettlement.Interaction[](0),
                new ICowSettlement.Interaction[](0)
            ];
    }

    function _createSimpleSettleData(uint256 tokenCount) private returns (bytes memory) {
        address[] memory tokens = new address[](tokenCount);
        uint256[] memory clearingPrices = new uint256[](tokenCount);
        for (uint256 i = 0; i < tokenCount; i++) {
            tokens[i] = makeAddr(string(abi.encodePacked("Settle Token #", vm.toString(i + 1))));
            clearingPrices[i] = 100 * (i + 1);
        }
        return abi.encodeCall(
            ICowSettlement.settle, (tokens, clearingPrices, new ICowSettlement.Trade[](0), _emptyInteractions())
        );
    }

    function test_next_CallsWrapperAndThenNextSettlement() public {
        bytes memory settleData = abi.encodePacked(_createSimpleSettleData(1), hex"123456");
        bytes memory secondCallWrapperData = abi.encodePacked(uint16(3), hex"098765");
        bytes memory wrapperData = abi.encodePacked(uint16(2), hex"1234", address(wrapper1), secondCallWrapperData);

        // verify the external wrapper call data
        vm.expectCall(address(wrapper1), abi.encodeCall(ICowWrapper.wrappedSettle, (settleData, wrapperData)));

        // verify the internal wrapper call data
        vm.expectCall(address(wrapper1), abi.encodeCall(wrapper1.wrappedSettle, (settleData, secondCallWrapperData)));

        // the settlement contract gets called once after wrappers (including the surplus data at the end)
        vm.expectCall(address(mockSettlement), 0, settleData, 1);

        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_next_RevertsWhenNextWrapperReturnsIncorrectMagic() public {
        bytes memory settleData = abi.encodePacked(_createSimpleSettleData(1), hex"");
        bytes memory secondCallWrapperData = abi.encodePacked(uint16(3), hex"098765");
        bytes memory wrapperData = abi.encodePacked(uint16(2), hex"1234", address(wrapper2), secondCallWrapperData);

        // There are a few edge cases so test in succession. To reduce code duplication its easiest to run them all here.
        // Unfortunately its not possible to set explanation text in `expectRevert`, so use the trace to identify the failing case.
        vm.startPrank(solver);

        // Mock no calldata returned
        vm.mockCall(
            address(wrapper2),
            ICowWrapper.wrappedSettle.selector,
            "" // Not going to be the expected magic value
        );
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.InvalidNextWrapper.selector, address(wrapper2)));
        wrapper1.wrappedSettle(settleData, wrapperData);

        // Mock incorrect bytes4 calldata returned
        vm.mockCall(
            address(wrapper2),
            ICowWrapper.wrappedSettle.selector,
            "0x12341234" // Same length but not going to be the expected magic value
        );
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.InvalidNextWrapper.selector, address(wrapper2)));
        wrapper1.wrappedSettle(settleData, wrapperData);

        // Mock too long calldata returned + correct first 4 bytes
        vm.mockCall(
            address(wrapper2),
            ICowWrapper.wrappedSettle.selector,
            abi.encodePacked(ICowWrapper.wrappedSettle.selector, "foobar") // Has magic value for the first 4 bytes, but not after
        );
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.InvalidNextWrapper.selector, address(wrapper2)));
        wrapper1.wrappedSettle(settleData, wrapperData);

        // Last call should not revert (sanity)
        vm.mockCall(
            address(wrapper2),
            ICowWrapper.wrappedSettle.selector,
            abi.encode(ICowWrapper.wrappedSettle.selector) // Correct magic
        );
        wrapper1.wrappedSettle(settleData, wrapperData);
        vm.stopPrank();
    }

    function test_next_BubblesNestedWrapCallRevrt() public {
        bytes memory settleData = abi.encodePacked(_createSimpleSettleData(1), hex"");
        bytes memory secondCallWrapperData = abi.encodePacked(uint16(3), hex"098765");
        bytes memory wrapperData = abi.encodePacked(uint16(2), hex"1234", address(wrapper2), secondCallWrapperData);

        // Mock wrapper2 to return incorrect value
        vm.mockCallRevert(
            address(wrapper2), ICowWrapper.wrappedSettle.selector, abi.encodeWithSelector(TestRevert.selector)
        );

        vm.expectRevert(abi.encodeWithSelector(TestRevert.selector));
        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsWithNotASolver() public {
        bytes memory settleData = _createSimpleSettleData(0);
        address notASolver = makeAddr("notASolver");

        // Should revert when called by non-solver
        vm.prank(notASolver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, notASolver));
        wrapper1.wrappedSettle(settleData, hex"");
    }

    function test_wrappedSettle_RevertsOnInvalidSettleSelector() public {
        bytes memory settleData = abi.encodePacked(bytes4(0xdeadbeef), hex"1234");
        bytes memory wrapperData = hex"0000"; // Empty wrapper data, goes straight to settlement
        vm.prank(solver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.InvalidSettleData.selector, settleData));
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_integration_ThreeWrappersChained() public {
        address[] memory tokens = new address[](2);
        tokens[0] = address(0x1);
        tokens[1] = address(0x2);

        uint256[] memory clearingPrices = new uint256[](2);
        clearingPrices[0] = 100;
        clearingPrices[1] = 200;

        ICowSettlement.Trade[] memory trades = new ICowSettlement.Trade[](1);
        trades[0] = ICowSettlement.Trade({
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            receiver: address(0x123),
            sellAmount: 1000,
            buyAmount: 900,
            validTo: uint32(block.timestamp + 1000),
            appData: bytes32(uint256(1)),
            feeAmount: 10,
            flags: 0,
            executedAmount: 0,
            signature: hex"aabbccddee"
        });

        bytes memory settleData =
            abi.encodeCall(ICowSettlement.settle, (tokens, clearingPrices, trades, _emptyInteractions()));

        // Build the chained wrapper data:
        // solver -> wrapper1 -> wrapper2 -> wrapper1 -> wrapper3 -> mockSettlement
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](4);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex""});
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({target: address(wrapper2), data: hex""});
        wrapperCalls[2] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"828348"});
        wrapperCalls[3] = CowWrapperHelpers.WrapperCall({target: address(wrapper3), data: hex""});

        bytes memory wrapperData = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // all the wrappers gets called, with wrapper 1 called twice
        vm.expectCall(address(wrapper1), 0, abi.encodePacked(ICowWrapper.wrappedSettle.selector), 2);
        vm.expectCall(address(wrapper2), 0, abi.encodePacked(ICowWrapper.wrappedSettle.selector), 1);
        vm.expectCall(address(wrapper3), 0, abi.encodePacked(ICowWrapper.wrappedSettle.selector), 1);

        // the settlement gets called with the full data
        vm.expectCall(address(mockSettlement), new bytes(0));

        // Call wrapper1 as the solver
        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsOnZeroLengthWrapperData() public {
        bytes memory settleData = _createSimpleSettleData(0);
        bytes memory wrapperData = hex""; // Completely empty wrapper data

        vm.prank(solver);
        vm.expectRevert(); // Should revert with out-of-bounds array access
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsOnOneByteWrapperData() public {
        bytes memory settleData = _createSimpleSettleData(0);
        bytes memory wrapperData = hex"01"; // Only 1 byte - not enough to read the 2-byte length

        vm.prank(solver);
        vm.expectRevert(); // Should revert with out-of-bounds array access
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_SucceedsWithZeroLengthIndicator() public {
        bytes memory settleData = _createSimpleSettleData(0);
        bytes memory wrapperData = hex"0000"; // 2 bytes indicating 0-length wrapper data

        // Should call settlement directly with no wrapper-specific data
        vm.expectCall(address(mockSettlement), 0, settleData, 1);

        vm.prank(solver);
        require(
            wrapper1.wrappedSettle(settleData, wrapperData) == ICowWrapper.wrappedSettle.selector,
            "Expected return selector"
        );
    }

    function test_wrappedSettle_SucceedsWithMaximumLengthWrapperData() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Create maximum length wrapper data (65535 bytes)
        // Format: [2-byte length = 0xFFFF][65535 bytes of data]
        bytes memory maxData = new bytes(65_535);
        for (uint256 i = 0; i < 65_535; i++) {
            // casting to 'uint8' is safe because its already being truncated ty less than the maximum value by the modulo
            // forge-lint: disable-next-line(unsafe-typecast)
            maxData[i] = bytes1(uint8(i % 256));
        }

        bytes memory wrapperData = abi.encodePacked(uint16(65_535), maxData);

        // Should successfully parse the maximum length data and call settlement
        vm.expectCall(address(mockSettlement), 0, settleData, 1);

        vm.prank(solver);
        require(
            wrapper1.wrappedSettle(settleData, wrapperData) == ICowWrapper.wrappedSettle.selector,
            "Expected return selector"
        );
    }

    function test_wrappedSettle_RevertsWhenDataShorterThanIndicated() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Wrapper data claims to be 100 bytes but only provides 50
        bytes memory shortData = new bytes(50);
        bytes memory wrapperData = abi.encodePacked(uint16(100), shortData);

        vm.prank(solver);
        vm.expectRevert(); // Should revert with out-of-bounds array access
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_SucceedsWithMaxLengthAndNextWrapper() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Create maximum length wrapper data followed by next wrapper address
        bytes memory maxData = new bytes(65_535);
        for (uint256 i = 0; i < 65_535; i++) {
            // casting to 'uint8' is safe because its already being truncated ty less than the maximum value by the modulo
            // forge-lint: disable-next-line(unsafe-typecast)
            maxData[i] = bytes1(uint8(i % 256));
        }

        // Format: [2-byte length = 0xFFFF][65535 bytes of data][20-byte next wrapper address][remaining data]
        bytes memory nextWrapperData = hex"00030000FF"; // 3 bytes of data for next wrapper
        bytes memory wrapperData = abi.encodePacked(type(uint16).max, maxData, address(wrapper2), nextWrapperData);

        // Should call wrapper2 with the remaining data
        vm.expectCall(address(wrapper2), 0, abi.encodePacked(ICowWrapper.wrappedSettle.selector), 1);

        vm.prank(solver);
        require(
            wrapper1.wrappedSettle(settleData, wrapperData) == ICowWrapper.wrappedSettle.selector,
            "Expected return selector"
        );
    }

    function test_wrappedSettle_RevertsWithInsufficientLengthData() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Format: [1-byte length = 1 (insufficient)]
        bytes memory wrapperData = hex"01";

        vm.expectRevert(new bytes(0));
        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsWithInsufficientCallData() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Format: [2-byte length = 0xa][9 bytes of data (insufficient)]
        bytes memory wrapperData = hex"000A123412341234123412";

        vm.expectRevert(new bytes(0));
        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }
}
