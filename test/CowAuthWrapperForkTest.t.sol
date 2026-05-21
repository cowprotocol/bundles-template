// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {IERC1271} from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {CowAuthWrapper, CowAuthLibrary} from "src/CowAuthWrapper.sol";
import {ICowSettlement, ICowAuthentication, ICowWrapper, CowWrapper} from "src/CowWrapper.sol";
import {BasicAuthWrapper, WrapperParams, WRAPPER_PARAMS_TYPE_HASH, WRAPPER_AND_APP_DATA_TYPE_HASH} from
    "src/examples/BasicAuthWrapper.sol";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// Stands in for the real settlement so we control the isValidSignature callback
// without needing real token balances.  Uses the real settlement's domain separator
// and the real mainnet authenticator so the authentication path is exercised.
contract MockSettlement is ICowSettlement {
    ICowAuthentication public immutable authenticator;
    bytes32 public immutable domainSeparator;
    address public vaultRelayer = address(0);

    // Written by the test before each wrappedSettle call.
    address public erc1271Target;
    bytes32 public erc1271Digest;
    bytes public erc1271SigData;
    bool public settleWasCalled;

    constructor(ICowAuthentication auth, bytes32 domSep) {
        authenticator = auth;
        domainSeparator = domSep;
    }

    function setCallback(address target, bytes32 digest, bytes calldata sigData) external {
        erc1271Target = target;
        erc1271Digest = digest;
        erc1271SigData = sigData;
        settleWasCalled = false;
    }

    function settle(
        address[] calldata,
        uint256[] calldata,
        ICowSettlement.Trade[] calldata,
        ICowSettlement.Interaction[][3] calldata
    ) external {
        // Mirrors what GPv2Settlement does for ERC-1271 orders.
        bytes4 magic = IERC1271(erc1271Target).isValidSignature(erc1271Digest, erc1271SigData);
        require(magic == IERC1271.isValidSignature.selector, "isValidSignature returned wrong magic value");
        settleWasCalled = true;
    }

    function setPreSignature(bytes calldata, bool) external {}
}

// ---------------------------------------------------------------------------
// Fork test
// ---------------------------------------------------------------------------

contract CowAuthWrapperForkTest is Test {
    address constant MAINNET_SETTLEMENT = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41;
    address constant MAINNET_AUTHENTICATOR = 0x2c4c28DDBdAc9C5E7055b4C863b72eA0149D8aFE;

    bytes32 constant KIND_SELL = keccak256("sell");
    bytes32 constant BALANCE_ERC20 = keccak256("erc20");

    MockSettlement internal mockSettlement;
    BasicAuthWrapper internal wrapper;

    // Test account that "owns" orders.  Its address also serves as sellToken — see
    // NOTE: OWNER EXTRACTION below.
    uint256 internal ownerKey;
    address internal owner;

    function setUp() public {
        vm.createSelectFork("mainnet");

        ownerKey = uint256(keccak256("cow auth wrapper test owner"));
        owner = vm.addr(ownerKey);

        ICowAuthentication auth = ICowAuthentication(MAINNET_AUTHENTICATOR);
        bytes32 settlementDomSep = ICowSettlement(MAINNET_SETTLEMENT).domainSeparator();

        mockSettlement = new MockSettlement(auth, settlementDomSep);
        wrapper = new BasicAuthWrapper(ICowSettlement(address(mockSettlement)));

        // Register the test contract as a solver so it can call wrappedSettle.
        address manager = _authenticatorManager();
        vm.prank(manager);
        (bool ok,) = MAINNET_AUTHENTICATOR.call(abi.encodeWithSignature("addSolver(address)", address(this)));
        require(ok, "addSolver(test) failed");
    }

    // -----------------------------------------------------------------------
    // Domain separator sanity checks
    // -----------------------------------------------------------------------

    function test_settlementDomainSeparator_matchesWrapper() public view {
        assertEq(
            wrapper.SETTLEMENT_DOMAIN_SEPARATOR(),
            mockSettlement.domainSeparator(),
            "wrapper should cache the settlement domain separator at construction"
        );
    }

    function test_wrapperDomainSeparator_derivedFromWrapperAddress() public view {
        bytes32 expected = CowAuthLibrary.computeDomainSeparator(address(wrapper));
        assertEq(wrapper.WRAPPER_DOMAIN_SEPARATOR(), expected, "wrapper domain separator mismatch");
    }

    function test_domainTypeHash_matchesSpec() public pure {
        bytes32 expected =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        assertEq(CowAuthLibrary.DOMAIN_TYPE_HASH, expected, "DOMAIN_TYPE_HASH mismatch");
    }

    // -----------------------------------------------------------------------
    // End-to-end: pre-approved hash path
    // -----------------------------------------------------------------------

    // NOTE: OWNER EXTRACTION
    // isValidSignature extracts the "owner" as address(bytes20(signatureData[77:97])).
    // signatureData[65:97] is the first 32-byte ABI slot of the order encodeData = sellToken,
    // and [77:97] is the last 20 bytes of that slot (the address value itself).
    // Therefore owner == sellToken.  Both tests set sellToken = owner so that the
    // pre-approved hash check and ECDSA recovery operate on the correct account.
    //
    // NOTE: PRE-APPROVED vs ECDSA BRANCH SELECTION
    // isValidSignature dispatches on signatureData[64] — the v byte of the [r 32][s 32][v 1] sig.
    // v == 0 → pre-approved path; v ∈ {27,28} → ECDSA path.
    // The pre-approved test sends 65 zero bytes for the sig region (v = 0).
    // The ECDSA test sends a real vm.sign output packed as [r][s][v].

    function test_preApprovedHash_endToEnd() public {
        console.log("=== test_preApprovedHash_endToEnd ===");

        // sellToken == owner so isValidSignature's owner extraction resolves to our account.
        address sellToken = owner;
        address buyToken = address(0xBEEF);
        address receiver = address(0xCAFE);
        uint256 sellAmount = 1 ether;
        uint256 buyAmount = 2000e6;
        uint32 validTo = uint32(block.timestamp + 1 hours);
        uint256 feeAmount = 0;

        WrapperParams memory params =
            WrapperParams({target: makeAddr("target"), amount: 42_000e18, label: "my-wrapper-label"});

        console.log("WrapperParams.target:  ", params.target);
        console.log("WrapperParams.amount:  ", uint256(params.amount));
        console.log("WrapperParams.label:   ", params.label);

        bytes32 originalAppData = keccak256("pre-approved-app-data");
        console.log("originalAppData:");
        console.logBytes32(originalAppData);

        (bytes memory wrapperData, bytes32 wrapperParamsHash, bytes32 orderAppDataHash) =
            _buildWrapperData(originalAppData, params);

        console.log("WRAPPER_PARAMS_TYPE_HASH:");
        console.logBytes32(WRAPPER_PARAMS_TYPE_HASH);
        console.log("wrapperParamsHash (EIP-712 struct hash of WrapperParams):");
        console.logBytes32(wrapperParamsHash);
        console.log("orderAppDataHash (WrapperAndAppData struct hash, placed in order appData field):");
        console.logBytes32(orderAppDataHash);

        bytes memory encodeData = _buildEncodeData(sellToken, buyToken, receiver, sellAmount, buyAmount, validTo, orderAppDataHash, feeAmount);
        assertEq(encodeData.length, 384);

        bytes32 settlementDomSep = wrapper.SETTLEMENT_DOMAIN_SEPARATOR();
        bytes32 wrapperDomSep = wrapper.WRAPPER_DOMAIN_SEPARATOR();
        bytes32 settlementOrderDigest = _orderDigest(settlementDomSep, CowAuthLibrary.ORDER_TYPE_HASH, encodeData);
        bytes32 wrapperOrderDigest =
            _orderDigest(wrapperDomSep, wrapper.ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH(), encodeData);

        console.log("settlementOrderDigest:");
        console.logBytes32(settlementOrderDigest);
        console.log("wrapperOrderDigest (what owner pre-approves / signs):");
        console.logBytes32(wrapperOrderDigest);

        vm.prank(owner);
        wrapper.setPreApprovedHash(wrapperOrderDigest, true);
        assertTrue(wrapper.isHashPreApproved(owner, wrapperOrderDigest));

        // v = 0 in the sig region → pre-approved branch.
        bytes memory signatureData = abi.encodePacked(new bytes(65), encodeData);
        assertEq(signatureData.length, 449);

        mockSettlement.setCallback(address(wrapper), settlementOrderDigest, signatureData);

        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (new address[](0), new uint256[](0), new ICowSettlement.Trade[](0), _emptyInteractions())
        );
        bytes memory chainedWrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        bytes4 result = wrapper.wrappedSettle(settleData, chainedWrapperData);

        assertEq(result, ICowWrapper.wrappedSettle.selector);
        assertTrue(mockSettlement.settleWasCalled());
    }

    // -----------------------------------------------------------------------
    // End-to-end: ECDSA signature path
    // -----------------------------------------------------------------------

    function test_ecdsaSignature_endToEnd() public {
        console.log("=== test_ecdsaSignature_endToEnd ===");

        address sellToken = owner;
        address buyToken = address(0xBEEF);
        address receiver = address(0xCAFE);
        uint256 sellAmount = 1 ether;
        uint256 buyAmount = 2000e6;
        uint32 validTo = uint32(block.timestamp + 1 hours);
        uint256 feeAmount = 0;

        WrapperParams memory params =
            WrapperParams({target: makeAddr("target"), amount: 42_000e18, label: "my-wrapper-label"});

        console.log("WrapperParams.target:  ", params.target);
        console.log("WrapperParams.amount:  ", uint256(params.amount));
        console.log("WrapperParams.label:   ", params.label);

        bytes32 originalAppData = keccak256("ecdsa-app-data");
        console.log("originalAppData:");
        console.logBytes32(originalAppData);

        (bytes memory wrapperData, bytes32 wrapperParamsHash, bytes32 orderAppDataHash) =
            _buildWrapperData(originalAppData, params);

        console.log("WRAPPER_PARAMS_TYPE_HASH:");
        console.logBytes32(WRAPPER_PARAMS_TYPE_HASH);
        console.log("wrapperParamsHash (EIP-712 struct hash of WrapperParams):");
        console.logBytes32(wrapperParamsHash);
        console.log("orderAppDataHash (WrapperAndAppData struct hash, placed in order appData field):");
        console.logBytes32(orderAppDataHash);

        bytes memory encodeData = _buildEncodeData(sellToken, buyToken, receiver, sellAmount, buyAmount, validTo, orderAppDataHash, feeAmount);
        assertEq(encodeData.length, 384);

        bytes32 settlementDomSep = wrapper.SETTLEMENT_DOMAIN_SEPARATOR();
        bytes32 wrapperDomSep = wrapper.WRAPPER_DOMAIN_SEPARATOR();
        bytes32 settlementOrderDigest = _orderDigest(settlementDomSep, CowAuthLibrary.ORDER_TYPE_HASH, encodeData);
        bytes32 wrapperOrderDigest =
            _orderDigest(wrapperDomSep, wrapper.ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH(), encodeData);

        console.log("settlementOrderDigest:");
        console.logBytes32(settlementOrderDigest);
        console.log("wrapperOrderDigest (what the owner signs):");
        console.logBytes32(wrapperOrderDigest);

        // Owner signs the wrapper-domain digest.  OZ ECDSA.recoverCalldata reads the sig as [r][s][v].
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, wrapperOrderDigest);
        console.log("owner:  ", owner);
        console.log("sig.v:  ", uint256(v));
        console.log("sig.r:");
        console.logBytes32(r);
        console.log("sig.s:");
        console.logBytes32(s);

        bytes memory ecdsaSig = abi.encodePacked(r, s, v);
        assertEq(ecdsaSig.length, 65);
        // v ∈ {27,28} is never 0, so the ECDSA branch will be taken (not pre-approved).
        assertNotEq(v, 0, "v should be 27 or 28");

        bytes memory signatureData = abi.encodePacked(ecdsaSig, encodeData);
        assertEq(signatureData.length, 449);

        mockSettlement.setCallback(address(wrapper), settlementOrderDigest, signatureData);

        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (new address[](0), new uint256[](0), new ICowSettlement.Trade[](0), _emptyInteractions())
        );
        bytes memory chainedWrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        assertFalse(wrapper.isHashPreApproved(owner, wrapperOrderDigest), "should not be pre-approved");

        bytes4 result = wrapper.wrappedSettle(settleData, chainedWrapperData);

        assertEq(result, ICowWrapper.wrappedSettle.selector);
        assertTrue(mockSettlement.settleWasCalled());
    }

    // -----------------------------------------------------------------------
    // Pre-approved hash: replay protection
    // -----------------------------------------------------------------------

    function test_preApprovedHash_cannotBeConsumedTwice() public {
        bytes32 digest = keccak256("some digest");

        vm.prank(owner);
        wrapper.setPreApprovedHash(digest, true);

        vm.prank(owner);
        wrapper.setPreApprovedHash(digest, false); // sets to CONSUMED

        vm.prank(owner);
        vm.expectRevert();
        wrapper.setPreApprovedHash(digest, true); // must revert: already consumed
    }

    // -----------------------------------------------------------------------
    // Reverts: not a solver
    // -----------------------------------------------------------------------

    function test_wrappedSettle_revertsIfCallerNotSolver() public {
        address nonSolver = makeAddr("nonSolver");
        vm.prank(nonSolver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, nonSolver));
        wrapper.wrappedSettle("", "");
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// @notice Builds the 160-byte wrapperData and derives the two commitment hashes.
    ///
    /// wrapperData layout:
    ///   [0:32]    originalAppData
    ///   [32:64]   WRAPPER_PARAMS_TYPE_HASH
    ///   [64:96]   WrapperParams.target   (address ABI-padded to 32 bytes)
    ///   [96:128]  WrapperParams.amount   (uint128 ABI-padded to 32 bytes)
    ///   [128:160] keccak256(WrapperParams.label as bytes)
    ///
    /// The slice wrapperData[32:] is the EIP-712 struct encoding of WrapperParams, so
    /// keccak256(wrapperData[32:]) == wrapperParamsHash, which is what _wrap stores as
    /// WrapperAndAppData.wrapperData.
    function _buildWrapperData(bytes32 originalAppData, WrapperParams memory params)
        internal
        pure
        returns (bytes memory wrapperData, bytes32 wrapperParamsHash, bytes32 orderAppDataHash)
    {
        bytes memory paramsEncodeData = abi.encode(params.target, uint256(params.amount), keccak256(bytes(params.label)));

        wrapperParamsHash = keccak256(abi.encodePacked(WRAPPER_PARAMS_TYPE_HASH, paramsEncodeData));

        // orderAppDataHash = hashStruct(WrapperAndAppData) — proper EIP-712 with type hash prefix.
        orderAppDataHash = keccak256(abi.encodePacked(WRAPPER_AND_APP_DATA_TYPE_HASH, originalAppData, wrapperParamsHash));

        wrapperData = abi.encodePacked(originalAppData, WRAPPER_PARAMS_TYPE_HASH, paramsEncodeData);
    }

    function _buildEncodeData(
        address sellToken,
        address buyToken,
        address receiver,
        uint256 sellAmount,
        uint256 buyAmount,
        uint32 validTo,
        bytes32 orderAppDataHash,
        uint256 feeAmount
    ) internal pure returns (bytes memory) {
        return abi.encode(
            sellToken,
            buyToken,
            receiver,
            sellAmount,
            buyAmount,
            validTo,
            orderAppDataHash,
            feeAmount,
            KIND_SELL,
            false,
            BALANCE_ERC20,
            BALANCE_ERC20
        );
    }

    function _orderDigest(bytes32 domainSeparator, bytes32 typeHash, bytes memory encodeData)
        internal
        pure
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encodePacked(typeHash, encodeData));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _authenticatorManager() internal returns (address) {
        (bool ok, bytes memory data) = MAINNET_AUTHENTICATOR.call(abi.encodeWithSignature("manager()"));
        require(ok, "manager() call failed");
        return abi.decode(data, (address));
    }

    function _emptyInteractions() internal pure returns (ICowSettlement.Interaction[][3] memory) {}
}
