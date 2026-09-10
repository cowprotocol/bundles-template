// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {IERC1271} from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {CowAuthLibrary, CowAuthWrapper} from "src/CowAuthWrapper.sol";
import {CowWrapper, ICowAuthentication, ICowSettlement, ICowWrapper} from "src/CowWrapper.sol";
import {
    BasicAuthWrapper,
    WRAPPER_AND_APP_DATA_TYPE_HASH,
    WRAPPER_PARAMS_TYPE_HASH,
    WrapperParams
} from "src/examples/BasicAuthWrapper.sol";

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

    // Auto-generated getter matches ICowSettlement.filledAmount(bytes).
    mapping(bytes => uint256) public filledAmount;

    // Written by the test before each wrappedSettle call.
    address public erc1271Target;
    bytes32 public erc1271Digest;
    bytes public erc1271SigData;
    uint32 public erc1271ValidTo;
    bool public settleWasCalled;
    // When true (default), `settle` records a fill for the order's uid so the wrapper's post-settle
    // `filledAmount` check passes. Set false to simulate a settlement that never fills the order.
    bool public fillOrder = true;

    constructor(ICowAuthentication auth, bytes32 domSep) {
        authenticator = auth;
        domainSeparator = domSep;
    }

    function setCallback(address target, bytes32 digest, bytes calldata sigData, uint32 validTo) external {
        erc1271Target = target;
        erc1271Digest = digest;
        erc1271SigData = sigData;
        erc1271ValidTo = validTo;
        settleWasCalled = false;
    }

    function setFillOrder(bool value) external {
        fillOrder = value;
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

        // Simulate GPv2 recording the fill for this order's uid (orderDigest ‖ owner ‖ validTo), where the
        // owner is the EIP-1271 verifier (the wrapper). The wrapper reads this to confirm the order settled.
        if (fillOrder) {
            bytes memory orderUid = abi.encodePacked(erc1271Digest, erc1271Target, erc1271ValidTo);
            filledAmount[orderUid] += 1 ether;
        }
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
        vm.createSelectFork(vm.envString("FORK_RPC_URL"));

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
    // BasicAuthWrapper uses the default _authorizingOwner, which reads the owner as the sell token (word 0
    // of the order data now carried in wrapperData). Both tests set sellToken = owner so that the
    // pre-approved hash check and ECDSA recovery operate on the correct account.
    //
    // NOTE: PRE-APPROVED vs ECDSA BRANCH SELECTION
    // The owner authorization is now verified in `_wrap` (not `isValidSignature`), reading the 65-byte
    // signature carried in wrapperData at `[416:481]`. `_commitOrder` dispatches on signature[64] — the v
    // byte of the [r 32][s 32][v 1] sig. v == 0 → pre-approved path; v ∈ {27,28} → ECDSA path.
    // The pre-approved test embeds 65 zero bytes for the sig region (v = 0).
    // The ECDSA test embeds a real vm.sign output packed as [r][s][v].
    // The EIP-1271 signatureData GPv2 forwards to `isValidSignature` is unused, so the mock is primed with
    // an empty sig payload.

    /// @dev Empty settle calldata; the mock drives the isValidSignature callback via `setCallback`.
    function _emptySettleData() internal pure returns (bytes memory) {
        return abi.encodeCall(
            ICowSettlement.settle,
            (new address[](0), new uint256[](0), new ICowSettlement.Trade[](0), _emptyInteractions())
        );
    }

    function test_preApprovedHash_endToEnd() public {
        // sellToken == owner so BasicAuthWrapper's default _authorizingOwner resolves to our account.
        WrapperParams memory params =
            WrapperParams({target: makeAddr("target"), amount: 42_000e18, label: "my-wrapper-label"});
        bytes32 nestedAppData = keccak256("pre-approved-app-data");
        (, bytes32 orderAppData) = _appDataHashes(nestedAppData, params);

        uint32 validTo = uint32(block.timestamp + 1 hours);
        bytes memory orderData =
            _buildEncodeData(owner, address(0xBEEF), address(0xCAFE), 1 ether, 2000e6, validTo, orderAppData, 0);
        assertEq(orderData.length, 384);

        bytes32 settlementOrderDigest =
            _orderDigest(wrapper.SETTLEMENT_DOMAIN_SEPARATOR(), CowAuthLibrary.ORDER_TYPE_HASH, orderData);
        bytes32 wrapperOrderDigest = _orderDigest(
            wrapper.WRAPPER_DOMAIN_SEPARATOR(), wrapper.ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH(), orderData
        );

        vm.prank(owner);
        wrapper.setPreApprovedHash(wrapperOrderDigest, true);
        assertTrue(wrapper.isHashPreApproved(owner, wrapperOrderDigest));

        // The order data AND the 65-byte sig region (v = 0 → pre-approved branch) now travel in wrapperData;
        // the EIP-1271 signatureData GPv2 forwards is unused.
        mockSettlement.setCallback(address(wrapper), settlementOrderDigest, hex"", validTo);

        bytes4 result = wrapper.wrappedSettle(
            _emptySettleData(), _chained(_buildWrapperData(nestedAppData, orderData, new bytes(65), params))
        );

        assertEq(result, ICowWrapper.wrappedSettle.selector);
        assertTrue(mockSettlement.settleWasCalled());
    }

    // -----------------------------------------------------------------------
    // End-to-end: ECDSA signature path
    // -----------------------------------------------------------------------

    function test_ecdsaSignature_endToEnd() public {
        WrapperParams memory params =
            WrapperParams({target: makeAddr("target"), amount: 42_000e18, label: "my-wrapper-label"});
        bytes32 nestedAppData = keccak256("ecdsa-app-data");
        uint32 validTo = uint32(block.timestamp + 1 hours);

        bytes memory orderData;
        {
            (, bytes32 orderAppData) = _appDataHashes(nestedAppData, params);
            orderData =
                _buildEncodeData(owner, address(0xBEEF), address(0xCAFE), 1 ether, 2000e6, validTo, orderAppData, 0);
        }

        // Owner signs the wrapper-domain digest. OZ ECDSA.recoverCalldata reads the sig as [r][s][v]. The
        // signature is carried in wrapperData and verified in `_wrap`. Scoped so the signing locals are freed.
        bytes memory wrapperData;
        {
            bytes32 wrapperOrderDigest = _orderDigest(
                wrapper.WRAPPER_DOMAIN_SEPARATOR(), wrapper.ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH(), orderData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, wrapperOrderDigest);
            assertNotEq(v, 0, "v should be 27 or 28"); // v != 0 → ECDSA branch, not pre-approved
            assertFalse(wrapper.isHashPreApproved(owner, wrapperOrderDigest), "should not be pre-approved");
            wrapperData = _buildWrapperData(nestedAppData, orderData, abi.encodePacked(r, s, v), params);
        }

        mockSettlement.setCallback(
            address(wrapper),
            _orderDigest(wrapper.SETTLEMENT_DOMAIN_SEPARATOR(), CowAuthLibrary.ORDER_TYPE_HASH, orderData),
            hex"",
            validTo
        );

        bytes4 result = wrapper.wrappedSettle(_emptySettleData(), _chained(wrapperData));

        assertEq(result, ICowWrapper.wrappedSettle.selector);
        assertTrue(mockSettlement.settleWasCalled());
    }

    // -----------------------------------------------------------------------
    // Reverts: order validation in _wrap / isValidSignature
    // -----------------------------------------------------------------------

    /// @dev Builds a fully valid ECDSA-signed order and primes the mock's callback. Returns the pieces the
    ///      revert tests need so each can perturb exactly one thing.
    function _buildValidEcdsaOrder()
        internal
        returns (bytes memory settleData, bytes memory wrapperData, bytes32 settlementOrderDigest, uint32 validTo)
    {
        address sellToken = owner; // default _authorizingOwner reads the sell token as the authorizer
        validTo = uint32(block.timestamp + 1 hours);

        WrapperParams memory params =
            WrapperParams({target: makeAddr("target"), amount: 42_000e18, label: "revert-label"});
        bytes32 nestedAppData = keccak256("revert-app-data");
        (, bytes32 orderAppData) = _appDataHashes(nestedAppData, params);

        bytes memory orderData =
            _buildEncodeData(sellToken, address(0xBEEF), address(0xCAFE), 1 ether, 2000e6, validTo, orderAppData, 0);

        settlementOrderDigest =
            _orderDigest(wrapper.SETTLEMENT_DOMAIN_SEPARATOR(), CowAuthLibrary.ORDER_TYPE_HASH, orderData);
        bytes32 wrapperOrderDigest = _orderDigest(
            wrapper.WRAPPER_DOMAIN_SEPARATOR(), wrapper.ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH(), orderData
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, wrapperOrderDigest);
        // The owner's signature travels in wrapperData; the EIP-1271 signatureData is unused.
        mockSettlement.setCallback(address(wrapper), settlementOrderDigest, hex"", validTo);

        settleData = abi.encodeCall(
            ICowSettlement.settle,
            (new address[](0), new uint256[](0), new ICowSettlement.Trade[](0), _emptyInteractions())
        );
        wrapperData = _buildWrapperData(nestedAppData, orderData, abi.encodePacked(r, s, v), params);
    }

    function _chained(bytes memory wrapperData) internal pure returns (bytes memory) {
        return abi.encodePacked(uint16(wrapperData.length), wrapperData);
    }

    /// @dev Builds a valid order (sellToken = owner, so the default _authorizingOwner resolves to `owner`)
    ///      and returns the pieces needed to assemble wrapperData with an arbitrary signature.
    function _prepareOrder(bytes32 nestedAppData, WrapperParams memory params)
        internal
        view
        returns (bytes memory orderData, bytes32 settlementOrderDigest, bytes32 wrapperOrderDigest, uint32 validTo)
    {
        validTo = uint32(block.timestamp + 1 hours);
        (, bytes32 orderAppData) = _appDataHashes(nestedAppData, params);
        orderData = _buildEncodeData(owner, address(0xBEEF), address(0xCAFE), 1 ether, 2000e6, validTo, orderAppData, 0);
        settlementOrderDigest =
            _orderDigest(wrapper.SETTLEMENT_DOMAIN_SEPARATOR(), CowAuthLibrary.ORDER_TYPE_HASH, orderData);
        wrapperOrderDigest = _orderDigest(
            wrapper.WRAPPER_DOMAIN_SEPARATOR(), wrapper.ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH(), orderData
        );
    }

    /// @dev An order whose ECDSA signature (carried in wrapperData) recovers to someone other than the owner
    ///      is rejected in `_wrap`, before settlement runs.
    function test_wrappedSettle_revertsOnWrongEcdsaSigner() public {
        WrapperParams memory params = WrapperParams({target: makeAddr("t"), amount: 1, label: "x"});
        bytes32 nestedAppData = keccak256("wrong-signer");
        (bytes memory orderData, bytes32 sDigest, bytes32 wDigest, uint32 validTo) =
            _prepareOrder(nestedAppData, params);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(keccak256("not-owner")), wDigest);
        mockSettlement.setCallback(address(wrapper), sDigest, hex"", validTo);
        bytes memory wrapperData = _buildWrapperData(nestedAppData, orderData, abi.encodePacked(r, s, v), params);

        vm.expectPartialRevert(CowAuthWrapper.Unauthorized.selector);
        wrapper.wrappedSettle(_emptySettleData(), _chained(wrapperData));
    }

    /// @dev An order taking the pre-approved path (v = 0) whose hash was never approved is rejected in `_wrap`.
    function test_wrappedSettle_revertsIfPreApprovalMissing() public {
        WrapperParams memory params = WrapperParams({target: makeAddr("t"), amount: 1, label: "x"});
        bytes32 nestedAppData = keccak256("no-preapproval");
        (bytes memory orderData, bytes32 sDigest,, uint32 validTo) = _prepareOrder(nestedAppData, params);

        mockSettlement.setCallback(address(wrapper), sDigest, hex"", validTo);
        // v = 0 → pre-approved branch, but the digest was never approved.
        bytes memory wrapperData = _buildWrapperData(nestedAppData, orderData, new bytes(65), params);

        vm.expectPartialRevert(CowAuthWrapper.Unauthorized.selector);
        wrapper.wrappedSettle(_emptySettleData(), _chained(wrapperData));
    }

    /// @dev If the settlement returns without filling the order, the post-settle check must revert so a
    ///      solver cannot benefit from `_authedWrap`'s side effects without the order actually settling.
    function test_wrappedSettle_revertsIfOrderNotFilled() public {
        (bytes memory settleData, bytes memory wrapperData, bytes32 digest,) = _buildValidEcdsaOrder();
        mockSettlement.setFillOrder(false); // settle runs isValidSignature but records no fill

        vm.expectRevert(abi.encodeWithSelector(CowAuthWrapper.OrderNotFilled.selector, digest));
        wrapper.wrappedSettle(settleData, _chained(wrapperData));
    }

    /// @dev The order's on-chain appData must match the WrapperAndAppData envelope derived from the params.
    function test_wrappedSettle_revertsOnAppDataMismatch() public {
        (bytes memory settleData, bytes memory wrapperData,,) = _buildValidEcdsaOrder();
        // Corrupt the nestedAppData (first 32 bytes) so the recomputed envelope no longer matches the
        // orderAppData baked into the embedded orderData.
        wrapperData[0] = bytes1(uint8(wrapperData[0]) ^ 0x01);

        vm.expectPartialRevert(CowAuthWrapper.OrderAppDataMismatch.selector);
        wrapper.wrappedSettle(settleData, _chained(wrapperData));
    }

    /// @dev wrapperData shorter than `nestedAppData(32) ‖ orderData(384) ‖ signature(65)` is rejected up front.
    function test_wrappedSettle_revertsOnShortWrapperData() public {
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (new address[](0), new uint256[](0), new ICowSettlement.Trade[](0), _emptyInteractions())
        );
        bytes memory tooShort = new bytes(100); // < 481

        vm.expectPartialRevert(CowAuthWrapper.InvalidWrapperData.selector);
        wrapper.wrappedSettle(settleData, _chained(tooShort));
    }

    /// @dev isValidSignature must reject a digest that `_wrap` never committed in this transaction. The
    ///      signatureData argument is unused (authorization is verified in `_wrap`), so it is passed empty.
    function test_isValidSignature_revertsForUncommittedOrder() public {
        bytes32 unknownDigest = keccak256("never committed");
        vm.expectRevert(abi.encodeWithSelector(CowAuthWrapper.UnknownOrder.selector, unknownDigest));
        wrapper.isValidSignature(unknownDigest, hex"");
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

    /// @notice Derives the two commitment hashes for a set of WrapperParams.
    ///
    /// The on-chain wrapperData layout consumed by `_wrap` is now:
    ///   [0:32]     nestedAppData
    ///   [32:416]   order orderData (the 12-field CoW order the user signed)
    ///   [416:481]  owner signature `[r ‖ s ‖ v]` over the wrapper order digest (v = 0 → pre-approved path)
    ///   [481:]     abi.encode(WrapperParams)   (raw ABI encoding, label string intact)
    ///
    /// Because the order orderData sits between nestedAppData and the params, and itself depends on the
    /// orderAppData derived here, the full wrapperData is assembled by the caller (via `_buildWrapperData`)
    /// once the orderData and signature are known.
    function _appDataHashes(bytes32 nestedAppData, WrapperParams memory params)
        internal
        pure
        returns (bytes32 wrapperParamsHash, bytes32 orderAppData)
    {
        // wrapperParamsHash == hashStruct(WrapperParams): the dynamic `label` is replaced by its hash and
        // the struct type hash is prefixed. Mirrors BasicAuthWrapper._wrapperSigningData.
        wrapperParamsHash = keccak256(
            abi.encode(WRAPPER_PARAMS_TYPE_HASH, params.target, params.amount, keccak256(bytes(params.label)))
        );

        // orderAppData = hashStruct(WrapperAndAppData) — proper EIP-712 with type hash prefix.
        orderAppData = keccak256(abi.encodePacked(WRAPPER_AND_APP_DATA_TYPE_HASH, nestedAppData, wrapperParamsHash));
    }

    /// @notice Assembles the on-chain wrapperData:
    ///         `nestedAppData ‖ orderData ‖ signature(65) ‖ abi.encode(params)`.
    function _buildWrapperData(
        bytes32 nestedAppData,
        bytes memory orderData,
        bytes memory signature,
        WrapperParams memory params
    ) internal pure returns (bytes memory wrapperData) {
        wrapperData = abi.encodePacked(nestedAppData, orderData, signature, abi.encode(params));
    }

    function _buildEncodeData(
        address sellToken,
        address buyToken,
        address receiver,
        uint256 sellAmount,
        uint256 buyAmount,
        uint32 validTo,
        bytes32 orderAppData,
        uint256 feeAmount
    ) internal pure returns (bytes memory) {
        return abi.encode(
            sellToken,
            buyToken,
            receiver,
            sellAmount,
            buyAmount,
            validTo,
            orderAppData,
            feeAmount,
            KIND_SELL,
            false,
            BALANCE_ERC20,
            BALANCE_ERC20
        );
    }

    function _orderDigest(bytes32 domainSeparator, bytes32 typeHash, bytes memory orderData)
        internal
        pure
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encodePacked(typeHash, orderData));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _authenticatorManager() internal returns (address) {
        (bool ok, bytes memory data) = MAINNET_AUTHENTICATOR.call(abi.encodeWithSignature("manager()"));
        require(ok, "manager() call failed");
        return abi.decode(data, (address));
    }

    function _emptyInteractions() internal pure returns (ICowSettlement.Interaction[][3] memory) {}
}
