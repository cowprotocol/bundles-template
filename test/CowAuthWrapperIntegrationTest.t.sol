// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CowAuthWrapper} from "src/CowAuthWrapper.sol";
import {ICowAuthentication, ICowSettlement, ICowWrapper} from "src/CowWrapper.sol";
import {WRAPPER_PARAMS_TYPE_HASH, WRAPPER_TYPE_HASH_POSTFIX, WrapperParams} from "src/examples/BasicAuthWrapper.sol";

// ---------------------------------------------------------------------------
// Test implementation: authorizing owner sourced from the wrapperData
// ---------------------------------------------------------------------------

/// @dev A minimal `CowAuthWrapper` implementation that resolves the authorizing owner from a field in
///      the (trusted) wrapperData rather than from the default sellToken slot. We reuse
///      `WrapperParams.target` as the "owner" field purely for demonstration.
///
///      This is NOT presented as a hardened ownership model, but it is not merely a hack either:
///      `WrapperParams` is hashed into the order's `appData` commitment (`orderAppData`), which is
///      part of the EIP-712 digest the owner pre-approves / signs. So the owner value is bound into the
///      authorization — a solver cannot substitute a different owner without invalidating both the
///      signature and the on-chain order-digest match. A real implementation would derive the owner from
///      a dedicated, semantically meaningful field (e.g. a Safe address) the same way.
///
///      Mechanics: `_authorizingOwner` now receives the (trusted, signature-bound) `params` directly, so
///      the owner can be decoded from `WrapperParams.target` with no transient-storage plumbing.
contract WrapperDataOwnerAuthWrapper is CowAuthWrapper {
    constructor(ICowSettlement settlement) CowAuthWrapper(WRAPPER_TYPE_HASH_POSTFIX, settlement) {}

    function name() external pure returns (string memory) {
        return "WrapperData Owner Auth Wrapper";
    }

    /// @inheritdoc CowAuthWrapper
    /// @dev Identical to `BasicAuthWrapper`: the raw wrapperData is `abi.encode(WrapperParams)`.
    function _wrapperSigningData(bytes calldata wrapperData) internal pure override returns (bytes memory) {
        WrapperParams memory params = abi.decode(wrapperData, (WrapperParams));
        return abi.encode(WRAPPER_PARAMS_TYPE_HASH, params.target, params.amount, keccak256(bytes(params.label)));
    }

    /// @dev No custom pre/post-settlement logic needed; just continue the chain into settlement.
    function _authedWrap(bytes calldata settleData, bytes calldata, bytes calldata remaining) internal override {
        _next(settleData, remaining);
    }

    /// @dev Overrides `CowAuthWrapper._authorizingOwner` to derive the owner from the signature-bound params.
    function _authorizingOwner(bytes calldata, bytes calldata params) internal pure override returns (address) {
        return abi.decode(params, (WrapperParams)).target;
    }

    /// @dev Validates the wrapperData decodes into `WrapperParams`.
    function validateWrapperData(bytes calldata data) external pure override {
        require(data.length >= 32, "wrapperData too short");
        abi.decode(data[32:], (WrapperParams));
    }
}

// ---------------------------------------------------------------------------
// Integration test: drives the REAL deployed GPv2Settlement end-to-end.
// ---------------------------------------------------------------------------

/// @notice Unlike `CowAuthWrapperForkTest` (which mocks the settlement so it can synthesise the ERC-1271
///         callback without moving funds), this suite calls the genuine mainnet settlement contract with
///         a real order and real ERC-20 balances, pinned to a fixed block. It verifies the full path:
///         solver auth -> wrapper `_wrap` -> `SETTLEMENT.settle` -> `vaultRelayer` pulls the sell token
///         -> EIP-1271 `isValidSignature` callback -> buy token delivered to the receiver.
contract CowAuthWrapperIntegrationTest is Test {
    // Pinned mainnet block for deterministic fork state.
    uint256 constant FORK_BLOCK = 25_500_000;

    address constant MAINNET_SETTLEMENT = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41;
    address constant MAINNET_AUTHENTICATOR = 0x2c4c28DDBdAc9C5E7055b4C863b72eA0149D8aFE;

    IERC20 constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    bytes32 constant KIND_SELL = keccak256("sell");
    bytes32 constant BALANCE_ERC20 = keccak256("erc20");

    // GPv2Trade flags: signing scheme eip1271 (2 << 5 = 0x40), kind sell (bit 0 = 0), fill-or-kill
    // (bit 1 = 0), erc20 sell balance (bit 3 = 0), erc20 buy balance (bit 4 = 0).
    uint256 constant FLAGS_EIP1271_SELL = 0x40;

    uint256 constant SELL_AMOUNT = 1 ether; // WETH sold
    uint256 constant BUY_AMOUNT = 2000e6; // USDC bought
    uint256 constant FEE_AMOUNT = 0;

    WrapperDataOwnerAuthWrapper internal wrapper;
    address internal vaultRelayer;

    // The account that authorizes the order (ECDSA signer / pre-approved-hash owner). Decoupled from CoW's
    // order owner, which is always the wrapper (the EIP-1271 verifier that holds and sells the funds).
    uint256 internal ownerKey;
    address internal owner;
    address internal solver;
    address internal receiver;

    function setUp() public {
        vm.createSelectFork(vm.envString("FORK_RPC_URL"), FORK_BLOCK);

        ownerKey = uint256(keccak256("cow auth wrapper integration owner"));
        owner = vm.addr(ownerKey);
        solver = makeAddr("solver");
        receiver = makeAddr("receiver");

        wrapper = new WrapperDataOwnerAuthWrapper(ICowSettlement(MAINNET_SETTLEMENT));
        vaultRelayer = ICowSettlement(MAINNET_SETTLEMENT).vaultRelayer();

        // Register both the solver EOA (calls `wrappedSettle`) and the wrapper (calls `settle`) as solvers.
        address manager = _authenticatorManager();
        vm.startPrank(manager);
        _addSolver(solver);
        _addSolver(address(wrapper));
        vm.stopPrank();
    }

    // -----------------------------------------------------------------------
    // End-to-end against the real settlement
    // -----------------------------------------------------------------------

    function test_realSettlement_preApproved_endToEnd() public {
        _runEndToEnd({useEcdsa: false});
    }

    function test_realSettlement_ecdsa_endToEnd() public {
        _runEndToEnd({useEcdsa: true});
    }

    /// @notice The on-chain `computeOrderAppData` getter (used by the orderbook to validate a wrapper
    ///         order's orderAppData) must return exactly the envelope hash the order commits to.
    function test_computeOrderAppData_matchesEnvelope() public view {
        bytes32 nestedAppData = keccak256("integration-app-data");
        WrapperParams memory params = WrapperParams({target: owner, amount: 42_000e18, label: "integration"});
        (, bytes32 orderAppData) = _appDataHashes(nestedAppData, params);

        assertEq(
            wrapper.computeOrderAppData(_commitmentData(nestedAppData, params)),
            orderAppData,
            "getter must reproduce the WrapperAndAppData envelope hash"
        );
    }

    function _runEndToEnd(bool useEcdsa) internal {
        console.log(useEcdsa ? "=== real settlement (ECDSA) ===" : "=== real settlement (pre-approved) ===");

        (bytes memory settleData, bytes memory chainedWrapperData) = _buildOrderAndFund(useEcdsa);

        uint256 wrapperWethBefore = WETH.balanceOf(address(wrapper));
        uint256 receiverUsdcBefore = USDC.balanceOf(receiver);
        uint256 settlementUsdcBefore = USDC.balanceOf(MAINNET_SETTLEMENT);

        vm.prank(solver);
        bytes4 result = wrapper.wrappedSettle(settleData, chainedWrapperData);

        // clearingPrices are chosen so executedBuyAmount == BUY_AMOUNT (see `_buildSettleData`).
        assertEq(result, ICowWrapper.wrappedSettle.selector, "wrappedSettle magic value");
        assertEq(
            wrapperWethBefore - WETH.balanceOf(address(wrapper)), SELL_AMOUNT + FEE_AMOUNT, "WETH pulled from wrapper"
        );
        assertEq(USDC.balanceOf(receiver) - receiverUsdcBefore, BUY_AMOUNT, "USDC delivered to receiver");
        assertEq(settlementUsdcBefore - USDC.balanceOf(MAINNET_SETTLEMENT), BUY_AMOUNT, "USDC left settlement");

        console.log("WETH pulled from wrapper:", SELL_AMOUNT + FEE_AMOUNT);
        console.log("USDC delivered to receiver:", BUY_AMOUNT);
    }

    /// @dev Builds the order, authorizes it (pre-approval or ECDSA), and funds both sides with real tokens.
    function _buildOrderAndFund(bool useEcdsa)
        internal
        returns (bytes memory settleData, bytes memory chainedWrapperData)
    {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // `WrapperParams.target` doubles as the authorizing owner in this demo implementation.
        bytes32 nestedAppData = keccak256("integration-app-data");
        WrapperParams memory params = WrapperParams({target: owner, amount: 42_000e18, label: "integration"});
        (, bytes32 orderAppData) = _appDataHashes(nestedAppData, params);

        bytes memory orderData = _buildEncodeData(
            address(WETH), address(USDC), receiver, SELL_AMOUNT, BUY_AMOUNT, validTo, orderAppData, FEE_AMOUNT
        );
        assertEq(orderData.length, 384);

        bytes memory signatureData = _buildSignatureData(useEcdsa, orderData);

        // Fund the trade with real tokens: the wrapper (CoW order owner) holds and approves the sell token;
        // the settlement holds the buy-side liquidity that will be paid to the receiver.
        deal(address(WETH), address(wrapper), SELL_AMOUNT + FEE_AMOUNT);
        vm.prank(address(wrapper));
        WETH.approve(vaultRelayer, type(uint256).max);
        deal(address(USDC), MAINNET_SETTLEMENT, BUY_AMOUNT);

        settleData = _buildSettleData(validTo, orderAppData, signatureData);
        // On-chain wrapperData now embeds the order orderData between nestedAppData and the params.
        bytes memory wrapperData = _buildWrapperData(nestedAppData, orderData, params);
        chainedWrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);
    }

    /// @dev Produces the 65-byte EIP-1271 signature payload (the order data now travels in wrapperData).
    ///      ECDSA path signs the wrapper-domain digest; pre-approved path uses a zero sig (v = 0) and records
    ///      the digest as pre-approved by `owner`.
    function _buildSignatureData(bool useEcdsa, bytes memory orderData) internal returns (bytes memory sig) {
        bytes32 wrapperOrderDigest = _orderDigest(
            wrapper.WRAPPER_DOMAIN_SEPARATOR(), wrapper.ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH(), orderData
        );

        if (useEcdsa) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, wrapperOrderDigest);
            assertTrue(v == 27 || v == 28, "unexpected v");
            sig = abi.encodePacked(r, s, v);
        } else {
            sig = new bytes(65); // v = 0 => pre-approved path
            vm.prank(owner);
            wrapper.setPreApprovedHash(wrapperOrderDigest, true);
            assertTrue(wrapper.isHashPreApproved(owner, wrapperOrderDigest));
        }

        assertEq(sig.length, 65);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// @dev Builds `ICowSettlement.settle` calldata for a single eip1271 sell order (WETH -> USDC).
    ///      tokens = [WETH, USDC]; clearingPrices are set so
    ///      executedBuyAmount = SELL_AMOUNT * prices[sell] / prices[buy] = BUY_AMOUNT.
    function _buildSettleData(uint32 validTo, bytes32 orderAppData, bytes memory signatureData)
        internal
        view
        returns (bytes memory)
    {
        address[] memory tokens = new address[](2);
        tokens[0] = address(WETH);
        tokens[1] = address(USDC);

        uint256[] memory prices = new uint256[](2);
        prices[0] = BUY_AMOUNT; // sellPrice
        prices[1] = SELL_AMOUNT; // buyPrice

        ICowSettlement.Trade[] memory trades = new ICowSettlement.Trade[](1);
        trades[0] = ICowSettlement.Trade({
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            receiver: receiver,
            sellAmount: SELL_AMOUNT,
            buyAmount: BUY_AMOUNT,
            validTo: validTo,
            appData: orderAppData,
            feeAmount: FEE_AMOUNT,
            flags: FLAGS_EIP1271_SELL,
            executedAmount: 0, // ignored for fill-or-kill
            // eip1271 signature = 20-byte verifier (this wrapper) followed by the wrapper's signatureData.
            signature: abi.encodePacked(address(wrapper), signatureData)
        });

        return abi.encodeCall(ICowSettlement.settle, (tokens, prices, trades, _emptyInteractions()));
    }

    /// @notice Derives the WrapperAndAppData commitment hashes.
    ///         Mirrors `CowAuthWrapperForkTest` / `BasicAuthWrapper._wrapperSigningData`.
    function _appDataHashes(bytes32 nestedAppData, WrapperParams memory params)
        internal
        pure
        returns (bytes32 wrapperParamsHash, bytes32 orderAppData)
    {
        wrapperParamsHash = keccak256(
            abi.encode(
                keccak256("WrapperParams(address target,uint128 amount,string label)"),
                params.target,
                params.amount,
                keccak256(bytes(params.label))
            )
        );
        orderAppData = keccak256(
            abi.encodePacked(
                keccak256(
                    "WrapperAndAppData(bytes32 nestedAppData,WrapperParams wrapperData)WrapperParams(address target,uint128 amount,string label)"
                ),
                nestedAppData,
                wrapperParamsHash
            )
        );
    }

    /// @notice The pre-order commitment tuple `nestedAppData ‖ abi.encode(params)` accepted by
    ///         `computeOrderAppData`. NOT the on-chain wrapperData (which also embeds the order orderData).
    function _commitmentData(bytes32 nestedAppData, WrapperParams memory params) internal pure returns (bytes memory) {
        return abi.encodePacked(nestedAppData, abi.encode(params));
    }

    /// @notice The full on-chain wrapperData: `nestedAppData ‖ orderData ‖ abi.encode(params)`.
    function _buildWrapperData(bytes32 nestedAppData, bytes memory orderData, WrapperParams memory params)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(nestedAppData, orderData, abi.encode(params));
    }

    function _buildEncodeData(
        address sellToken,
        address buyToken,
        address receiver_,
        uint256 sellAmount,
        uint256 buyAmount,
        uint32 validTo,
        bytes32 orderAppData,
        uint256 feeAmount
    ) internal pure returns (bytes memory) {
        return abi.encode(
            sellToken,
            buyToken,
            receiver_,
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

    function _addSolver(address who) internal {
        (bool ok,) = MAINNET_AUTHENTICATOR.call(abi.encodeWithSignature("addSolver(address)", who));
        require(ok, "addSolver failed");
    }

    function _emptyInteractions() internal pure returns (ICowSettlement.Interaction[][3] memory) {}
}
