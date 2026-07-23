// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {CowAuthWrapper} from "../CowAuthWrapper.sol";
import {ICowSettlement} from "../CowWrapper.sol";

// ---------------------------------------------------------------------------
// WrapperParams: the application-specific data nested inside every order.
// Exported as file-level symbols so off-chain code can import them for
// building and verifying the EIP-712 typed data.
// ---------------------------------------------------------------------------

struct WrapperParams {
    address target;
    uint128 amount;
    string label;
}

bytes32 constant WRAPPER_PARAMS_TYPE_HASH = keccak256("WrapperParams(address target,uint128 amount,string label)");

// Full EIP-712 definition of the `WrapperAndAppData` envelope struct (up to and including its own closing
// paren), passed to CowAuthWrapper as `wrapperStructDef`. Its second field references `WrapperParams`.
string constant WRAPPER_AND_APP_DATA_STRUCT_DEF = "WrapperAndAppData(bytes32 nestedAppData,WrapperParams wrapperData)";

// The referenced struct definitions the envelope depends on, passed to CowAuthWrapper as `referencedTypeDefs`.
// Here that is just `WrapperParams`.
string constant WRAPPER_PARAMS_STRUCT_DEF = "WrapperParams(address target,uint128 amount,string label)";

// Type hash of the WrapperAndAppData envelope (including its referenced sub-type). keccak256 of this
// type hash together with the nestedAppData and the WrapperParams hashStruct yields the orderAppData —
// the value placed in the CoW order's `appData` field so that both the settlement and the wrapper can
// verify the order is correctly bound to these WrapperParams.
bytes32 constant WRAPPER_AND_APP_DATA_TYPE_HASH = keccak256(
    "WrapperAndAppData(bytes32 nestedAppData,WrapperParams wrapperData)WrapperParams(address target,uint128 amount,string label)"
);

// ---------------------------------------------------------------------------
// BasicAuthWrapper
// ---------------------------------------------------------------------------

contract BasicAuthWrapper is CowAuthWrapper {
    constructor(ICowSettlement settlement)
        CowAuthWrapper(WRAPPER_AND_APP_DATA_STRUCT_DEF, WRAPPER_PARAMS_STRUCT_DEF, settlement)
    {}

    event AuthedData(uint128 indexed amount, string message);

    function name() external pure returns (string memory) {
        return "Basic Auth Demo Wrapper";
    }

    /// @inheritdoc CowAuthWrapper
    /// @dev The raw wrapperData is `abi.encode(WrapperParams)`. `label` is a dynamic string, so per
    ///      EIP-712 its encoding is `keccak256(bytes(label))`; the static fields are inlined. Prefixing
    ///      the struct type hash yields bytes whose keccak256 equals `hashStruct(WrapperParams)`.
    function _wrapperSigningData(bytes calldata wrapperData) internal pure override returns (bytes memory) {
        WrapperParams memory params = abi.decode(wrapperData, (WrapperParams));
        return abi.encode(WRAPPER_PARAMS_TYPE_HASH, params.target, params.amount, keccak256(bytes(params.label)));
    }

    /// @dev `wrapperData` here is the raw `abi.encode(WrapperParams)` tail (with the original `label`
    ///      string intact), so it decodes directly into the trusted, signature-bound parameters.
    function _authedWrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remaining)
        internal
        override
    {
        _next(settleData, remaining);

        WrapperParams memory params = abi.decode(wrapperData, (WrapperParams));

        emit AuthedData(params.amount, string(abi.encodePacked("Trusted data! ", params.label)));
    }

    /// @inheritdoc CowAuthWrapper
    /// @dev This wrapper is itself the EIP-1271 verifier GPv2 calls and the account the sell tokens are pulled
    ///      from, so CoW's order owner is this contract. (Distinct from the authorizing owner, which the
    ///      default `_authorizingOwner` reads from the order's sell-token slot.)
    function _settlementOrderOwner(bytes calldata, bytes calldata) internal view override returns (address) {
        return address(this);
    }

    /// @dev wrapperData = 32 bytes nestedAppData ‖ 384 bytes order orderData ‖ 65 bytes owner signature ‖
    ///      `abi.encode(WrapperParams)`. The length is variable because `label` is a dynamic string, so we
    ///      validate by decoding rather than by size (beyond requiring the fixed nestedAppData + orderData +
    ///      signature prefix is present).
    function validateWrapperData(bytes calldata data) external pure override {
        require(data.length >= 32 + 384 + 65, "wrapperData too short");
        abi.decode(data[32 + 384 + 65:], (WrapperParams));
    }
}
