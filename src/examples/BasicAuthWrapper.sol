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

// Completes "WrapperAndAppData(bytes32 appData," — passed to CowAuthWrapper as wrapperTypeHashPostfix.
string constant WRAPPER_TYPE_HASH_POSTFIX =
    "WrapperParams wrapperData)WrapperParams(address target,uint128 amount,string label)";

// hashStruct type hash for the WrapperAndAppData envelope (including its referenced sub-type).
// This is the value placed in the CoW order's appData field so that both the settlement and
// the wrapper can verify the order is correctly bound to these WrapperParams.
bytes32 constant WRAPPER_AND_APP_DATA_TYPE_HASH = keccak256(
    "WrapperAndAppData(bytes32 appData,WrapperParams wrapperData)WrapperParams(address target,uint128 amount,string label)"
);

// ---------------------------------------------------------------------------
// BasicAuthWrapper
// ---------------------------------------------------------------------------

contract BasicAuthWrapper is CowAuthWrapper {
    constructor(ICowSettlement settlement) CowAuthWrapper(WRAPPER_TYPE_HASH_POSTFIX, settlement) {}

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

    /// @dev wrapperData = 32 bytes originalAppData followed by `abi.encode(WrapperParams)`. The length is
    ///      variable because `label` is a dynamic string, so we validate by decoding rather than by size.
    function validateWrapperData(bytes calldata data) external pure override {
        require(data.length >= 32, "wrapperData too short");
        abi.decode(data[32:], (WrapperParams));
    }
}
