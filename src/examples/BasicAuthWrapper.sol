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

    function name() external pure returns (string memory) {
        return "Basic Auth Demo Wrapper";
    }

    // wrapperData received here is wrapperData[32:] from CowAuthWrapper._wrap, i.e. the bytes
    // whose keccak256 equals WrapperAndAppData.wrapperData.  Layout:
    //   [0:32]   WRAPPER_PARAMS_TYPE_HASH
    //   [32:64]  target  (address ABI-padded to 32 bytes; actual address at [44:64])
    //   [64:96]  amount  (uint128 ABI-padded to 32 bytes)
    //   [96:128] keccak256(label as bytes)
    //
    // Decode example:
    //   address target   = address(bytes20(wrapperData[44:64]));
    //   uint128 amount   = uint128(uint256(bytes32(wrapperData[64:96])));
    //   bytes32 labelHash = bytes32(wrapperData[96:128]);
    function _authedWrap(bytes calldata settleData, bytes calldata, bytes calldata remaining)
        internal
        override
    {
        _next(settleData, remaining);
    }

    // wrapperData = 32 bytes originalAppData + 128 bytes WrapperParams struct encoding = 160 bytes.
    function validateWrapperData(bytes calldata data) external pure override {
        require(data.length == 160, "wrapperData must be exactly 160 bytes");
    }
}
