// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IERC1271} from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ICowSettlement, CowWrapper} from "./CowWrapper.sol";
import {PreApprovedHashes} from "./PreApprovedHashes.sol";

/// @dev Collection of EIP-712 type hashes. These hashes match those used by the CoW settlement contract.
library CowAuthLibrary {
    /// @dev The EIP-712 type hash for the domain separator used in the CoW settlement contract. We intentionally hardcode this here to prevent an unnecessary external call at wrapper deployment time.
    /// Tests are used to verify it matches up with the expected value from production.
    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    struct WrapperAndAppData {
        bytes32 appData;
        bytes32 wrapperData; // can be represented in the type hash as the actual type
    }

    bytes32 internal constant ORDER_TYPE_HASH = keccak256(
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
    );

    /// @dev The EIP-712 type hash for the order struct used in the CoW settlement contract. Similar to DOMAIN_TYPE_HASH, it is intentionally hardcoded here.
    /// We replace `appData` with `wrapperAndAppData` to allow for the wrapper to include additional data in the signature, but the actual type hash is the same as the one used by the settlement contract, just with this one field swap.
    string internal constant ORDER_TYPE_HASH_PLUS_WRAPPER_AND_APP_DATA_PREFIX =
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,WrapperAndAppData wrapperAndAppData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)WrapperAndAppData(bytes32 appData,";

    /// @notice Compute the EIP-712 domain separator for the CowAuthWrapper contract
    /// @param creationAddress The address of the CowAuthWrapper contract
    /// @return domainSeparator The computed domain separator
    function computeDomainSeparator(address creationAddress) internal view returns (bytes32 domainSeparator) {
        return
            /// forge-lint: disable-next-line(asm-keccak256)
            keccak256(abi.encode(DOMAIN_TYPE_HASH, keccak256("CowAuthWrapper"), keccak256("1"), block.chainid, creationAddress));
    }
}

/// @notice 
abstract contract CowAuthWrapper is CowWrapper, PreApprovedHashes, IERC1271 {

    error Unauthorized(address);
    error OrderHashMismatch(bytes32 computed, bytes32 provided);
    error InvalidSignatureOrderData(bytes data);

    bytes32 public immutable WRAPPER_DOMAIN_SEPARATOR;
    bytes32 public immutable SETTLEMENT_DOMAIN_SEPARATOR;
    bytes32 public immutable ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH;
    bytes32 public immutable WRAPPER_AND_APP_DATA_TYPE_HASH;

    // @param wrapperTypeHashPostfix A string to be appended to the type hash of the wrapper's domain separator. This allows for multiple wrappers with different type hashes, which can be useful for differentiating between different wrapper versions or types in the future.
    // Example value: "MyWrapperParams params)MyWrapperParams(string param1,uint256 param2)"
    constructor(string memory wrapperTypeHashPostfix, ICowSettlement settlement) CowWrapper(settlement) {
        WRAPPER_DOMAIN_SEPARATOR = CowAuthLibrary.computeDomainSeparator(address(this));

        SETTLEMENT_DOMAIN_SEPARATOR = SETTLEMENT.domainSeparator();

        ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH = keccak256(
            abi.encodePacked(
                CowAuthLibrary.ORDER_TYPE_HASH_PLUS_WRAPPER_AND_APP_DATA_PREFIX,
                wrapperTypeHashPostfix
            )
        );

        WRAPPER_AND_APP_DATA_TYPE_HASH = keccak256(
            abi.encodePacked("WrapperAndAppData(bytes32 appData,", wrapperTypeHashPostfix)
        );
    }

    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        CowAuthLibrary.WrapperAndAppData memory d = CowAuthLibrary.WrapperAndAppData({
            appData: abi.decode(wrapperData, (bytes32)), // appData is the first bytes given in the wrapperData
            wrapperData: keccak256(wrapperData[32:]) // the rest of the wrapperData (after the first 32 bytes) is hashed to get the wrapperData hash, which is included in the signature verification
        });

        bytes32 orderAppDataHash = keccak256(abi.encodePacked(WRAPPER_AND_APP_DATA_TYPE_HASH, d.appData, d.wrapperData));

        assembly {
            // set the orderAppDataHash in storage so that it can be verified in the isValidSignature function
            tstore(orderAppDataHash, 1)
        }

        // TODO: storing the orderAppData hash for later verification works great *AS LONG AS* the setltement cotnract is called and
        // completes its validation. If it doesn't, then the settlement contract could just not have any effect. So this needs to be ensured somehow.

        _authedWrap(settleData, wrapperData[32:], remainingWrapperData);
    }

    function _authedWrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal virtual;

    /// @notice Implements EIP1271 `isValidSignature`. This function expects a 65 byte RSV signature, followed by the 416 byte CoW order data.
    /// The signature should be the same as the EIP-712 hash normally given to the settlement contract, except the domain separator should be `WRAPPER_DOMAIN_SEPARATOR()` from this contract.
    /// The provided order data needs to match up with the currently processed order, as its orderDigest will be checked to match against the `orderDigest` provided by the settlement contract.
    /// @dev A large portion of this code was copied from `GPv2Signer`'s' `ecdsaRecover` function. The idea is that the same signature the user would use. However, the order could be replayed between the wrapper/user account's orders if we use the orderDigest as is, so we recompute the order digest using a new domain separator for the Wrapper
    /// for a regular CoW order is also used here.
    /// @param orderDigest the order digest as recognized by the settlement contract. This is used to prevent replay attacks with other orders, as we check that the order data provided in the signature data matches up with this digest.
    /// @param signatureData A bytes data with the following encoding:
    /// --------------------
    /// | ecdsa signature | original appData | encodeData for CoW order |
    /// | 65 bytes        | 32 bytes         | 384 bytes                |
    /// See EIP-712 "Definition of encodeData" for information on how to set up the order data encoding.
    /// Of primary note, the string fields (kind, sellTokenBalance, buyTokenBalance) are pre-hashed to bytes32.
    /// NOTE: the original order signature that is provided to CoW protocol will *also*
    /// contain 20-byte address of this Wrapper contract at the beginning (but it gets stripped before calling this function).
    function isValidSignature(bytes32 orderDigest, bytes calldata signatureData)
        external
        view
        returns (bytes4 magicValue)
    {
        bytes32 wrapperOrderDigest;
        {
            // Ensure that we have all the order data. 65 for the signature length, plus 384 (12 fields * 32 bytes) for the order data.
            require(signatureData.length >= 65 + 384, InvalidSignatureOrderData(signatureData));

            // Ensure the app data received by the settlement contract matches our own known app data
            {
                bytes32 resolvedAppData = bytes32(signatureData[65 + 32 * 6:65 + 32 * 7]);

                assembly {
                    resolvedAppData := tload(resolvedAppData)
                }

                require(resolvedAppData != bytes32(0), InvalidSignatureOrderData(signatureData));
            }

            bytes memory orderData = signatureData[65:449];
            bytes32 settlementTypeHash = CowAuthLibrary.ORDER_TYPE_HASH;
            bytes32 wrapperTypeHash = ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH;
            bytes32 settlementStructHash;
            bytes32 wrapperStructHash;

            // NOTE: Compute the EIP-712 order struct hash in place. As suggested
            // in the EIP proposal, noting that the order struct has 12 fields, and
            // prefixing the type hash `(1 + 12) * 32 = 416` bytes to hash.
            // NOTE: The input data *assumes* that the string fields (ex. "kind") are
            // pre-hashed to bytes32 in accordance with EIP-712.
            // <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#rationale-for-encodedata>
            assembly {
                let originalLength := mload(orderData)
                mstore(orderData, settlementTypeHash)
                settlementStructHash := keccak256(orderData, 416)
                mstore(orderData, wrapperTypeHash)
                wrapperStructHash := keccak256(orderData, 416)
                mstore(orderData, originalLength)
            }

            bytes32 settlementDomainSeparator = SETTLEMENT_DOMAIN_SEPARATOR;
            bytes32 wrapperDomainSeparator = WRAPPER_DOMAIN_SEPARATOR;
            bytes32 settlementOrderDigest;

            bytes memory message = abi.encodePacked("\x19\x01", wrapperDomainSeparator, wrapperStructHash);

            // We use assembly for the keccak256 hashing due to inefficient impl warning by foundry https://getfoundry.sh/forge/linting/#asm-keccak256
            assembly ("memory-safe") {
                wrapperOrderDigest := keccak256(add(message, 32), 66)
                // The difference between the wrapper and settlement order digests is only the domainSeparator and structHash.
                // So we can get both hashes pretty efficiently through assembly by replacing it
                // 34 = 32 (length byte) + 2 ("\x19\x01")
                mstore(add(message, 34), settlementDomainSeparator)
                // 66 = 2 ("\x19\x01") + 32 (domain separator) + 32 (struct hash)
                mstore(add(message, 66), settlementStructHash)
                settlementOrderDigest := keccak256(add(message, 32), 66)
            }

            if (settlementOrderDigest != orderDigest) {
                revert OrderHashMismatch(settlementOrderDigest, orderDigest);
            }
        }

        // use the owner recorded in the GPv2Order object
        address owner = address(bytes20(signatureData[77:97]));

        if (signatureData[64] == 0) {
            // no signature provided, so has to be a pre-approved hash
            require(isHashPreApproved(owner, wrapperOrderDigest), Unauthorized(owner));
        } else {
            address signer = ECDSA.recoverCalldata(wrapperOrderDigest, signatureData[:65]);
            require(signer == owner, Unauthorized(signer));
        }

        return IERC1271.isValidSignature.selector;
    }
}
