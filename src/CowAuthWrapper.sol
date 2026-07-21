// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
import {PreApprovedHashes} from "./PreApprovedHashes.sol";
import {IERC1271} from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {IERC165} from "openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";

/// @dev Collection of EIP-712 type hashes. These hashes match those used by the CoW settlement contract.
library CowAuthLibrary {
    /// @dev The EIP-712 type hash for the domain separator used in the CoW settlement contract. We intentionally hardcode this here to prevent an unnecessary external call at wrapper deployment time.
    /// Tests are used to verify it matches up with the expected value from production.
    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev The two-part commitment an auth-wrapped order carries. `hashStruct(WrapperAndAppData)` is the
    ///      `orderAppData` — the value placed in the CoW order's `appData` field. Its `nestedAppData` field
    ///      is the ordinary CoW app-data hash the order would carry if it were not wrapped. See the README
    ///      section "Two app-data hashes" for the full picture.
    struct WrapperAndAppData {
        // ordinary CoW app-data hash: keccak256 of the app-data document *excluding* this wrapper's own
        // call (so it is free of any self-reference and can be computed client-side before the wrapper data)
        bytes32 nestedAppData;
        bytes32 wrapperData; // hashStruct of the wrapper's params
    }

    /// @dev Canonical CoW `Order` type hash. NOTE: the `bytes32 appData` field here is the CoW-protocol
    ///      field name and MUST NOT be renamed (the settlement digest depends on it); for an auth-wrapped
    ///      order the *value* in that field is the `orderAppData`.
    bytes32 internal constant ORDER_TYPE_HASH = keccak256(
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
    );

    /// @dev The EIP-712 type hash for the order struct used in the CoW settlement contract. Similar to DOMAIN_TYPE_HASH, it is intentionally hardcoded here.
    /// We replace the order's `appData` field with a `WrapperAndAppData wrapperAndAppData` struct so the wrapper can bind additional data into the signature; the `orderAppData` the order commits to becomes `hashStruct(WrapperAndAppData)`. The rest of the type is identical to the settlement's.
    string internal constant ORDER_TYPE_HASH_PLUS_WRAPPER_AND_APP_DATA_PREFIX =
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,WrapperAndAppData wrapperAndAppData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)WrapperAndAppData(bytes32 nestedAppData,";

    /// @notice Compute the EIP-712 domain separator for the CowAuthWrapper contract
    /// @param creationAddress The address of the CowAuthWrapper contract
    /// @return domainSeparator The computed domain separator
    function computeDomainSeparator(address creationAddress) internal view returns (bytes32 domainSeparator) {
        return
        /// forge-lint: disable-next-line(asm-keccak256)
        keccak256(
            abi.encode(DOMAIN_TYPE_HASH, keccak256("CowAuthWrapper"), keccak256("1"), block.chainid, creationAddress)
        );
    }
}

/// @notice Marker interface identifying a wrapper that binds its wrapper data into the order via the
///         `WrapperAndAppData` envelope and self-verifies through EIP-1271. Backends detect an auth wrapper
///         (vs. a plain `CowWrapper` that routes via `metadata.wrappers`) with
///         `IERC165(wrapper).supportsInterface(type(ICowAuthWrapper).interfaceId)`, then read the getters
///         below to reconstruct the envelope / wrapper order digest.
interface ICowAuthWrapper is IERC1271 {
    function WRAPPER_DOMAIN_SEPARATOR() external view returns (bytes32);
    function WRAPPER_AND_APP_DATA_TYPE_HASH() external view returns (bytes32);
    function ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH() external view returns (bytes32);
    /// @notice Recomputes the `orderAppData` (`hashStruct(WrapperAndAppData)`) that an order must carry in
    ///         its `appData` field to settle through this wrapper, given the on-chain `wrapperData` for this
    ///         wrapper. Lets off-chain order validation verify a submitted order's `orderAppData` without
    ///         needing this wrapper's Solidity ABI.
    function computeOrderAppData(bytes calldata wrapperData) external view returns (bytes32);
}

/// @notice
abstract contract CowAuthWrapper is CowWrapper, PreApprovedHashes, IERC1271, IERC165 {
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
            abi.encodePacked(CowAuthLibrary.ORDER_TYPE_HASH_PLUS_WRAPPER_AND_APP_DATA_PREFIX, wrapperTypeHashPostfix)
        );

        WRAPPER_AND_APP_DATA_TYPE_HASH =
            keccak256(abi.encodePacked("WrapperAndAppData(bytes32 nestedAppData,", wrapperTypeHashPostfix));
    }

    /// @inheritdoc IERC165
    /// @dev Advertises the auth-wrapper capability so backends can distinguish it from a plain CowWrapper.
    ///      `virtual` so concrete wrappers may advertise additional interfaces.
    function supportsInterface(bytes4 interfaceId) public pure virtual override returns (bool) {
        return interfaceId == type(ICowAuthWrapper).interfaceId || interfaceId == type(IERC1271).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        // The `nestedAppData` occupies the first 32 bytes of `wrapperData`; the raw wrapper-specific params
        // follow. `_computeOrderAppData` folds these into the `orderAppData` (the `WrapperAndAppData` struct
        // hash) exactly as an off-chain signer / the orderbook does.
        bytes32 orderAppData = _computeOrderAppData(wrapperData[32:], bytes32(wrapperData[:32]));

        assembly {
            // record the orderAppData so it can be verified against the order's appData in isValidSignature
            tstore(orderAppData, 1)
        }

        // TODO: storing the orderAppData for later verification works great *AS LONG AS* the setltement cotnract is called and
        // completes its validation. If it doesn't, then the settlement contract could just not have any effect. So this needs to be ensured somehow.

        _authedWrap(settleData, wrapperData[32:], remainingWrapperData);
    }

    /// @notice Recomputes the `orderAppData` (`hashStruct(WrapperAndAppData)`) that an order MUST carry in
    ///         its `appData` field to settle through this wrapper, given the on-chain `wrapperData`.
    /// @dev Mirrors exactly what `_wrap` commits (and what `isValidSignature` later requires via transient
    ///      storage), so off-chain order validation can verify a submitted order's `orderAppData` without
    ///      needing this wrapper's Solidity ABI. `wrapperData` is laid out as `nestedAppData(32) ‖ params`.
    function computeOrderAppData(bytes calldata wrapperData) external view returns (bytes32) {
        return _computeOrderAppData(wrapperData[32:], bytes32(wrapperData[:32]));
    }

    /// @dev Hashes the `WrapperAndAppData` envelope into the `orderAppData`:
    ///      keccak256(WRAPPER_AND_APP_DATA_TYPE_HASH ‖ nestedAppData ‖ keccak256(_wrapperSigningData(params))).
    function _computeOrderAppData(bytes calldata wrapperParams, bytes32 nestedAppData) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                WRAPPER_AND_APP_DATA_TYPE_HASH, nestedAppData, keccak256(_wrapperSigningData(wrapperParams))
            )
        );
    }

    function _authedWrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        virtual;

    /// @notice Returns the effective EIP-712 signing data for this wrapper's raw wrapper-specific data.
    /// @dev `keccak256` of the returned value MUST equal the EIP-712 `hashStruct` of the wrapper's nested
    ///      data type, i.e. `keccak256(typeHash ‖ encodeData)`. Per EIP-712, `encodeData` inlines static
    ///      fields and replaces every dynamic value (string, bytes, array, sub-struct) with its keccak256
    ///      hash. If the raw wrapperData contains no nested/dynamic properties it is already in EIP-712
    ///      encoded form (a type hash followed by static words) and can be returned unchanged.
    /// @param wrapperData The raw wrapper-specific data (the bytes following the 32-byte `nestedAppData`
    ///        prefix). This is the same slice handed to `_authedWrap`, so it may carry raw dynamic values
    ///        for the wrapper's own use even though only their hashes are committed into the signature.
    /// @return The EIP-712 signing data whose keccak256 is the nested-struct hash committed into the signature.
    function _wrapperSigningData(bytes calldata wrapperData) internal view virtual returns (bytes memory);

    /// @notice Returns the account that must have authorized the order currently being validated — i.e. the
    ///         account whose ECDSA signature must recover, or whose pre-approved hash must be set, in
    ///         `isValidSignature`.
    /// @dev This is an authorization identity and is intentionally decoupled from CoW's notion of the order
    ///      owner (the EIP-1271 verifier, which is always THIS wrapper and is where sell tokens are pulled
    ///      from). The default reads the 20 bytes at the sellToken position of the supplied order data, which
    ///      suits simple demos where the sell token doubles as the authorizer. Wrappers with a real ownership
    ///      model (e.g. a Safe that pre-approved the digest) should override this to return that identity.
    /// @param signatureData The full `isValidSignature` signature payload (65-byte ECDSA slot followed by the
    ///        order `encodeData`), so overrides may derive the owner from any order field if desired.
    function _authorizingOwner(bytes calldata signatureData) internal view virtual returns (address) {
        return address(bytes20(signatureData[77:97]));
    }

    /// @notice Implements EIP1271 `isValidSignature`. This function expects a 65 byte RSV signature, followed by the 416 byte CoW order data.
    /// The signature should be the same as the EIP-712 hash normally given to the settlement contract, except the domain separator should be `WRAPPER_DOMAIN_SEPARATOR()` from this contract.
    /// The provided order data needs to match up with the currently processed order, as its orderDigest will be checked to match against the `orderDigest` provided by the settlement contract.
    /// @dev A large portion of this code was copied from `GPv2Signer`'s' `ecdsaRecover` function. The idea is that the same signature the user would use. However, the order could be replayed between the wrapper/user account's orders if we use the orderDigest as is, so we recompute the order digest using a new domain separator for the Wrapper
    /// for a regular CoW order is also used here.
    /// @param orderDigest the order digest as recognized by the settlement contract. This is used to prevent replay attacks with other orders, as we check that the order data provided in the signature data matches up with this digest.
    /// @param signatureData A bytes data with the following encoding:
    /// --------------------
    /// | ecdsa signature | encodeData for CoW order |
    /// | 65 bytes        | 384 bytes                |
    /// The order's `appData` field (word 6 of encodeData) carries the `orderAppData`.
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

            // Ensure the orderAppData carried by the order (word 6 of encodeData) is one this wrapper
            // committed to in `_wrap` (recorded in transient storage), binding the order to our params.
            {
                bytes32 orderAppData = bytes32(signatureData[65 + 32 * 6:65 + 32 * 7]);

                assembly {
                    orderAppData := tload(orderAppData)
                }

                require(orderAppData != bytes32(0), InvalidSignatureOrderData(signatureData));
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

        // The account that must have authorized this order (ECDSA signer or pre-approved-hash owner).
        address owner = _authorizingOwner(signatureData);

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
