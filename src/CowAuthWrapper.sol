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

    /// @dev Canonical CoW `Order` type hash.
    bytes32 internal constant ORDER_TYPE_HASH = keccak256(
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
    );

    /// @dev The EIP-712 `Order` struct definition
    string internal constant ORDER_TYPE_STRING =
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,WrapperAndAppData wrapperAndAppData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)";

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
    function computeOrderAppData(string calldata nestedAppData, bytes calldata wrapperParams)
        external
        view
        returns (bytes32);
}

/// @notice
abstract contract CowAuthWrapper is CowWrapper, PreApprovedHashes, IERC1271, IERC165 {
    error Unauthorized(address);
    /// @dev The order's on-chain `appData` field does not match the WrapperAndAppData envelope derived from
    ///      the (trusted) wrapperData — the solver's params are not the ones the user signed over.
    error OrderAppDataMismatch(bytes32 computed, bytes32 orderAppData);
    /// @dev `wrapperData` handed to `_wrap` is shorter than `nestedAppData(32) ‖ orderData(384) ‖ signature(65)`.
    error InvalidWrapperData(bytes wrapperData);
    /// @dev `isValidSignature` was invoked for a digest `_wrap` never committed in this transaction.
    error UnknownOrder(bytes32 orderDigest);
    /// @dev After settlement returned, the order this wrapper authorized was not actually filled
    error OrderNotFilled(bytes32 settlementOrderDigest);

    /// @dev Transient-storage namespace for recalling orders which have been approved during isValidSignature
    bytes32 private constant _PENDING_WRAPPER_DIGEST_NS = keccak256("CowAuthWrapper.pending.wrapperOrderDigest");

    bytes32 public immutable WRAPPER_DOMAIN_SEPARATOR;
    bytes32 public immutable SETTLEMENT_DOMAIN_SEPARATOR;
    bytes32 public immutable ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH;
    bytes32 public immutable WRAPPER_AND_APP_DATA_TYPE_HASH;

    /// @param wrapperStructDef The FULL EIP-712 definition of the `WrapperAndAppData` struct — i.e.
    ///        `"WrapperAndAppData(bytes32 nestedAppData,<PrimaryParamsType> <name>)"` — where the concrete
    ///        wrapper's own params struct is the second field. Example:
    ///        `"WrapperAndAppData(bytes32 nestedAppData,MetaOrder metaOrder)"`.
    /// @param referencedTypeDefs The concrete wrapper's referenced struct definitions, concatenated in EIP-712
    ///        CANONICAL (alphabetical-by-type-name) order and each sorting BEFORE "WrapperAndAppData". Example:
    ///        `"MetaOrder(...)SafeTx(...)"`.
    /// @dev Both EIP-712 type hashes are assembled here in canonical (alphabetical) referenced-type order, so
    ///      a standard wallet's `eth_signTypedData_v4` (which always sorts referenced types alphabetically)
    ///      reproduces the wrapper order digest exactly — enabling structured signing (not just raw-hash /
    ///      pre-approval). For the Order type the referenced set is `{MetaOrder, SafeTx, WrapperAndAppData}`;
    ///      since "WrapperAndAppData" sorts last, it comes after `referencedTypeDefs`.
    constructor(string memory wrapperStructDef, string memory referencedTypeDefs, ICowSettlement settlement)
        CowWrapper(settlement)
    {
        WRAPPER_DOMAIN_SEPARATOR = CowAuthLibrary.computeDomainSeparator(address(this));

        SETTLEMENT_DOMAIN_SEPARATOR = SETTLEMENT.domainSeparator();

        // Order type: Order(...) ‖ MetaOrder(...) ‖ SafeTx(...) ‖ WrapperAndAppData(...) — canonical.
        ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH =
            keccak256(abi.encodePacked(CowAuthLibrary.ORDER_TYPE_STRING, referencedTypeDefs, wrapperStructDef));

        // WrapperAndAppData type: WrapperAndAppData(...) ‖ MetaOrder(...) ‖ SafeTx(...) — canonical.
        WRAPPER_AND_APP_DATA_TYPE_HASH = keccak256(abi.encodePacked(wrapperStructDef, referencedTypeDefs));
    }

    /// @inheritdoc IERC165
    /// @dev Advertises the auth-wrapper capability so backends can distinguish it from a plain CowWrapper.
    ///      `virtual` so concrete wrappers may advertise additional interfaces.
    function supportsInterface(bytes4 interfaceId) public pure virtual override returns (bool) {
        return interfaceId == type(ICowAuthWrapper).interfaceId || interfaceId == type(IERC1271).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    /// @notice CoW wrapper entry point for an auth-wrapped order.
    /// @dev Unpacks the relevant data, authorizes it through _commitOrder, calls _authedWrap
    ///      with the validated signedWrapperData, and validates that the settlement actually executed
    ///      the order with a check on the filledAmount.
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        require(wrapperData.length >= 32 + 384 + 65, InvalidWrapperData(wrapperData));

        // Unpack
        bytes calldata signature = wrapperData[32 + 384:32 + 384 + 65];
        bytes calldata wrapperParams = wrapperData[32 + 384 + 65:];

        // Perform the validations
        (bytes memory orderUid, uint256 filledBefore, bytes32 settlementOrderDigest) =
            _commitOrder(wrapperData[32:32 + 384], wrapperParams, bytes32(wrapperData[:32]), signature);

        // Execute this wrapper's payload operation and continue the chain
        _authedWrap(settleData, wrapperParams, remainingWrapperData);

        // Confirm the settlement actually filled the order we expected.
        require(SETTLEMENT.filledAmount(orderUid) > filledBefore, OrderNotFilled(settlementOrderDigest));
    }

    /// @dev Validates the order against the wrapper params, verifies the owner's authorization over the
    ///      wrapper-domain order digest, records that digest in transient storage (keyed by the settlement digest
    ///      GPv2 will pass to `isValidSignature`), and returns the GPv2 orderUid plus its current filled amount
    ///      so `_wrap` can confirm the order was actually executed.
    /// @param orderData The 384-byte order orderData.
    /// @param wrapperParams The raw wrapper-specific params.
    /// @param nestedAppData The ordinary CoW app-data hash committed inside the WrapperAndAppData envelope.
    /// @param signature The 65-byte `[r ‖ s ‖ v]` owner authorization over the wrapper order digest. `v == 0`
    ///        selects the pre-approved-hash path.
    function _commitOrder(
        bytes calldata orderData,
        bytes calldata wrapperParams,
        bytes32 nestedAppData,
        bytes calldata signature
    ) private returns (bytes memory orderUid, uint256 filledBefore, bytes32 settlementOrderDigest) {
        // Verify that the nestedAppData corresponds with the appData in the order
        {
            bytes32 orderAppData = _computeOrderAppData(nestedAppData, wrapperParams);
            bytes32 orderAppDataInOrder = bytes32(orderData[6 * 32:7 * 32]);
            require(orderAppData == orderAppDataInOrder, OrderAppDataMismatch(orderAppData, orderAppDataInOrder));
        }

        // Recompute the settlement- and wrapper-domain order digests from the order data.
        bytes32 wrapperOrderDigest;
        (settlementOrderDigest, wrapperOrderDigest) = _computeOrderDigests(orderData);

        // Verify the wrapperOrderDigest was signed by _authorizingOwner
        {
            address owner = _authorizingOwner(orderData, wrapperParams);
            if (signature[64] == 0) {
                // no ECDSA signature provided, so it has to be a pre-approved hash
                require(isHashPreApproved(owner, wrapperOrderDigest), Unauthorized(owner));
            } else {
                address signer = ECDSA.recoverCalldata(wrapperOrderDigest, signature);
                require(signer == owner, Unauthorized(signer));
            }
        }

        // Authorize the settlementOrderDigest for trading
        {
            bytes32 digestSlot = _pendingSlot(settlementOrderDigest);
            assembly {
                tstore(digestSlot, wrapperOrderDigest)
            }
        }

        // We also need the order UID to check the order trade status
        orderUid = abi.encodePacked(
            settlementOrderDigest,
            _settlementOrderOwner(orderData, wrapperParams),
            uint32(uint256(bytes32(orderData[32 * 5:32 * 6])))
        );
        filledBefore = SETTLEMENT.filledAmount(orderUid);
    }

    /// @notice Computes the `orderAppData` (`hashStruct(WrapperAndAppData)`) that the CoW order MUST carry in
    ///         its `appData` field to settle through this wrapper, given the `nestedAppData ‖ wrapperParams`
    ///         commitment tuple.
    function computeOrderAppData(string calldata nestedAppData, bytes calldata wrapperParams)
        external
        view
        returns (bytes32)
    {
        return _computeOrderAppData(keccak256(bytes(nestedAppData)), wrapperParams);
    }

    /// @dev Hashes the `WrapperAndAppData` envelope into the `orderAppData`:
    ///      keccak256(WRAPPER_AND_APP_DATA_TYPE_HASH ‖ nestedAppData ‖ keccak256(_wrapperSigningData(wrapperParams))).
    function _computeOrderAppData(bytes32 nestedAppData, bytes calldata wrapperParams) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                WRAPPER_AND_APP_DATA_TYPE_HASH, nestedAppData, keccak256(_wrapperSigningData(wrapperParams))
            )
        );
    }

    function _authedWrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        virtual;

    /// @notice Returns the effective EIP-712 data which should be supplied directly to EIP-712 `hashStruct()`.
    /// @dev `keccak256` of the returned value MUST equal the EIP-712 `hashStruct` of the wrapper's nested
    ///      data type, i.e. `keccak256(typeHash ‖ wrapperData)`'. Per EIP-712, `wrapperData` inlines static
    ///      fields and replaces every dynamic value (string, bytes, array, sub-struct) with its keccak256
    ///      hash. If the raw wrapperData contains no nested/dynamic properties, it is already in EIP-712
    ///      encoded form (a type hash followed by static words) and can be directly returned unchanged.
    /// @return The EIP-712 hashStruct of the wrapper data.
    function _wrapperSigningData(bytes calldata wrapperData) internal view virtual returns (bytes memory);

    /// @notice Returns the account that must have authorized the order currently being wrapped — i.e. the
    ///         account whose ECDSA signature must recover, or whose pre-approved hash must be set, when
    ///         `_wrap` verifies the owner authorization.
    /// @dev This is an authorization identity and is intentionally decoupled from CoW's notion of the order
    ///      owner (the EIP-1271 verifier, which is defined by `_settlementOrderOwner` and is CoW Settlement pulls
    ///      the sell tokens).
    function _authorizingOwner(
        bytes calldata,
        /* orderData */
        bytes calldata /* wrapperParams */
    )
        internal
        view
        virtual
        returns (address);

    /// @notice Returns the account CoW Protocol treats as the order's owner — the EIP-1271 verifier GPv2
    ///         calls `isValidSignature` on, and the account GPv2 pulls the order's sell tokens from. It is
    ///         woven into the `orderUid` the fill check keys on, so it MUST equal the address GPv2 derives as
    ///         the owner from the trade's EIP-1271 signature.
    /// @dev In most cases, `address(this)` should be returned by this function. However, if a smart contract
    ///      account which is simply forwarding its order validation via `isValidSignature`, then the appropriate
    ///      smart contract account address should be returned instead.
    function _settlementOrderOwner(
        bytes calldata,
        /* orderData */
        bytes calldata /* wrapperParams */
    )
        internal
        view
        virtual
        returns (address)
    {
        return address(this);
    }

    /// @notice Recomputes the settlement- and wrapper-domain EIP-712 order digests from an order's orderData.
    /// @dev A large portion of this was copied from `GPv2Signer`'s `ecdsaRecover`: the wrapper-domain digest
    ///      is the same shape a regular CoW signature uses, except the domain separator is this wrapper's.
    ///      Using a distinct domain separator prevents an order signed for the wrapper from being replayed as
    ///      a plain CoW order (and vice-versa). Both digests are computed here because `_wrap` needs the
    ///      settlement one (to build the orderUid / key the transient commitment that GPv2 will look up) and
    ///      the wrapper one (what the user actually signs, verified in `isValidSignature`).
    /// @param orderData The 384-byte order data (12 fields * 32 bytes). Its string fields (kind,
    ///        sellTokenBalance, buyTokenBalance) are assumed already pre-hashed to bytes32 per EIP-712.
    /// @return settlementOrderDigest The digest GPv2 recognizes (settlement domain separator).
    /// @return wrapperOrderDigest The digest the order owner signs / pre-approves (wrapper domain separator).
    function _computeOrderDigests(bytes calldata orderData)
        internal
        view
        returns (bytes32 settlementOrderDigest, bytes32 wrapperOrderDigest)
    {
        // Copy the calldata order data into memory so we can prefix the EIP-712 type hash in place.
        bytes memory orderDataMem = orderData;
        bytes32 settlementTypeHash = CowAuthLibrary.ORDER_TYPE_HASH;
        bytes32 wrapperTypeHash = ORDER_PLUS_WRAPPER_AND_APP_DATA_TYPE_HASH;
        bytes32 settlementStructHash;
        bytes32 wrapperStructHash;

        // NOTE: Compute the EIP-712 order struct hash in place. As suggested in the EIP proposal, noting the
        // order struct has 12 fields, prefixing the type hash gives `(1 + 12) * 32 = 416` bytes to hash.
        // <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#rationale-for-encodedata>
        assembly {
            let originalLength := mload(orderDataMem)
            mstore(orderDataMem, settlementTypeHash)
            settlementStructHash := keccak256(orderDataMem, 416)
            mstore(orderDataMem, wrapperTypeHash)
            wrapperStructHash := keccak256(orderDataMem, 416)
            mstore(orderDataMem, originalLength)
        }

        bytes32 settlementDomainSeparator = SETTLEMENT_DOMAIN_SEPARATOR;
        bytes32 wrapperDomainSeparator = WRAPPER_DOMAIN_SEPARATOR;

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
    }

    /// @dev Derives the transient-storage slot that carries the pending order's verified wrapper digest from
    ///      `_wrap` to `isValidSignature`, namespaced by `settlementOrderDigest` so it never collides with
    ///      transient slots a concrete wrapper might use.
    function _pendingSlot(bytes32 settlementOrderDigest) private pure returns (bytes32 digestSlot) {
        // forge-lint: disable-next-line(asm-keccak256)
        digestSlot = keccak256(abi.encodePacked(_PENDING_WRAPPER_DIGEST_NS, settlementOrderDigest));
    }

    /// @notice Implements EIP-1271 `isValidSignature`, called by GPv2 during `settle` for the order this
    ///         wrapper verifies. It confirms `_wrap` committed exactly this order earlier in the same
    ///         transaction and returns the magic value. If the settlement attempts to fill with an unexpected
    ///         order, this function will fail. If the settlement doesn't execute the
    ///.        order as expected, _wrap will fail its post-check.
    /// @param orderDigest The order digest as recognized by the settlement contract.
    function isValidSignature(
        bytes32 orderDigest,
        bytes calldata /* signatureData */
    )
        external
        view
        returns (bytes4 magicValue)
    {
        bytes32 digestSlot = _pendingSlot(orderDigest);
        bytes32 wrapperOrderDigest;
        assembly {
            wrapperOrderDigest := tload(digestSlot)
        }

        // A zero digest means `_wrap` did not commit this exact order in this transaction.
        require(wrapperOrderDigest != bytes32(0), UnknownOrder(orderDigest));

        return IERC1271.isValidSignature.selector;
    }
}
