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
    ///         its `appData` field to settle through this wrapper, given the `nestedAppData ‖ params`
    ///         commitment tuple. Lets off-chain order validation verify a submitted order's `orderAppData`
    ///         without needing this wrapper's Solidity ABI.
    /// @dev NOTE: the argument is the pre-order commitment (`nestedAppData(32) ‖ params`), which off-chain
    ///      code has *before* building the order. It is NOT the on-chain `wrapperData` handed to `_wrap`,
    ///      which additionally embeds the 384-byte order orderData between the two (see `_wrap`).
    function computeOrderAppData(bytes calldata nestedAppDataAndParams) external view returns (bytes32);
}

/// @notice
abstract contract CowAuthWrapper is CowWrapper, PreApprovedHashes, IERC1271, IERC165 {
    error Unauthorized(address);
    /// @dev The order's on-chain `appData` field does not match the WrapperAndAppData envelope derived from
    ///      the (trusted) wrapperData — the solver's params are not the ones the user signed over.
    error OrderAppDataMismatch(bytes32 computed, bytes32 orderAppData);
    /// @dev `wrapperData` handed to `_wrap` is shorter than `nestedAppData(32) ‖ orderData(384)`.
    error InvalidWrapperData(bytes wrapperData);
    /// @dev The `signatureData` handed to `isValidSignature` is shorter than the 65-byte ECDSA slot.
    error InvalidSignature(bytes signatureData);
    /// @dev `isValidSignature` was invoked for a digest `_wrap` never committed in this transaction.
    error UnknownOrder(bytes32 orderDigest);
    /// @dev After settlement returned, the order this wrapper authorized was not actually filled — so we
    ///      cannot conclude `isValidSignature` ran. See the guarantee documented on `_wrap`.
    error OrderNotFilled(bytes32 settlementOrderDigest);

    /// @dev Transient-storage namespaces. Per-order slots are `keccak256(namespace ‖ settlementOrderDigest)`
    ///      so the two values `_wrap` hands to `isValidSignature` cannot collide with each other or with
    ///      transient slots a concrete wrapper might use.
    bytes32 private constant _PENDING_WRAPPER_DIGEST_NS = keccak256("CowAuthWrapper.pending.wrapperOrderDigest");
    bytes32 private constant _PENDING_OWNER_NS = keccak256("CowAuthWrapper.pending.owner");

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

    /// @notice CoW wrapper entry point for an auth-wrapped order.
    /// @dev New in this design: the order the user signed (its 384-byte EIP-712 `orderData`) is carried in
    ///      `wrapperData` rather than in the EIP-1271 `signatureData`. This lets the wrapper compute the
    ///      settlement order digest itself, and — after settlement returns — confirm on the settlement
    ///      contract that this exact order was filled.
    ///
    ///      SECURITY GUARANTEE (why the fill check is sound): GPv2 only increments `filledAmount` for an
    ///      order after it has been executed, and for an EIP-1271 order it executes only after
    ///      `isValidSignature` returns the magic value. The `orderUid` we check pins `owner = address(this)`
    ///      (CoW's order owner is the EIP-1271 verifier, i.e. this wrapper). An `eip712` order cannot have a
    ///      keyless contract as owner, and a `presign` order with this wrapper as owner is unreachable
    ///      (`setPreSignature` requires `msg.sender == owner`, and the wrapper never calls it). So the only
    ///      way `filledAmount[orderUid]` can rise is the eip1271 path, which forces our `isValidSignature`
    ///      to have run and passed for exactly `settlementOrderDigest`. This closes the previous gap where a
    ///      solver could settle without ever triggering our authorization yet still benefit from
    ///      `_authedWrap`'s side effects. It also means an auth wrapper only authorizes orders for which it
    ///      is itself the verifier/owner (relevant when chaining wrappers).
    ///
    ///      wrapperData layout: `nestedAppData(32) ‖ orderData(384) ‖ params`.
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        require(wrapperData.length >= 32 + 384, InvalidWrapperData(wrapperData));

        bytes calldata params = wrapperData[32 + 384:];

        // Validate the order, commit what `isValidSignature` needs to transient storage, and read the
        // pre-settlement filled amount for the order's uid. Split into a helper to keep `_wrap` within the
        // EVM stack limit (the default profile compiles without via-IR).
        (bytes memory orderUid, uint256 filledBefore, bytes32 settlementOrderDigest) =
            _commitOrder(wrapperData[32:32 + 384], params, bytes32(wrapperData[:32]));

        _authedWrap(settleData, params, remainingWrapperData);

        // Confirm the settlement actually filled THIS order (see SECURITY GUARANTEE above). The transient
        // slots set by `_commitOrder` are left as-is; transient storage auto-clears at the end of the tx.
        require(SETTLEMENT.filledAmount(orderUid) > filledBefore, OrderNotFilled(settlementOrderDigest));
    }

    /// @dev Validates the order against the wrapper params, records the wrapper-domain digest + authorizing
    ///      owner in transient storage (keyed by the settlement digest GPv2 will pass to `isValidSignature`),
    ///      and returns the GPv2 orderUid plus its current filled amount so `_wrap` can confirm the fill.
    /// @param orderData The 384-byte order orderData.
    /// @param params The raw wrapper-specific params.
    /// @param nestedAppData The ordinary CoW app-data hash committed inside the WrapperAndAppData envelope.
    function _commitOrder(bytes calldata orderData, bytes calldata params, bytes32 nestedAppData)
        private
        returns (bytes memory orderUid, uint256 filledBefore, bytes32 settlementOrderDigest)
    {
        // Bind the solver-supplied params to the user-signed order: the order's `appData` field (word 6 of
        // orderData) MUST equal the WrapperAndAppData envelope hash derived from nestedAppData + params.
        {
            bytes32 orderAppData = _computeOrderAppData(params, nestedAppData);
            bytes32 orderAppDataInOrder = bytes32(orderData[32 * 6:32 * 7]);
            require(orderAppData == orderAppDataInOrder, OrderAppDataMismatch(orderAppData, orderAppDataInOrder));
        }

        // Recompute the settlement- and wrapper-domain order digests from the order data, then stash what
        // `isValidSignature` needs keyed by the digest GPv2 will pass to the EIP-1271 callback.
        bytes32 wrapperOrderDigest;
        (settlementOrderDigest, wrapperOrderDigest) = _computeOrderDigests(orderData);
        {
            (bytes32 digestSlot, bytes32 ownerSlot) = _pendingSlots(settlementOrderDigest);
            address owner = _authorizingOwner(orderData, params);
            assembly {
                tstore(digestSlot, wrapperOrderDigest)
                tstore(ownerSlot, owner)
            }
        }

        // GPv2 orderUid = orderDigest ‖ owner ‖ validTo. validTo is word 5 of orderData (a uint32 stored
        // right-aligned in its 32-byte word, so read the whole word and downcast — do NOT read the leading
        // 4 bytes, which are zero). The owner pinned here is this wrapper (CoW's order owner is the verifier).
        orderUid =
            abi.encodePacked(settlementOrderDigest, address(this), uint32(uint256(bytes32(orderData[32 * 5:32 * 6]))));
        filledBefore = SETTLEMENT.filledAmount(orderUid);
    }

    /// @notice Recomputes the `orderAppData` (`hashStruct(WrapperAndAppData)`) that an order MUST carry in
    ///         its `appData` field to settle through this wrapper, given the `nestedAppData ‖ params`
    ///         commitment tuple.
    /// @dev Mirrors exactly what `_wrap` requires (the order's `appData` field must equal this), so off-chain
    ///      order validation can verify a submitted order's `orderAppData` without needing this wrapper's
    ///      Solidity ABI. NOTE: the argument is `nestedAppData(32) ‖ params` — the pre-order commitment,
    ///      which off-chain code has before building the order. It is NOT the on-chain `wrapperData` handed
    ///      to `_wrap` (which additionally embeds the 384-byte order orderData between the two).
    function computeOrderAppData(bytes calldata nestedAppDataAndParams) external view returns (bytes32) {
        return _computeOrderAppData(nestedAppDataAndParams[32:], bytes32(nestedAppDataAndParams[:32]));
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
    ///      data type, i.e. `keccak256(typeHash ‖ orderData)`. Per EIP-712, `orderData` inlines static
    ///      fields and replaces every dynamic value (string, bytes, array, sub-struct) with its keccak256
    ///      hash. If the raw wrapperData contains no nested/dynamic properties it is already in EIP-712
    ///      encoded form (a type hash followed by static words) and can be returned unchanged.
    /// @param wrapperData The raw wrapper-specific params (the bytes following the `nestedAppData(32) ‖
    ///        orderData(384)` prefix). This is the same slice handed to `_authedWrap`, so it may carry
    ///        raw dynamic values for the wrapper's own use even though only their hashes are committed into
    ///        the signature.
    /// @return The EIP-712 signing data whose keccak256 is the nested-struct hash committed into the signature.
    function _wrapperSigningData(bytes calldata wrapperData) internal view virtual returns (bytes memory);

    /// @notice Returns the account that must have authorized the order currently being wrapped — i.e. the
    ///         account whose ECDSA signature must recover, or whose pre-approved hash must be set, in
    ///         `isValidSignature`.
    /// @dev This is an authorization identity and is intentionally decoupled from CoW's notion of the order
    ///      owner (the EIP-1271 verifier, which is always THIS wrapper and is where sell tokens are pulled
    ///      from). The default reads the 20 bytes at the sellToken position of the order (word 0), which
    ///      suits simple demos where the sell token doubles as the authorizer. Wrappers with a real ownership
    ///      model (e.g. a Safe that pre-approved the digest) should override this — e.g. to derive the owner
    ///      from a dedicated field carried in the (trusted, signature-bound) `params`.
    /// @param orderData The 384-byte EIP-712 order data carried in the wrapperData. The default reads the
    ///        sell token (word 0) from it; the second (unnamed) argument is the raw wrapper-specific params,
    ///        which overrides can decode to derive the owner instead.
    function _authorizingOwner(
        bytes calldata orderData,
        bytes calldata /* params */
    )
        internal
        view
        virtual
        returns (address)
    {
        return address(bytes20(orderData[12:32]));
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

    /// @dev Derives the two transient-storage slots that carry the pending order from `_wrap` to
    ///      `isValidSignature`, namespaced by `settlementOrderDigest` so they never collide with each other
    ///      or with transient slots a concrete wrapper might use.
    function _pendingSlots(bytes32 settlementOrderDigest) private pure returns (bytes32 digestSlot, bytes32 ownerSlot) {
        // forge-lint: disable-next-line(asm-keccak256)
        digestSlot = keccak256(abi.encodePacked(_PENDING_WRAPPER_DIGEST_NS, settlementOrderDigest));
        // forge-lint: disable-next-line(asm-keccak256)
        ownerSlot = keccak256(abi.encodePacked(_PENDING_OWNER_NS, settlementOrderDigest));
    }

    /// @notice Implements EIP-1271 `isValidSignature`, called by GPv2 during `settle` for the order this
    ///         wrapper verifies. It verifies the order owner's authorization (ECDSA signature or pre-approved
    ///         hash) against the wrapper-domain order digest that `_wrap` committed earlier in this same
    ///         transaction.
    /// @dev The order data is NO LONGER carried here — `_wrap` received it in `wrapperData`, computed the
    ///      wrapper-domain digest and the authorizing owner, and stashed them in transient storage keyed by
    ///      the settlement order digest. GPv2 passes that same settlement digest as `orderDigest`, so a
    ///      missing (zero) entry means either `_wrap` never committed this order or the settle trade's order
    ///      fields differ from the wrapperData (their digests would differ) — both are rejected. This
    ///      implicitly enforces the old "settlement digest matches" check.
    /// @param orderDigest The order digest as recognized by the settlement contract.
    /// @param signatureData The 65-byte `[r ‖ s ‖ v]` ECDSA signature. `v == 0` selects the pre-approved-hash
    ///        path. (The verifier address GPv2 strips from the trade signature is not included here.)
    function isValidSignature(bytes32 orderDigest, bytes calldata signatureData)
        external
        view
        returns (bytes4 magicValue)
    {
        require(signatureData.length >= 65, InvalidSignature(signatureData));

        (bytes32 digestSlot, bytes32 ownerSlot) = _pendingSlots(orderDigest);
        bytes32 wrapperOrderDigest;
        address owner;
        assembly {
            wrapperOrderDigest := tload(digestSlot)
            owner := tload(ownerSlot)
        }

        // A zero digest means `_wrap` did not commit this exact order in this transaction.
        require(wrapperOrderDigest != bytes32(0), UnknownOrder(orderDigest));

        if (signatureData[64] == 0) {
            // no ECDSA signature provided, so it has to be a pre-approved hash
            require(isHashPreApproved(owner, wrapperOrderDigest), Unauthorized(owner));
        } else {
            address signer = ECDSA.recoverCalldata(wrapperOrderDigest, signatureData[:65]);
            require(signer == owner, Unauthorized(signer));
        }

        return IERC1271.isValidSignature.selector;
    }
}
