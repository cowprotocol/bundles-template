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

    /// @dev The EIP-712 `Order` struct definition (type string up to and including its own closing paren).
    /// We replace the order's `appData` field with a `WrapperAndAppData wrapperAndAppData` struct so the wrapper
    /// can bind additional data into the signature; the `orderAppData` the order commits to becomes
    /// `hashStruct(WrapperAndAppData)`. The rest of the type is identical to the settlement's. The referenced
    /// struct definitions are appended by the constructor in EIP-712 CANONICAL (alphabetical) order so a
    /// standard wallet's `eth_signTypedData_v4` reproduces the wrapper order digest.
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
    /// @dev `wrapperData` handed to `_wrap` is shorter than `nestedAppData(32) ‖ orderData(384) ‖ signature(65)`.
    error InvalidWrapperData(bytes wrapperData);
    /// @dev `isValidSignature` was invoked for a digest `_wrap` never committed in this transaction.
    error UnknownOrder(bytes32 orderDigest);
    /// @dev After settlement returned, the order this wrapper authorized was not actually filled — so we
    ///      cannot conclude `isValidSignature` ran. See the guarantee documented on `_wrap`.
    error OrderNotFilled(bytes32 settlementOrderDigest);

    /// @dev Transient-storage namespace. The per-order slot is `keccak256(namespace ‖ settlementOrderDigest)`
    ///      so the value `_wrap` hands to `isValidSignature` cannot collide with transient slots a concrete
    ///      wrapper might use.
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
    /// @dev In this design both the order the user signed (its 384-byte EIP-712 `orderData`) AND the owner's
    ///      65-byte authorization signature over the wrapper order digest are carried in `wrapperData` rather
    ///      than in the EIP-1271 `signatureData` GPv2 forwards to `isValidSignature`. This lets the wrapper
    ///      compute the settlement order digest itself and — critically — verify the owner's authorization
    ///      HERE, in the wrapper's own execution frame, BEFORE `_authedWrap` runs any side effects.
    ///
    ///      SECURITY GUARANTEE (authorization cannot be bypassed): the owner authorization (ECDSA signature or
    ///      pre-approved hash over the wrapper order digest) is verified in `_commitOrder`, which runs before
    ///      `_authedWrap`. Previously this verification lived in `isValidSignature`, reached only via GPv2 →
    ///      the owner account's EIP-1271 entry point (for `CoWSafeWrapper`, the Safe's fallback handler → this
    ///      wrapper). That made it subvertible: a solver-chosen `pre` interaction executed as the owner account
    ///      could change that account's authentication (e.g. repoint the Safe's fallback handler at an attacker
    ///      contract that returns the magic value unconditionally), so `isValidSignature` — and with it the
    ///      whole authorization check — was skipped while `_authedWrap`'s side effects (and the fill) still
    ///      happened. Verifying in `_wrap` closes that: `_authedWrap` (hence any owner-account-authentication
    ///      change in `pre`) only runs AFTER a valid owner authorization for exactly this order is proven, and
    ///      that proof does not route through the owner account at all.
    ///
    ///      The fill check (`filledAmount` rose) is retained as a separate guarantee that the intended order
    ///      actually settled: GPv2 only increments `filledAmount` after executing the order, and the `orderUid`
    ///      pins `owner = _settlementOrderOwner(...)` (each concrete wrapper states it explicitly). So the
    ///      owner-authorized `pre`/`post` can never run around a no-op settle.
    ///
    ///      wrapperData layout: `nestedAppData(32) ‖ orderData(384) ‖ signature(65) ‖ params`.
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        require(wrapperData.length >= 32 + 384 + 65, InvalidWrapperData(wrapperData));

        bytes calldata signature = wrapperData[32 + 384:32 + 384 + 65];
        bytes calldata params = wrapperData[32 + 384 + 65:];

        // Validate the order, verify the owner's authorization, commit what `isValidSignature` needs to
        // transient storage, and read the pre-settlement filled amount for the order's uid. Split into a helper
        // to keep `_wrap` within the EVM stack limit (the default profile compiles without via-IR).
        (bytes memory orderUid, uint256 filledBefore, bytes32 settlementOrderDigest) =
            _commitOrder(wrapperData[32:32 + 384], params, bytes32(wrapperData[:32]), signature);

        _authedWrap(settleData, params, remainingWrapperData);

        // Confirm the settlement actually filled THIS order (see SECURITY GUARANTEE above). The transient
        // slots set by `_commitOrder` are left as-is; transient storage auto-clears at the end of the tx.
        require(SETTLEMENT.filledAmount(orderUid) > filledBefore, OrderNotFilled(settlementOrderDigest));
    }

    /// @dev Validates the order against the wrapper params, verifies the owner's authorization over the
    ///      wrapper-domain order digest (the check moved here from `isValidSignature` — see the SECURITY
    ///      GUARANTEE on `_wrap`), records that digest in transient storage (keyed by the settlement digest
    ///      GPv2 will pass to `isValidSignature`), and returns the GPv2 orderUid plus its current filled amount
    ///      so `_wrap` can confirm the fill.
    /// @param orderData The 384-byte order orderData.
    /// @param params The raw wrapper-specific params.
    /// @param nestedAppData The ordinary CoW app-data hash committed inside the WrapperAndAppData envelope.
    /// @param signature The 65-byte `[r ‖ s ‖ v]` owner authorization over the wrapper order digest. `v == 0`
    ///        selects the pre-approved-hash path.
    function _commitOrder(bytes calldata orderData, bytes calldata params, bytes32 nestedAppData, bytes calldata signature)
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

        // Recompute the settlement- and wrapper-domain order digests from the order data.
        bytes32 wrapperOrderDigest;
        (settlementOrderDigest, wrapperOrderDigest) = _computeOrderDigests(orderData);

        // Verify the order owner's authorization over the wrapper order digest HERE — before any side effects
        // run (see the SECURITY GUARANTEE on `_wrap`). The owner is the account whose ECDSA signature must
        // recover, or whose pre-approved hash must be set, as stated by the concrete wrapper.
        {
            address owner = _authorizingOwner(orderData, params);
            if (signature[64] == 0) {
                // no ECDSA signature provided, so it has to be a pre-approved hash
                require(isHashPreApproved(owner, wrapperOrderDigest), Unauthorized(owner));
            } else {
                address signer = ECDSA.recoverCalldata(wrapperOrderDigest, signature);
                require(signer == owner, Unauthorized(signer));
            }
        }

        // Stash the verified wrapper digest keyed by the digest GPv2 will pass to the EIP-1271 callback, so
        // that in the honest (untampered) flow `isValidSignature` blesses ONLY this order.
        {
            bytes32 digestSlot = _pendingSlot(settlementOrderDigest);
            assembly {
                tstore(digestSlot, wrapperOrderDigest)
            }
        }

        // GPv2 orderUid = orderDigest ‖ owner ‖ validTo. validTo is word 5 of orderData (a uint32 stored
        // right-aligned in its 32-byte word, so read the whole word and downcast — do NOT read the leading
        // 4 bytes, which are zero). The owner is the account CoW treats as the order owner, stated explicitly
        // by the concrete wrapper via `_settlementOrderOwner` (CoWSafeWrapper → the position Safe). See the
        // SECURITY GUARANTEE on `_wrap`.
        orderUid = abi.encodePacked(
            settlementOrderDigest,
            _settlementOrderOwner(orderData, params),
            uint32(uint256(bytes32(orderData[32 * 5:32 * 6])))
        );
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
    ///         account whose ECDSA signature must recover, or whose pre-approved hash must be set, when
    ///         `_wrap` verifies the owner authorization.
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

    /// @notice Returns the account CoW Protocol treats as the order's owner — the EIP-1271 verifier GPv2
    ///         calls `isValidSignature` on, and the account GPv2 pulls the order's sell tokens from. It is
    ///         woven into the `orderUid` the fill check keys on, so it MUST equal the address GPv2 derives as
    ///         the owner from the trade's EIP-1271 signature.
    /// @dev Intentionally abstract — this is security-critical and must never be assumed. Each concrete
    ///      wrapper states its owner explicitly: a wrapper that is itself the verifier and sell-token source
    ///      returns `address(this)`; one whose funds and signature live on a controlled smart account (e.g.
    ///      `CoWSafeWrapper`, where the position Safe holds the sell tokens and forwards `isValidSignature` to
    ///      the wrapper via its fallback handler) returns that account. The returned account must be a keyless
    ///      contract for the fill-check guarantee to hold (see the SECURITY GUARANTEE on `_wrap`).
    /// @param orderData The 384-byte EIP-712 order data carried in the wrapperData.
    /// @param params The raw wrapper-specific params (e.g. abi.encode(MetaOrder)), which overrides can decode.
    function _settlementOrderOwner(bytes calldata orderData, bytes calldata params)
        internal
        view
        virtual
        returns (address);

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
    ///         transaction and returns the magic value.
    /// @dev The owner authorization is NO LONGER checked here — `_wrap` received the order and the owner's
    ///      65-byte signature in `wrapperData`, verified the authorization in its own execution frame, and
    ///      stashed the verified wrapper digest in transient storage keyed by the settlement order digest (see
    ///      the SECURITY GUARANTEE on `_wrap` for why the check moved). GPv2 passes that same settlement digest
    ///      as `orderDigest`, so a missing (zero) entry means either `_wrap` never committed this order or the
    ///      settle trade's order fields differ from the wrapperData (their digests would differ) — both are
    ///      rejected, so GPv2 blesses only the exact order `_wrap` authorized. The `signatureData` GPv2
    ///      forwards is unused: the authorization no longer depends on it (or on being reached through the
    ///      owner account's EIP-1271 entry point at all).
    /// @param orderDigest The order digest as recognized by the settlement contract.
    function isValidSignature(bytes32 orderDigest, bytes calldata /* signatureData */ )
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
