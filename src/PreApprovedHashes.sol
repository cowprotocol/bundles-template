// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

/// @title PreApprovedHashes
/// @notice Abstract contract for managing pre-approved operation hashes
/// @dev Allows users to pre-approve specific operations without requiring signatures each time
abstract contract PreApprovedHashes {
    /// @dev Marker value indicating a hash is pre-approved
    uint256 internal constant PRE_APPROVED = uint256(keccak256("PreApprovedHashes.PreApproved"));
    uint256 internal constant CONSUMED = uint256(keccak256("PreApprovedHashes.Consumed"));

    /// @notice Storage indicating whether or not a signed calldata hash has been approved by an owner
    /// @dev Maps owner -> hash(orderParameters) -> approval status
    mapping(address => mapping(bytes32 => uint256)) public preApprovedHashes;

    /// @notice Event emitted when an owner pre-approves or revokes a hash
    event PreApprovedHash(address indexed owner, bytes32 indexed hash, bool approved);

    /// @notice Event emitted when a pre-approved hash is used and is no longer valid because its consumed
    event PreApprovedHashConsumed(address indexed owner, bytes32 indexed hash);

    /// @notice Revert reason given when a hash has already been consumed, and therefore cannot be used
    /// @dev If the hash had simply never been approved in the first place, the error will be HashNotApproved
    error AlreadyConsumed(address owner, bytes32 hash);

    /// @notice Revert reason given when a pre approved hash is being consumed, but it hasnt actually been approved.
    /// @dev If the hash has been approved in the past, but it was consumed, the error will be AlreadyConsumed
    error HashNotApproved(address owner, bytes32 hash);

    /// @notice Pre-approve a hash of signed calldata for future execution, or permanently revoke it.
    /// @dev Once a hash is pre-approved, it can only be consumed once. This prevents replay attacks.
    /// @dev Even if the hash hasn't already been pre-approved, it can still be consumed by calling this function with approved=false.
    /// The idea here is to prevent any future delayed approval (ex. through EIP-4337 or other gassless execution or settlement service) of the same hash, effectively allowing "cancel" functionality.
    /// @param hash The keccak256 hash of the order parameters
    /// @param approved True to approve the hash, false to revoke approval or prevent a future approval.
    function setPreApprovedHash(bytes32 hash, bool approved) external {
        require(preApprovedHashes[msg.sender][hash] != CONSUMED, AlreadyConsumed(msg.sender, hash));

        if (approved) {
            preApprovedHashes[msg.sender][hash] = PRE_APPROVED;
        } else {
            preApprovedHashes[msg.sender][hash] = CONSUMED;
        }
        emit PreApprovedHash(msg.sender, hash, approved);
    }

    /// @notice Check if a hash is pre-approved for an owner
    /// @param owner The owner address
    /// @param hash The hash to check
    /// @return True if the hash is pre-approved, false otherwise
    function isHashPreApproved(address owner, bytes32 hash) public view returns (bool) {
        return preApprovedHashes[owner][hash] == PRE_APPROVED;
    }

    /// @notice Check if a hash is pre-approved for an owner. If it is, changes it to be consumed.
    /// @param owner The owner address
    /// @param hash The hash to check
    function _consumePreApprovedHash(address owner, bytes32 hash) internal {
        if (preApprovedHashes[owner][hash] == PRE_APPROVED) {
            preApprovedHashes[owner][hash] = CONSUMED;
            emit PreApprovedHashConsumed(owner, hash);
        } else if (preApprovedHashes[owner][hash] == CONSUMED) {
            revert AlreadyConsumed(owner, hash);
        } else {
            revert HashNotApproved(owner, hash);
        }
    }
}
