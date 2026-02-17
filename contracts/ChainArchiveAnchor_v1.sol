// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract ChainArchiveAnchor {
    // Maximum number of slots per entry to prevent excessive gas usage in events
    uint256 public constant MAX_SLOTS = 100;

    // Custom errors
    error ArrayTooLong(uint256 provided, uint256 maximum);
    error EmptySlotsNotAllowed();

    /**
     * @dev Emitted when new data entry is anchored
     * @param id Indexed identifier
     * @param slots Array of bytes32 values
     */
    event Entry(
        bytes32 indexed id,
        bytes32[] slots
    );

    /**
     * @dev Anchor a batch of data points under a single ID.
     * @param id Hashed identifier
     * @param slots Array of up to MAX_SLOTS bytes32 values
     *
     * Requirements:
     * - 0 < slots.length <= MAX_SLOTS (prevents spam and DoS)
     */
    function anchorData(bytes32 id, bytes32[] calldata slots) external {
        if (slots.length == 0) {
            revert EmptySlotsNotAllowed();
        }

        if (slots.length > MAX_SLOTS) {
            revert ArrayTooLong(slots.length, MAX_SLOTS);
        }

        emit Entry(id, slots);
    }
}
