// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/ChainArchiveAnchor.sol";

contract ChainArchiveAnchorTest is Test {
    ChainArchiveAnchor public anchor;

    event Entry(bytes32 indexed id, bytes32[] slots);

    function setUp() public {
        anchor = new ChainArchiveAnchor();
    }

    function testAnchorData() public {
        bytes32 id = keccak256("test-id");
        bytes32[] memory slots = new bytes32[](2);
        slots[0] = keccak256("slot1");
        slots[1] = keccak256("slot2");

        vm.expectEmit(true, false, false, true);
        emit Entry(id, slots);
        anchor.anchorData(id, slots);
    }

    function testRevertEmptySlots() public {
        bytes32 id = keccak256("test-id");
        bytes32[] memory slots = new bytes32[](0);

        vm.expectRevert(ChainArchiveAnchor.EmptySlotsNotAllowed.selector);
        anchor.anchorData(id, slots);
    }

    function testRevertArrayTooLong() public {
        bytes32 id = keccak256("test-id");
        uint256 maxPlusOne = anchor.MAX_SLOTS() + 1;
        bytes32[] memory slots = new bytes32[](maxPlusOne);

        vm.expectRevert(
            abi.encodeWithSelector(
                ChainArchiveAnchor.ArrayTooLong.selector,
                maxPlusOne,
                anchor.MAX_SLOTS()
            )
        );
        anchor.anchorData(id, slots);
    }

    function testMaxSlots() public {
        bytes32 id = keccak256("test-id");
        uint256 max = anchor.MAX_SLOTS();
        bytes32[] memory slots = new bytes32[](max);

        vm.expectEmit(true, false, false, true);
        emit Entry(id, slots);
        anchor.anchorData(id, slots);
    }
}
