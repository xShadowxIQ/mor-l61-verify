// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/// L61 behavioural cross-check of the LIVE, unverified SessionRouter facet.
/// Declared selector set is taken from the repo source; no vm.etch/vm.store/mockCall.
interface ISR61 {
    function getSessionId(address user_, address provider_, bytes32 bidId_, uint256 nonce_) external pure returns (bytes32);
    function startOfTheDay(uint128 timestamp_) external pure returns (uint128);
    function setMaxSessionDuration(uint128 maxSessionDuration_) external;
    function owner() external view returns (address);
}

contract Lane61Verify is Test {
    uint256 constant BLOCK = 61_444_135;
    address constant DIAMOND = 0x6aBE1d282f72B474E54527D93b979A4f64d3030a;
    address constant FACET = 0x3a3952f0e57b343f00b31f7da039ef16389b7260;

    bytes4 constant ERR_TOO_SHORT = 0xf0f669df; // keccak("SessionMaxDurationTooShort()")[0:4]
    bytes32 constant OWNER_SLOT = keccak256("diamond.standard.diamond.ownable.storage");

    function setUp() public {
        vm.createSelectFork(vm.envString("RPC_URL"), BLOCK);
    }

    function _owner() internal view returns (address) {
        return address(uint160(uint256(vm.load(DIAMOND, OWNER_SLOT))));
    }

    function test_live_runtime_code_hash_and_length() public {
        bytes memory code = FACET.code;
        assertEq(code.length, 18535, "live facet code length");
        assertEq(
            keccak256(code),
            0x935d0cfbd2f0c2aa31d13a5f16c2a244d879d69dfb7ce0f8588a3055e02b56b4,
            "live facet keccak256"
        );
    }

    function test_live_getSessionId_matches_repo_formula() public {
        address u = address(0x1234);
        address p = address(0xBEEF);
        bytes32 bid = keccak256("l61-bid");
        uint256 nonce = 42;
        bytes32 expected = keccak256(abi.encodePacked(u, p, bid, nonce));
        assertEq(ISR61(FACET).getSessionId(u, p, bid, nonce), expected, "facet getSessionId");
        assertEq(ISR61(DIAMOND).getSessionId(u, p, bid, nonce), expected, "diamond->facet getSessionId");
    }

    function test_live_startOfTheDay_matches_repo_formula() public {
        uint128 t = 1_700_000_123;
        uint128 expected = t - (t % 86_400);
        assertEq(ISR61(FACET).startOfTheDay(t), expected, "facet startOfTheDay");
        assertEq(ISR61(DIAMOND).startOfTheDay(t), expected, "diamond->facet startOfTheDay");
    }

    function test_live_setMaxDuration_floor_299_reverts_with_exact_selector() public {
        address own = _owner();
        require(own != address(0), "no diamond owner at pin");
        vm.prank(own);
        vm.expectRevert(ERR_TOO_SHORT);
        ISR61(DIAMOND).setMaxSessionDuration(299); // MIN_SESSION_DURATION = 300
    }

    function test_live_setMaxDuration_boundary_300_accepted() public {
        address own = _owner();
        require(own != address(0), "no diamond owner at pin");
        vm.prank(own);
        ISR61(DIAMOND).setMaxSessionDuration(300);
        // reaching here proves the 300 floor boundary is inclusive on the live facet
    }
}
