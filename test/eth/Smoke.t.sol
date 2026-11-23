// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @notice Smoke test: proves the fork harness + RPC wiring works in CI.
contract Smoke is Test {
    uint256 constant BLOCK = 26_477_225;

    function test_fork_is_live() public {
        vm.createSelectFork(vm.envString("RPC_URL"), BLOCK);
        assertEq(block.chainid, 1, "expected ethereum mainnet");
        // DepositPool (USDC) is an ERC1967 proxy; bytecode must be present.
        address pool = 0x6cCE082851Add4c535352f596662521B4De4750E;
        uint256 size;
        assembly {
            size := extcodesize(pool)
        }
        console.log("pool codesize", size);
        assertGt(size, 0, "no code at DepositPool proxy");
    }
}
