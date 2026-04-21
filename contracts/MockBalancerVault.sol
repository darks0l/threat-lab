// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockBalancerVault
 * @notice Minimal mock of Balancer V2 Vault for flash loan simulation on Anvil.
 *         Does NOT require real Balancer — just simulates the flash loan interface.
 *         DO NOT use in production. For research only.
 */
contract MockBalancerVault {
    // ── Flash Loan ─────────────────────────────────────────────────────────

    /**
     * @notice Flash loan entry point. Sends tokens to recipient, then calls onFlashLoan.
     * @param recipient Who receives the loan and gets the callback
     * @param tokens    Token addresses (must have this contract hold balances)
     * @param amounts   Amounts to lend per token
     * @param userData  Passed through to the callback (attack calldata)
     */
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external {
        require(tokens.length == amounts.length, "Length mismatch");
        require(tokens.length > 0, "Empty loan");

        // Pull tokens from caller (caller must approve or this contract must hold tokens)
        for (uint256 i = 0; i < tokens.length; i++) {
            require(amounts[i] > 0, "Zero amount");
        }

        // Send loaned tokens to recipient
        for (uint256 i = 0; i < tokens.length; i++) {
            _safeTransfer(tokens[i], recipient, amounts[i]);
        }

        // Callback so recipient can execute attack logic with the borrowed capital
        IFlashLoanRecipient(recipient).receiveFlashLoan(tokens, amounts, _computeFees(amounts), userData);
    }

    /**
     * @notice Pull tokens into this vault (for funding flash loans)
     */
    function fund(address token, uint256 amount) external {
        _safeTransferFrom(token, msg.sender, address(this), amount);
    }

    // ── Internals ──────────────────────────────────────────────────────────

    function _safeTransfer(address token, address to, uint256 amount) internal {
        (bool ok, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok, "Transfer failed");
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        (bool ok, ) = token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount));
        require(ok, "TransferFrom failed");
    }

    // 0.0001% fee (Balancer-style, very small for testing)
    function _computeFees(uint256[] memory amounts) internal pure returns (uint256[] memory fees) {
        fees = new uint256[](amounts.length);
        for (uint256 i = 0; i < amounts.length; i++) {
            fees[i] = amounts[i] / 100000;
        }
    }
}

interface IFlashLoanRecipient {
    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external;
}
