// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title FlashLoanAttacker
 * @notice A generalized flash loan attacker pattern.
 *         Executes arbitrary logic with flash-borrowed capital.
 *         DO NOT use in production. For research only.
 *
 * Attack vector: Borrows large amounts via flash loan, manipulates
 * market prices or executes arbitrage, then returns the loan in the same tx.
 * MEV bots can sandwich this to steal the profit.
 */
contract FlashLoanAttacker {
    address public constant UNISWAP_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address public constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    struct AttackParams {
        address target;
        address borrowToken;
        uint256 borrowAmount;
        bytes callData;
    }

    // @audit-info - executes arbitrary callData against borrowed capital
    function executeAttack(AttackParams calldata params) external {
        // 1. Flash borrow
        IFlashLoanLender lender = IFlashLoanLender(0xBa12222222228d8ba445958a90aD4eEfc7d8Ce2A); // Balancer vault
        address[] memory tokens = new address[](1);
        tokens[0] = params.borrowToken;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = params.borrowAmount;

        lender.flashLoan(address(this), tokens, amounts, "");

        // 2. Execute attack logic with the borrowed capital
        (bool success, ) = params.target.call{value: 0}(params.callData);
        require(success, "Attack execution failed");

        // 3. Pay back is handled in the onFlashLoan callback
    }

    function receiveFlashLoan(
        address[] memory, // tokens
        uint256[] memory, // amounts
        uint256[] memory, // fee amounts
        bytes memory
    ) external {
        // Pay back the loan + fees
        // In a real attack, profit would be extracted before this executes
    }

    // For testing: allow funding the contract
    receive() external payable {}
}

interface IFlashLoanLender {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}
