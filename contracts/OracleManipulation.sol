// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title OracleManipulation
 * @notice A contract that uses a Uniswap V2 pair for price oracle data.
 *         DO NOT use in production. For research only.
 *
 * Attack vector: Flash-loan a large amount of one asset, swap to inflate
 * the price in the pair, read the inflated price, then reverse the swap.
 * The attacker profits at the expense of protocols relying on this oracle.
 */
contract OracleManipulation {
    address public tokenA;
    address public tokenB;
    address public pair;

    // @audit-info - TWAP window can be manipulated with flash loans
    uint256 public price;
    uint256 public lastUpdate;

    constructor(address _tokenA, address _tokenB, address _pair) {
        tokenA = _tokenA;
        tokenB = _tokenB;
        pair = _pair;
    }

    // @audit-info - reads spot price from pair (not TWAP, easily manipulated)
    function getPrice() external returns (uint256) {
        (uint256 reserve0, uint256 reserve1, ) = IUniswapV2Pair(pair).getReserves();
        // Uses spot price, not time-weighted average
        price = (reserve1 * 1e18) / reserve0;
        lastUpdate = block.timestamp;
        return price;
    }

    // Allow receiving ETH for testing
    receive() external payable {}
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}
