// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title LiquidationSqueeze
 * @notice Simulates an Aave V2 liquidation attack via oracle manipulation.
 *         On Anvil: deploys mock AToken and PriceOracle, simulates the full liquidation flow.
 *         On mainnet/L2: can be wired to real Aave V2 pool for live testing.
 *         DO NOT use in production. For research only.
 *
 * Attack flow:
 *   1. Victim has a collateral position (e.g., ETH) borrowed against (e.g., USDC)
 *   2. Flash loan a large amount of the collateral asset
 *   3. Swap to inflate the price oracle feed
 *   4. Call liquidate() — victim's position appears undercollateralized due to manipulated price
 *   5. Seize collateral at unfair bonus rate
 *   6. Restore oracle price, return flash loan
 */
contract LiquidationSqueeze {
    // ── Mock Aave-style lending ─────────────────────────────────────────────

    // Simplified user position
    struct UserPosition {
        address collateralAsset;
        address borrowAsset;
        uint256 collateralAmount;
        uint256 borrowAmount;
        uint256 healthFactor; // 1e18 precision
    }

    mapping(address => UserPosition) public positions;
    address public owner;

    // Mock price oracle (address => USD price in 1e18)
    mapping(address => uint256) public prices;

    // Liquidation bonus: 10% (Aave style)
    uint256 public constant LIQUIDATION_BONUS = 110; // 110% = 10% bonus
    uint256 public constant LIQUIDATION_THRESHOLD = 1e18; // healthFactor < 1 = liquidatable

    // Mock tokens
    mapping(address => uint256) public balanceOf;

    constructor() {
        owner = msg.sender;
    }

    // ── Setup ─────────────────────────────────────────────────────────────

    /**
     * @notice Set up a victim's borrowing position
     */
    function setupVictim(
        address collateralAsset,
        address borrowAsset,
        uint256 collateralAmount,
        uint256 borrowAmount
    ) external {
        uint256 collateralValue = collateralAmount * getPrice(collateralAsset);
        uint256 borrowValue = borrowAmount * getPrice(borrowAsset);
        require(collateralValue > borrowValue, "Not overcollateralized");

        positions[owner] = UserPosition({
            collateralAsset: collateralAsset,
            borrowAsset: borrowAsset,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount,
            healthFactor: (collateralValue * 1e18) / borrowValue
        });
    }

    /**
     * @notice Set oracle price for an asset (manipulate it)
     */
    function setPrice(address asset, uint256 price) external {
        require(msg.sender == owner, "Not owner");
        prices[asset] = price;
    }

    /**
     * @notice Get price of an asset from the oracle
     */
    function getPrice(address asset) public view returns (uint256) {
        if (prices[asset] != 0) return prices[asset];
        // Default prices for mock
        if (asset == address(1)) return 2000e18; // ETH in USDC terms (mock)
        return 1e18; // Default
    }

    /**
     * @notice Manipulate oracle price by inflationFactor (e.g. 150 = 50%% price increase)
     */
    function manipulateOracle(address asset, uint256 inflationFactor) external {
        require(msg.sender == owner, "Not owner");
        uint256 currentPrice = prices[asset] != 0 ? prices[asset] : 1e18;
        prices[asset] = (currentPrice * inflationFactor) / 100;
    }

    /**
     * @notice Liquidate a victim's position at the current (manipulated) oracle price
     * @param victim Address of the victim
     * @return seized Amount of collateral seized
     */
    function liquidate(address victim) external returns (uint256 seized) {
        require(msg.sender == owner, "Not owner");
        UserPosition storage pos = positions[victim];
        require(pos.collateralAmount > 0, "No position");

        // Inline health factor check at current (manipulated) price
        uint256 collateralValue = pos.collateralAmount * getPrice(pos.collateralAsset);
        uint256 borrowValue = pos.borrowAmount * getPrice(pos.borrowAsset);
        require(borrowValue > 0, "No debt");
        uint256 hf = (collateralValue * 1e18) / borrowValue;
        require(hf < LIQUIDATION_THRESHOLD, "Not liquidatable - health factor OK");

        // Calculate seized collateral (with bonus)
        seized = (pos.collateralAmount * LIQUIDATION_BONUS) / 100;
        require(seized <= pos.collateralAmount, "Overflow");

        // Transfer seized collateral to attacker
        pos.collateralAmount -= seized;
        pos.borrowAmount = 0;
        pos.healthFactor = type(uint256).max;

        emit Liquidated(victim, msg.sender, seized, pos.collateralAsset);
    }

    /**
     * @notice Step 3: Restore oracle price after attack
     */
    function restoreOracle(address asset, uint256 originalPrice) external {
        require(msg.sender == owner, "Not owner");
        prices[asset] = originalPrice;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    receive() external payable {}

    event Liquidated(address indexed victim, address indexed attacker, uint256 seizedAmount, address asset);
}
