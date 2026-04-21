// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SandwichAttacker
 * @notice MEV sandwich attack — front-runs a victim swap, then back-runs to capture spread.
 *         Simulates Uniswap V2 AMM behavior on Anvil.
 *         DO NOT use in production. For research only.
 *
 * Flow:
 *   1. Deploy with capital
 *   2. frontrun(): swap TokenA→TokenB to move price against victim's position
 *   3. Victim swaps TokenA→TokenB at worse rate (victim's loss = our gain)
 *   4. backrun(): swap TokenB→TokenA at the inflated price to capture profit
 */
contract SandwichAttacker {
    // Simplified Uniswap V2 pair simulation
    address public tokenA;
    address public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;

    address public owner;
    uint256 public constant FEE = 3; // 0.3% Uniswap-style fee

    constructor(address _tokenA, address _tokenB) {
        tokenA = _tokenA;
        tokenB = _tokenB;
        owner = msg.sender;
    }

    // ── AMM Logic ─────────────────────────────────────────────────────────────

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        public
        pure
        returns (uint256)
    {
        require(amountIn > 0, "INSUFFICIENT_INPUT_AMOUNT");
        require(reserveIn > 0 && reserveOut > 0, "INSUFFICIENT_LIQUIDITY");
        uint256 amountInWithFee = amountIn * (1000 - FEE);
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        return numerator / denominator;
    }

    // Initialize reserves (simulate adding liquidity)
    function initReserves(uint256 _reserveA, uint256 _reserveB) external {
        require(msg.sender == owner, "Not owner");
        reserveA = _reserveA;
        reserveB = _reserveB;
    }

    // ── Exploit Steps ────────────────────────────────────────────────────────

    /**
     * @notice Step 1: Front-run — swap TokenA → TokenB to inflate the price
     * @param amountIn Amount of TokenA to swap in
     * @param targetPool Address of the victim's DEX pool (used as price reference)
     */
    function frontrun(uint256 amountIn, address targetPool) external {
        require(msg.sender == owner, "Not owner");
        // Swap TokenA for TokenB on the simulated pair
        uint256 amountOut = getAmountOut(amountIn, reserveA, reserveB);
        reserveA += amountIn;
        reserveB -= amountOut;
        emit FrontRun(msg.sender, amountIn, amountOut);
    }

    /**
     * @notice Step 3: Back-run — swap TokenB → TokenA at the now-inflated price
     * @param amountIn Amount of TokenB to swap back
     */
    function backrun(uint256 amountIn) external {
        require(msg.sender == owner, "Not owner");
        uint256 amountOut = getAmountOut(amountIn, reserveB, reserveA);
        reserveB += amountIn;
        reserveA -= amountOut;
        emit BackRun(msg.sender, amountIn, amountOut);
    }

    /**
     * @notice Withdraw profit to owner
     */
    function withdrawProfit(address token, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", owner, amount));
        require(success, "Transfer failed");
    }

    /**
     * @notice Fund this contract with tokens (for testing)
     */
    function receiveTokens(address token, uint256 amount) external {
        // In real scenario, would pull from caller
    }

    // Allow receiving ETH/tokens
    receive() external payable {}

    event FrontRun(address indexed attacker, uint256 amountIn, uint256 amountOut);
    event BackRun(address indexed attacker, uint256 amountIn, uint256 amountOut);
}

/**
 * @title SimpleToken
 * @notice Mintable/Burnable ERC20 for test scenarios.
 */
contract SimpleToken {
    string public name;
    string public symbol;
    uint8 public decimals;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        if (from != msg.sender) {
            require(allowance[from][msg.sender] >= amount, "Not allowed");
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
