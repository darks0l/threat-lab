// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MinimalUniswapV2
 * @notice Minimal mock of Uniswap V2 for price manipulation simulation on Anvil.
 *         Deploys: TestToken (mintable ERC20), UniswapV2Pair (constant-product AMM),
 *                   UniswapV2Router, and a MockOracle that reads from the pair.
 *         DO NOT use in production. For research only.
 */

// ── TestToken ─────────────────────────────────────────────────────────────────

contract TestToken {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply_;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply_ += amount;
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
        uint256 allowed = allowance[from][msg.sender];
        if (from != msg.sender) {
            require(allowed >= amount, "Not allowed");
            allowance[from][msg.sender] = allowed - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

// ── UniswapV2Pair ─────────────────────────────────────────────────────────────

/**
 * @notice Constant-product AMM pair (x * y = k).
 *         Supports flash loans via the swap callback.
 */
contract UniswapV2Pair {
    address public token0;
    address public token1;
    uint112 private _reserve0;
    uint112 private _reserve1;
    uint32 private _blockTimestampLast;

    uint256 public constant FEE = 3; // 0.3% LP fee
    uint256 public constant MINIMUM_LIQUIDITY = 1000;

    mapping(address => uint256) public balanceOf;
    uint256 private _totalSupplyLP;
    mapping(address => uint256) private _lps;

    event Mint(address indexed sender, uint256 amount0, uint256 amount1);
    event Burn(address indexed sender, uint256 amount0, uint256 amount1, address to);
    event Swap(address indexed sender, uint256 amount0Out, uint256 amount1Out, address indexed to);
    event Sync(uint112 reserve0, uint112 reserve1);

    function initialize(address __token0, address __token1) external {
        require(_reserve0 == 0 && _reserve1 == 0, "Already initialized");
        token0 = __token0;
        token1 = __token1;
    }

    // ── AMM core ─────────────────────────────────────────────────────────────

    function _update(uint256 bal0, uint256 bal1) internal {
        require(bal0 <= type(uint112).max && bal1 <= type(uint112).max, "Overflow");
        _reserve0 = uint112(bal0);
        _reserve1 = uint112(bal1);
        _blockTimestampLast = uint32(block.timestamp);
        emit Sync(_reserve0, _reserve1);
    }

    function getReserves() public view returns (uint112 r0, uint112 r1, uint32 last) {
        r0 = _reserve0;
        r1 = _reserve1;
        last = _blockTimestampLast;
    }

    // ── LP token supply ─────────────────────────────────────────────────────

    function _mintLP(address to, uint256 amount) internal {
        _lps[to] += amount;
        _totalSupplyLP += amount;
    }

    function _burnLP(address from, uint256 amount) internal {
        _lps[from] -= amount;
        _totalSupplyLP -= amount;
    }

    function totalLP() public view returns (uint256) { return _totalSupplyLP; }

    // ── Mint/burn (add/remove liquidity) ────────────────────────────────────

    function mint(address to) external returns (uint256 liquidity) {
        (uint112 r0, uint112 r1,) = getReserves();
        uint256 bal0 = IERC20(token0).balanceOf(address(this));
        uint256 bal1 = IERC20(token1).balanceOf(address(this));
        uint256 amount0 = bal0 - r0;
        uint256 amount1 = bal1 - r1;

        uint256 _total = totalLP();
        if (_total == 0) {
            liquidity = _sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            _mintLP(address(0), MINIMUM_LIQUIDITY);
        } else {
            liquidity = _min((amount0 * _total) / r0, (amount1 * _total) / r1);
        }
        require(liquidity > 0, "Insufficient liquidity minted");
        _mintLP(to, liquidity);
        _update(bal0, bal1);
        emit Mint(address(0), amount0, amount1);
    }

    function burn(address to) external returns (uint256 amount0, uint256 amount1) {
        uint256 liq = _lps[address(this)];
        uint256 _total = totalLP();
        amount0 = (liq * IERC20(token0).balanceOf(address(this))) / _total;
        amount1 = (liq * IERC20(token1).balanceOf(address(this))) / _total;
        require(amount0 > 0 && amount1 > 0, "Insufficient liquidity burned");
        _burnLP(address(this), liq);
        _safeTransfer(token0, to, amount0);
        _safeTransfer(token1, to, amount1);
        _update(IERC20(token0).balanceOf(address(this)), IERC20(token1).balanceOf(address(this)));
        emit Burn(address(0), amount0, amount1, to);
    }

    // ── Swap ────────────────────────────────────────────────────────────────

    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
        require(amount0Out > 0 || amount1Out > 0, "Insufficient output amount");
        (uint112 r0, uint112 r1,) = getReserves();
        require(amount0Out < r0 && amount1Out < r1, "Insufficient reserves");

        if (amount0Out > 0) _safeTransfer(token0, to, amount0Out);
        if (amount1Out > 0) _safeTransfer(token1, to, amount1Out);
        if (data.length > 0) {
            IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
        }

        uint256 bal0 = IERC20(token0).balanceOf(address(this));
        uint256 bal1 = IERC20(token1).balanceOf(address(this));

        uint256 amount0In = bal0 > r0 - amount0Out ? bal0 - (r0 - amount0Out) : 0;
        uint256 amount1In = bal1 > r1 - amount1Out ? bal1 - (r1 - amount1Out) : 0;
        require(amount0In > 0 || amount1In > 0, "Insufficient input amount");

        uint256 bal0Adj = bal0 * 1000 - amount0In * FEE;
        uint256 bal1Adj = bal1 * 1000 - amount1In * FEE;
        require(bal0Adj * bal1Adj >= uint256(r0) * uint256(r1) * 1_000_000, "K invariant violated");

        _update(bal0, bal1);
        emit Swap(msg.sender, amount0Out, amount1Out, to);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    function _safeTransfer(address token, address to, uint256 amount) internal {
        (bool ok,) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok, "Transfer failed");
    }

    function _sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        while (z < x) { x = z; z = (x + x / z) / 2; }
        return x;
    }

    function _min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; }
}

// ── UniswapV2Router ──────────────────────────────────────────────────────────

contract UniswapV2Router {
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256,
        uint256,
        address to
    ) external returns (uint256, uint256) {
        IERC20(tokenA).transferFrom(msg.sender, address(this), amountADesired);
        IERC20(tokenB).transferFrom(msg.sender, address(this), amountBDesired);
        return (amountADesired, amountBDesired);
    }

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256,
        address[] calldata path,
        address to
    ) external returns (uint256[] memory amounts) {
        require(path.length >= 2, "Invalid path");
        amounts = new uint256[](path.length);
        amounts[0] = amountIn;
        IERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
        uint256 amountOut = _getAmountOut(amountIn, 1_000_000, 1_000_000);
        IERC20(path[path.length - 1]).transfer(to, amountOut);
        for (uint256 i = 1; i < path.length; i++) {
            amounts[i] = amountOut;
        }
    }

    function _getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) internal pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 1000 + amountInWithFee;
        return numerator / denominator;
    }
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IUniswapV2Callee {
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external;
}
