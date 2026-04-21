import type { Scenario } from './schemas.js';

/**
 * Built-in attack scenarios.
 * Each scenario includes the exploit steps, expected outcome, and metadata.
 * The platform grows smarter as researchers add more.
 */
export const SCENARIOS: Scenario[] = [
  {
    id: 'reentrancy-101',
    name: 'Reentrancy Vault Drain',
    description:
      'A vulnerable vault that allows recursive ETH withdrawals due to an external call made before state update. Classic entry-point for reentrancy attacks.',
    pattern: 'reentrancy',
    severity: 'critical',
    templateContract: 'ReentrancyVault',
    exploitSteps: [
      {
        step: 1,
        action: 'deploy',
        description: 'Deploy ReentrancyVault contract',
      },
      {
        step: 2,
        action: 'send',
        target: 'ReentrancyVault',
        method: 'deposit',
        value: '10 ETH',
        description: 'Fund the vault with 10 ETH',
      },
      {
        step: 3,
        action: 'deploy',
        description: 'Deploy the attacker contract with the vault address',
      },
      {
        step: 4,
        action: 'call',
        target: 'Attacker',
        method: 'attack',
        args: ['10 ETH'],
        description: 'Call the attack function — triggers recursive withdraw',
      },
    ],
    expectedOutcome: 'Attacker drains the full vault balance in a single transaction.',
    difficulty: 'beginner',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'solidity', 'reentrancy', 'owasp'],
  },
  {
    id: 'oracle-manipulation-101',
    name: 'Uniswap V2 Spot Price Oracle Manipulation',
    description:
      'A price oracle that reads spot reserves from a Uniswap V2 pair without TWAP smoothing. A flash loan can inflate the price 10-100x in a single block.',
    pattern: 'oracle-manipulation',
    severity: 'high',
    templateContract: 'OracleManipulation',
    exploitSteps: [
      {
        step: 1,
        action: 'deploy',
        description: 'Deploy the OracleManipulation contract with a Uniswap pair',
      },
      {
        step: 2,
        action: 'flash-loan',
        description: 'Flash borrow 1M of tokenA from Balancer',
      },
      {
        step: 3,
        action: 'swap',
        target: 'UniswapPair',
        method: 'swap',
        args: ['1000000', '0', 'attackerAddress'],
        description: 'Swap large amount of tokenA → tokenB to inflate price',
      },
      {
        step: 4,
        action: 'call',
        target: 'OracleManipulation',
        method: 'getPrice',
        description: 'Read the inflated price — now 10-100x higher',
      },
      {
        step: 5,
        action: 'swap',
        target: 'UniswapPair',
        method: 'swap',
        args: ['0', '1000000', 'attackerAddress'],
        description: 'Reverse the swap to restore original state',
      },
    ],
    expectedOutcome: 'Oracle reports manipulated price. Profit from the price differential on downstream protocols.',
    difficulty: 'intermediate',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'uniswap', 'oracle', 'flash-loan', 'mev'],
  },
  {
    id: 'flash-loan-101',
    name: 'Flash Loan Arbitrage with Balancer',
    description:
      'Borrow 1M DAI via Balancer flash loan, execute arbitrage across two DEXs, return the loan — all in one transaction.',
    pattern: 'flash-loan-attack',
    severity: 'medium',
    templateContract: 'FlashLoanAttacker',
    exploitSteps: [
      {
        step: 1,
        action: 'flash-loan',
        description: 'Request 1M DAI from Balancer vault',
      },
      {
        step: 2,
        action: 'swap',
        target: 'DEX-A',
        method: 'swap',
        args: ['1M DAI → USDC'],
        description: 'Buy USDC on DEX A (slightly cheaper)',
      },
      {
        step: 3,
        action: 'swap',
        target: 'DEX-B',
        method: 'swap',
        args: ['USDC → DAI'],
        description: 'Sell USDC on DEX B (slightly higher price)',
      },
      {
        step: 4,
        action: 'call',
        target: 'FlashLoanAttacker',
        method: 'receiveFlashLoan',
        description: 'Pay back the 1M DAI + fees in callback',
      },
    ],
    expectedOutcome: 'Profit extracted after flash loan fees. MEV bots typically sandwich this.',
    difficulty: 'beginner',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'flash-loan', 'defi', 'arbitrage'],
  },
  {
    id: 'sandwich-attack-101',
    name: 'MEV Sandwich Attack',
    description:
      'A victim calls swap(sell ETH for USDC). An MEV bot detects the pending tx in the mempool, front-runs with a swap that drives the ETH price down, then back-runs with a swap that buys ETH back at the lower price — extracting value from the victim.',
    pattern: 'sandwich-attack',
    severity: 'high',
    templateContract: 'SandwichAttacker',
    exploitSteps: [
      {
        step: 1,
        action: 'deploy',
        description: 'Deploy the SandwichAttacker contract with capital for the attack',
      },
      {
        step: 2,
        action: 'call',
        target: 'SandwichAttacker',
        method: 'frontrun',
        args: ['victimDex', 'tokenIn', 'tokenOut', 'victimAmount'],
        description: 'Swap ETH → token to inflate the price before victim swap',
      },
      {
        step: 3,
        action: 'call',
        target: 'SandwichAttacker',
        method: 'backrun',
        args: ['tokenOut', 'tokenIn', 'profitAmount'],
        description: 'Swap token → ETH at the inflated price to capture the spread',
      },
    ],
    expectedOutcome: 'Victim receives fewer tokens than expected. Attacker captures the MEV value extracted from the price impact.',
    difficulty: 'intermediate',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'mev', 'sandwich', 'mempoo', 'defi'],
  },
  {
    id: 'governance-attack-101',
    name: 'Governor Timelock Hijack',
    description:
      'A proposal to add a malicious actor to the timelock is queued and executed. The attacker gains the ability to execute arbitrary calls through the timelock, draining the protocol treasury or executing harmful upgrades.',
    pattern: 'access-control',
    severity: 'critical',
    templateContract: 'GovernanceAttack',
    exploitSteps: [
      {
        step: 1,
        action: 'deploy',
        description: 'Deploy the attacker contract with governance parameters',
      },
      {
        step: 2,
        action: 'call',
        target: 'Governor',
        method: 'propose',
        args: ['maliciousProposalCalldata'],
        description: 'Submit a governance proposal with hidden harmful execution',
      },
      {
        step: 3,
        action: 'call',
        target: 'Governor',
        method: 'queue',
        args: ['proposalId', 'eta'],
        description: 'Queue the proposal after the voting period passes',
      },
      {
        step: 4,
        action: 'call',
        target: 'GovernanceAttack',
        method: 'executeProposal',
        args: ['target', 'value', 'data'],
        description: 'Execute once the timelock delay expires — gain treasury or admin access',
      },
    ],
    expectedOutcome: 'Attacker uses governance to grant themselves the TIMELOCK_ADMIN_ROLE or drain treasury via the compromised timelock.',
    difficulty: 'advanced',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'governance', 'compound', 'access-control', 'timelock'],
  },
  {
    id: 'liquidation-attack-101',
    name: 'Aave V2 Liquidation Attack',
    description:
      'A user has a borrowing position near the liquidation threshold. An attacker triggers a price manipulation (via a flash loan on Uniswap), making the collateral appear undercollateralized. The attacker calls liquidate() to claim a bonus on the seized collateral — the victim loses more than necessary.',
    pattern: 'oracle-manipulation',
    severity: 'high',
    templateContract: 'LiquidationAttacker',
    exploitSteps: [
      {
        step: 1,
        action: 'deploy',
        description: 'Deploy LiquidationAttacker with a funded wallet',
      },
      {
        step: 2,
        action: 'flash-loan',
        description: 'Flash borrow a large amount of asset to manipulate — e.g. 10M USDC',
      },
      {
        step: 3,
        action: 'swap',
        target: 'UniswapV2Pair',
        method: 'swap',
        args: ['USDCAmount', '0', 'attackerAddress'],
        description: 'Swap USDC → asset on the pair used as Aave price oracle — inflate the price feed',
      },
      {
        step: 4,
        action: 'call',
        target: 'AavePool',
        method: 'liquidate',
        args: ['collateralAsset', 'debtAsset', 'user', 'closeFactor'],
        description: 'Liquidate the victim — the inflated price means less collateral is required to repay the debt',
      },
      {
        step: 5,
        action: 'swap',
        target: 'UniswapV2Pair',
        method: 'swap',
        args: ['0', 'USDCAmount', 'attackerAddress'],
        description: 'Restore the Uniswap price to avoid detection',
      },
    ],
    expectedOutcome: 'Attacker seizes a bonus amount of collateral due to the manipulated oracle price. Victim is liquidated at an unfair rate.',
    difficulty: 'advanced',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'aave', 'liquidation', 'oracle', 'flash-loan', 'mev'],
  },
];

export function getScenario(id: string): Scenario | undefined {
  return SCENARIOS.find(s => s.id === id);
}

export function listScenarios(): Scenario[] {
  return SCENARIOS;
}
