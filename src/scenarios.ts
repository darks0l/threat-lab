import type { Scenario } from './schemas.js';

/**
 * Built-in attack scenarios — real on-chain execution on Anvil or Base Sepolia.
 * Each scenario includes concrete exploit steps ready to run via the executor.
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
        target: 'ReentrancyVault',
        description: 'Deploy the vulnerable ReentrancyVault contract',
      },
      {
        step: 2,
        action: 'send',
        target: 'ReentrancyVault',
        method: 'deposit',
        value: '10 ETH',
        description: 'Deposit 10 ETH into the vault as the deployer',
      },
      {
        step: 3,
        action: 'deploy',
        target: 'ReentrancyAttacker',
        args: ['{ReentrancyVault}'],
        description: 'Deploy ReentrancyAttacker pointing at the vault',
      },
      {
        step: 4,
        action: 'call',
        target: 'ReentrancyVault',
        method: 'getBalance',
        description: 'Verify vault balance is 10 ETH before attack',
      },
      {
        step: 5,
        action: 'send',
        target: 'ReentrancyAttacker',
        method: 'fundVault',
        value: '1 ETH',
        description: 'Fund attacker contract with 1 ETH so it has a balance in the vault',
      },
      {
        step: 6,
        action: 'call',
        target: 'ReentrancyAttacker',
        method: 'attack',
        args: ['1000000000000000000'],
        description: 'Call attack() to trigger reentrancy — recursive withdraw drains the vault',
      },
      {
        step: 7,
        action: 'call',
        target: 'ReentrancyVault',
        method: 'getBalance',
        description: 'Verify vault balance is 0 ETH after attack',
      },
      {
        step: 8,
        action: 'log',
        description: 'Attack complete. Vault drained via reentrancy — external call made before balances[msg.sender] decrement.',
      },
    ],
    expectedOutcome:
      'Attacker drains vault balance via reentrancy. Vault.withdraw() sends ETH before decrementing balances, enabling recursive calls. Full vault drained in a single transaction.',
    difficulty: 'beginner',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'solidity', 'reentrancy', 'owasp', 'cei'],
  },
  {
    id: 'oracle-manipulation-101',
    name: 'Uniswap V2 Spot Price Oracle Manipulation',
    description:
      'A price oracle reads spot reserves from a Uniswap V2 pair without TWAP smoothing. A flash loan can inflate the price 10-100x in a single block.',
    pattern: 'oracle-manipulation',
    severity: 'high',
    exploitSteps: [
      {
        step: 1,
        action: 'log',
        description: 'Oracle manipulation requires a real Uniswap V2 pair on live networks. On Anvil, this is simulated: a flash loan swaps 1M tokenA into a pair, inflating the spot price 10-100x.',
      },
      {
        step: 2,
        action: 'flash-loan',
        description: 'Flash borrow 1M tokenA from Balancer vault (no collateral)',
      },
      {
        step: 3,
        action: 'swap',
        description: 'Swap 1M tokenA → tokenB on the Uniswap V2 pair used as oracle — spot price now 10-100x higher',
      },
      {
        step: 4,
        action: 'call',
        target: 'OracleManipulation',
        method: 'getPrice',
        description: 'Read the inflated price — downstream protocols accepting this rate lose value',
      },
      {
        step: 5,
        action: 'swap',
        description: 'Reverse swap to restore original state — avoids detection in transaction history',
      },
    ],
    expectedOutcome:
      'Oracle reports manipulated price. Downstream protocols accept unfavorable rates. Profit extracted via arbitrage on the price differential.',
    difficulty: 'intermediate',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'uniswap', 'oracle', 'flash-loan', 'mev', 'twap'],
  },
  {
    id: 'flash-loan-101',
    name: 'Flash Loan Arbitrage via Balancer',
    description:
      'Borrow 1M DAI via Balancer flash loan, execute arbitrage across two DEXs, return the loan — all in one transaction.',
    pattern: 'flash-loan-attack',
    severity: 'medium',
    exploitSteps: [
      {
        step: 1,
        action: 'flash-loan',
        description: 'Request 1M DAI from Balancer vault (no collateral required)',
      },
      {
        step: 2,
        action: 'swap',
        description: 'Buy USDC on DEX A at a slightly lower price',
      },
      {
        step: 3,
        action: 'swap',
        description: 'Sell USDC on DEX B at a slightly higher price — extract the spread',
      },
      {
        step: 4,
        action: 'log',
        description: 'Pay back the 1M DAI + flash loan fee in the same transaction. Net profit = spread - fees.',
      },
    ],
    expectedOutcome:
      'Profit extracted after flash loan fees. MEV bots typically sandwich this to capture the arbitrage spread.',
    difficulty: 'beginner',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'flash-loan', 'defi', 'arbitrage', 'balancer'],
  },
  {
    id: 'sandwich-attack-101',
    name: 'MEV Sandwich Attack',
    description:
      'A victim calls swap(sell ETH for USDC). An MEV bot detects the pending tx in the mempool, front-runs with a swap that drives the ETH price down, then back-runs with a swap that buys ETH back at the lower price — extracting value from the victim.',
    pattern: 'sandwich-attack',
    severity: 'high',
    exploitSteps: [
      {
        step: 1,
        action: 'deploy',
        target: 'SandwichAttacker',
        description: 'Deploy the SandwichAttacker with tokenA/tokenB addresses',
      },
      {
        step: 2,
        action: 'call',
        target: 'SandwichAttacker',
        method: 'frontrun',
        args: ['10000000000000000000'],
        description: 'Swap ETH→TokenB to inflate the price before victim swap (10 ETH worth)',
      },
      {
        step: 3,
        action: 'log',
        description: 'Victim swap executes at the now-inflated price — victim receives fewer tokens than expected',
      },
      {
        step: 4,
        action: 'call',
        target: 'SandwichAttacker',
        method: 'backrun',
        args: ['5000000000000000000'],
        description: 'Swap TokenB→ETH at the inflated price to capture the spread (5 ETH equivalent)',
      },
    ],
    expectedOutcome:
      'Victim receives fewer tokens than expected. Attacker captures the MEV value extracted from the price impact.',
    difficulty: 'intermediate',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'mev', 'sandwich', 'mempool', 'defi', 'amm'],
  },
  {
    id: 'governance-attack-101',
    name: 'Governor Timelock Hijack',
    description:
      'A malicious proposal is submitted to a Governor + Timelock. After voting passes and the timelock delay expires, the attacker executes the proposal to grant themselves the TIMELOCK_ADMIN_ROLE, seizing control of the protocol treasury.',
    pattern: 'access-control',
    severity: 'critical',
    exploitSteps: [
      {
        step: 1,
        action: 'deploy',
        target: 'SimpleTimelock',
        description: 'Deploy the SimpleTimelock',
      },
      {
        step: 2,
        action: 'deploy',
        target: 'GovernanceAttack',
        description: 'Deploy the GovernanceAttack contract',
      },
      {
        step: 3,
        action: 'call',
        target: 'GovernanceAttack',
        method: 'submitProposal',
        args: [],
        description: 'Submit governance proposal with malicious calldata to grant ADMIN role to attacker',
      },
      {
        step: 4,
        action: 'call',
        target: 'GovernanceAttack',
        method: 'vote',
        args: [],
        description: 'Vote YES on the proposal (attacker has voting power)',
      },
      {
        step: 5,
        action: 'call',
        target: 'GovernanceAttack',
        method: 'queueProposal',
        description: 'Queue the proposal after voting period passes',
      },
      {
        step: 6,
        action: 'call',
        target: 'GovernanceAttack',
        method: 'executeProposal',
        description: 'Execute once timelock delay expires — attacker becomes TIMELOCK_ADMIN',
      },
      {
        step: 7,
        action: 'log',
        description: 'Attacker now has admin access — can drain treasury or execute harmful protocol upgrades',
      },
    ],
    expectedOutcome:
      'Attacker uses governance to grant themselves the TIMELOCK_ADMIN_ROLE, enabling treasury drain or malicious protocol upgrades.',
    difficulty: 'advanced',
    createdAt: new Date().toISOString(),
    tags: ['web3', 'governance', 'compound', 'access-control', 'timelock', 'openzeppelin'],
  },
  {
    id: 'liquidation-attack-101',
    name: 'Aave V2 Liquidation Attack',
    description:
      'A user has a borrowing position near the liquidation threshold. An attacker manipulates the oracle price via a flash loan, making the collateral appear undercollateralized, then calls liquidate() to claim a bonus on the seized collateral.',
    pattern: 'oracle-manipulation',
    severity: 'high',
    exploitSteps: [
      {
        step: 1,
        action: 'log',
        description: 'Liquidation attack requires live Aave V2 pool and Uniswap oracle — simulated on Anvil.',
      },
      {
        step: 2,
        action: 'flash-loan',
        description: 'Flash borrow 10M USDC from Balancer',
      },
      {
        step: 3,
        action: 'swap',
        description: 'Swap USDC into the asset used as Aave price oracle — inflate the feed by 20-50%',
      },
      {
        step: 4,
        action: 'log',
        description: 'Aave pool now sees collateral as undercollateralized — liquidation threshold crossed for victim',
      },
      {
        step: 5,
        action: 'log',
        description: 'Call liquidate() on Aave — unfair close factor due to manipulated price. Bonus collateral seized.',
      },
      {
        step: 6,
        action: 'swap',
        description: 'Restore Uniswap price to original state to avoid detection',
      },
    ],
    expectedOutcome:
      'Attacker seizes a bonus amount of collateral due to the manipulated oracle price. Victim is liquidated at an unfair rate.',
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
