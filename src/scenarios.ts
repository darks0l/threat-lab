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
];

export function getScenario(id: string): Scenario | undefined {
  return SCENARIOS.find(s => s.id === id);
}

export function listScenarios(): Scenario[] {
  return SCENARIOS;
}
