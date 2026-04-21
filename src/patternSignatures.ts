/**
 * Shared attack pattern signatures — single source of truth.
 * Used by both analyzer.ts (regex-based) and patternDetector.ts (keyword-based).
 *
 * DO NOT duplicate these in other files. Import from here.
 */

import type { AttackPattern } from './schemas.js';

// ── Regex signatures (for scanning Solidity source code) ──────────────────────

export const PATTERN_REGEX: Record<AttackPattern, RegExp[]> = {
  'reentrancy': [
    /\bcall\{value\s*:/,
    /\.(call|transfer|send)\s*\(\s*\)/,
    /msg\.sender\.call/,
    /_update.*before.*call/,
  ],
  'oracle-manipulation': [
    /getReserves\(\)/,
    /spot.*price/i,
    /uint256.*reserve/,
    /price.*feed/i,
  ],
  'flash-loan-attack': [
    /flashLoan/i,
    /onFlashLoan/i,
    /flash/i,
    / balancer /i,
  ],
  'access-control': [
    /onlyOwner|onlyAdmin|requiresAuth|auth_\w+/,
    /msg\.sender\s*!=\s*owner/,
    /public.*without.*check/i,
  ],
  'front-running': [
    /gasPrice|gas.*price/i,
    /MEV|miner.*extract/i,
    /arbitrage/i,
  ],
  'sandwich-attack': [
    /front.*run|back.*run/i,
    /sandwich/i,
    /borrow.*swap.*repay/i,
  ],
  'integer-overflow': [
    /uint256.*\+.*uint256/,
    /safemath/i,
    /overflow/i,
  ],
  'delegatecall-injection': [
    /delegatecall/i,
    /implementation.*storage/i,
    /proxy.*upgrade/i,
  ],
  'permit-front-run': [
    /permit\(|EIP712.*permit/i,
    /signature.*replay/i,
  ],
  'liquidation-attack': [
    /liquidate\(|liquidatePosition/i,
    /healthFactor|health.*factor/i,
    /liquidation.*bonus/i,
    /closeFactor|close.*factor/i,
  ],
  'unknown': [],
};

// ── Keyword signatures (for scanning text/summaries/reports) ───────────────────

export const PATTERN_KEYWORDS: Record<AttackPattern, string[]> = {
  'reentrancy': ['reentranc', 'recursive', 'callback', 'call{value'],
  'oracle-manipulation': ['getReserves', 'spot price', 'manipulat', 'twap'],
  'flash-loan-attack': ['flashLoan', 'flash loan', 'borrow', 'callback'],
  'access-control': ['onlyOwner', 'onlyAdmin', 'auth', 'permission'],
  'front-running': ['gasPrice', 'front.run', 'MEV', 'arbitrage'],
  'sandwich-attack': ['sandwich', 'front.run', 'back.run', 'slippage'],
  'integer-overflow': ['overflow', 'Safemath', 'unchecked', 'wrap'],
  'delegatecall-injection': ['delegatecall', 'implementation', 'proxy'],
  'permit-front-run': ['permit', 'EIP712', 'signature', 'replay'],
  'liquidation-attack': ['liquidate', 'healthFactor', 'liquidation', 'collateral'],
  'unknown': [],
};

// ── String signatures (for narrative matching in patternDetector) ─────────────

export const PATTERN_SIGNATURES: Record<AttackPattern, string[]> = {
  'reentrancy': [
    'external call before state update',
    'call{value:} in withdraw function',
    'no reentrancy guard',
    'recursive call pattern',
  ],
  'oracle-manipulation': [
    'spot price oracle',
    ' Uniswap V2 pair reserves',
    'no TWAP smoothing',
    'flash loan price impact',
  ],
  'flash-loan-attack': [
    'flash loan callback',
    'Balancer vault',
    'arbitrage in single transaction',
    'no collateral required',
  ],
  'access-control': [
    'missing access control check',
    'owner-only function',
    'missing requiresAuth',
    'unchecked external call privilege',
  ],
  'front-running': [
    'gas price oracle',
    'MEV extraction',
    'arbitrage sandwich',
    'tx order dependency',
  ],
  'sandwich-attack': [
    'front-run + back-run',
    'borrow-swap-repay pattern',
    'uniswap v2 flash swap',
    'slippage exploitation',
  ],
  'integer-overflow': [
    'unchecked arithmetic',
    'uint256 addition overflow',
    'Safemath not used',
    'wrapping arithmetic',
  ],
  'delegatecall-injection': [
    'delegatecall to user-supplied address',
    'implementation slot storage',
    'proxy upgrade pattern',
    'unused implementation address',
  ],
  'permit-front-run': [
    'EIP712 permit signature',
    'signature replay attack',
    'nonce reuse',
    'invalid signature validation',
  ],
  'liquidation-attack': [
    'liquidation threshold',
    'health factor below 1',
    'oracle price manipulation',
    'collateral seizure',
  ],
  'unknown': [],
};

// ── Pattern inference from text ───────────────────────────────────────────────

export function inferPattern(text: string): AttackPattern {
  const lower = text.toLowerCase();
  if (/reentranc/.test(lower)) return 'reentrancy';
  if (/oracle.*manip|price.*manip|spot.*price/.test(lower)) return 'oracle-manipulation';
  if (/flash.?loan/.test(lower)) return 'flash-loan-attack';
  if (/access.?control|permission|privilege/.test(lower)) return 'access-control';
  if (/front.?run|sandwich/.test(lower)) return 'sandwich-attack';
  if (/integer.*over|overflow|unchecked.*arith/.test(lower)) return 'integer-overflow';
  if (/delegatecall|implementation.*storage/.test(lower)) return 'delegatecall-injection';
  if (/permit.*replay|eip712.*permit/.test(lower)) return 'permit-front-run';
  if (/liquidat|health.?factor|collateral.*seiz/.test(lower)) return 'liquidation-attack';
  return 'unknown';
}