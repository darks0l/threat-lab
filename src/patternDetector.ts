/**
 * Pattern detector — matches new findings against the growing pattern library.
 * The more submissions, the smarter the detection.
 */

import type { AttackPattern, ThreatReport, Finding } from './schemas.js';

export interface PatternMatch {
  pattern: AttackPattern;
  confidence: number;
  matchedOn: string[]; // which signature triggered
  similarReports: string[]; // reportIds of similar past findings
}

const PATTERN_SIGNATURES: Record<AttackPattern, string[]> = {
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
  'unknown': [],
};

const PATTERN_KEYWORDS: Record<AttackPattern, string[]> = {
  'reentrancy': ['reentranc', 'recursive', 'callback', 'call{value'],
  'oracle-manipulation': ['getReserves', 'spot price', 'manipulat', 'twap'],
  'flash-loan-attack': ['flashLoan', 'flash loan', 'borrow', 'callback'],
  'access-control': ['onlyOwner', 'onlyAdmin', 'auth', 'permission'],
  'front-running': ['gasPrice', 'front.run', 'MEV', 'arbitrage'],
  'sandwich-attack': ['sandwich', 'front.run', 'back.run', 'slippage'],
  'integer-overflow': ['overflow', 'Safemath', 'unchecked', 'wrap'],
  'delegatecall-injection': ['delegatecall', 'implementation', 'proxy'],
  'permit-front-run': ['permit', 'EIP712', 'signature', 'replay'],
  'unknown': [],
};

/**
 * Match a text (code, trace, or report) against known attack signatures.
 * Returns confidence scores for each pattern.
 */
export function detectPatterns(text: string): PatternMatch[] {
  const lower = text.toLowerCase();
  const matches: PatternMatch[] = [];

  for (const [pattern, signatures] of Object.entries(PATTERN_SIGNATURES)) {
    const pat = pattern as AttackPattern;
    const keywords = PATTERN_KEYWORDS[pat];

    const matchedSigs = signatures.filter(sig =>
      lower.includes(sig.toLowerCase())
    );
    const matchedKws = keywords.filter(kw =>
      lower.includes(kw.toLowerCase())
    );

    const score = (matchedSigs.length * 0.6 + matchedKws.length * 0.4) /
      (signatures.length * 0.6 + keywords.length * 0.4);

    if (score > 0) {
      matches.push({
        pattern: pat,
        confidence: Math.min(score, 1),
        matchedOn: [...matchedSigs, ...matchedKws],
        similarReports: [],
      });
    }
  }

  return matches.sort((a, b) => b.confidence - a.confidence);
}

/**
 * Match a finding against historical reports to surface similar attacks.
 */
export async function findSimilarReports(
  report: ThreatReport,
  library: ThreatReport[],
): Promise<PatternMatch[]> {
  const text = `${report.summary} ${report.findings.map(f => f.description).join(' ')}`;
  const matches = detectPatterns(text);

  // Tag similar reports
  for (const match of matches) {
    match.similarReports = library
      .filter(r =>
        r.reportId !== report.reportId &&
        r.attackPattern === match.pattern
      )
      .slice(0, 3)
      .map(r => r.reportId);
  }

  return matches;
}

/**
 * Score a submission based on how much it adds to the pattern library.
 * New patterns or high-confidence detections get higher scores.
 */
export function scoreSubmission(report: ThreatReport, library: ThreatReport[]): number {
  const existingCount = library.filter(r => r.attackPattern === report.attackPattern).length;
  const baseScore = existingCount === 0 ? 10 : 1; // New pattern = 10x bonus
  const confidenceBonus = report.confidence * 5;

  return baseScore + confidenceBonus;
}
