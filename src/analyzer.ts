/**
 * AI-powered threat analysis engine.
 * Sends exploit traces to Bankr gateway for LLM analysis,
 * returns structured threat reports.
 */

import { z } from 'zod';
import { randomUUID } from 'crypto';
import type { Finding, ThreatReport, AttackPattern, Severity } from './schemas.js';
import { PATTERN_REGEX, inferPattern } from './patternSignatures.js';

// Bankr LLM gateway — set BANKR_API_KEY env var to enable AI analysis
// Falls back to signature-based detection if key not set
const BANKR_API_URL = process.env.BANKR_API_URL ?? 'https://gateway.bankr.gg/v1/chat/completions';
const BANKR_API_KEY = process.env.BANKR_API_KEY ?? '';

// ── Prompt templates ─────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a DeFi security researcher. Analyze the provided blockchain transaction trace or contract code and identify the specific attack pattern used. Output a structured finding with:
1. Attack pattern (from: reentrancy, oracle-manipulation, flash-loan-attack, access-control, front-running, sandwich-attack, integer-overflow, delegatecall-injection, permit-front-run)
2. Severity (critical/high/medium/low/informational)
3. Title — concise description
4. Full description — how the attack works step by step
5. CVSS score (0-10) if applicable
6. Affected contracts
7. Recommendations to prevent it`;

function buildAnalysisPrompt(scenarioName: string, scenarioDesc: string, txTrace: string, contractCode: string): string {
  return `## Scenario: ${scenarioName}
${scenarioDesc}

## Transaction Trace:
${txTrace || 'No trace available — analyze contract code directly.'}

## Contract Code:
\`\`\`solidity
${contractCode}
\`\`\`

${!txTrace ? 'No transaction was executed. Based on the contract code above, identify the vulnerability and describe the exploit scenario.' : 'Based on the transaction trace and contract code above, identify the attack pattern, severity, and provide a detailed analysis.'}

Respond with your analysis.`;
}

// ── Pattern matchers (shared from patternSignatures.ts) ─────────────────────

function detectPatternBySignature(code: string): AttackPattern {
  const matches: { pattern: AttackPattern; count: number }[] = [];

  for (const [pattern, regexes] of Object.entries(PATTERN_REGEX)) {
    const count = regexes.filter(r => r.test(code)).length;
    if (count > 0) matches.push({ pattern: pattern as AttackPattern, count });
  }

  if (matches.length === 0) return 'unknown';
  matches.sort((a, b) => b.count - a.count);
  return matches[0].pattern;
}

// ── Main analysis ─────────────────────────────────────────────────────────────

export interface AnalysisInput {
  scenarioId: string;
  scenarioName: string;
  scenarioDesc: string;
  txTrace?: string;
  contractCode: string;
  chainId?: number;
  model?: string;
}

/**
 * Analyze contract code or transaction trace using Bankr LLM gateway.
 * Falls back to signature-based detection if LLM unavailable.
 */
export async function analyzeThreat(input: AnalysisInput): Promise<ThreatReport> {
  const { scenarioId, scenarioName, scenarioDesc, txTrace, contractCode, chainId = 1, model } = input;

  // Fast path: signature-based detection
  const detectedPattern = detectPatternBySignature(contractCode);

  let llmAnalysis: { summary: string; severity: Severity; confidence: number; recommendations: string[] } | null = null;

  try {
    if (!BANKR_API_KEY) throw new Error('BANKR_API_KEY not set');

    const prompt = buildAnalysisPrompt(scenarioName, scenarioDesc, txTrace ?? '', contractCode);
    const response = await fetch(BANKR_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${BANKR_API_KEY}`,
      },
      body: JSON.stringify({
        model: model ?? 'anthropic/claude-sonnet-4-6',
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: prompt },
        ],
        max_tokens: 1024,
        temperature: 0.3,
      }),
    });

    if (!response.ok) throw new Error(`Bankr API error: ${response.status}`);
    const data = await response.json() as { choices: { message: { content: string } }[] };
    const content = data.choices[0]?.message?.content ?? '';
    llmAnalysis = parseAnalysisResponse(content);
  } catch {
    // LLM unavailable — use signature-based detection as fallback
    llmAnalysis = {
      summary: `Signature-based detection: likely ${detectedPattern} attack. Manual review recommended.`,
      severity: detectedPattern === 'unknown' ? 'medium' : 'high',
      confidence: 0.4,
      recommendations: [
        'Review contract with a professional audit',
        'Use Slither or Mythril for static analysis',
        'Implement CEI pattern (Checks-Effects-Interactions)',
      ],
    };
  }

  return {
    reportId: randomUUID(),
    scenarioId,
    attackPattern: llmAnalysis ? inferPattern(llmAnalysis.summary) : detectedPattern,
    severity: llmAnalysis?.severity ?? 'high',
    summary: llmAnalysis?.summary ?? `Detected: ${detectedPattern}`,
    findings: [
      {
        title: `Potential ${detectedPattern} vulnerability`,
        description: llmAnalysis?.summary ?? 'Detected via code signature analysis.',
        evidence: contractCode.slice(0, 500),
      },
    ],
    aiModel: model ?? 'bankr-default',
    confidence: llmAnalysis?.confidence ?? 0.4,
    recommendations: llmAnalysis?.recommendations ?? [],
    createdAt: new Date().toISOString(),
  };
}

function parseAnalysisResponse(response: unknown): {
  summary: string;
  severity: Severity;
  confidence: number;
  recommendations: string[];
} {
  const text = typeof response === 'string' ? response : JSON.stringify(response);

  // Try to extract structured fields from LLM response
  const severityMatch = text.match(/severity:\s*(critical|high|medium|low|informational)/i);
  const patternMatch = text.match(/attack pattern:\s*(\w+[\w-]*)/i);
  const cvssMatch = text.match(/cvss:?\s*(\d+\.?\d*)/i);

  return {
    summary: text.slice(0, 1000),
    severity: (severityMatch?.[1]?.toLowerCase() as Severity) ?? 'high',
    confidence: cvssMatch ? parseFloat(cvssMatch[1]) / 10 : 0.7,
    recommendations: extractRecommendations(text),
  };
}

function extractRecommendations(text: string): string[] {
  const recs: string[] = [];
  const recSection = text.match(/recommendations?[:\s](.+?)(?:\n\n|$)/is);
  if (recSection) {
    const items = recSection[1].split(/[-•\d]+\./).filter(Boolean);
    for (const item of items.slice(0, 4)) {
      const cleaned = item.trim().replace(/^[a-z]\)\s*/, '');
      if (cleaned.length > 10) recs.push(cleaned.slice(0, 200));
    }
  }
  return recs.length > 0 ? recs : ['Conduct a professional audit', 'Use static analysis tools'];
}

// inferPattern now imported from patternSignatures.ts
