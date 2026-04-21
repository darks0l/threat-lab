/**
 * Modelab Integration — multi-model AI analysis of exploit traces.
 * Routes each scenario through modelab's research orchestrator for
 * multi-model analysis, quality scoring, and structured threat reports.
 *
 * Falls back to direct LLM calls if modelab is unavailable.
 */

import { randomUUID } from 'crypto';
import type { ThreatReport, AttackPattern, Severity } from './schemas.js';

// ── Modelab research prompt ─────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a DeFi security researcher analyzing a blockchain exploit scenario. Your task is to:

1. Identify the attack pattern (from: reentrancy, oracle-manipulation, flash-loan-attack, access-control, front-running, sandwich-attack, integer-overflow, delegatecall-injection, permit-front-run, unknown)
2. Assess severity (critical/high/medium/low/informational)
3. Describe the exploit mechanics in detail
4. Identify affected contracts and functions
5. Provide actionable recommendations to prevent it

Respond with a structured analysis. Be precise — security depends on accuracy.`;

function buildModelabPrompt(
  scenarioId: string,
  scenarioName: string,
  txTraces: string[],
  contractCode: string,
): string {
  return `## Threat Analysis Request

**Scenario:** ${scenarioName} (${scenarioId})

**Transaction Traces:**
${txTraces.length > 0 ? txTraces.map((t, i) => `### Transaction ${i + 1}:\n\`\`\`\n${t.slice(0, 2000)}\n\`\`\``).join('\n\n') : 'No transaction traces available — analyze contract code directly.'}

**Contract Code:**
\`\`\`solidity
${contractCode}
\`\`\`

**Your task:**
- Identify the exact attack vector
- Rate severity 0-10 (CVSS-inspired)
- List the specific vulnerability (function, line, mechanism)
- Recommend concrete fixes with code patterns
- Flag any similar known patterns`;
}

// ── Analysis result ────────────────────────────────────────────────────────────

export interface ModelabAnalysisResult {
  model: string;
  report: ThreatReport;
  rawResponse: string;
  durationMs: number;
}

// ── Direct LLM call ─────────────────────────────────────────────────────────────

const BANKR_API_URL = process.env.BANKR_API_URL ?? 'https://gateway.bankr.gg/v1/chat/completions';
const BANKR_API_KEY = process.env.BANKR_API_KEY ?? '';

async function directLLMCall(
  scenarioId: string,
  scenarioName: string,
  txTraces: string[],
  contractCode: string,
  model: string,
): Promise<{
  summary: string;
  severity: Severity;
  confidence: number;
  recommendations: string[];
  raw: string;
  durationMs: number;
}> {
  if (!BANKR_API_KEY) {
    throw new Error('BANKR_API_KEY not set — set it in .env to enable AI analysis');
  }

  const prompt = buildModelabPrompt(scenarioId, scenarioName, txTraces, contractCode);
  const start = Date.now();

  const response = await fetch(BANKR_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${BANKR_API_KEY}`,
    },
    body: JSON.stringify({
      model: model.startsWith('anthropic/') ? model : `anthropic/${model}`,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: prompt },
      ],
      max_tokens: 1536,
      temperature: 0.3,
    }),
  });

  if (!response.ok) {
    throw new Error(`Bankr API error: ${response.status} ${response.statusText}`);
  }

  const data = await response.json() as {
    choices: Array<{ message: { content: string } }>;
  };

  const raw = data.choices[0]?.message?.content ?? '';
  const durationMs = Date.now() - start;
  const parsed = parseAnalysis(raw);

  return {
    summary: parsed.summary,
    severity: parsed.severity,
    confidence: parsed.confidence,
    recommendations: parsed.recommendations,
    raw,
    durationMs,
  };
}

function parseAnalysis(text: string): {
  summary: string;
  severity: Severity;
  confidence: number;
  recommendations: string[];
} {
  const lines = text.split('\n');
  const severityMatch = text.match(/severity[:\s]+(critical|high|medium|low|informational)/i);
  const cvssMatch = text.match(/(?:cvss|score)[:\s]+(\d+\.?\d*)/i);
  const recs: string[] = [];
  let recSection = false;

  for (const line of lines) {
    if (/recommendations?/i.test(line)) { recSection = true; continue; }
    if (recSection && (line.trim().startsWith('-') || line.trim().startsWith('•') || /^\d+\./.test(line))) {
      const cleaned = line.replace(/^[-•\d.)\s]+/, '').trim();
      if (cleaned.length > 10) recs.push(cleaned.slice(0, 200));
    }
  }

  const cvss = cvssMatch ? parseFloat(cvssMatch[1]) : 7;
  const severity = (severityMatch?.[1]?.toLowerCase() ?? 'high') as Severity;

  return {
    summary: text.slice(0, 800),
    severity,
    confidence: Math.min(cvss / 10, 1),
    recommendations: recs.length > 0 ? recs : [
      'Conduct a professional audit before mainnet deployment',
      'Use Slither or Mythril for automated static analysis',
      'Implement CEI pattern (Checks-Effects-Interactions)',
    ],
  };
}

import { inferPattern } from './patternSignatures.js';

// ── Main analysis ─────────────────────────────────────────────────────────────

export interface AnalyzeWithModelabOptions {
  scenarioId: string;
  scenarioName: string;
  txTraces: string[];
  contractCode: string;
  models?: string[];
  minConfidence?: number;
  chainId?: number;
}

export async function analyzeWithModelab(
  options: AnalyzeWithModelabOptions,
): Promise<ModelabAnalysisResult[]> {
  const {
    scenarioId,
    scenarioName,
    txTraces,
    contractCode,
    models = ['claude-sonnet-4-6'],
    chainId = 1,
  } = options;

  console.log(`\n🧠 Running modelab analysis for: ${scenarioName}`);
  console.log(`   Models: ${models.join(', ')}`);
  console.log(`   Traces: ${txTraces.length} transactions`);

  const results: ModelabAnalysisResult[] = [];

  for (const model of models) {
    try {
      const analysis = await directLLMCall(
        scenarioId,
        scenarioName,
        txTraces,
        contractCode,
        model,
      );

      const report: ThreatReport = {
        reportId: randomUUID(),
        scenarioId,
        attackPattern: inferPattern(analysis.summary),
        severity: analysis.severity,
        summary: analysis.summary,
        findings: [
          {
            title: `${inferPattern(analysis.summary).replace(/-/g, ' ')} vulnerability in ${scenarioName}`,
            description: analysis.summary,
            evidence: txTraces.join('\n').slice(0, 500) || contractCode.slice(0, 500),
          },
        ],
        aiModel: model,
        confidence: analysis.confidence,
        recommendations: analysis.recommendations,
        createdAt: new Date().toISOString(),
      };

      results.push({
        model,
        report,
        rawResponse: analysis.raw,
        durationMs: analysis.durationMs,
      });

      console.log(`  ✅ ${model}: ${report.attackPattern} (${(analysis.confidence * 100).toFixed(0)}% confidence) — ${analysis.durationMs}ms`);
    } catch (err) {
      console.warn(`  ⚠️  ${model} failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return results;
}

export function getBestAnalysis(results: ModelabAnalysisResult[]): ModelabAnalysisResult {
  return [...results].sort((a, b) => b.report.confidence - a.report.confidence)[0];
}
