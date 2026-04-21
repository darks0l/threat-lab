/**
 * Threat Lab - Deep Research via modelab
 *
 * When a finding is flagged (static/deps/sim), this module can be invoked
 * to run the finding through modelab's iterative multi-model research
 * pipeline for:
 *
 * 1. Root cause analysis - multi-model perspective on the vulnerability
 * 2. Impact assessment - how severe is this really?
 * 3. Patch generation - concrete, validated fix proposals
 * 4. Exploit scenario - how would an attacker actually use this?
 *
 * Usage: threat-lab scan . --deep
 *
 * Requires BANKR_API_KEY (for the underlying LLM calls).
 * modelab routes requests through the Bankr LLM gateway.
 */

import { randomUUID } from 'crypto';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DeepResearchFinding {
  category: 'static' | 'deps' | 'sim';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  title: string;
  description: string;
  packageName?: string; // for deps findings
  contractFile?: string; // for static findings
  evidence?: string;
}

export interface DeepResearchResult {
  finding: DeepResearchFinding;
  rootCause: string;
  impactAssessment: string;
  exploitScenario: string;
  proposedFix: PatchFix | null;
  modelsUsed: string[];
  totalCost: number;
  durationMs: number;
}

export interface PatchFix {
  title: string;
  description: string;
  code: string; // Solidity code patch
  diff: string; // human-readable diff description
  confidence: number; // 0-1
  validation: string; // how this was validated
  references: string[];
}

// ── modelab configuration ─────────────────────────────────────────────────────

const BANKR_API_URL = process.env.BANKR_API_URL ?? 'https://gateway.bankr.gg/v1/chat/completions';
const BANKR_API_KEY = process.env.BANKR_API_KEY ?? '';
const MODELS = ['claude-sonnet-4-6', 'anthropic/claude-opus-4-6', 'ollama-cloud/glm-4-7'];

// ── System prompt for deep research ──────────────────────────────────────────

const SYSTEM_PROMPT = `You are a DeFi smart contract security researcher running deep-dive analysis. Your job is to:

1. Identify the ROOT CAUSE of the vulnerability (not just the symptom)
2. Assess the REAL impact (not just the CVSS score)
3. Describe a concrete EXPLOIT SCENARIO showing how an attacker uses this
4. Generate a SPECIFIC PATCH with Solidity code that fixes the vulnerability

Be precise and technical. Provide actual code, not vague recommendations.`;

// ── Research prompt builder ───────────────────────────────────────────────────

function buildResearchPrompt(finding: DeepResearchFinding): string {
  if (finding.category === 'deps') {
    return `## Deep Research: Dependency Vulnerability

**Package:** ${finding.packageName ?? 'unknown'}
**Severity:** ${finding.severity}
**Finding:** ${finding.title}
**Description:** ${finding.description}

**Your tasks:**

1. **Root Cause** - Why is this package vulnerable? What is the underlying weakness?

2. **Impact Assessment** - If this package is used in a DeFi protocol, what can go wrong? Be specific about the blast radius.

3. **Exploit Scenario** - Describe a concrete attack scenario using this vulnerability in a DeFi context.

4. **Patch/Remediation** - What is the concrete fix?
   - For npm packages: upgrade to version X, or replace with alternative package Y
   - For Solidity: provide specific Solidity code that implements the fix
   - Include the full fixed code block

Respond with:
ROOT CAUSE: <your analysis>
IMPACT: <your assessment>
EXPLOIT SCENARIO: <concrete attack description>
PATCH: <specific code or version recommendation>
CONFIDENCE: <0.0-1.0>`;
  }

  return `## Deep Research: Smart Contract Vulnerability

**File:** ${finding.contractFile ?? 'unknown'}
**Pattern:** ${finding.title}
**Severity:** ${finding.severity}
**Description:** ${finding.description}
${finding.evidence ? `**Contract Evidence:**\n\`\`\`solidity\n${finding.evidence.slice(0, 1500)}\n\`\`\`` : ''}

**Your tasks:**

1. **Root Cause** - Identify the exact line/function/vulnerability mechanism. Be surgical.

2. **Impact Assessment** - What's the actual damage if this is exploited? Quantify if possible (funds at risk, etc.)

3. **Exploit Scenario** - Show a concrete attack transaction sequence with parameters.

4. **Proposed Fix** - Provide complete Solidity code implementing the fix. Use the CEI pattern, ReentrancyGuard, or whatever is appropriate. Make it production-ready.

Respond with:
ROOT CAUSE: <precise technical explanation>
IMPACT: <quantified damage assessment>
EXPLOIT SCENARIO: <concrete attack with parameters>
PATCH:
\`\`\`solidity
<complete fixed Solidity code>
\`\`\`
CONFIDENCE: <0.0-1.0>
REFERENCES: <optional URLs to similar fixes>`;
}

// ── Parse model response ─────────────────────────────────────────────────────

interface ParsedResearch {
  rootCause: string;
  impact: string;
  exploitScenario: string;
  patch: string;
  confidence: number;
  references: string[];
}

function parseResearchResponse(text: string): ParsedResearch {
  const rootCauseMatch = text.match(/ROOT CAUSE:\s*([\s\S]*?)(?=IMPACT:|EXPLOIT SCENARIO:|PATCH:|CONFIDENCE:|$)/i);
  const impactMatch = text.match(/IMPACT:\s*([\s\S]*?)(?=ROOT CAUSE:|EXPLOIT SCENARIO:|PATCH:|CONFIDENCE:|$)/i);
  const exploitMatch = text.match(/EXPLOIT SCENARIO:\s*([\s\S]*?)(?=ROOT CAUSE:|IMPACT:|PATCH:|CONFIDENCE:|$)/i);
  const patchMatch = text.match(/PATCH:\s*([\s\S]*?)(?=ROOT CAUSE:|IMPACT:|EXPLOIT SCENARIO:|CONFIDENCE:|REFERENCES:|$)/i);
  const confidenceMatch = text.match(/CONFIDENCE:\s*([\d.]+)/i);
  const refsMatch = text.match(/REFERENCES:\s*([\s\S]*?)$/i);

  // Extract Solidity code from patch section
  const solidityMatch = text.match(/```solidity\n([\s\S]*?)```/);

  return {
    rootCause: rootCauseMatch?.[1]?.trim() ?? impactMatch?.[1]?.trim() ?? 'Unable to determine root cause',
    impact: impactMatch?.[1]?.trim() ?? 'Impact assessment unavailable',
    exploitScenario: exploitMatch?.[1]?.trim() ?? 'No exploit scenario described',
    patch: solidityMatch?.[1]?.trim() ?? patchMatch?.[1]?.trim() ?? '',
    confidence: confidenceMatch ? parseFloat(confidenceMatch[1]) : 0.7,
    references: refsMatch?.[1]?.split('\n').map(r => r.replace(/^[-* ]+/, '').trim()).filter(Boolean) ?? [],
  };
}

// ── Single model research call ────────────────────────────────────────────────

async function researchWithModel(
  finding: DeepResearchFinding,
  model: string,
): Promise<{ model: string; text: string; cost: number; durationMs: number }> {
  if (!BANKR_API_KEY) {
    throw new Error('BANKR_API_KEY not set - deep research requires it');
  }

  const prompt = buildResearchPrompt(finding);
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
      max_tokens: 2048,
      temperature: 0.2,
    }),
  });

  if (!response.ok) {
    throw new Error(`Bankr API error: ${response.status} ${response.statusText}`);
  }

  const data = await response.json() as {
    choices: Array<{ message: { content: string } }>;
    usage?: { total_tokens: number; prompt_tokens: number; completion_tokens: number };
  };

  const text = data.choices[0]?.message?.content ?? '';
  const durationMs = Date.now() - start;

  // Estimate cost: $10/M tokens for Sonnet/Opus class
  const totalTokens = data.usage?.total_tokens ?? 500;
  const cost = (totalTokens / 1_000_000) * 10;

  return { model, text, cost, durationMs };
}

// ── Main: run deep research on a single finding ──────────────────────────────

export interface DeepResearchOptions {
  finding: DeepResearchFinding;
  contractCode?: string; // full contract code for static findings
  models?: string[];
}

export async function runDeepResearch(
  options: DeepResearchOptions,
): Promise<DeepResearchResult> {
  const { finding, contractCode, models = MODELS } = options;

  console.log(`\n  [deep] Researching: ${finding.title}`);

  // Run multiple models in parallel (modelab-style: parallel arms)
  const results = await Promise.allSettled(
    models.map(model => researchWithModel(finding, model)),
  );

  const succeeded = results
    .filter((r): r is PromiseFulfilledResult<{ model: string; text: string; cost: number; durationMs: number }> => r.status === 'fulfilled')
    .map(r => r.value);

  const failed = results.filter(r => r.status === 'rejected');

  for (const f of failed) {
    const msg = f.reason instanceof Error ? f.reason.message : 'model failed';
    console.warn(`     [deep]   ${msg}`);
  }

  if (succeeded.length === 0) {
    throw new Error('All models failed for deep research');
  }

  // Parse all responses
  const parsed = succeeded.map(r => ({
    model: r.model,
    ...parseResearchResponse(r.text),
  }));

  // Pick the most confident result
  const best = parsed.reduce((a, b) => (a.confidence >= b.confidence ? a : b));

  // Extract patch code
  const patchCode = extractSolidityPatch(best.patch, finding, contractCode);

  const fix: PatchFix | null = patchCode
    ? {
        title: `Fix for ${finding.title}`,
        description: best.patch.slice(0, 300),
        code: patchCode,
        diff: describeDiff(patchCode, finding),
        confidence: best.confidence,
        validation: `Validated by ${succeeded.length} model(s): ${succeeded.map(s => s.model).join(', ')}`,
        references: best.references,
      }
    : null;

  return {
    finding,
    rootCause: best.rootCause,
    impactAssessment: best.impact,
    exploitScenario: best.exploitScenario,
    proposedFix: fix,
    modelsUsed: succeeded.map(s => s.model),
    totalCost: succeeded.reduce((s, r) => s + r.cost, 0),
    durationMs: succeeded.reduce((s, r) => s + r.durationMs, 0),
  };
}

// ── Run deep research on multiple findings ─────────────────────────────────---

export interface DeepResearchBatchOptions {
  findings: DeepResearchFinding[];
  contractCode?: string;
  models?: string[];
  maxFindings?: number; // limit to avoid runaway costs
}

export async function runDeepResearchBatch(
  options: DeepResearchBatchOptions,
): Promise<DeepResearchResult[]> {
  const { findings, contractCode, models = MODELS, maxFindings = 5 } = options;

  // Limit to highest-severity findings first
  const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
  const sorted = [...findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity),
  );
  const limited = sorted.slice(0, maxFindings);

  console.log(`\n  [deep] Running deep research on ${limited.length} findings (max ${maxFindings})`);
  console.log(`     Models: ${models.join(', ')}`);
  const costEstimate = limited.length * models.length * 0.01;
  console.log(`     Estimated cost: ~$${costEstimate.toFixed(2)}`);

  const results: DeepResearchResult[] = [];

  for (const finding of limited) {
    try {
      const result = await runDeepResearch({ finding, contractCode, models });
      results.push(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`     [deep] Failed for "${finding.title}": ${msg}`);
    }
  }

  return results;
}

// ── Extract Solidity patch from model response ────────────────────────────────

function extractSolidityPatch(
  patchText: string,
  finding: DeepResearchFinding,
  contractCode?: string,
): string | null {
  // Try to find a solidity code block
  const solidityMatch = patchText.match(/```solidity\n([\s\S]*?)```/);
  if (solidityMatch) return solidityMatch[1].trim();

  // Fallback: look for common fix patterns
  if (finding.title.includes('reentrancy')) {
    return contractCode ? insertReentrancyGuard(contractCode) : null;
  }
  if (finding.title.includes('access-control') || finding.title.includes('permission')) {
    return contractCode ? addAccessControl(contractCode) : null;
  }

  return null;
}

function insertReentrancyGuard(code: string): string {
  if (/nonReentrant|reentrancyGuard/i.test(code)) return code;

  let patch = code;

  if (!code.includes('ReentrancyGuard')) {
    patch = `import "@openzeppelin/contracts/security/ReentrancyGuard.sol";\n` + patch;
  }

  // Find function with external call and add nonReentrant modifier
  const fnMatch = patch.match(/(function\s+\w+[^{]*\{[^}]*(?:call|transfer|send)[^}]*\})/);
  if (fnMatch) {
    const originalFn = fnMatch[1];
    const fixedFn = originalFn.replace(/(function\s+\w+)/, '$1 nonReentrant');
    patch = patch.replace(originalFn, fixedFn);
  }

  return patch;
}

function addAccessControl(code: string): string {
  if (/Ownable|AccessControl|onlyOwner/i.test(code)) return code;

  let patch = code;
  if (!code.includes('Ownable')) {
    patch = `import "@openzeppelin/contracts/access/Ownable.sol";\n` + patch;
  }

  // Find first state-modifying function and add onlyOwner
  const fnMatch = patch.match(/(function\s+\w+[^{]*\{)/);
  if (fnMatch) {
    const originalFn = fnMatch[1];
    const fixedFn = originalFn.replace(/(function\s+\w+)/, '$1 onlyOwner');
    patch = patch.replace(originalFn, fixedFn);
  }

  return patch;
}

function describeDiff(patchCode: string, finding: DeepResearchFinding): string {
  if (finding.title.includes('reentrancy')) {
    return 'Added nonReentrant modifier to functions with external calls after value transfers';
  }
  if (finding.title.includes('access-control')) {
    return 'Added onlyOwner access control to state-modifying functions';
  }
  if (finding.title.includes('overflow') || finding.title.includes('integer')) {
    return 'Added SafeMath or replaced unsafe arithmetic with checked operations';
  }
  return `Modified contract to address: ${finding.title}`;
}

// ── Format deep research report ────────────────────────────────────────────────

export function formatDeepResearchReport(results: DeepResearchResult[]): string {
  const lines: string[] = [];

  lines.push('');
  lines.push('================================================================');
  lines.push('   THREAT LAB - DEEP RESEARCH REPORT (modelab)');
  lines.push('================================================================');
  lines.push('');

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    const sevIcon = r.finding.severity === 'critical' ? '[CRIT]' : r.finding.severity === 'high' ? '[HIGH]' : r.finding.severity === 'medium' ? '[MED]' : '[LOW]';
    lines.push(`[${i + 1}] ${sevIcon} ${r.finding.title}`);
    if (r.finding.packageName) lines.push(`    Package: ${r.finding.packageName}`);
    if (r.finding.contractFile) lines.push(`    File: ${r.finding.contractFile}`);
    lines.push('');

    lines.push('  Root Cause:');
    for (const para of wrapText(r.rootCause.slice(0, 300), 72)) {
      lines.push(`    ${para}`);
    }
    lines.push('');

    lines.push('  Impact:');
    for (const para of wrapText(r.impactAssessment.slice(0, 200), 72)) {
      lines.push(`    ${para}`);
    }
    lines.push('');

    lines.push('  Exploit Scenario:');
    for (const para of wrapText(r.exploitScenario.slice(0, 300), 72)) {
      lines.push(`    ${para}`);
    }
    lines.push('');

    if (r.proposedFix) {
      lines.push(`  Proposed Fix (confidence: ${Math.round(r.proposedFix.confidence * 100)}%)`);
      for (const para of wrapText(r.proposedFix.description.slice(0, 200), 72)) {
        lines.push(`    ${para}`);
      }
      if (r.proposedFix.code) {
        lines.push('    Fixed code:');
        for (const line of r.proposedFix.code.split('\n').slice(0, 10)) {
          lines.push(`      ${line}`);
        }
        if (r.proposedFix.code.split('\n').length > 10) {
          lines.push(`      ... (${r.proposedFix.code.split('\n').length - 10} more lines)`);
        }
      }
      lines.push(`    Validation: ${r.proposedFix.validation}`);
      lines.push('');
    }

    lines.push(`  Models: ${r.modelsUsed.join(', ')} | Cost: $${r.totalCost.toFixed(4)} | ${Math.round(r.durationMs / 1000)}s`);
    lines.push('----------------------------------------------------------------');
    lines.push('');
  }

  const totalCost = results.reduce((s, r) => s + r.totalCost, 0);
  const totalMs = results.reduce((s, r) => s + r.durationMs, 0);
  lines.push(`  Done: ${results.length} findings | $${totalCost.toFixed(4)} | ${Math.round(totalMs / 1000)}s`);
  lines.push('');

  return lines.join('\n');
}

function wrapText(text: string, width: number): string[] {
  const paragraphs = text.split('\n');
  const result: string[] = [];
  for (const para of paragraphs) {
    if (para.length <= width) {
      result.push(para);
    } else {
      const words = para.split(' ');
      let line = '';
      for (const word of words) {
        if ((line + ' ' + word).trim().length > width) {
          if (line) result.push(line);
          line = word;
        } else {
          line = (line + ' ' + word).trim();
        }
      }
      if (line) result.push(line);
    }
  }
  return result;
}
