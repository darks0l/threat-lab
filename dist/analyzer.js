/**
 * AI-powered threat analysis engine.
 * Sends exploit traces to Bankr gateway for LLM analysis,
 * returns structured threat reports.
 */
import { randomUUID } from 'crypto';
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
function buildAnalysisPrompt(scenarioName, scenarioDesc, txTrace, contractCode) {
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
function detectPatternBySignature(code) {
    const matches = [];
    for (const [pattern, regexes] of Object.entries(PATTERN_REGEX)) {
        const count = regexes.filter(r => r.test(code)).length;
        if (count > 0)
            matches.push({ pattern: pattern, count });
    }
    if (matches.length === 0)
        return 'unknown';
    matches.sort((a, b) => b.count - a.count);
    return matches[0].pattern;
}
function extractEvidenceSnippets(contractCode, pattern) {
    const lines = contractCode.split(/\r?\n/);
    const regexes = PATTERN_REGEX[pattern] ?? [];
    const snippets = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!regexes.some((regex) => regex.test(line)))
            continue;
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 2);
        const block = lines.slice(start, end)
            .map((entry, idx) => `${start + idx + 1}: ${entry.trimEnd()}`)
            .join('\n')
            .trim();
        if (block && !snippets.includes(block))
            snippets.push(block);
        if (snippets.length >= 3)
            break;
    }
    return snippets;
}
function fallbackSeverityFor(pattern) {
    switch (pattern) {
        case 'reentrancy':
        case 'access-control':
        case 'delegatecall-injection':
            return 'critical';
        case 'oracle-manipulation':
        case 'flash-loan-attack':
        case 'integer-overflow':
        case 'liquidation-attack':
            return 'high';
        case 'permit-front-run':
        case 'front-running':
        case 'sandwich-attack':
            return 'medium';
        default:
            return 'medium';
    }
}
function fallbackRecommendations(pattern) {
    const common = [
        'Run Slither/Mythril and compare results against these flagged code paths',
        'Add regression tests that exercise the suspicious path before shipping',
    ];
    switch (pattern) {
        case 'reentrancy':
            return ['Apply CEI ordering and add a reentrancy guard on value-moving paths', 'Move state updates before external calls or use pull-pattern withdrawals', ...common];
        case 'oracle-manipulation':
            return ['Use TWAP or oracle sanity bounds instead of raw spot reserves', 'Guard large price deltas and single-block oracle reads', ...common];
        case 'flash-loan-attack':
            return ['Assume attackers can borrow size instantly; gate critical pricing/state transitions accordingly', 'Add invariant checks around callbacks and same-tx balance changes', ...common];
        case 'access-control':
            return ['Add explicit authorization checks to privileged functions', 'Audit every external/admin path for missing role enforcement', ...common];
        case 'delegatecall-injection':
            return ['Lock implementation targets behind strict allowlists/governance checks', 'Validate storage-slot and upgrade authorization assumptions', ...common];
        case 'integer-overflow':
            return ['Use checked arithmetic or explicit bounds before math on attacker-controlled inputs', 'Review unchecked blocks and accumulator math carefully', ...common];
        default:
            return ['Review the flagged code path manually and tighten invariants around it', ...common];
    }
}
function buildFallbackAnalysis(contractCode, detectedPattern) {
    const evidence = extractEvidenceSnippets(contractCode, detectedPattern);
    const severity = fallbackSeverityFor(detectedPattern);
    const confidence = detectedPattern === 'unknown' ? 0.35 : evidence.length >= 2 ? 0.78 : 0.62;
    const summary = detectedPattern === 'unknown'
        ? 'No high-confidence exploit pattern matched. Contract looks inconclusive from signatures alone, so this needs deeper manual review.'
        : `Signature analysis flagged a likely ${detectedPattern} path with concrete code evidence. This should be treated as a real security lead, not a cosmetic lint warning.`;
    const findings = detectedPattern === 'unknown'
        ? [{
                title: 'Low-confidence static signal',
                description: 'The scanner did not find a known exploit signature with enough confidence to classify the issue automatically.',
                evidence: contractCode.slice(0, 300),
            }]
        : evidence.map((snippet, index) => ({
            title: `${detectedPattern} evidence ${index + 1}`,
            description: `Matched ${detectedPattern} signature in contract code`,
            evidence: snippet,
        }));
    return {
        summary,
        severity,
        confidence,
        recommendations: fallbackRecommendations(detectedPattern),
        findings,
    };
}
/**
 * Analyze contract code or transaction trace using Bankr LLM gateway.
 * Falls back to signature-based detection if LLM unavailable.
 */
export async function analyzeThreat(input) {
    const { scenarioId, scenarioName, scenarioDesc, txTrace, contractCode, chainId = 1, model } = input;
    // Fast path: signature-based detection
    const detectedPattern = detectPatternBySignature(contractCode);
    let llmAnalysis = null;
    try {
        if (!BANKR_API_KEY)
            throw new Error('BANKR_API_KEY not set');
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
        if (!response.ok)
            throw new Error(`Bankr API error: ${response.status}`);
        const data = await response.json();
        const content = data.choices[0]?.message?.content ?? '';
        llmAnalysis = parseAnalysisResponse(content);
    }
    catch {
        // LLM unavailable — use signature-based detection as fallback
        llmAnalysis = buildFallbackAnalysis(contractCode, detectedPattern);
    }
    const resolvedPattern = llmAnalysis ? inferPattern(`${llmAnalysis.summary}\n${llmAnalysis.findings?.map(f => `${f.title} ${f.description}`).join('\n') ?? ''}`) : detectedPattern;
    const findings = llmAnalysis?.findings && llmAnalysis.findings.length > 0
        ? llmAnalysis.findings
        : [
            {
                title: `Potential ${detectedPattern} vulnerability`,
                description: llmAnalysis?.summary ?? 'Detected via code signature analysis.',
                evidence: contractCode.slice(0, 500),
            },
        ];
    return {
        reportId: randomUUID(),
        scenarioId,
        attackPattern: resolvedPattern,
        severity: llmAnalysis?.severity ?? 'high',
        summary: llmAnalysis?.summary ?? `Detected: ${detectedPattern}`,
        findings,
        aiModel: model ?? 'bankr-default',
        confidence: llmAnalysis?.confidence ?? 0.4,
        recommendations: llmAnalysis?.recommendations ?? [],
        createdAt: new Date().toISOString(),
    };
}
function parseAnalysisResponse(response) {
    const text = typeof response === 'string' ? response : JSON.stringify(response);
    // Try to extract structured fields from LLM response
    const severityMatch = text.match(/severity:\s*(critical|high|medium|low|informational)/i);
    const patternMatch = text.match(/attack pattern:\s*(\w+[\w-]*)/i);
    const cvssMatch = text.match(/cvss:?\s*(\d+\.?\d*)/i);
    return {
        summary: text.slice(0, 1000),
        severity: severityMatch?.[1]?.toLowerCase() ?? 'high',
        confidence: cvssMatch ? parseFloat(cvssMatch[1]) / 10 : 0.7,
        recommendations: extractRecommendations(text),
    };
}
function extractRecommendations(text) {
    const recs = [];
    const recSection = text.match(/recommendations?[:\s](.+?)(?:\n\n|$)/is);
    if (recSection) {
        const items = recSection[1].split(/[-•\d]+\./).filter(Boolean);
        for (const item of items.slice(0, 4)) {
            const cleaned = item.trim().replace(/^[a-z]\)\s*/, '');
            if (cleaned.length > 10)
                recs.push(cleaned.slice(0, 200));
        }
    }
    return recs.length > 0 ? recs : ['Conduct a professional audit', 'Use static analysis tools'];
}
// inferPattern now imported from patternSignatures.ts
//# sourceMappingURL=analyzer.js.map