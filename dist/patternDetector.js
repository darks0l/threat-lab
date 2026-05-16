/**
 * Pattern detector — matches new findings against the growing pattern library.
 * The more submissions, the smarter the detection.
 */
import { PATTERN_SIGNATURES, PATTERN_KEYWORDS } from './patternSignatures.js';
// PATTERN_SIGNATURES and PATTERN_KEYWORDS now imported from patternSignatures.ts
// (single source of truth — no more duplication)
/**
 * Match a text (code, trace, or report) against known attack signatures.
 * Returns confidence scores for each pattern.
 */
export function detectPatterns(text) {
    const lower = text.toLowerCase();
    const matches = [];
    for (const [pattern, signatures] of Object.entries(PATTERN_SIGNATURES)) {
        const pat = pattern;
        const keywords = PATTERN_KEYWORDS[pat];
        const matchedSigs = signatures.filter(sig => lower.includes(sig.toLowerCase()));
        const matchedKws = keywords.filter(kw => lower.includes(kw.toLowerCase()));
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
export async function findSimilarReports(report, library) {
    const text = `${report.summary} ${report.findings.map(f => f.description).join(' ')}`;
    const matches = detectPatterns(text);
    // Tag similar reports
    for (const match of matches) {
        match.similarReports = library
            .filter(r => r.reportId !== report.reportId &&
            r.attackPattern === match.pattern)
            .slice(0, 3)
            .map(r => r.reportId);
    }
    return matches;
}
/**
 * Score a submission based on how much it adds to the pattern library.
 * New patterns or high-confidence detections get higher scores.
 */
export function scoreSubmission(report, library) {
    const existingCount = library.filter(r => r.attackPattern === report.attackPattern).length;
    const baseScore = existingCount === 0 ? 10 : 1; // New pattern = 10x bonus
    const confidenceBonus = report.confidence * 5;
    return baseScore + confidenceBonus;
}
//# sourceMappingURL=patternDetector.js.map