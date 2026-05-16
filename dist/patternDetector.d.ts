/**
 * Pattern detector — matches new findings against the growing pattern library.
 * The more submissions, the smarter the detection.
 */
import type { AttackPattern, ThreatReport } from './schemas.js';
export interface PatternMatch {
    pattern: AttackPattern;
    confidence: number;
    matchedOn: string[];
    similarReports: string[];
}
/**
 * Match a text (code, trace, or report) against known attack signatures.
 * Returns confidence scores for each pattern.
 */
export declare function detectPatterns(text: string): PatternMatch[];
/**
 * Match a finding against historical reports to surface similar attacks.
 */
export declare function findSimilarReports(report: ThreatReport, library: ThreatReport[]): Promise<PatternMatch[]>;
/**
 * Score a submission based on how much it adds to the pattern library.
 * New patterns or high-confidence detections get higher scores.
 */
export declare function scoreSubmission(report: ThreatReport, library: ThreatReport[]): number;
//# sourceMappingURL=patternDetector.d.ts.map