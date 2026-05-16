/**
 * Threat Lab — Unified Scanner
 *
 * Single-pass security analysis combining three complementary approaches:
 *  1. Static analysis     — signature patterns + AI deep-read of contract code
 *  2. Dependency audit   — OSV + npm advisories + Socket.dev + typo-squat
 *  3. Exploit simulation — deploy to Anvil, run attack scenarios, AI analysis
 *
 * Usage:
 *   threat-lab scan <contract.sol>  # single file
 *   threat-lab scan <dir>          # all .sol files in directory
 *   threat-lab scan <dir> --quick  # skip exploit simulation (faster)
 *   threat-lab scan <dir> --no-deps # skip dependency audit
 *   threat-lab scan <dir> --no-sim  # skip exploit simulation
 *   threat-lab scan <dir> --network anvil|base-sepolia
 *
 * Output: unified threat report with per-category findings and overall severity.
 */
import { type PatternMatch } from './patternDetector.js';
import { type ThreatIntelResult } from './threatIntel.js';
import type { ThreatReport, Severity } from './schemas.js';
export interface ScanResult {
    file: string;
    staticAnalysis: StaticResult | null;
    dependencyAudit: DepAuditResult | null;
    threatIntel: ThreatIntelResult[];
    exploitSim: ExploitSimResult | null;
    overallSeverity: Severity;
    threatScore: number;
    findings: ConsolidatedFinding[];
    recommendations: string[];
    durationMs: number;
    errors: string[];
}
interface StaticResult {
    patterns: PatternMatch[];
    aiReport: ThreatReport | null;
    contractCode: string;
}
interface DepAuditResult {
    summary: string;
    threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
    vulns: VulnerabilitySummary[];
    advisories: AdvisorySummary[];
    score: number;
}
interface VulnerabilitySummary {
    package: string;
    severity: string;
    title: string;
    url: string;
}
interface AdvisorySummary {
    id: string;
    severity: string;
    title: string;
    url: string;
    activeExploit?: boolean;
}
interface ExploitSimResult {
    scenarioId: string;
    scenarioName: string;
    success: boolean;
    aiReport: ThreatReport | null;
    output: string;
    severity: Severity;
}
export declare function severityMeetsOrExceeds(actual: Severity, threshold: Severity): boolean;
export declare function getWorstScanSeverity(results: ScanResult[]): Severity;
interface ConsolidatedFinding {
    category: 'static' | 'deps' | 'sim';
    severity: Severity;
    title: string;
    description: string;
    evidence?: string;
    recommendation?: string;
}
export declare function findSolFiles(target: string): Promise<string[]>;
export declare function generateReport(results: ScanResult[]): string;
export interface ScanOptions {
    target: string;
    quick?: boolean;
    noDeps?: boolean;
    noSim?: boolean;
    noIntel?: boolean;
    network?: string;
    models?: string[];
    deep?: boolean;
    outputPath?: string;
}
export interface ScanPayload {
    scannedAt: string;
    target: string;
    results: ScanResult[];
}
export interface ScanDiffEntry {
    file: string;
    status: 'new' | 'resolved' | 'changed' | 'unchanged';
    currentSeverity?: Severity;
    previousSeverity?: Severity;
    currentScore?: number;
    previousScore?: number;
}
export interface ScanDiffSummary {
    baselineTarget: string;
    currentTarget: string;
    baselineScannedAt: string;
    currentScannedAt: string;
    added: number;
    resolved: number;
    changed: number;
    unchanged: number;
    entries: ScanDiffEntry[];
}
export declare function buildScanPayload(target: string, results: ScanResult[]): ScanPayload;
export declare function loadScanPayload(path: string): Promise<ScanPayload>;
export declare function compareScanPayloads(current: ScanPayload, baseline: ScanPayload): ScanDiffSummary;
export declare function formatScanDiff(summary: ScanDiffSummary): string;
export declare function scanTarget(options: ScanOptions): Promise<ScanResult[]>;
export {};
//# sourceMappingURL=scanner.d.ts.map