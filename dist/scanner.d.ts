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
import { analyzeThreat } from './analyzer.js';
import { type PatternMatch } from './patternDetector.js';
import { auditDependencies } from './audit.js';
import { executeScenario, isAnvilRunning } from './executor.js';
import { analyzeWithModelab, getBestAnalysis } from './modelabIntegration.js';
import { runThreatIntel, type ThreatIntelResult } from './threatIntel.js';
import type { ThreatReport, Severity } from './schemas.js';
export declare const scannerDeps: {
    analyzeThreat: typeof analyzeThreat;
    auditDependencies: typeof auditDependencies;
    executeScenario: typeof executeScenario;
    isAnvilRunning: typeof isAnvilRunning;
    analyzeWithModelab: typeof analyzeWithModelab;
    getBestAnalysis: typeof getBestAnalysis;
    runThreatIntel: typeof runThreatIntel;
};
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
    category: 'static' | 'deps' | 'intel' | 'sim';
    severity: Severity;
    title: string;
    description: string;
    evidence?: string;
    recommendation?: string;
    packageName?: string;
    correlated?: boolean;
    dedupeKey?: string;
}
export declare function formatSecurityGateDecision(results: ScanResult[], threshold: Severity): string;
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
    saveArtifacts?: boolean;
}
export interface WatchOptions extends ScanOptions {
    intervalMs?: number;
    maxIterations?: number;
    outputDir?: string;
    scanRunner?: (options: ScanOptions) => Promise<ScanResult[]>;
}
export interface WatchIterationResult {
    iteration: number;
    scannedAt: string;
    payload: ScanPayload;
    diff: ScanDiffSummary | null;
    alerts: string[];
}
export interface ScanPayload {
    scannedAt: string;
    target: string;
    results: ScanResult[];
}
export interface ScanPayloadExecutiveSummary {
    scannedAt: string;
    target: string;
    fileCount: number;
    overallSeverity: Severity;
    averageScore: number;
    findingsBySeverity: Record<Severity, number>;
    findingsByCategory: Record<ConsolidatedFinding['category'], number>;
    correlatedIntelAlerts: number;
    activeExploitIntelAlerts: number;
    confirmedSimulationFindings: number;
    hotspots: Array<{
        file: string;
        severity: Severity;
        threatScore: number;
        topFinding: string | null;
        recommendation: string | null;
    }>;
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
export declare function summarizeScanPayload(payload: ScanPayload): ScanPayloadExecutiveSummary;
export declare function formatScanPayloadSummary(payload: ScanPayload): string;
export declare function loadScanPayload(path: string): Promise<ScanPayload>;
export declare function compareScanPayloads(current: ScanPayload, baseline: ScanPayload): ScanDiffSummary;
export declare function formatScanDiff(summary: ScanDiffSummary): string;
export declare function watchTarget(options: WatchOptions): Promise<WatchIterationResult[]>;
export declare function scanTarget(options: ScanOptions): Promise<ScanResult[]>;
export {};
//# sourceMappingURL=scanner.d.ts.map