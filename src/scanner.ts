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

import { readFile, readdir, stat, writeFile } from 'fs/promises';
import { join, extname, relative } from 'path';
import { analyzeThreat } from './analyzer.js';
import { detectPatterns, type PatternMatch } from './patternDetector.js';
import { auditDependencies } from './audit.js';
import { executeScenario, isAnvilRunning } from './executor.js';
import { getScenario, listScenarios } from './scenarios.js';
import { analyzeWithModelab, getBestAnalysis } from './modelabIntegration.js';
import { runThreatIntel, type ThreatIntelResult } from './threatIntel.js';
import { runDeepResearchBatch, formatDeepResearchReport, type DeepResearchFinding } from './deepResearch.js';
import type { ThreatReport, AttackPattern, Severity } from './schemas.js';

// ── Types ──────────────────────────────────────────────────────────────────────

export interface ScanResult {
  file: string;
  staticAnalysis: StaticResult | null;
  dependencyAudit: DepAuditResult | null;
  threatIntel: ThreatIntelResult[];
  exploitSim: ExploitSimResult | null;
  overallSeverity: Severity;
  threatScore: number; // 0-100
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
  score: number; // 0-100
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

// ── Severity mapping ────────────────────────────────────────────────────────────

const SEVERITY_SCORE: Record<Severity, number> = {
  critical: 100,
  high: 70,
  medium: 40,
  low: 20,
  informational: 5,
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

function severityIndex(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function severityMeetsOrExceeds(actual: Severity, threshold: Severity): boolean {
  return severityIndex(actual) <= severityIndex(threshold);
}

function worstSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[Math.min(severityIndex(a), severityIndex(b))];
}

export function getWorstScanSeverity(results: ScanResult[]): Severity {
  return results.reduce<Severity>((worst, result) => worstSeverity(worst, result.overallSeverity), 'informational');
}

function computeThreatScore(results: ScanResult): number {
  const weights = { static: 0.3, intel: 0.25, deps: 0.2, sim: 0.25 };
  let score = 0;
  if (results.staticAnalysis?.aiReport) {
    score += SEVERITY_SCORE[results.staticAnalysis.aiReport.severity] * weights.static;
  }
  if (results.threatIntel.length > 0) {
    const intelSev = results.threatIntel.reduce((worst: string, t: ThreatIntelResult) => {
      const order = ['critical', 'high', 'medium', 'low', 'none'] as const;
      return order.indexOf(t.overallSeverity) < order.indexOf(worst as 'critical' | 'high' | 'medium' | 'low' | 'none') ? t.overallSeverity : worst;
    }, 'none');
    const intelScore = intelSev === 'critical' ? 100 : intelSev === 'high' ? 75 : intelSev === 'medium' ? 50 : intelSev === 'low' ? 25 : 0;
    score += intelScore * weights.intel;
  }
  if (results.dependencyAudit) {
    score += results.dependencyAudit.score * weights.deps;
  }
  if (results.exploitSim?.aiReport) {
    score += SEVERITY_SCORE[results.exploitSim.aiReport.severity] * weights.sim;
  }
  return Math.min(100, Math.round(score));
}

interface ConsolidatedFinding {
  category: 'static' | 'deps' | 'sim';
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  recommendation?: string;
}

// ── File discovery ─────────────────────────────────────────────────────────────

export async function findSolFiles(target: string): Promise<string[]> {
  const files: string[] = [];
  let targetStat;
  try {
    targetStat = await stat(target);
  } catch {
    return files; // non-existent path → empty result
  }

  if (targetStat.isFile()) {
    if (extname(target) === '.sol') files.push(target);
    return files;
  }

  async function walk(dir: string) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'dist' && entry.name !== 'cache') {
        await walk(full);
      } else if (entry.isFile() && extname(entry.name) === '.sol') {
        files.push(full);
      }
    }
  }

  await walk(target);
  return files;
}

// ── Core scanners ─────────────────────────────────────────────────────────────

async function runStaticAnalysis(filePath: string): Promise<StaticResult> {
  const code = await readFile(filePath, 'utf-8');

  // Fast path: signature-based pattern detection
  const patterns = detectPatterns(code);

  // Deep path: AI analysis via Bankr gateway
  let aiReport: ThreatReport | null = null;
  try {
    aiReport = await analyzeThreat({
      scenarioId: `scan:${relative('.', filePath)}`,
      scenarioName: filePath,
      scenarioDesc: 'Unified scan of user-submitted contract',
      contractCode: code,
    });
  } catch (err) {
    // Non-fatal — signature results still valid
  }

  return { patterns, aiReport, contractCode: code };
}

// ── Layer 2b: Threat Intelligence (live web search) ───────────────────────────

async function runThreatIntelLayer(
  projectPath: string,
): Promise<ThreatIntelResult[]> {
  // Read package.json to get all deps
  try {
    const { readFile } = await import('fs/promises');
    const pkgPath = join(projectPath, 'package.json');
    const pkg = JSON.parse(await readFile(pkgPath, 'utf-8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };
    const pkgs = [
      ...Object.entries(pkg.dependencies ?? {}),
      ...Object.entries(pkg.devDependencies ?? {}),
      ...Object.entries(pkg.optionalDependencies ?? {}),
    ].map(([name, version]) => ({ name, version: version.replace(/^[\^~>=<]/, '') }));

    if (pkgs.length === 0) return [];
    return await runThreatIntel({ packages: pkgs });
  } catch {
    return [];
  }
}

async function runDependencyAudit(projectPath: string): Promise<DepAuditResult> {
  try {
    const audit = await auditDependencies({
      projectPath,
      includeDev: true,
      socketDev: true,
      runNpmAudit: true,
    });

    const vulns: VulnerabilitySummary[] = [];
    const advisories: AdvisorySummary[] = [];

    // Collect npm audit vulns — cast to avoid type mismatch on npm's internal shape
    const npmVulns = (audit.npmAudit as Record<string, unknown> | null)?.vulnerabilities;
    if (npmVulns && typeof npmVulns === 'object') {
      for (const [pkg, vuln] of Object.entries(npmVulns as Record<string, { severity: string; title?: string; url?: string }>)) {
        vulns.push({
          package: pkg,
          severity: vuln.severity,
          title: vuln.title ?? `Vulnerability in ${pkg}`,
          url: vuln.url ?? '',
        });
      }
    }

    // Collect OSV results — access via bracket notation to bypass strict type check
    const osvData = (audit as Record<string, unknown>).osv as
      { results?: Array<{ vulns?: Array<{ id: string; severity?: Array<{ score: string }>; summary?: string; url: string; database_specific?: Record<string, unknown> }> }> } | undefined;
    if (osvData?.results) {
      for (const r of osvData.results) {
        for (const vuln of r.vulns ?? []) {
          const sev = vuln.severity?.[0]?.score ?? 'medium';
          advisories.push({
            id: vuln.id,
            severity: sev,
            title: vuln.summary ?? vuln.id,
            url: vuln.url,
            activeExploit: vuln.database_specific?.url?.toString().includes('actively') ?? false,
          });
        }
      }
    }

    // Collect Socket.dev results
    const socketDev = (audit as Record<string, unknown>).socketDev as { maliciousDetections?: Array<{ packageName: string; description?: string }> } | undefined;
    if (socketDev?.maliciousDetections) {
      for (const m of socketDev.maliciousDetections) {
        vulns.push({
          package: m.packageName,
          severity: 'critical',
          title: m.description ?? 'Malicious package detected by Socket.dev',
          url: '',
        });
      }
    }

    const rawThreatLevel = audit.summary.threatLevel;
    const threatLevel: DepAuditResult['threatLevel'] =
      rawThreatLevel === 'critical' ? 'critical'
        : rawThreatLevel === 'high' ? 'high'
        : rawThreatLevel === 'medium' ? 'medium'
        : rawThreatLevel === 'low' ? 'low'
        : 'none';
    const score = threatLevel === 'critical' ? 100 : threatLevel === 'high' ? 75 : threatLevel === 'medium' ? 50 : threatLevel === 'low' ? 25 : 0;

    return { summary: `Found ${vulns.length + advisories.length} issues`, threatLevel, vulns, advisories, score };
  } catch (err) {
    return {
      summary: `Audit unavailable: ${err instanceof Error ? err.message : String(err)}`,
      threatLevel: 'none',
      vulns: [],
      advisories: [],
      score: 0,
    };
  }
}

async function runExploitSim(filePath: string, network: string): Promise<ExploitSimResult | null> {
  // Try to match the contract to a built-in scenario
  const code = (await readFile(filePath, 'utf-8')).toLowerCase();
  const scenarios = listScenarios();

  // Find the best matching scenario based on code signatures
  let matchedScenario = scenarios.find(s => {
    const sigs: Record<string, RegExp[]> = {
      'reentrancy': [/\.call\{value:/, /reentrancy/i, /withdraw/i],
      'oracle-manipulation': [/getReserves/i, /price.*feed/i, /spot.*price/i],
      'flash-loan-attack': [/flashLoan/i, /onFlashLoan/i, /balancer/i],
      'sandwich-attack': [/sandwich/i, /front.*run/i, /back.*run/i, /mev/i],
      'liquidation-attack': [/liquidate/i, /healthFactor/i, /collateral/i],
      'access-control': [/onlyOwner/i, /onlyAdmin/i, /requiresAuth/i],
      'integer-overflow': [/overflow/i, /unchecked/i, /safemath/i],
      'delegatecall-injection': [/delegatecall/i, /implementation/i, /proxy/i],
    };
    const patSigs = sigs[s.pattern] ?? [];
    return patSigs.some(r => r.test(code));
  });

  if (!matchedScenario) return null;

  try {
    const result = await executeScenario(matchedScenario, { network });

    // Extract traces from step results
    const stepTraces = result.steps
      .filter(s => s.txHash)
      .map(s => `Step ${s.step} [${s.action}]: tx=${s.txHash} success=${s.success} description="${s.description}"${s.returnData ? ' return=' + s.returnData.slice(0, 100) : ''}`);
    const anyStepFailed = result.steps.some(s => !s.success);
    const stepErrors = result.steps.filter(s => s.error).map(s => `Step ${s.step}: ${s.error}`);

    // Run AI analysis on the simulation output
    let aiReport: ThreatReport | null = null;
    try {
      const modelabResults = await analyzeWithModelab({
        scenarioId: matchedScenario.id,
        scenarioName: matchedScenario.name,
        txTraces: stepTraces,
        contractCode: await readFile(filePath, 'utf-8'),
        models: ['claude-sonnet-4-6'],
      });
      if (modelabResults.length > 0) {
        aiReport = getBestAnalysis(modelabResults).report;
      }
    } catch {
      // Non-fatal
    }

    return {
      scenarioId: matchedScenario.id,
      scenarioName: matchedScenario.name,
      success: !anyStepFailed,
      aiReport,
      output: stepErrors.length > 0 ? stepErrors.join('\n') : stepTraces.join('\n'),
      severity: (aiReport?.severity ?? matchedScenario.severity) as Severity,
    };
  } catch (err) {
    return {
      scenarioId: matchedScenario.id,
      scenarioName: matchedScenario.name,
      success: false,
      aiReport: null,
      output: String(err),
      severity: matchedScenario.severity as Severity,
    };
  }
}

// ── Report generation ─────────────────────────────────────────────────────────

export function generateReport(results: ScanResult[]): string {
  const lines: string[] = [];
  const overallWorst = getWorstScanSeverity(results);
  const avgScore = results.length > 0 ? Math.round(results.reduce((s, r) => s + r.threatScore, 0) / results.length) : 0;

  lines.push('');
  lines.push('╔═══════════════════════════════════════════════════════════════════╗');
  lines.push('║              🔬 THREAT LAB — UNIFIED SCAN REPORT                ║');
  lines.push('╚═══════════════════════════════════════════════════════════════════╝');
  lines.push('');

  // ── Summary ──
  const sevIcon = overallWorst === 'critical' ? '🔴' : overallWorst === 'high' ? '🟠' : overallWorst === 'medium' ? '🟡' : overallWorst === 'low' ? '🟢' : '⚪';
  lines.push(`  ${sevIcon}  Overall Threat: ${overallWorst.toUpperCase()}  |  Score: ${avgScore}/100  |  Files: ${results.length}`);
  lines.push('');

  // ── Per-file results ──
  for (const r of results) {
    const icon = r.overallSeverity === 'critical' ? '🔴' : r.overallSeverity === 'high' ? '🟠' : r.overallSeverity === 'medium' ? '🟡' : r.overallSeverity === 'low' ? '🟢' : '⚪';
    lines.push(`  ${icon}  ${r.file}`);
    lines.push(`      Threat Score: ${r.threatScore}/100`);

    if (r.staticAnalysis) {
      const { patterns, aiReport } = r.staticAnalysis;
      if (patterns.length > 0) {
        const top = patterns.slice(0, 3).map(p => `${p.pattern}`).join(', ');
        lines.push(`      Static: ${patterns.length} pattern match(es) → ${top}`);
      }
      if (aiReport) {
        lines.push(`      AI Analysis: ${aiReport.attackPattern} [${aiReport.severity}] ${(aiReport.confidence * 100).toFixed(0)}% confident`);
        lines.push(`      Summary: ${aiReport.summary.slice(0, 120).replace(/\n/g, ' ')}`);
      } else {
        lines.push(`      Static: No patterns detected`);
      }
    }

    if (r.threatIntel.length > 0) {
      const activeExploits = r.threatIntel.filter(t => t.hasActiveExploit);
      const worst = r.threatIntel.reduce((worst: string, t) => {
        const order = ['critical', 'high', 'medium', 'low', 'none'] as const;
        return order.indexOf(t.overallSeverity) < order.indexOf(worst as 'critical' | 'high' | 'medium' | 'low' | 'none') ? t.overallSeverity : worst;
      }, 'none');
      const sevIcon2 = worst === 'critical' ? '🔴' : worst === 'high' ? '🟠' : worst === 'medium' ? '🟡' : worst === 'low' ? '🟢' : '⚪';
      const totalResults = r.threatIntel.reduce((s, t) => s + t.searches.reduce((ss, sr) => ss + sr.resultCount, 0), 0);
      const alertCount = r.threatIntel.reduce((s, t) => s + t.searches.reduce((ss, sr) => ss + sr.findings.filter(f => f.isAlert).length, 0), 0);
      lines.push(`      Threat Intel: ${sevIcon2} ${worst.toUpperCase()} | ${totalResults} web mentions | ${alertCount} alert(s) [last 14 days]`);
      if (activeExploits.length > 0) {
        lines.push(`        🚨 LIVE THREAT: ${activeExploits.length} package(s) with active exploit discussion online`);
      }
    }

    if (r.dependencyAudit) {
      const { threatLevel, vulns, advisories } = r.dependencyAudit;
      const total = vulns.length + advisories.length;
      lines.push(`      Dependencies: ${total} issue(s) → ${threatLevel.toUpperCase()}`);
      if (vulns.length > 0) lines.push(`        Notable: ${vulns.slice(0, 2).map(v => `${v.package}@${v.severity}`).join(', ')}`);
      if (advisories.some(a => a.activeExploit)) {
        lines.push(`        🚨 ACTIVE EXPLOIT ADVISORIES DETECTED`);
      }
    }

    if (r.exploitSim) {
      const { scenarioName, success } = r.exploitSim;
      lines.push(`      Simulation: ${scenarioName} — ${success ? 'exploit SUCCESSFUL (finding is real)' : 'exploit FAILED'}`);
    }

    if (r.errors.length > 0) {
      lines.push(`      Errors: ${r.errors.slice(0, 2).join('; ')}`);
    }
    lines.push('');
  }

  // ── Consolidated Recommendations ──
  const allRecs = results.flatMap(r => r.recommendations);
  const uniqueRecs = [...new Set(allRecs)].slice(0, 8);
  if (uniqueRecs.length > 0) {
    lines.push('  💡 Recommendations:');
    for (const rec of uniqueRecs) {
      lines.push(`     • ${rec}`);
    }
    lines.push('');
  }

  // ── Legend ──
  lines.push('  Legend:  🔴 critical  🟠 high  🟡 medium  🟢 low  ⚪ informational');
  lines.push(`  Duration: ${(results.reduce((s, r) => s + r.durationMs, 0) / 1000).toFixed(1)}s total`);
  lines.push('');

  return lines.join('\n');
}

// ── Main scan orchestrator ────────────────────────────────────────────────────

export interface ScanOptions {
  target: string;
  quick?: boolean;       // skip exploit simulation
  noDeps?: boolean;      // skip dependency audit
  noSim?: boolean;       // skip exploit simulation
  noIntel?: boolean;     // skip live threat intel (Layer 2b)
  network?: string;
  models?: string[];
  deep?: boolean;         // run deep research on flagged findings via modelab
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

export function buildScanPayload(target: string, results: ScanResult[]): ScanPayload {
  return {
    scannedAt: new Date().toISOString(),
    target,
    results,
  };
}

function buildMarkdownReport(target: string, results: ScanResult[]): string {
  const payload = buildScanPayload(target, results);
  const overallWorst = getWorstScanSeverity(results);
  const avgScore = results.length > 0 ? Math.round(results.reduce((s, r) => s + r.threatScore, 0) / results.length) : 0;
  const lines: string[] = [];

  lines.push('# Threat Lab Scan Report');
  lines.push('');
  lines.push(`- Scanned at: ${payload.scannedAt}`);
  lines.push(`- Target: ${target}`);
  lines.push(`- Overall threat: ${overallWorst.toUpperCase()}`);
  lines.push(`- Average score: ${avgScore}/100`);
  lines.push(`- Files scanned: ${results.length}`);
  lines.push('');

  for (const r of results) {
    lines.push(`## ${r.file}`);
    lines.push(`- Severity: ${r.overallSeverity}`);
    lines.push(`- Threat score: ${r.threatScore}/100`);

    if (r.staticAnalysis?.aiReport) {
      lines.push(`- AI pattern: ${r.staticAnalysis.aiReport.attackPattern}`);
      lines.push(`- AI confidence: ${(r.staticAnalysis.aiReport.confidence * 100).toFixed(0)}%`);
      lines.push(`- AI summary: ${r.staticAnalysis.aiReport.summary}`);
    }

    if (r.staticAnalysis?.patterns.length) {
      lines.push(`- Pattern matches: ${r.staticAnalysis.patterns.map(p => `${p.pattern} (${(p.confidence * 100).toFixed(0)}%)`).join(', ')}`);
    }

    if (r.dependencyAudit) {
      lines.push(`- Dependency audit: ${r.dependencyAudit.threatLevel} (${r.dependencyAudit.vulns.length + r.dependencyAudit.advisories.length} issue(s))`);
    }

    if (r.threatIntel.length) {
      const active = r.threatIntel.filter(t => t.hasActiveExploit).length;
      lines.push(`- Threat intel packages flagged: ${r.threatIntel.length}${active ? ` (${active} active exploit)` : ''}`);
    }

    if (r.exploitSim) {
      lines.push(`- Exploit simulation: ${r.exploitSim.scenarioName} (${r.exploitSim.success ? 'successful' : 'failed'})`);
    }

    if (r.recommendations.length) {
      lines.push('- Recommendations:');
      for (const rec of r.recommendations) lines.push(`  - ${rec}`);
    }

    if (r.errors.length) {
      lines.push('- Errors:');
      for (const err of r.errors) lines.push(`  - ${err}`);
    }

    lines.push('');
  }

  return lines.join('\n');
}

export async function loadScanPayload(path: string): Promise<ScanPayload> {
  const raw = await readFile(path, 'utf-8');
  return JSON.parse(raw) as ScanPayload;
}

export function compareScanPayloads(current: ScanPayload, baseline: ScanPayload): ScanDiffSummary {
  const currentMap = new Map(current.results.map(result => [result.file, result]));
  const baselineMap = new Map(baseline.results.map(result => [result.file, result]));
  const files = [...new Set([...currentMap.keys(), ...baselineMap.keys()])].sort();

  const entries: ScanDiffEntry[] = files.map((file) => {
    const currentResult = currentMap.get(file);
    const baselineResult = baselineMap.get(file);

    if (currentResult && !baselineResult) {
      return {
        file,
        status: 'new',
        currentSeverity: currentResult.overallSeverity,
        currentScore: currentResult.threatScore,
      };
    }

    if (!currentResult && baselineResult) {
      return {
        file,
        status: 'resolved',
        previousSeverity: baselineResult.overallSeverity,
        previousScore: baselineResult.threatScore,
      };
    }

    const changed = currentResult!.overallSeverity !== baselineResult!.overallSeverity
      || currentResult!.threatScore !== baselineResult!.threatScore;

    return {
      file,
      status: changed ? 'changed' : 'unchanged',
      currentSeverity: currentResult!.overallSeverity,
      previousSeverity: baselineResult!.overallSeverity,
      currentScore: currentResult!.threatScore,
      previousScore: baselineResult!.threatScore,
    };
  });

  return {
    baselineTarget: baseline.target,
    currentTarget: current.target,
    baselineScannedAt: baseline.scannedAt,
    currentScannedAt: current.scannedAt,
    added: entries.filter(entry => entry.status === 'new').length,
    resolved: entries.filter(entry => entry.status === 'resolved').length,
    changed: entries.filter(entry => entry.status === 'changed').length,
    unchanged: entries.filter(entry => entry.status === 'unchanged').length,
    entries,
  };
}

export function formatScanDiff(summary: ScanDiffSummary): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('╔═══════════════════════════════════════════════════════════════════╗');
  lines.push('║                 🔁 THREAT LAB — SCAN DIFF                       ║');
  lines.push('╚═══════════════════════════════════════════════════════════════════╝');
  lines.push('');
  lines.push(`  Baseline: ${summary.baselineTarget} @ ${summary.baselineScannedAt}`);
  lines.push(`  Current:  ${summary.currentTarget} @ ${summary.currentScannedAt}`);
  lines.push('');
  lines.push(`  New: ${summary.added}  |  Resolved: ${summary.resolved}  |  Changed: ${summary.changed}  |  Unchanged: ${summary.unchanged}`);
  lines.push('');

  for (const entry of summary.entries.filter(item => item.status !== 'unchanged')) {
    if (entry.status === 'new') {
      lines.push(`  ➕ ${entry.file}`);
      lines.push(`     New finding: ${entry.currentSeverity} (${entry.currentScore}/100)`);
      continue;
    }
    if (entry.status === 'resolved') {
      lines.push(`  ✅ ${entry.file}`);
      lines.push(`     Resolved: ${entry.previousSeverity} (${entry.previousScore}/100)`);
      continue;
    }
    lines.push(`  🔄 ${entry.file}`);
    lines.push(`     ${entry.previousSeverity} (${entry.previousScore}/100) → ${entry.currentSeverity} (${entry.currentScore}/100)`);
  }

  if (summary.entries.every(item => item.status === 'unchanged')) {
    lines.push('  No material scan deltas.');
  }

  lines.push('');
  return lines.join('\n');
}

async function saveScanArtifacts(target: string, results: ScanResult[], outputPath?: string): Promise<void> {
  const payload = buildScanPayload(target, results);

  if (outputPath) {
    const normalized = outputPath.toLowerCase();
    if (normalized.endsWith('.md')) {
      await writeFile(outputPath, buildMarkdownReport(target, results), 'utf-8');
      console.log(`  📄 Scan report saved: ${outputPath}`);
      return;
    }
    await writeFile(outputPath, JSON.stringify(payload, null, 2), 'utf-8');
    console.log(`  📄 Scan report saved: ${outputPath}`);
    return;
  }

  const jsonPath = `threat-lab-report-${Date.now()}.json`;
  await writeFile(jsonPath, JSON.stringify(payload, null, 2), 'utf-8');
  console.log(`  📄 JSON report saved: ${jsonPath}`);
}

export async function scanTarget(options: ScanOptions): Promise<ScanResult[]> {
  const { target, quick = false, noDeps = false, noSim = false, noIntel = false, network = 'anvil', deep = false, outputPath } = options;

  console.log(`\n🔬 Threat Lab — Scanning ${target}`);
  if (!noDeps) console.log('   [1/4] Dependency audit  (OSV + npm advisories + Socket.dev)');
  if (!noIntel) console.log('   [2/4] Live threat intel (Brave Search + GH advisories, 14-day window)');
  if (!noSim && !quick) console.log('   [3/4] Exploit simulation (Anvil deployment + AI analysis)');
  console.log('   [4/4] Static analysis  (signature patterns + AI deep-read)');
  console.log('');

  const startAll = Date.now();
  const files = await findSolFiles(target);

  if (files.length === 0) {
    console.warn(`  No .sol files found at ${target}`);
    return [];
  }

  const results: ScanResult[] = [];

  for (const file of files) {
    const t0 = Date.now();
    const errors: string[] = [];
    const recommendations: string[] = [];

    // ── Run all three in parallel ──
    const [staticRes, depRes, intelRes, simRes] = await Promise.allSettled([
      runStaticAnalysis(file),
      noDeps ? Promise.resolve(null) : runDependencyAudit(target),
      noIntel ? Promise.resolve(null) : runThreatIntelLayer(target),
      quick || noSim ? Promise.resolve(null) : runExploitSim(file, network),
    ]);

    const staticAnalysis = staticRes.status === 'fulfilled' ? staticRes.value : null;
    const dependencyAudit = depRes.status === 'fulfilled' ? depRes.value : null;
    const threatIntel: ThreatIntelResult[] = intelRes.status === 'fulfilled' && intelRes.value != null ? intelRes.value : [];
    const exploitSim = simRes.status === 'fulfilled' ? simRes.value : null;

    // Collect errors
    if (staticRes.status === 'rejected') errors.push(`static: ${staticRes.reason}`);
    if (depRes.status === 'rejected') errors.push(`deps: ${depRes.reason}`);
    if (intelRes.status === 'rejected') errors.push(`intel: ${intelRes.reason}`);
    if (simRes.status === 'rejected') errors.push(`sim: ${simRes.reason}`);

    // Determine overall severity
    const severities: Severity[] = [];
    if (staticAnalysis?.aiReport) severities.push(staticAnalysis.aiReport.severity);
    if (staticAnalysis?.patterns.length) severities.push('high');
    if (dependencyAudit) {
      if (dependencyAudit.threatLevel === 'critical') severities.push('critical');
      else if (dependencyAudit.threatLevel === 'high') severities.push('high');
      else if (dependencyAudit.threatLevel === 'medium') severities.push('medium');
    }
    if (threatIntel.length > 0) {
      const worstIntel = threatIntel.reduce((worst: string, t) => {
        const order = ['critical', 'high', 'medium', 'low', 'none'] as const;
        return order.indexOf(t.overallSeverity) < order.indexOf(worst as 'critical' | 'high' | 'medium' | 'low' | 'none') ? t.overallSeverity : worst;
      }, 'none');
      if (worstIntel === 'critical') severities.push('critical');
      else if (worstIntel === 'high') severities.push('high');
      else if (worstIntel === 'medium') severities.push('medium');
    }
    if (exploitSim?.aiReport) severities.push(exploitSim.aiReport.severity);
    else if (exploitSim?.success) severities.push('high');

    const overallSeverity = severities.length > 0
      ? severities.reduce(worstSeverity)
      : 'informational';

    // Collect recommendations
    if (staticAnalysis?.aiReport?.recommendations) {
      recommendations.push(...staticAnalysis.aiReport.recommendations);
    }
    if (dependencyAudit?.threatLevel === 'critical' || dependencyAudit?.threatLevel === 'high') {
      recommendations.push('Address high/critical dependency vulnerabilities before deployment');
    }
    if (dependencyAudit?.advisories.some(a => a.activeExploit)) {
      recommendations.push('🚨 ACTIVE EXPLOIT: Update affected packages immediately');
    }
    if (threatIntel.some(t => t.hasActiveExploit)) {
      recommendations.push('🚨 LIVE THREAT: Packages with active exploits found — do NOT use until confirmed safe');
    }
    if (exploitSim?.success) {
      recommendations.push(`Exploit simulation confirmed: review ${exploitSim.scenarioName} pattern`);
    }

    // Compute threat score
    const scanResult: ScanResult = {
      file,
      staticAnalysis,
      dependencyAudit,
      threatIntel,
      exploitSim,
      overallSeverity,
      threatScore: 0, // filled below
      findings: [],    // filled below
      recommendations: [...new Set(recommendations)],
      durationMs: Date.now() - t0,
      errors,
    };
    scanResult.threatScore = computeThreatScore(scanResult);

    results.push(scanResult);

    // Per-file console output
    const sevIcon = scanResult.overallSeverity === 'critical' ? '🔴' : scanResult.overallSeverity === 'high' ? '🟠' : scanResult.overallSeverity === 'medium' ? '🟡' : scanResult.overallSeverity === 'low' ? '🟢' : '⚪';
    const simTag = exploitSim ? (exploitSim.success ? '⚡ EXPLOITED' : '✅ safe') : noSim || quick ? '⏭ skipped' : '—';
    const activeCount = threatIntel.filter(t => t.hasActiveExploit).length;
    const intelTag = activeCount > 0 ? `🚨 LIVE THREAT (${activeCount})` : noIntel ? '⏭ intel off' : '🌐 intel ok';
    console.log(`  ${sevIcon} ${file} [score: ${scanResult.threatScore}] [${simTag}] [${intelTag}]`);
  }

  // ── Print full report ──
  const report = generateReport(results);
  console.log(report);

  // ── Deep research via modelab ──
  if (deep) {
    console.log('\n🔬 Running deep research via modelab on flagged findings...');
    const deepFindings: DeepResearchFinding[] = [];

    for (const r of results) {
      // Collect static findings
      if (r.staticAnalysis?.aiReport) {
        deepFindings.push({
          category: 'static',
          severity: r.staticAnalysis.aiReport.severity,
          title: `${r.staticAnalysis.aiReport.attackPattern} in ${r.file}`,
          description: r.staticAnalysis.aiReport.summary,
          contractFile: r.file,
          evidence: r.staticAnalysis.contractCode.slice(0, 500),
        });
      }
      // Collect threat intel findings with active exploits
      if (r.threatIntel.length > 0) {
        for (const intel of r.threatIntel) {
          for (const finding of intel.searches) {
            for (const f of finding.findings.filter((ff: { isAlert: boolean }) => ff.isAlert)) {
              deepFindings.push({
                category: 'deps',
                severity: 'critical',
                title: `Active exploit: ${f.title}`,
                description: f.snippet,
                packageName: intel.packageName,
              });
            }
          }
        }
      }
    }

    if (deepFindings.length > 0) {
      const deepResults = await runDeepResearchBatch({
        findings: deepFindings,
        contractCode: results[0]?.staticAnalysis?.contractCode,
        models: ['claude-sonnet-4-6', 'anthropic/claude-opus-4-6'],
        maxFindings: 5,
      });
      const deepReport = formatDeepResearchReport(deepResults);
      console.log(deepReport);

      // Save deep research report
      const deepPath = `threat-lab-deep-research-${Date.now()}.json`;
      await writeFile(deepPath, JSON.stringify({ scannedAt: new Date().toISOString(), target, deepResults }, null, 2));
      console.log(`  📄 Deep research report saved: ${deepPath}`);
    } else {
      console.log('  No critical findings to deep-research — scan is clean!');
    }
  }

  // ── Save report artifact ──
  await saveScanArtifacts(target, results, outputPath);

  const totalMs = Date.now() - startAll;
  console.log(`\n  ✅ Scan complete in ${(totalMs / 1000).toFixed(1)}s`);

  return results;
}
