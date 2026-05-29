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
import { readFile, readdir, stat, writeFile, mkdir } from 'fs/promises';
import { join, extname, relative, dirname } from 'path';
import { analyzeThreat } from './analyzer.js';
import { detectPatterns } from './patternDetector.js';
import { auditDependencies } from './audit.js';
import { executeScenario, isAnvilRunning } from './executor.js';
import { listScenarios } from './scenarios.js';
import { analyzeWithModelab, getBestAnalysis } from './modelabIntegration.js';
import { runThreatIntel } from './threatIntel.js';
import { runDeepResearchBatch, formatDeepResearchReport } from './deepResearch.js';
export const scannerDeps = {
    analyzeThreat,
    auditDependencies,
    executeScenario,
    isAnvilRunning,
    analyzeWithModelab,
    getBestAnalysis,
    runThreatIntel,
};
// ── Severity mapping ────────────────────────────────────────────────────────────
const SEVERITY_SCORE = {
    critical: 100,
    high: 70,
    medium: 40,
    low: 20,
    informational: 5,
};
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
function severityIndex(severity) {
    return SEVERITY_ORDER.indexOf(severity);
}
export function severityMeetsOrExceeds(actual, threshold) {
    return severityIndex(actual) <= severityIndex(threshold);
}
function worstSeverity(a, b) {
    return SEVERITY_ORDER[Math.min(severityIndex(a), severityIndex(b))];
}
export function getWorstScanSeverity(results) {
    return results.reduce((worst, result) => worstSeverity(worst, result.overallSeverity), 'informational');
}
function computeThreatScore(results) {
    const weights = { static: 0.3, intel: 0.25, deps: 0.2, sim: 0.25 };
    let score = 0;
    if (results.staticAnalysis?.aiReport) {
        score += SEVERITY_SCORE[results.staticAnalysis.aiReport.severity] * weights.static;
    }
    if (results.threatIntel.length > 0) {
        const intelSev = results.threatIntel.reduce((worst, t) => {
            const order = ['critical', 'high', 'medium', 'low', 'none'];
            return order.indexOf(t.overallSeverity) < order.indexOf(worst) ? t.overallSeverity : worst;
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
function normalizeSeverity(value) {
    const lower = String(value ?? '').toLowerCase();
    if (lower === 'critical')
        return 'critical';
    if (lower === 'high')
        return 'high';
    if (lower === 'medium' || lower === 'moderate')
        return 'medium';
    if (lower === 'low')
        return 'low';
    return 'informational';
}
function normalizePackageName(value) {
    const normalized = String(value ?? '').trim().toLowerCase();
    return normalized || null;
}
function getDependencyPackageSignals(dependencyAudit) {
    const signals = new Set();
    for (const vuln of dependencyAudit?.vulns ?? []) {
        const pkg = normalizePackageName(vuln.package);
        if (pkg)
            signals.add(pkg);
    }
    for (const advisory of dependencyAudit?.advisories ?? []) {
        const title = String(advisory.title || '').toLowerCase();
        const id = String(advisory.id || '').toLowerCase();
        for (const token of [...signals]) {
            if (title.includes(token) || id.includes(token)) {
                signals.add(token);
            }
        }
    }
    return signals;
}
async function loadDeclaredDependencyNames(projectPath) {
    try {
        const pkgPath = join(projectPath, 'package.json');
        const pkg = JSON.parse(await readFile(pkgPath, 'utf-8'));
        return new Set([
            ...Object.keys(pkg.dependencies ?? {}),
            ...Object.keys(pkg.devDependencies ?? {}),
            ...Object.keys(pkg.optionalDependencies ?? {}),
        ].map((name) => name.toLowerCase()));
    }
    catch {
        return new Set();
    }
}
function isIntelCorrelated(packageName, dependencyAudit, declaredDependencies = new Set()) {
    const pkg = normalizePackageName(packageName);
    if (!pkg)
        return false;
    return declaredDependencies.has(pkg) || getDependencyPackageSignals(dependencyAudit).has(pkg);
}
function dedupeFindings(findings) {
    const seen = new Set();
    return findings.filter((finding) => {
        const key = finding.dedupeKey
            ?? [finding.category, finding.packageName ?? '', finding.title, finding.evidence ?? finding.description].join('|').toLowerCase();
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
}
function summarizeFindings(results) {
    const bySeverity = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
    };
    const byCategory = {
        static: 0,
        deps: 0,
        intel: 0,
        sim: 0,
    };
    let correlatedIntelAlerts = 0;
    let activeExploitIntelAlerts = 0;
    for (const finding of results.flatMap(r => r.findings)) {
        bySeverity[finding.severity] += 1;
        byCategory[finding.category] += 1;
        if (finding.category === 'intel' && finding.correlated)
            correlatedIntelAlerts += 1;
        if (finding.category === 'intel' && finding.severity === 'critical')
            activeExploitIntelAlerts += 1;
    }
    return { bySeverity, byCategory, correlatedIntelAlerts, activeExploitIntelAlerts };
}
export function formatSecurityGateDecision(results, threshold) {
    const worst = getWorstScanSeverity(results);
    const summary = summarizeFindings(results);
    const status = severityMeetsOrExceeds(worst, threshold) ? 'failed' : 'passed';
    return [
        `Security gate ${status}: worst severity ${worst} vs threshold ${threshold}`,
        `critical=${summary.bySeverity.critical}, high=${summary.bySeverity.high}, medium=${summary.bySeverity.medium}`,
        `deps=${summary.byCategory.deps}, intel=${summary.byCategory.intel}, correlated-intel=${summary.correlatedIntelAlerts}, sim=${summary.byCategory.sim}`,
    ].join(' | ');
}
function buildConsolidatedFindings(scan) {
    const findings = [];
    const dependencySignals = getDependencyPackageSignals(scan.dependencyAudit);
    const declaredDependencies = scan.declaredDependencies ?? new Set();
    if (scan.staticAnalysis?.aiReport) {
        const report = scan.staticAnalysis.aiReport;
        findings.push({
            category: 'static',
            severity: report.severity,
            title: `${report.attackPattern} analysis for ${scan.file}`,
            description: report.summary,
            evidence: report.findings.map(f => `${f.title}: ${f.evidence}`).slice(0, 3).join(' | ') || scan.staticAnalysis.contractCode.slice(0, 300),
            recommendation: report.recommendations[0],
            dedupeKey: `static:${scan.file}:${report.attackPattern}:${report.summary}`,
        });
    }
    for (const pattern of scan.staticAnalysis?.patterns ?? []) {
        findings.push({
            category: 'static',
            severity: pattern.confidence >= 0.75 ? 'high' : pattern.confidence >= 0.45 ? 'medium' : 'low',
            title: `Pattern match: ${pattern.pattern}`,
            description: `Signature/keyword match at ${(pattern.confidence * 100).toFixed(0)}% confidence`,
            evidence: pattern.matchedOn.slice(0, 5).join(', '),
            dedupeKey: `pattern:${scan.file}:${pattern.pattern}:${pattern.matchedOn.slice(0, 3).join(',')}`,
        });
    }
    for (const vuln of scan.dependencyAudit?.vulns ?? []) {
        findings.push({
            category: 'deps',
            severity: normalizeSeverity(vuln.severity),
            title: `${vuln.package}: ${vuln.title}`,
            description: `Dependency vulnerability affecting ${vuln.package}`,
            evidence: vuln.url,
            recommendation: 'Upgrade, replace, or remove the affected package before deployment',
            packageName: vuln.package,
            dedupeKey: `deps:${vuln.package}:${vuln.title}:${vuln.url}`,
        });
    }
    for (const advisory of scan.dependencyAudit?.advisories ?? []) {
        findings.push({
            category: 'deps',
            severity: normalizeSeverity(advisory.severity),
            title: `${advisory.id}: ${advisory.title}`,
            description: advisory.activeExploit ? 'Advisory indicates active exploit pressure' : 'Dependency advisory detected during audit',
            evidence: advisory.url,
            recommendation: advisory.activeExploit ? 'Patch immediately and verify transitive exposure' : 'Review advisory and upgrade if affected',
            dedupeKey: `advisory:${advisory.id}:${advisory.title}:${advisory.url}`,
        });
    }
    for (const intel of scan.threatIntel) {
        const pkg = normalizePackageName(intel.packageName);
        const correlated = !!pkg && (declaredDependencies.has(pkg) || dependencySignals.has(pkg));
        for (const search of intel.searches) {
            for (const finding of search.findings) {
                const severity = finding.isAlert
                    ? (correlated ? 'critical' : 'high')
                    : correlated
                        ? normalizeSeverity(intel.overallSeverity)
                        : 'low';
                findings.push({
                    category: 'intel',
                    severity,
                    title: `${intel.packageName}: ${finding.title}`,
                    description: finding.snippet || `Live threat intel hit from ${finding.source}`,
                    evidence: finding.url,
                    recommendation: finding.isAlert
                        ? (correlated
                            ? 'Treat as live threat intel on an in-use dependency and confirm package safety before release'
                            : 'Active exploit chatter exists, but package correlation is weak — verify dependency usage before escalating')
                        : (correlated
                            ? 'Review recent intel for this in-use dependency and decide whether the package needs escalation'
                            : 'Intel mention is uncorrelated to audited dependencies; keep as background context unless repeated'),
                    packageName: intel.packageName,
                    correlated,
                    dedupeKey: `intel:${intel.packageName}:${finding.url || finding.title}`,
                });
            }
        }
    }
    if (scan.exploitSim) {
        findings.push({
            category: 'sim',
            severity: scan.exploitSim.severity,
            title: `Exploit simulation: ${scan.exploitSim.scenarioName}`,
            description: scan.exploitSim.success ? 'Built-in exploit scenario reproduced successfully' : 'Scenario executed but did not fully reproduce',
            evidence: scan.exploitSim.output.slice(0, 500),
            recommendation: scan.exploitSim.success ? `Prioritize fixes for the ${scan.exploitSim.scenarioId} class immediately` : 'Review simulation output and scenario assumptions',
            dedupeKey: `sim:${scan.exploitSim.scenarioId}:${scan.file}`,
        });
    }
    return dedupeFindings(findings);
}
// ── File discovery ─────────────────────────────────────────────────────────────
export async function findSolFiles(target) {
    const files = [];
    let targetStat;
    try {
        targetStat = await stat(target);
    }
    catch {
        return files; // non-existent path → empty result
    }
    if (targetStat.isFile()) {
        if (extname(target) === '.sol')
            files.push(target);
        return files;
    }
    async function walk(dir) {
        const entries = await readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
            const full = join(dir, entry.name);
            if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'dist' && entry.name !== 'cache') {
                await walk(full);
            }
            else if (entry.isFile() && extname(entry.name) === '.sol') {
                files.push(full);
            }
        }
    }
    await walk(target);
    return files;
}
// ── Core scanners ─────────────────────────────────────────────────────────────
async function runStaticAnalysis(filePath) {
    const code = await readFile(filePath, 'utf-8');
    // Fast path: signature-based pattern detection
    const patterns = detectPatterns(code);
    // Deep path: AI analysis via Bankr gateway
    let aiReport = null;
    try {
        aiReport = await scannerDeps.analyzeThreat({
            scenarioId: `scan:${relative('.', filePath)}`,
            scenarioName: filePath,
            scenarioDesc: 'Unified scan of user-submitted contract',
            contractCode: code,
        });
    }
    catch (err) {
        // Non-fatal — signature results still valid
    }
    return { patterns, aiReport, contractCode: code };
}
// ── Layer 2b: Threat Intelligence (live web search) ───────────────────────────
async function runThreatIntelLayer(projectPath) {
    // Read package.json to get all deps
    try {
        const { readFile } = await import('fs/promises');
        const pkgPath = join(projectPath, 'package.json');
        const pkg = JSON.parse(await readFile(pkgPath, 'utf-8'));
        const pkgs = [
            ...Object.entries(pkg.dependencies ?? {}),
            ...Object.entries(pkg.devDependencies ?? {}),
            ...Object.entries(pkg.optionalDependencies ?? {}),
        ].map(([name, version]) => ({ name, version: version.replace(/^[\^~>=<]/, '') }));
        if (pkgs.length === 0)
            return [];
        return await scannerDeps.runThreatIntel({ packages: pkgs });
    }
    catch {
        return [];
    }
}
async function runDependencyAudit(projectPath) {
    try {
        const audit = await scannerDeps.auditDependencies({
            projectPath,
            includeDev: true,
            socketDev: true,
            runNpmAudit: true,
        });
        const vulns = [];
        const advisories = [];
        // Collect npm audit vulns — cast to avoid type mismatch on npm's internal shape
        const npmVulns = audit.npmAudit?.vulnerabilities;
        if (npmVulns && typeof npmVulns === 'object') {
            for (const [pkg, vuln] of Object.entries(npmVulns)) {
                vulns.push({
                    package: pkg,
                    severity: vuln.severity,
                    title: vuln.title ?? `Vulnerability in ${pkg}`,
                    url: vuln.url ?? '',
                });
            }
        }
        // Collect OSV results — access via bracket notation to bypass strict type check
        const osvData = audit.osv;
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
        const socketDev = audit.socketDev;
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
        const threatLevel = rawThreatLevel === 'critical' ? 'critical'
            : rawThreatLevel === 'high' ? 'high'
                : rawThreatLevel === 'medium' ? 'medium'
                    : rawThreatLevel === 'low' ? 'low'
                        : 'none';
        const score = threatLevel === 'critical' ? 100 : threatLevel === 'high' ? 75 : threatLevel === 'medium' ? 50 : threatLevel === 'low' ? 25 : 0;
        return { summary: `Found ${vulns.length + advisories.length} issues`, threatLevel, vulns, advisories, score };
    }
    catch (err) {
        return {
            summary: `Audit unavailable: ${err instanceof Error ? err.message : String(err)}`,
            threatLevel: 'none',
            vulns: [],
            advisories: [],
            score: 0,
        };
    }
}
async function runExploitSim(filePath, network) {
    // Try to match the contract to a built-in scenario
    const code = (await readFile(filePath, 'utf-8')).toLowerCase();
    const scenarios = listScenarios();
    // Find the best matching scenario based on code signatures
    let matchedScenario = scenarios.find(s => {
        const sigs = {
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
    if (!matchedScenario)
        return null;
    try {
        const result = await scannerDeps.executeScenario(matchedScenario, { network });
        // Extract traces from step results
        const stepTraces = result.steps
            .filter(s => s.txHash)
            .map(s => `Step ${s.step} [${s.action}]: tx=${s.txHash} success=${s.success} description="${s.description}"${s.returnData ? ' return=' + s.returnData.slice(0, 100) : ''}`);
        const anyStepFailed = result.steps.some(s => !s.success);
        const stepErrors = result.steps.filter(s => s.error).map(s => `Step ${s.step}: ${s.error}`);
        // Run AI analysis on the simulation output
        let aiReport = null;
        try {
            const modelabResults = await scannerDeps.analyzeWithModelab({
                scenarioId: matchedScenario.id,
                scenarioName: matchedScenario.name,
                txTraces: stepTraces,
                contractCode: await readFile(filePath, 'utf-8'),
                models: ['claude-sonnet-4-6'],
            });
            if (modelabResults.length > 0) {
                aiReport = scannerDeps.getBestAnalysis(modelabResults).report;
            }
        }
        catch {
            // Non-fatal
        }
        return {
            scenarioId: matchedScenario.id,
            scenarioName: matchedScenario.name,
            success: !anyStepFailed,
            aiReport,
            output: stepErrors.length > 0 ? stepErrors.join('\n') : stepTraces.join('\n'),
            severity: (aiReport?.severity ?? matchedScenario.severity),
        };
    }
    catch (err) {
        return {
            scenarioId: matchedScenario.id,
            scenarioName: matchedScenario.name,
            success: false,
            aiReport: null,
            output: String(err),
            severity: matchedScenario.severity,
        };
    }
}
// ── Report generation ─────────────────────────────────────────────────────────
export function generateReport(results) {
    const lines = [];
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
            }
            else {
                lines.push(`      Static: No patterns detected`);
            }
        }
        if (r.threatIntel.length > 0) {
            const activeExploits = r.threatIntel.filter(t => t.hasActiveExploit);
            const worst = r.threatIntel.reduce((worst, t) => {
                const order = ['critical', 'high', 'medium', 'low', 'none'];
                return order.indexOf(t.overallSeverity) < order.indexOf(worst) ? t.overallSeverity : worst;
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
            if (vulns.length > 0)
                lines.push(`        Notable: ${vulns.slice(0, 2).map(v => `${v.package}@${v.severity}`).join(', ')}`);
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
export function buildScanPayload(target, results) {
    return {
        scannedAt: new Date().toISOString(),
        target,
        results,
    };
}
function buildMarkdownReport(target, results) {
    const payload = buildScanPayload(target, results);
    const overallWorst = getWorstScanSeverity(results);
    const avgScore = results.length > 0 ? Math.round(results.reduce((s, r) => s + r.threatScore, 0) / results.length) : 0;
    const allFindings = results.flatMap(r => r.findings);
    const summary = summarizeFindings(results);
    const criticalCount = summary.bySeverity.critical;
    const intelAlerts = summary.activeExploitIntelAlerts;
    const simConfirmed = summary.byCategory.sim;
    const lines = [];
    lines.push('# Threat Lab Scan Report');
    lines.push('');
    lines.push(`- Scanned at: ${payload.scannedAt}`);
    lines.push(`- Target: ${target}`);
    lines.push(`- Overall threat: ${overallWorst.toUpperCase()}`);
    lines.push(`- Average score: ${avgScore}/100`);
    lines.push(`- Files scanned: ${results.length}`);
    lines.push(`- Critical findings: ${criticalCount}`);
    lines.push(`- Live intel alerts: ${intelAlerts}`);
    lines.push(`- Correlated intel alerts: ${summary.correlatedIntelAlerts}`);
    lines.push(`- Confirmed simulation findings: ${simConfirmed}`);
    lines.push('');
    lines.push('## Threat Snapshot');
    if (allFindings.length === 0) {
        lines.push('- No structured findings emitted.');
    }
    else {
        for (const finding of allFindings
            .slice()
            .sort((a, b) => severityIndex(a.severity) - severityIndex(b.severity))
            .slice(0, 8)) {
            lines.push(`- [${finding.severity.toUpperCase()}] (${finding.category}) ${finding.title}`);
        }
    }
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
            for (const rec of r.recommendations)
                lines.push(`  - ${rec}`);
        }
        if (r.findings.length) {
            lines.push('- Evidence ledger:');
            for (const finding of r.findings.slice(0, 5)) {
                lines.push(`  - [${finding.severity}] (${finding.category}) ${finding.title}`);
                lines.push(`    - ${finding.description}`);
                if (finding.category === 'intel')
                    lines.push(`    - correlated: ${finding.correlated ? 'yes' : 'no'}`);
                if (finding.evidence)
                    lines.push(`    - evidence: ${finding.evidence.replace(/\s+/g, ' ').slice(0, 220)}`);
            }
        }
        if (r.errors.length) {
            lines.push('- Errors:');
            for (const err of r.errors)
                lines.push(`  - ${err}`);
        }
        lines.push('');
    }
    return lines.join('\n');
}
function sarifLevelFor(severity) {
    if (severity === 'critical' || severity === 'high')
        return 'error';
    if (severity === 'medium' || severity === 'low')
        return 'warning';
    return 'note';
}
function buildSarifRuleId(finding) {
    return (`${finding.category}/${finding.title}`)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '') || `${finding.category}-finding`;
}
function buildSarifReport(target, results) {
    const flattened = results.flatMap((result) => result.findings.map((finding) => ({ result, finding })));
    const ruleMap = new Map();
    for (const { finding } of flattened) {
        const ruleId = buildSarifRuleId(finding);
        if (!ruleMap.has(ruleId)) {
            ruleMap.set(ruleId, {
                id: ruleId,
                name: finding.title,
                shortDescription: { text: finding.title },
                fullDescription: { text: finding.description },
                properties: { tags: [finding.category, finding.severity], precision: 'high' },
                help: finding.recommendation ? { text: finding.recommendation } : undefined,
            });
        }
    }
    return {
        version: '2.1.0',
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'threat-lab',
                        version: '0.4.0',
                        informationUri: 'https://github.com/darks0l/threat-lab',
                        rules: [...ruleMap.values()],
                    },
                },
                results: flattened.map(({ result, finding }) => ({
                    ruleId: buildSarifRuleId(finding),
                    level: sarifLevelFor(finding.severity),
                    message: {
                        text: [finding.description, finding.evidence, finding.recommendation].filter(Boolean).join(' | '),
                    },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: {
                                    uri: relative(target, result.file) || result.file,
                                },
                            },
                        },
                    ],
                    properties: {
                        severity: finding.severity,
                        category: finding.category,
                        threatScore: result.threatScore,
                        packageName: finding.packageName,
                        correlated: finding.correlated,
                    },
                })),
            },
        ],
    };
}
export async function loadScanPayload(path) {
    const raw = await readFile(path, 'utf-8');
    return JSON.parse(raw);
}
export function compareScanPayloads(current, baseline) {
    const currentMap = new Map(current.results.map(result => [result.file, result]));
    const baselineMap = new Map(baseline.results.map(result => [result.file, result]));
    const files = [...new Set([...currentMap.keys(), ...baselineMap.keys()])].sort();
    const entries = files.map((file) => {
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
        const changed = currentResult.overallSeverity !== baselineResult.overallSeverity
            || currentResult.threatScore !== baselineResult.threatScore;
        return {
            file,
            status: changed ? 'changed' : 'unchanged',
            currentSeverity: currentResult.overallSeverity,
            previousSeverity: baselineResult.overallSeverity,
            currentScore: currentResult.threatScore,
            previousScore: baselineResult.threatScore,
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
export function formatScanDiff(summary) {
    const lines = [];
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
async function saveScanArtifacts(target, results, outputPath) {
    const payload = buildScanPayload(target, results);
    if (outputPath) {
        await mkdir(dirname(outputPath), { recursive: true });
        const normalized = outputPath.toLowerCase();
        if (normalized.endsWith('.md')) {
            await writeFile(outputPath, buildMarkdownReport(target, results), 'utf-8');
            console.log(`  📄 Scan report saved: ${outputPath}`);
            return;
        }
        if (normalized.endsWith('.sarif') || normalized.endsWith('.sarif.json')) {
            await writeFile(outputPath, JSON.stringify(buildSarifReport(target, results), null, 2), 'utf-8');
            console.log(`  📄 SARIF report saved: ${outputPath}`);
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
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
function buildWatchAlerts(diff) {
    if (!diff)
        return [];
    const alerts = [];
    const seen = new Set();
    for (const entry of diff.entries) {
        if (entry.status === 'new' && entry.currentSeverity && severityMeetsOrExceeds(entry.currentSeverity, 'high')) {
            const alert = `NEW ${entry.currentSeverity.toUpperCase()} finding: ${entry.file} (${entry.currentScore}/100)`;
            if (!seen.has(alert)) {
                alerts.push(alert);
                seen.add(alert);
            }
        }
        if (entry.status === 'changed' && entry.currentSeverity && entry.previousSeverity) {
            const escalated = severityIndex(entry.currentSeverity) < severityIndex(entry.previousSeverity);
            const scoreRaised = (entry.currentScore ?? 0) > (entry.previousScore ?? 0);
            if (escalated || scoreRaised) {
                const alert = `ESCALATED ${entry.file}: ${entry.previousSeverity} (${entry.previousScore}/100) → ${entry.currentSeverity} (${entry.currentScore}/100)`;
                if (!seen.has(alert)) {
                    alerts.push(alert);
                    seen.add(alert);
                }
            }
        }
    }
    return alerts;
}
async function writeWatchPayload(outputDir, iteration, payload) {
    if (!outputDir)
        return;
    await writeFile(join(outputDir, `watch-${String(iteration).padStart(3, '0')}.json`), JSON.stringify(payload, null, 2), 'utf-8');
}
export async function watchTarget(options) {
    const { intervalMs = 60_000, maxIterations = 0, outputDir, scanRunner = scanTarget, outputPath: _outputPath, saveArtifacts: _saveArtifacts, ...scanOptions } = options;
    if (outputDir) {
        await mkdir(outputDir, { recursive: true });
        await writeFile(join(outputDir, '.keep'), '', 'utf-8');
    }
    const history = [];
    let baseline = null;
    let iteration = 0;
    console.log(`\n👁️ Threat Lab Watch — monitoring ${scanOptions.target}`);
    console.log(`   Interval: ${(intervalMs / 1000).toFixed(1)}s`);
    console.log(`   Iterations: ${maxIterations > 0 ? maxIterations : 'until stopped'}`);
    if (outputDir)
        console.log(`   Snapshot dir: ${outputDir}`);
    while (maxIterations === 0 || iteration < maxIterations) {
        iteration += 1;
        console.log(`\n━━━━━━━━━━ Watch iteration ${iteration} ━━━━━━━━━━`);
        const results = await scanRunner({
            ...scanOptions,
            saveArtifacts: false,
        });
        const payload = {
            scannedAt: new Date().toISOString(),
            target: scanOptions.target,
            results,
        };
        const diff = baseline ? compareScanPayloads(payload, baseline) : null;
        const alerts = buildWatchAlerts(diff);
        if (diff) {
            console.log(formatScanDiff(diff));
            if (alerts.length > 0) {
                console.log('  🚨 Monitor alerts:');
                for (const alert of alerts)
                    console.log(`     • ${alert}`);
            }
            else {
                console.log('  ✅ No new high-signal escalations this cycle.');
            }
        }
        else {
            console.log('  Baseline snapshot established. Future cycles will diff against this run.');
        }
        await writeWatchPayload(outputDir, iteration, payload);
        history.push({ iteration, scannedAt: payload.scannedAt, payload, diff, alerts });
        baseline = payload;
        if (maxIterations > 0 && iteration >= maxIterations)
            break;
        await sleep(intervalMs);
    }
    return history;
}
export async function scanTarget(options) {
    const { target, quick = false, noDeps = false, noSim = false, noIntel = false, network = 'anvil', deep = false, outputPath, saveArtifacts = true } = options;
    console.log(`\n🔬 Threat Lab — Scanning ${target}`);
    if (!noDeps)
        console.log('   [1/4] Dependency audit  (OSV + npm advisories + Socket.dev)');
    if (!noIntel)
        console.log('   [2/4] Live threat intel (Brave Search + GH advisories, 14-day window)');
    if (!noSim && !quick)
        console.log('   [3/4] Exploit simulation (Anvil deployment + AI analysis)');
    console.log('   [4/4] Static analysis  (signature patterns + AI deep-read)');
    console.log('');
    const startAll = Date.now();
    const files = await findSolFiles(target);
    if (files.length === 0) {
        console.warn(`  No .sol files found at ${target}`);
        return [];
    }
    const projectDepPromise = noDeps ? Promise.resolve(null) : runDependencyAudit(target);
    const projectIntelPromise = noIntel ? Promise.resolve(null) : runThreatIntelLayer(target);
    const declaredDepsPromise = loadDeclaredDependencyNames(target);
    const [projectDepRes, projectIntelRes, declaredDepsRes] = await Promise.allSettled([projectDepPromise, projectIntelPromise, declaredDepsPromise]);
    const declaredDependencies = declaredDepsRes.status === 'fulfilled' ? declaredDepsRes.value : new Set();
    const sharedDependencyAudit = projectDepRes.status === 'fulfilled' ? projectDepRes.value : null;
    const sharedThreatIntel = projectIntelRes.status === 'fulfilled' && projectIntelRes.value != null
        ? projectIntelRes.value.filter((intel) => {
            if (sharedDependencyAudit == null)
                return true;
            return isIntelCorrelated(intel.packageName, sharedDependencyAudit, declaredDependencies) || intel.hasActiveExploit;
        })
        : [];
    const sharedDepError = projectDepRes.status === 'rejected' ? `deps: ${projectDepRes.reason}` : null;
    const sharedIntelError = projectIntelRes.status === 'rejected' ? `intel: ${projectIntelRes.reason}` : null;
    const results = [];
    for (const file of files) {
        const t0 = Date.now();
        const errors = [];
        const recommendations = [];
        // ── Run all three in parallel ──
        const [staticRes, simRes] = await Promise.allSettled([
            runStaticAnalysis(file),
            quick || noSim ? Promise.resolve(null) : runExploitSim(file, network),
        ]);
        const staticAnalysis = staticRes.status === 'fulfilled' ? staticRes.value : null;
        const dependencyAudit = sharedDependencyAudit;
        const threatIntel = sharedThreatIntel;
        const exploitSim = simRes.status === 'fulfilled' ? simRes.value : null;
        // Collect errors
        if (staticRes.status === 'rejected')
            errors.push(`static: ${staticRes.reason}`);
        if (sharedDepError)
            errors.push(sharedDepError);
        if (sharedIntelError)
            errors.push(sharedIntelError);
        if (simRes.status === 'rejected')
            errors.push(`sim: ${simRes.reason}`);
        // Determine overall severity
        const severities = [];
        if (staticAnalysis?.aiReport)
            severities.push(staticAnalysis.aiReport.severity);
        if (staticAnalysis?.patterns.length)
            severities.push('high');
        if (dependencyAudit) {
            if (dependencyAudit.threatLevel === 'critical')
                severities.push('critical');
            else if (dependencyAudit.threatLevel === 'high')
                severities.push('high');
            else if (dependencyAudit.threatLevel === 'medium')
                severities.push('medium');
        }
        if (threatIntel.length > 0) {
            const worstIntel = threatIntel.reduce((worst, t) => {
                const order = ['critical', 'high', 'medium', 'low', 'none'];
                return order.indexOf(t.overallSeverity) < order.indexOf(worst) ? t.overallSeverity : worst;
            }, 'none');
            if (worstIntel === 'critical')
                severities.push('critical');
            else if (worstIntel === 'high')
                severities.push('high');
            else if (worstIntel === 'medium')
                severities.push('medium');
        }
        if (exploitSim?.aiReport)
            severities.push(exploitSim.aiReport.severity);
        else if (exploitSim?.success)
            severities.push('high');
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
        if (threatIntel.some(t => t.hasActiveExploit && isIntelCorrelated(t.packageName, dependencyAudit, declaredDependencies))) {
            recommendations.push('🚨 LIVE THREAT: In-use packages with active exploits found — do NOT use until confirmed safe');
        }
        else if (threatIntel.some(t => t.hasActiveExploit)) {
            recommendations.push('⚠️ Active exploit chatter found in threat intel, but dependency correlation is weak — verify actual usage before escalating');
        }
        if (exploitSim?.success) {
            recommendations.push(`Exploit simulation confirmed: review ${exploitSim.scenarioName} pattern`);
        }
        // Compute threat score
        const scanResult = {
            file,
            staticAnalysis,
            dependencyAudit,
            threatIntel,
            exploitSim,
            overallSeverity,
            threatScore: 0, // filled below
            findings: buildConsolidatedFindings({
                file,
                staticAnalysis,
                dependencyAudit,
                threatIntel,
                exploitSim,
                declaredDependencies,
            }),
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
        const correlatedActiveCount = threatIntel.filter(t => t.hasActiveExploit && isIntelCorrelated(t.packageName, dependencyAudit, declaredDependencies)).length;
        const intelTag = correlatedActiveCount > 0
            ? `🚨 LIVE THREAT (${correlatedActiveCount} correlated)`
            : activeCount > 0
                ? `⚠️ intel weak-signal (${activeCount})`
                : noIntel ? '⏭ intel off' : '🌐 intel ok';
        console.log(`  ${sevIcon} ${file} [score: ${scanResult.threatScore}] [${simTag}] [${intelTag}]`);
    }
    // ── Print full report ──
    const report = generateReport(results);
    console.log(report);
    // ── Deep research via modelab ──
    if (deep) {
        console.log('\n🔬 Running deep research via modelab on flagged findings...');
        const deepFindings = [];
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
                        for (const f of finding.findings.filter((ff) => ff.isAlert)) {
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
        }
        else {
            console.log('  No critical findings to deep-research — scan is clean!');
        }
    }
    // ── Save report artifact ──
    if (saveArtifacts) {
        await saveScanArtifacts(target, results, outputPath);
    }
    const totalMs = Date.now() - startAll;
    console.log(`\n  ✅ Scan complete in ${(totalMs / 1000).toFixed(1)}s`);
    return results;
}
//# sourceMappingURL=scanner.js.map