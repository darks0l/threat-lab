import { describe, it, expect, afterEach, vi } from 'vitest';
import { readFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { writeFile, mkdir, rm } from 'fs/promises';

describe('scanner file discovery', () => {
  const tmp = join(tmpdir(), `threat-lab-test-${Date.now()}`);

  async function cleanupTmp() {
    try { await rm(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
  }

  afterEach(async () => {
    await cleanupTmp();
  });

  it('finds .sol files in a directory', async () => {
    const { findSolFiles } = await import('../src/scanner.js');

    await mkdir(join(tmp, 'contracts'), { recursive: true });
    await writeFile(join(tmp, 'contracts', 'Token.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'contracts', 'Vault.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'README.md'), '# test'); // should be ignored

    const files = await findSolFiles(tmp);
    const solFiles = files.filter(f => f.endsWith('.sol'));

    expect(solFiles.length).toBe(2);
    expect(solFiles.some(f => f.includes('Token.sol'))).toBe(true);
    expect(solFiles.some(f => f.includes('Vault.sol'))).toBe(true);
  });

  it('handles single file target', async () => {
    const { findSolFiles } = await import('../src/scanner.js');

    await mkdir(join(tmp, 'contracts'), { recursive: true });
    const singleFile = join(tmp, 'contracts', 'Single.sol');
    await writeFile(singleFile, 'pragma solidity ^0.8.0;');

    const files = await findSolFiles(singleFile);
    expect(files.length).toBe(1);
    expect(files[0]).toBe(singleFile);
  });

  it('ignores node_modules, dist, and cache directories', async () => {
    const { findSolFiles } = await import('../src/scanner.js');

    await mkdir(join(tmp, 'node_modules', 'pkg'), { recursive: true });
    await mkdir(join(tmp, 'dist', 'contracts'), { recursive: true });
    await mkdir(join(tmp, 'cache'), { recursive: true });
    await mkdir(join(tmp, 'src'), { recursive: true });
    await writeFile(join(tmp, 'node_modules', 'pkg', 'Evil.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'dist', 'contracts', 'Built.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'cache', 'Cached.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'src', 'Valid.sol'), 'pragma solidity ^0.8.0;');

    const files = await findSolFiles(tmp);
    const solFiles = files.filter(f => f.endsWith('.sol'));

    expect(solFiles.length).toBe(1);
    expect(solFiles[0]).toContain('Valid.sol');
  });

  it('returns empty array for non-existent path', async () => {
    const { findSolFiles } = await import('../src/scanner.js');
    const files = await findSolFiles('/non/existent/path');
    expect(files).toEqual([]);
  });

  it('writes markdown scan reports when output path ends in .md', async () => {
    const { scanTarget } = await import('../src/scanner.js');

    await mkdir(join(tmp, 'contracts'), { recursive: true });
    await writeFile(join(tmp, 'contracts', 'Vault.sol'), 'pragma solidity ^0.8.0; contract Vault {}');
    const output = join(tmp, 'scan-report.md');

    const results = await scanTarget({
      target: tmp,
      quick: true,
      noDeps: true,
      noIntel: true,
      outputPath: output,
    });

    expect(results.length).toBe(1);
    const report = await readFile(output, 'utf-8');
    expect(report).toContain('# Threat Lab Scan Report');
    expect(report).toContain('contracts');
    expect(report).toContain('Correlated intel alerts');
  });

  it('writes json scan reports to custom output paths', async () => {
    const { scanTarget } = await import('../src/scanner.js');

    await mkdir(join(tmp, 'contracts'), { recursive: true });
    await writeFile(join(tmp, 'contracts', 'Vault.sol'), 'pragma solidity ^0.8.0; contract Vault {}');
    const output = join(tmp, 'scan-report.json');

    const results = await scanTarget({
      target: tmp,
      quick: true,
      noDeps: true,
      noIntel: true,
      outputPath: output,
    });

    expect(results.length).toBe(1);
    const payload = JSON.parse(await readFile(output, 'utf-8')) as { target: string; results: Array<{ file: string }> };
    expect(payload.target).toBe(tmp);
    expect(payload.results.length).toBe(1);
    expect(payload.results[0].file).toContain('Vault.sol');
  });

  it('compares current and baseline scan payloads', async () => {
    const scanner = await import('../src/scanner.js');
    const { compareScanPayloads, formatScanDiff } = scanner;

    const baseline: scanner.ScanPayload = {
      scannedAt: '2026-05-15T00:00:00.000Z',
      target: 'baseline-project',
      results: [
        {
          file: 'contracts/A.sol',
          staticAnalysis: null,
          dependencyAudit: null,
          threatIntel: [],
          exploitSim: null,
          overallSeverity: 'high',
          threatScore: 70,
          findings: [],
          recommendations: [],
          durationMs: 10,
          errors: [],
        },
        {
          file: 'contracts/Removed.sol',
          staticAnalysis: null,
          dependencyAudit: null,
          threatIntel: [],
          exploitSim: null,
          overallSeverity: 'medium',
          threatScore: 40,
          findings: [],
          recommendations: [],
          durationMs: 10,
          errors: [],
        },
      ],
    };

    const current: scanner.ScanPayload = {
      scannedAt: '2026-05-16T00:00:00.000Z',
      target: 'current-project',
      results: [
        {
          file: 'contracts/A.sol',
          staticAnalysis: null,
          dependencyAudit: null,
          threatIntel: [],
          exploitSim: null,
          overallSeverity: 'critical',
          threatScore: 100,
          findings: [],
          recommendations: [],
          durationMs: 10,
          errors: [],
        },
        {
          file: 'contracts/New.sol',
          staticAnalysis: null,
          dependencyAudit: null,
          threatIntel: [],
          exploitSim: null,
          overallSeverity: 'low',
          threatScore: 20,
          findings: [],
          recommendations: [],
          durationMs: 10,
          errors: [],
        },
      ],
    };

    const diff = compareScanPayloads(current, baseline);
    expect(diff.added).toBe(1);
    expect(diff.resolved).toBe(1);
    expect(diff.changed).toBe(1);
    expect(diff.unchanged).toBe(0);

    const formatted = formatScanDiff(diff);
    expect(formatted).toContain('THREAT LAB — SCAN DIFF');
    expect(formatted).toContain('contracts/New.sol');
    expect(formatted).toContain('contracts/Removed.sol');
    expect(formatted).toContain('contracts/A.sol');
  });

  it('evaluates severity thresholds for security gates', async () => {
    const scanner = await import('../src/scanner.js');
    const { severityMeetsOrExceeds, getWorstScanSeverity, formatSecurityGateDecision } = scanner;

    const results: scanner.ScanResult[] = [
      {
        file: 'contracts/A.sol',
        staticAnalysis: null,
        dependencyAudit: null,
        threatIntel: [],
        exploitSim: null,
        overallSeverity: 'medium',
        threatScore: 40,
        findings: [],
        recommendations: [],
        durationMs: 5,
        errors: [],
      },
      {
        file: 'contracts/B.sol',
        staticAnalysis: null,
        dependencyAudit: null,
        threatIntel: [],
        exploitSim: null,
        overallSeverity: 'high',
        threatScore: 70,
        findings: [],
        recommendations: [],
        durationMs: 5,
        errors: [],
      },
    ];

    expect(getWorstScanSeverity(results)).toBe('high');
    expect(severityMeetsOrExceeds('high', 'high')).toBe(true);
    expect(severityMeetsOrExceeds('critical', 'high')).toBe(true);
    expect(severityMeetsOrExceeds('medium', 'high')).toBe(false);
    expect(formatSecurityGateDecision(results, 'high')).toContain('worst severity high vs threshold high');
  });

  it('summarizes saved scan payloads into hotspots and rollups', async () => {
    const scanner = await import('../src/scanner.js');
    const { summarizeScanPayload, formatScanPayloadSummary } = scanner;

    const payload: scanner.ScanPayload = {
      scannedAt: '2026-07-12T12:00:00.000Z',
      target: 'demo-project',
      results: [
        {
          file: 'contracts/A.sol',
          staticAnalysis: null,
          dependencyAudit: null,
          threatIntel: [],
          exploitSim: null,
          overallSeverity: 'critical',
          threatScore: 92,
          findings: [{
            category: 'static',
            severity: 'critical',
            title: 'Reentrancy pattern',
            description: 'External call before state update',
            recommendation: 'Apply CEI',
          }],
          recommendations: ['Apply CEI'],
          durationMs: 5,
          errors: [],
        },
        {
          file: 'contracts/B.sol',
          staticAnalysis: null,
          dependencyAudit: null,
          threatIntel: [],
          exploitSim: null,
          overallSeverity: 'medium',
          threatScore: 41,
          findings: [],
          recommendations: ['Review invariants'],
          durationMs: 5,
          errors: [],
        },
      ],
    };

    const summary = summarizeScanPayload(payload);
    expect(summary.target).toBe('demo-project');
    expect(summary.overallSeverity).toBe('critical');
    expect(summary.averageScore).toBe(67);
    expect(summary.hotspots[0].file).toBe('contracts/A.sol');
    expect(summary.hotspots[0].topFinding).toBe('Reentrancy pattern');

    const formatted = formatScanPayloadSummary(payload);
    expect(formatted).toContain('Threat Lab Scan Summary');
    expect(formatted).toContain('Overall threat: CRITICAL');
    expect(formatted).toContain('contracts/A.sol');
    expect(formatted).toContain('Apply CEI');
  });

  it('builds watch alerts for new and escalated findings across monitor cycles', async () => {
    const scanner = await import('../src/scanner.js');
    const tmp = join(tmpdir(), `threat-lab-watch-${Date.now()}`);
    await mkdir(join(tmp, 'contracts'), { recursive: true });
    await writeFile(join(tmp, 'contracts', 'Vault.sol'), 'pragma solidity ^0.8.0; contract Vault {}');

    const cycleOne = [{
      file: join(tmp, 'contracts', 'Vault.sol'),
      staticAnalysis: null,
      dependencyAudit: null,
      threatIntel: [],
      exploitSim: null,
      overallSeverity: 'medium',
      threatScore: 40,
      findings: [],
      recommendations: [],
      durationMs: 5,
      errors: [],
    }] satisfies scanner.ScanResult[];

    const cycleTwo = [{
      file: join(tmp, 'contracts', 'Vault.sol'),
      staticAnalysis: null,
      dependencyAudit: null,
      threatIntel: [],
      exploitSim: null,
      overallSeverity: 'critical',
      threatScore: 100,
      findings: [],
      recommendations: [],
      durationMs: 5,
      errors: [],
    }] satisfies scanner.ScanResult[];

    const scanRunner = vi.fn()
      .mockResolvedValueOnce(cycleOne)
      .mockResolvedValueOnce(cycleTwo);

    const history = await scanner.watchTarget({
      target: tmp,
      quick: true,
      noDeps: true,
      noIntel: true,
      noSim: true,
      intervalMs: 1,
      maxIterations: 2,
      scanRunner,
    });

    expect(scanRunner).toHaveBeenCalledTimes(2);

    expect(history).toHaveLength(2);
    expect(history[0].diff).toBeNull();
    expect(history[1].alerts.some(alert => alert.includes('ESCALATED'))).toBe(true);

    await rm(tmp, { recursive: true, force: true });
  });
});

describe('scanner structured findings + project-level reuse', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('runs dependency audit and threat intel once per scan target and emits structured findings', async () => {
    const scanner = await import('../src/scanner.js');
    const analyzer = await import('../src/analyzer.js');
    const audit = await import('../src/audit.js');
    const threatIntel = await import('../src/threatIntel.js');
    const executor = await import('../src/executor.js');

    const tmp = join(tmpdir(), `threat-lab-project-scan-${Date.now()}`);
    await mkdir(join(tmp, 'contracts'), { recursive: true });
    await writeFile(join(tmp, 'package.json'), JSON.stringify({ dependencies: { ethers: '^6.13.0' } }, null, 2));
    await writeFile(join(tmp, 'contracts', 'A.sol'), 'pragma solidity ^0.8.0; contract A { function withdraw() external {} }');
    await writeFile(join(tmp, 'contracts', 'B.sol'), 'pragma solidity ^0.8.0; contract B { function withdraw() external {} }');

    const analyzeSpy = vi.spyOn(scanner.scannerDeps, 'analyzeThreat').mockResolvedValue({
      reportId: '11111111-1111-4111-8111-111111111111',
      scenarioId: 'scan:test',
      attackPattern: 'reentrancy',
      severity: 'high',
      summary: 'Potential reentrancy issue',
      findings: [{ title: 'External call before state change', description: 'danger', evidence: 'call before update' }],
      aiModel: 'test-model',
      confidence: 0.9,
      recommendations: ['Use CEI'],
      createdAt: new Date().toISOString(),
    });

    const auditSpy = vi.spyOn(scanner.scannerDeps, 'auditDependencies').mockResolvedValue({
      projectPath: tmp,
      auditPerformedAt: new Date().toISOString(),
      npmAudit: {
        version: '1',
        totalVulnerabilities: 1,
        breakdown: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        vulnerabilities: [{ id: 1, moduleName: 'lodash', severity: 'critical', title: 'Prototype pollution', url: 'https://example.com', affectedVersions: ['<1.0.0'], isTransitive: false }],
      },
      socketDev: null,
      osint: null,
      suspiciousPatterns: [],
      npmAuditErrors: [],
      dependencyCount: { total: 1, dev: 0, optional: 0 },
      summary: { threatLevel: 'critical', score: 90, vulnerablePackages: 1, suspiciousPackages: 0, totalFlags: 1, criticalActions: ['upgrade lodash'] },
    });

    const intelSpy = vi.spyOn(scanner.scannerDeps, 'runThreatIntel').mockResolvedValue([
      {
        packageName: 'ethers',
        packageVersion: '6.13.0',
        searches: [{
          source: 'github-advisory',
          query: 'ethers',
          resultCount: 1,
          freshestDate: new Date().toISOString(),
          findings: [{
            title: 'Active exploit chatter',
            url: 'https://example.com/advisory',
            date: new Date().toISOString(),
            snippet: 'Exploit discussion in the wild',
            source: 'GitHub Security Advisories',
            isAlert: true,
          }],
        }],
        overallSeverity: 'critical',
        hasActiveExploit: true,
        summary: 'critical intel',
        recommendations: ['patch now'],
      },
    ]);

    vi.spyOn(executor, 'isAnvilRunning').mockResolvedValue(false);

    const results = await scanner.scanTarget({ target: tmp, quick: true, noSim: true });

    expect(auditSpy).toHaveBeenCalledTimes(1);
    expect(intelSpy).toHaveBeenCalledTimes(1);
    expect(analyzeSpy).toHaveBeenCalledTimes(2);
    expect(results).toHaveLength(2);
    expect(results[0].findings.some(f => f.category === 'deps')).toBe(true);
    expect(results[0].findings.some(f => f.category === 'intel')).toBe(true);
    expect(results[0].findings.some(f => f.category === 'static')).toBe(true);
    expect(results[0].findings.filter(f => f.category === 'intel').every(f => f.correlated === true)).toBe(true);

    await rm(tmp, { recursive: true, force: true });
  });

  it('suppresses weak-signal intel when it does not correlate to audited dependencies', async () => {
    const scanner = await import('../src/scanner.js');

    const tmp = join(tmpdir(), `threat-lab-weak-intel-${Date.now()}`);
    await mkdir(join(tmp, 'contracts'), { recursive: true });
    await writeFile(join(tmp, 'package.json'), JSON.stringify({ dependencies: { ethers: '^6.13.0' } }, null, 2));
    await writeFile(join(tmp, 'contracts', 'Only.sol'), 'pragma solidity ^0.8.0; contract Only { function ping() external {} }');

    vi.spyOn(scanner.scannerDeps, 'analyzeThreat').mockRejectedValue(new Error('skip ai'));
    vi.spyOn(scanner.scannerDeps, 'auditDependencies').mockResolvedValue({
      projectPath: tmp,
      auditPerformedAt: new Date().toISOString(),
      npmAudit: null,
      socketDev: null,
      osint: null,
      suspiciousPatterns: [],
      npmAuditErrors: [],
      dependencyCount: { total: 1, dev: 0, optional: 0 },
      summary: { threatLevel: 'none', score: 0, vulnerablePackages: 0, suspiciousPackages: 0, totalFlags: 0, criticalActions: [] },
    });
    vi.spyOn(scanner.scannerDeps, 'runThreatIntel').mockResolvedValue([
      {
        packageName: 'totally-other-package',
        packageVersion: '1.0.0',
        searches: [{
          source: 'general',
          query: 'totally-other-package',
          resultCount: 1,
          freshestDate: new Date().toISOString(),
          findings: [{
            title: 'Mention somewhere',
            url: 'https://example.com/mention',
            date: new Date().toISOString(),
            snippet: 'Background chatter only',
            source: 'Some Blog',
            isAlert: false,
          }],
        }],
        overallSeverity: 'medium',
        hasActiveExploit: false,
        summary: 'weak intel',
        recommendations: [],
      },
    ]);

    const results = await scanner.scanTarget({ target: tmp, quick: true, noSim: true });
    expect(results).toHaveLength(1);
    expect(results[0].findings.some(f => f.category === 'intel')).toBe(false);

    await rm(tmp, { recursive: true, force: true });
  });
});
