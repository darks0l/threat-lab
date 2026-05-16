import { describe, it, expect, afterEach } from 'vitest';
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
    const { severityMeetsOrExceeds, getWorstScanSeverity } = scanner;

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
  });
});
