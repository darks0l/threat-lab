/**
 * Threat Lab — Dependency Audit Engine
 * 
 * Scans npm projects for:
 * - Known vulnerabilities (npm audit --json)
 * - Malicious packages (Socket.dev API)
 * - Suspicious patterns (postinstall scripts, typo-squats, etc.)
 * - Supply chain risk indicators
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile, existsSync } from 'fs';
import { join, resolve } from 'path';
import { readFile as fsReadFile } from 'fs/promises';
import axios from 'axios';
import type {
  AuditResult,
  NpmAuditResult,
  SocketAnalysis,
  SuspiciousPattern,
  AuditVulnerability,
  VulnerabilitySeverity,
  OsintResult,
} from './auditSchemas.js';

const execAsync = promisify(exec);

// ── Constants ─────────────────────────────────────────────────────────────────

const SOCKET_DEV_API = 'https://api.socket.dev/v0';
const SOCKET_DEV_KEY = process.env.SOCKET_DEV_API_KEY ?? '';

// Severity weights for scoring
const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 40,
  high: 25,
  medium: 10,
  low: 3,
  info: 1,
};

// Known malicious / suspicious package name patterns
const KNOWN_SQUAT_PATTERNS: Array<{ pattern: RegExp; type: SuspiciousPattern['type']; desc: string; severity: VulnerabilitySeverity }> = [
  { pattern: /^discord-canary$/i, type: 'typo-squat', desc: 'Typo-squat of discord package', severity: 'critical' },
  { pattern: /^discord-desktop$/i, type: 'typo-squat', desc: 'Typo-squat of discord package', severity: 'critical' },
  { pattern: /^twilioooo$/i, type: 'typo-squat', desc: 'Typo-squat of twilio', severity: 'critical' },
  { pattern: /^aws-sdk2$/i, type: 'typo-squat', desc: 'Typo-squat of aws-sdk', severity: 'critical' },
  { pattern: /^aws-config$/i, type: 'typo-squat', desc: 'Typo-squat of AWS package', severity: 'high' },
  { pattern: /^ethers5$/i, type: 'typo-squat', desc: 'Typo-squat of ethers.js', severity: 'high' },
  { pattern: /^node-fetch-npm$/i, type: 'typo-squat', desc: 'Typo-squat of node-fetch', severity: 'high' },
  { pattern: /^node-fetch-v2$/i, type: 'typo-squat', desc: 'Typo-squat of node-fetch', severity: 'high' },
  { pattern: /^ethereum-tokens$/i, type: 'suspicious-publisher', desc: 'Ethereum package from untrusted publisher', severity: 'high' },
  { pattern: /^web3-signer$/i, type: 'suspicious-publisher', desc: 'Signing package — verify publisher', severity: 'high' },
  { pattern: /^crypto-wallet-core$/i, type: 'suspicious-publisher', desc: 'Wallet-related package — verify publisher', severity: 'high' },
  { pattern: /^ethers-provider$/i, type: 'typo-squat', desc: 'Typo-squat of ethers.js provider packages', severity: 'high' },
  { pattern: /^ethers-contract$/i, type: 'typo-squat', desc: 'Typo-squat of ethers.js contract packages', severity: 'high' },
];

const DEPENDENCY_CONFUSION_PATTERNS = [
  'truffle', 'hardhat', 'forge', 'foundry', 'web3', 'ethers',
  '@types/node', '@types/express', '@types/react',
];

// ── Main audit function ──────────────────────────────────────────────────────

export interface AuditOptions {
  projectPath: string;
  includeDev?: boolean;
  socketDev?: boolean;
  socketDevKey?: string;
  runNpmAudit?: boolean;
}

/**
 * Run a full dependency audit on a project.
 * Checks npm vulnerabilities, Socket.dev for malicious packages,
 * and detects suspicious supply chain patterns.
 */
export async function auditDependencies(options: AuditOptions): Promise<AuditResult> {
  const {
    projectPath,
    includeDev = true,
    socketDev: enableSocket = !!SOCKET_DEV_KEY,
    socketDevKey = SOCKET_DEV_KEY,
    runNpmAudit = true,
  } = options;

  const projectDir = resolve(projectPath);

  console.log(`\n🔍 Starting dependency audit: ${projectDir}`);

  // 1. Read package.json
  const pkgJson = await loadPackageJson(projectDir);
  if (!pkgJson) {
    throw new Error(`No package.json found at ${projectDir}`);
  }

  const depCount = countDependencies(pkgJson);

  // 2. npm audit
  let npmAuditResult: AuditResult['npmAudit'] = null;
  const npmAuditErrors: string[] = [];

  if (runNpmAudit) {
    console.log('\n📦 Running npm audit...');
    const npmResult = await performNpmAudit(projectDir, includeDev);
    if (npmResult.ok && npmResult.data) {
      const parsed = parseNpmAuditResult(npmResult.data);
      npmAuditResult = parsed;
      console.log(`   Found ${parsed.totalVulnerabilities} vulnerabilities (${parsed.breakdown.critical} critical, ${parsed.breakdown.high} high)`);
    } else {
      npmAuditErrors.push(npmResult.error ?? 'npm audit failed');
      console.warn(`   ⚠️  npm audit failed: ${npmResult.error}`);
    }
  }

  // 3. Socket.dev analysis
  let socketResult: AuditResult['socketDev'] = null;

  if (enableSocket && socketDevKey) {
    console.log('\n🔎 Running Socket.dev analysis...');
    socketResult = await runSocketDevAnalysis(pkgJson, socketDevKey);
    console.log(`   Checked ${socketResult!.checkedPackages} packages`);
    console.log(`   Malicious detections: ${socketResult!.maliciousDetections.length}`);
    console.log(`   High risk: ${socketResult!.highRiskPackages.length}`);
  } else if (enableSocket) {
    console.log('\n🔎 Socket.dev checks skipped (no SOCKET_DEV_API_KEY set — get one at socket.dev)');
    socketResult = { checkedPackages: 0, maliciousDetections: [], highRiskPackages: [] };
  }

  // 4. OSINT / web search for active exploits and recent advisories
  let osintResult: AuditResult['osint'] = null;
  try {
    console.log('\n🌐 Running OSINT analysis (OSV.dev + npm Security Advisories)...');
    osintResult = await runOsintAnalysis(pkgJson);
    console.log(`   Checked ${osintResult!.checkedPackages} packages`);
    console.log(`   Active findings: ${osintResult!.findings.length}`);
    if (osintResult!.activeExploits.length > 0) {
      console.warn(`   🚨 ACTIVE EXPLOITS DETECTED: ${osintResult!.activeExploits.length}`);
    }
  } catch (err) {
    console.warn(`   ⚠️  OSINT analysis failed: ${err instanceof Error ? err.message : String(err)}`);
    osintResult = { checkedPackages: 0, findings: [], activeExploits: [] };
  }

  // 5. Pattern detection
  const suspiciousPatterns = detectSuspiciousPatterns(pkgJson, npmAuditResult, socketResult, osintResult);

  // 6. Summary
  const summary = buildAuditSummary(npmAuditResult, socketResult, osintResult, suspiciousPatterns, pkgJson);

  const result: AuditResult = {
    projectPath: projectDir,
    auditPerformedAt: new Date().toISOString(),
    npmAudit: npmAuditResult,
    socketDev: socketResult,
    osint: osintResult,
    suspiciousPatterns,
    npmAuditErrors,
    dependencyCount: depCount,
    summary,
  };

  printAuditSummary(result);
  return result;
}

// ── npm audit ────────────────────────────────────────────────────────────────

async function performNpmAudit(
  projectDir: string,
  includeDev: boolean,
): Promise<{ ok: boolean; data?: NpmAuditResult; error?: string }> {
  const devFlag = includeDev ? '--include=dev' : '';
  try {
    const { stdout } = await execAsync(
      `npm audit --json ${devFlag}`,
      { cwd: projectDir, timeout: 90_000, killSignal: 'SIGTERM' }
    );
    const data = JSON.parse(stdout) as NpmAuditResult;
    return { ok: true, data };
  } catch (err: unknown) {
    // npm audit exits with code 1 when vulnerabilities are found — still valid output
    if (err && typeof err === 'object' && 'stdout' in err) {
      try {
        const stdout = String((err as { stdout: unknown }).stdout);
        if (stdout) {
          const data = JSON.parse(stdout) as NpmAuditResult;
          return { ok: true, data };
        }
      } catch { /* fall through */ }
    }
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function parseNpmAuditResult(raw: NpmAuditResult): NonNullable<AuditResult['npmAudit']> {
  const vulns = raw.vulnerabilities ?? {};
  const meta = raw.metadata?.vulnerabilities;

  const vulnerabilities: AuditVulnerability[] = Object.entries(vulns).map(([name, adv]) => ({
    id: adv.id ?? 0,
    moduleName: name,
    severity: mapSeverity(adv.severity ?? 'unknown'),
    title: adv.title ?? `Vulnerability in ${name}`,
    url: adv.url,
    affectedVersions: adv.findings?.map(f => f.version) ?? [],
    isTransitive: adv.findings?.some(f => f.isTransitive) ?? false,
    via: adv.findings?.[0]?.version,
  }));

  return {
    version: raw.auditReportVersion ?? 'unknown',
    totalVulnerabilities: vulnerabilities.length,
    breakdown: {
      critical: meta?.critical ?? 0,
      high: meta?.high ?? 0,
      medium: meta?.moderate ?? 0,
      low: meta?.low ?? 0,
      info: meta?.info ?? 0,
    },
    vulnerabilities,
  };
}

function mapSeverity(s: string): VulnerabilitySeverity {
  const l = s.toLowerCase();
  if (l === 'critical') return 'critical';
  if (l === 'high') return 'high';
  if (l === 'moderate') return 'medium';
  if (l === 'low') return 'low';
  return 'info';
}

// ── Socket.dev ────────────────────────────────────────────────────────────────

async function runSocketDevAnalysis(
  pkgJson: { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string> },
  apiKey: string,
): Promise<NonNullable<AuditResult['socketDev']>> {
  const allDeps = {
    ...(pkgJson.dependencies ?? {}),
    ...(pkgJson.devDependencies ?? {}),
    ...(pkgJson.optionalDependencies ?? {}),
  };

  const maliciousDetections: Array<{ packageName: string; version: string; description?: string }> = [];
  const highRiskPackages: Array<{ packageName: string; version: string; riskTypes: string[]; description: string }> = [];
  let checkedPackages = 0;

  const entries = Object.entries(allDeps);
  const batchSize = 8; // conservative to avoid rate limits

  for (let i = 0; i < entries.length; i += batchSize) {
    const batch = entries.slice(i, i + batchSize);
    const pkgList = batch.map(([name, version]) => `${name}@${version}`).join(',');

    try {
      const response = await axios.get(`${SOCKET_DEV_API}/package/${pkgList}`, {
        headers: {
          'User-Agent': 'threat-lab/0.1.0',
          'API-Version': '2024-04-01',
          'X-API-Key': apiKey,
        },
        params: { version: '1' },
        timeout: 20_000,
      });

      const results: SocketAnalysis[] = Array.isArray(response.data)
        ? response.data
        : [response.data];

      for (const pkg of results) {
        checkedPackages++;
        const installedVersion = pkg.version ?? allDeps[pkg.name] ?? 'unknown';

        if (pkg.hasMaliciousCode) {
          maliciousDetections.push({
            packageName: pkg.name,
            version: installedVersion,
            description: pkg.additionalInfo?.hasInstallScripts
              ? 'Flagged as malicious by Socket.dev — has install scripts'
              : 'Flagged as malicious by Socket.dev',
          });
          continue;
        }

        // Collect risk signals
        const riskTypes: string[] = [];
        const info = pkg.additionalInfo;
        if (info?.hasInstallScripts) riskTypes.push('install-script');
        if (info?.hasLargeExpandos) riskTypes.push('large-expandos');
        if (info?.hasTypoSquats) riskTypes.push('typo-squat');
        if (info?.hasDependencyConfusion) riskTypes.push('dependency-confusion');
        if (info?.hasNativeSnippets) riskTypes.push('native-code');
        if (info?.hasSandboxEscapes) riskTypes.push('sandbox-escape');
        if (info?.hasTelemetryScript) riskTypes.push('telemetry');
        if (pkg.isArchived) riskTypes.push('archived-package');

        if (riskTypes.length >= 2 || (info?.hasInstallScripts && info?.hasLargeExpandos)) {
          highRiskPackages.push({
            packageName: pkg.name,
            version: installedVersion,
            riskTypes,
            description: `Risk signals: ${riskTypes.join(', ')}`,
          });
        }
      }
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 429) {
        console.warn(`   ⚠️  Socket.dev rate limited — stopping with ${checkedPackages} packages checked`);
        break;
      }
      console.warn(`   ⚠️  Socket.dev batch error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return { checkedPackages, maliciousDetections, highRiskPackages };
}

// ── OSINT / Web Search ─────────────────────────────────────────────────────────

/**
 * Query OSV.dev and npm Security Advisories for active exploits and recent
 * vulnerabilities not yet in the npm audit DB.
 *
 * Sources checked:
 *   - OSV.dev API (osv.dev/v1/query) — broad ecosystem coverage
 *   - npm Security Advisories API (api.npmjs.org/advisories) — npm-native
 *   - GitHub Security Advisories (api.github.com/advisories) — GH-scoped CVEs
 */

const ACTIVE_EXPLOIT_KEYWORDS = [
  'actively exploited', 'in the wild', 'proof of concept', 'poc available',
  'weaponized', 'active exploitation', 'public exploit', 'actively being exploited',
];

async function runOsintAnalysis(
  pkgJson: { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string> },
): Promise<NonNullable<AuditResult['osint']>> {
  const allDeps = {
    ...(pkgJson.dependencies ?? {}),
    ...(pkgJson.devDependencies ?? {}),
    ...(pkgJson.optionalDependencies ?? {}),
  };

  const findings: NonNullable<AuditResult['osint']>['findings'] = [];
  const activeExploits: NonNullable<AuditResult['osint']>['activeExploits'] = [];
  const checkedPackages = Object.keys(allDeps).length;

  const entries = Object.entries(allDeps);
  const batchSize = 10;

  for (let i = 0; i < entries.length; i += batchSize) {
    const batch = entries.slice(i, i + batchSize);
    await Promise.all(batch.map(async ([name, versionSpec]) => {
      const version = versionSpec.replace(/^[\^~>=<]/, '').split('/')[0];
      try {
        // ── OSV.dev ──────────────────────────────────────────────────────────
        await queryOsv(name, version, findings, activeExploits);
        // ── npm Security Advisories ──────────────────────────────────────────
        await queryNpmAdvisories(name, version, findings, activeExploits);
      } catch {
        // Non-blocking — individual package failures don't stop the whole scan
      }
    }));
  }

  return { checkedPackages, findings, activeExploits };
}

async function queryOsv(
  pkgName: string,
  version: string,
  findings: NonNullable<AuditResult['osint']>['findings'],
  activeExploits: NonNullable<AuditResult['osint']>['activeExploits'],
): Promise<void> {
  try {
    const resp = await axios.post(
      'https://osv.dev/v1/query',
      {
        package: { name: pkgName, ecosystem: 'npm' },
        version,
      },
      { timeout: 10_000, headers: { 'Content-Type': 'application/json' } },
    );
    const vulns: unknown[] = resp.data?.vulns ?? [];
    for (const v of vulns) {
      const vv = v as Record<string, unknown>;
      const severity = mapOsvSeverity(vv.severity as string | undefined);
      const summary = String(vv.summary ?? '');
      const references: string[] = (vv.references as Array<{ url: string }> ?? [])
        .map(r => r.url)
        .filter(Boolean);
      const published = String(vv.published ?? '');
      const isActive = ACTIVE_EXPLOIT_KEYWORDS.some(k =>
        summary.toLowerCase().includes(k) ||
        (vv.details ?? '').toString().toLowerCase().includes(k),
      );
      const id = String(vv.id ?? '');

      findings.push({
        packageName: pkgName,
        packageVersion: version,
        severity,
        title: summary || id,
        description: (vv.details as string)?.slice(0, 500),
        publishedDate: published || undefined,
        permalink: `https://osv.dev/vulnerability/${id}`,
        references,
        isActive,
      });

      if (isActive) {
        activeExploits.push({
          packageName: pkgName,
          title: summary || id,
          severity,
          permalink: `https://osv.dev/vulnerability/${id}`,
        });
      }
    }
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.status === 404) return; // no record
    throw err;
  }
}

async function queryNpmAdvisories(
  pkgName: string,
  version: string,
  findings: NonNullable<AuditResult['osint']>['findings'],
  activeExploits: NonNullable<AuditResult['osint']>['activeExploits'],
): Promise<void> {
  try {
    const resp = await axios.get(
      `https://api.npmjs.org/advisories/${encodeURIComponent(pkgName)}`,
      { timeout: 10_000 },
    );
    const advisories: Array<{
      id: number; title: string; severity: string; url: string;
      vulnerable_versions: string; published: string; overview: string;
      metadata?: { exploitability?: number };
    }> = resp.data?.advisories ?? [];

    for (const adv of advisories) {
      // Check if our version is affected
      if (!versionMatches(adv.vulnerable_versions, version)) continue;

      const severity = mapNpmSeverity(adv.severity);
      const isActive = ACTIVE_EXPLOIT_KEYWORDS.some(k =>
        adv.title.toLowerCase().includes(k) || adv.overview?.toLowerCase().includes(k),
      );

      findings.push({
        packageName: pkgName,
        packageVersion: version,
        severity,
        title: adv.title,
        description: adv.overview?.slice(0, 500),
        publishedDate: adv.published,
        permalink: adv.url || `https://www.npmjs.com/advisories/${adv.id}`,
        references: adv.url ? [adv.url] : [],
        isActive,
      });

      if (isActive) {
        activeExploits.push({
          packageName: pkgName,
          title: adv.title,
          severity,
          permalink: adv.url || `https://www.npmjs.com/advisories/${adv.id}`,
        });
      }
    }
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.status === 404) return;
    throw err;
  }
}

function versionMatches(vulnerableVersions: string, installed: string): boolean {
  if (!vulnerableVersions || vulnerableVersions === '*') return true;
  try {
    const { satisfies } = require('semver');
    return satisfies(installed, vulnerableVersions);
  } catch {
    return vulnerableVersions.includes(installed);
  }
}

function mapOsvSeverity(s?: string): VulnerabilitySeverity {
  const l = (s ?? '').toLowerCase();
  if (l.includes('critical')) return 'critical';
  if (l.includes('high')) return 'high';
  if (l.includes('medium') || l === 'moderate') return 'medium';
  if (l.includes('low')) return 'low';
  return 'info';
}

function mapNpmSeverity(s?: string): VulnerabilitySeverity {
  const l = (s ?? '').toLowerCase();
  if (l === 'critical') return 'critical';
  if (l === 'high') return 'high';
  if (l === 'moderate') return 'medium';
  if (l === 'low') return 'low';
  return 'info';
}

// ── Pattern detection ─────────────────────────────────────────────────────────

function detectSuspiciousPatterns(
  pkgJson: { name?: string; scripts?: Record<string, string>; dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; description?: string; repository?: string; license?: string },
  npmAudit: AuditResult['npmAudit'],
  socketDev: AuditResult['socketDev'],
  osintResult: AuditResult['osint'],
): SuspiciousPattern[] {
  const patterns: SuspiciousPattern[] = [];

  const allDeps = {
    ...(pkgJson.dependencies ?? {}),
    ...(pkgJson.devDependencies ?? {}),
    ...(pkgJson.optionalDependencies ?? {}),
  };

  // 1. Known squat / malicious patterns
  for (const depName of Object.keys(allDeps)) {
    const nameWithoutScope = depName.replace(/^@/, '');

    for (const sig of KNOWN_SQUAT_PATTERNS) {
      if (sig.pattern.test(nameWithoutScope) || sig.pattern.test(depName)) {
        patterns.push({
          type: sig.type,
          severity: sig.severity,
          packageName: depName,
          description: sig.desc,
          recommendation: `Remove "${depName}" and verify you installed the correct package from the correct publisher`,
        });
      }
    }

    // Generic dependency confusion check for common packages
    const baseName = nameWithoutScope.replace(/[-_]?\d+(\.\d+)*$/, ''); // strip version-like suffix
    if (DEPENDENCY_CONFUSION_PATTERNS.some(p => p.toLowerCase() === baseName.toLowerCase())) {
      const version = allDeps[depName];
      if (version && !version.startsWith('^') && !version.startsWith('~') && !version.startsWith('>=')) {
        patterns.push({
          type: 'dependency-confusion',
          severity: 'medium',
          packageName: depName,
          description: `${depName} has an unpinned version "${version}" — could be susceptible to dependency confusion if published to a different registry`,
          recommendation: `Pin ${depName} to a specific version: "${depName}@${version.replace(/^[\^~>=<]/, '')}"`,
        });
      }
    }
  }

  // 2. Vulnerabilities with install script / arbitrary code execution risk
  if (npmAudit) {
    for (const vuln of npmAudit.vulnerabilities) {
      const titleLower = vuln.title.toLowerCase();
      if (
        titleLower.includes('install') ||
        titleLower.includes('postinstall') ||
        titleLower.includes('arbitrary code') ||
        titleLower.includes('command injection') ||
        titleLower.includes('execution')
      ) {
        patterns.push({
          type: 'postinstall-exec',
          severity: vuln.severity === 'critical' || vuln.severity === 'high' ? 'high' : 'medium',
          packageName: vuln.moduleName,
          description: `Known vulnerability with install-script risk: "${vuln.title}"`,
          evidence: vuln.url,
          recommendation: `Review ${vuln.moduleName}'s install scripts before deploying — consider pinning to a patched version`,
        });
      }
    }
  }

  // 3. High-risk from Socket.dev
  if (socketDev) {
    for (const pkg of socketDev.highRiskPackages) {
      if (pkg.riskTypes.includes('sandbox-escape') || (pkg.riskTypes.includes('install-script') && pkg.riskTypes.includes('native-code'))) {
        patterns.push({
          type: 'sandbox-escape',
          severity: 'critical',
          packageName: pkg.packageName,
          description: `${pkg.packageName} combines install scripts with native code — highest supply chain risk`,
          recommendation: `DO NOT install ${pkg.packageName} in production without a full audit. Consider removing it.`,
        });
      } else if (pkg.riskTypes.includes('install-script')) {
        patterns.push({
          type: 'high-risk-install',
          severity: 'high',
          packageName: pkg.packageName,
          description: `${pkg.packageName} has install scripts that run during npm install — can execute arbitrary code`,
          evidence: pkg.riskTypes.join(', '),
          recommendation: `Verify the publisher identity of ${pkg.packageName}. Run in an isolated environment first.`,
        });
      }
    }
  }

  // 4. Suspicious publisher names
  if (socketDev) {
    for (const pkg of socketDev.highRiskPackages) {
      const hasSuspiciousPublisher = pkg.riskTypes.includes('suspicious-publisher');
      if (hasSuspiciousPublisher) {
        patterns.push({
          type: 'suspicious-publisher',
          severity: 'high',
          packageName: pkg.packageName,
          description: `${pkg.packageName} is published by a suspicious or anonymous publisher`,
          recommendation: `Verify ${pkg.packageName}'s publisher on npmjs.com before using in production`,
        });
      }
    }
  }

  // 4b. Active exploits from OSINT
  if (osintResult && osintResult.activeExploits.length > 0) {
    for (const exploit of osintResult.activeExploits) {
      patterns.push({
        type: 'recently-published',
        severity: exploit.severity === 'critical' ? 'critical' : 'high',
        packageName: exploit.packageName,
        description: `⚠️ ACTIVE EXPLOIT: ${exploit.title}`,
        evidence: exploit.permalink,
        recommendation: `DO NOT USE — actively exploited in the wild. Remove or isolate this package immediately.`,
      });
    }
  }

  // 5. Root package missing metadata
  const missing: string[] = [];
  if (!pkgJson.description) missing.push('description');
  if (!pkgJson.repository) missing.push('repository');
  if (!pkgJson.license) missing.push('license');
  if (missing.length >= 2 && pkgJson.scripts && Object.keys(pkgJson.scripts).length > 0) {
    patterns.push({
      type: 'suspicious-publisher',
      severity: 'low',
      packageName: (pkgJson.name as string) ?? 'ROOT',
      description: `Root package.json missing: ${missing.join(', ')} — could indicate a quickly-created or unmaintained project`,
      recommendation: 'If this is your project: add missing fields. If this is a dependency: verify its legitimacy.',
    });
  }

  return patterns;
}

// ── Summary scoring ───────────────────────────────────────────────────────────

function buildAuditSummary(
  npmAudit: AuditResult['npmAudit'],
  socketDev: AuditResult['socketDev'],
  osintResult: AuditResult['osint'],
  suspiciousPatterns: SuspiciousPattern[],
  _pkgJson: unknown,
): AuditResult['summary'] {
  const vulnCount = npmAudit?.totalVulnerabilities ?? 0;
  const maliciousCount = socketDev?.maliciousDetections.length ?? 0;
  const highRiskCount = socketDev?.highRiskPackages.length ?? 0;
  const osintFindingsCount = osintResult?.findings.length ?? 0;
  const activeExploitsCount = osintResult?.activeExploits.length ?? 0;
  const patternCount = suspiciousPatterns.length;

  const vulnScore = (npmAudit?.breakdown.critical ?? 0) * 40
    + (npmAudit?.breakdown.high ?? 0) * 25
    + (npmAudit?.breakdown.medium ?? 0) * 10
    + (npmAudit?.breakdown.low ?? 0) * 3;

  const totalScore = Math.min(
    vulnScore
    + maliciousCount * 50
    + highRiskCount * 15
    + activeExploitsCount * 80   // active exploits are the highest weight
    + osintFindingsCount * 5
    + patternCount * 8,
    100,
  );

  let threatLevel: AuditResult['summary']['threatLevel'];
  if (activeExploitsCount > 0 || maliciousCount > 0 || (npmAudit?.breakdown.critical ?? 0) > 0) {
    threatLevel = 'critical';
  } else if ((npmAudit?.breakdown.high ?? 0) > 2 || highRiskCount > 3 || patternCount > 5) {
    threatLevel = 'high';
  } else if (vulnCount > 0 || patternCount > 0 || osintFindingsCount > 0) {
    threatLevel = 'medium';
  } else if (totalScore > 5) {
    threatLevel = 'low';
  } else {
    threatLevel = 'safe';
  }

  const criticalActions: string[] = [];
  if (activeExploitsCount > 0 && osintResult) {
    criticalActions.push(`🚨 ACTIVE EXPLOITS: ${osintResult.activeExploits.map(e => `${e.packageName} (${e.permalink})`).join(', ')}`);
  }
  if (maliciousCount > 0 && socketDev) {
    criticalActions.push(`REMOVE malicious packages: ${socketDev.maliciousDetections.map(m => m.packageName).join(', ')}`);
  }
  if ((npmAudit?.breakdown.critical ?? 0) > 0) {
    criticalActions.push('Fix critical npm vulnerabilities before deploying');
  }
  if (suspiciousPatterns.some(p => p.type === 'sandbox-escape')) {
    criticalActions.push('CRITICAL: sandbox-escape risk detected — DO NOT deploy without removing the package(s)');
  }

  return {
    threatLevel,
    score: totalScore,
    vulnerablePackages: vulnCount,
    suspiciousPackages: maliciousCount + highRiskCount + osintFindingsCount,
    totalFlags: vulnCount + maliciousCount + highRiskCount + osintFindingsCount + patternCount,
    criticalActions,
  };
}

function printAuditSummary(result: AuditResult): void {
  const { summary } = result;

  const emoji: Record<string, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢',
    safe: '✅',
  };

  const e = emoji[summary.threatLevel] ?? '⚪';

  console.log(`\n${'─'.repeat(60)}`);
  console.log(`📋 DEPENDENCY AUDIT SUMMARY — ${result.projectPath}`);
  console.log(`${'─'.repeat(60)}`);
  console.log(`   Threat Level: ${e} ${summary.threatLevel.toUpperCase()} (score: ${summary.score}/100)`);
  console.log(`   Vulnerable packages: ${summary.vulnerablePackages}`);
  console.log(`   Suspicious packages: ${summary.suspiciousPackages}`);
  console.log(`   Total flags: ${summary.totalFlags}`);
  console.log(`   Dependencies: ${result.dependencyCount.total} total (${result.dependencyCount.dev} dev, ${result.dependencyCount.optional} optional)`);

  if (result.npmAudit) {
    const b = result.npmAudit.breakdown;
    console.log(`\n   npm audit:`);
    if (b.critical > 0) console.log(`     🔴 Critical: ${b.critical}`);
    if (b.high > 0) console.log(`     🟠 High: ${b.high}`);
    if (b.medium > 0) console.log(`     🟡 Medium: ${b.medium}`);
    if (b.low > 0) console.log(`     🟢 Low: ${b.low}`);
    if (summary.vulnerablePackages === 0) console.log(`     ✅ No vulnerabilities found`);
  } else {
    console.log(`\n   npm audit: skipped`);
  }

  if (result.socketDev) {
    if (result.socketDev.maliciousDetections.length > 0) {
      console.log(`\n   🚨 MALICIOUS PACKAGES:`);
      for (const m of result.socketDev.maliciousDetections) {
        console.log(`     - ${m.packageName}@${m.version}`);
        console.log(`       ${m.description ?? 'Flagged as malicious by Socket.dev'}`);
      }
    }
    if (result.socketDev.highRiskPackages.length > 0) {
      console.log(`\n   ⚠️  High-risk packages (${result.socketDev.highRiskPackages.length}):`);
      for (const p of result.socketDev.highRiskPackages.slice(0, 5)) {
        console.log(`     - ${p.packageName}@${p.version}: ${p.riskTypes.join(', ')}`);
      }
      if (result.socketDev.highRiskPackages.length > 5) {
        console.log(`       ... and ${result.socketDev.highRiskPackages.length - 5} more`);
      }
    }
  } else {
    console.log(`\n   Socket.dev: no API key (set SOCKET_DEV_API_KEY)`);
  }

  if (result.osint) {
    const activeExploits = result.osint.activeExploits;
    const recentFindings = result.osint.findings.filter(f => {
      if (!f.publishedDate) return false;
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
      return new Date(f.publishedDate) > sixMonthsAgo;
    });
    if (activeExploits.length > 0) {
      console.log(`\n   🚨 ACTIVE EXPLOITS (OSV.dev + npm Advisories):`);
      for (const e of activeExploits) {
        console.log(`     - ${e.packageName}: ${e.title}`);
        console.log(`       ${e.permalink}`);
      }
    }
    if (recentFindings.length > 0) {
      console.log(`\n   🌐 Recent advisories (last 6 months, OSV.dev + npm):`);
      for (const f of recentFindings.slice(0, 5)) {
        const se = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : '🟢';
        console.log(`     ${se} [${f.severity}] ${f.packageName}: ${f.title}`);
      }
      if (recentFindings.length > 5) {
        console.log(`       ... and ${recentFindings.length - 5} more`);
      }
    }
    if (activeExploits.length === 0 && recentFindings.length === 0) {
      console.log(`\n   🌐 OSINT (OSV.dev + npm): no recent advisories found`);
    }
  } else {
    console.log(`\n   🌐 OSINT: skipped`);
  }

  if (result.suspiciousPatterns.length > 0) {
    console.log(`\n   🔎 Suspicious patterns:`);
    const critical = result.suspiciousPatterns.filter(p => p.severity === 'critical');
    const high = result.suspiciousPatterns.filter(p => p.severity === 'high');
    const medium = result.suspiciousPatterns.filter(p => p.severity === 'medium');
    for (const p of [...critical, ...high, ...medium].slice(0, 8)) {
      const se = p.severity === 'critical' ? '🔴' : p.severity === 'high' ? '🟠' : '🟡';
      console.log(`     ${se} [${p.severity}] ${p.type}: ${p.packageName}`);
      console.log(`       ${p.description.slice(0, 100)}`);
    }
    if (result.suspiciousPatterns.length > 8) {
      console.log(`       ... and ${result.suspiciousPatterns.length - 8} more`);
    }
  }

  if (summary.criticalActions.length > 0) {
    console.log(`\n   🚨 CRITICAL ACTIONS REQUIRED:`);
    for (const action of summary.criticalActions) {
      console.log(`     - ${action}`);
    }
  }

  console.log(`${'─'.repeat(60)}\n`);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

interface PkgJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
  description?: string;
  repository?: string;
  license?: string;
}

async function loadPackageJson(projectDir: string): Promise<PkgJson | null> {
  const pkgPath = join(projectDir, 'package.json');
  if (!existsSync(pkgPath)) return null;
  try {
    const content = await fsReadFile(pkgPath, 'utf-8');
    return JSON.parse(content) as PkgJson;
  } catch {
    return null;
  }
}

function countDependencies(pkg: PkgJson): AuditResult['dependencyCount'] {
  return {
    total: Object.keys(pkg.dependencies ?? {}).length + Object.keys(pkg.devDependencies ?? {}).length + Object.keys(pkg.optionalDependencies ?? {}).length,
    dev: Object.keys(pkg.devDependencies ?? {}).length,
    optional: Object.keys(pkg.optionalDependencies ?? {}).length,
  };
}
