#!/usr/bin/env node
/**
 * threat-lab CLI — AI-powered security research platform.
 *
 * Usage:
 *   threat-lab list                         # List available scenarios
 *   threat-lab run <scenario-id>           # Execute scenario → analyze → add to library
 *   threat-lab analyze <contract.sol>      # Analyze a Solidity file
 *   threat-lab submit <submission.json>    # Submit a finding
 *   threat-lab patterns                    # Show known attack patterns
 *   threat-lab library                    # Show pattern library stats
 *   threat-lab library search <pattern>    # Search the library
 *   threat-lab export                      # Export library to JSON
 *   threat-lab status                       # Check Anvil / network status
 */

import { listScenarios, getScenario } from './scenarios.js';
import { analyzeThreat } from './analyzer.js';
import { detectPatterns } from './patternDetector.js';
import { submitFromFile } from './api.js';
import { getLibraryStats, searchLibrary, exportLibrary } from './library.js';
import { runThreatLab } from './runner.js';
import { isAnvilRunning } from './executor.js';
import { auditDependencies } from './audit.js';
import { scanTarget } from './scanner.js';
import { readFile } from 'fs/promises';

const args = process.argv.slice(2);
const command = args[0];

async function main() {
  switch (command) {
    case 'list': {
      const scenarios = listScenarios();
      const stats = await getLibraryStats();
      console.log(`\n🔬 Threat Lab — ${scenarios.length} scenarios | ${stats.totalEntries} library entries\n`);
      for (const s of scenarios) {
        const fill = ' '.repeat(30 - s.id.length);
        const severityColor = s.severity === 'critical' ? '🔴' : s.severity === 'high' ? '🟠' : s.severity === 'medium' ? '🟡' : '🟢';
        console.log(`  ${severityColor} ${s.id}${fill} [${s.severity.padEnd(10)}] ${s.name}`);
        console.log(`  ${''.padEnd(4)} ${s.description.slice(0, 65)}...`);
        console.log(`  ${''.padEnd(4)} difficulty: ${s.difficulty} | pattern: ${s.pattern}`);
        console.log();
      }
      break;
    }

    case 'run': {
      const scenarioId = args[1];
      if (!scenarioId) {
        console.error('Usage: threat-lab run <scenario-id> [--network anvil|base-sepolia] [--model claude-sonnet-4-6]');
        process.exit(1);
      }
      const network = args.includes('--network') ? args[args.indexOf('--network') + 1] : 'anvil';
      const modelIndex = args.indexOf('--model');
      const models = modelIndex !== -1 ? [args[modelIndex + 1]] : ['claude-sonnet-4-6'];

      const result = await runThreatLab(scenarioId, { network, models });
      if (!result.success) {
        console.error(`\n❌ Failed: ${result.error}`);
        process.exit(1);
      }
      break;
    }

    case 'analyze': {
      const filePath = args[1];
      if (!filePath) {
        console.error('Usage: threat-lab analyze <contract.sol>');
        process.exit(1);
      }
      try {
        const code = await readFile(filePath, 'utf-8');
        console.log(`\n🧠 Analyzing ${filePath}...\n`);

        // Fast path: signature-based detection
        const patterns = detectPatterns(code);
        if (patterns.length > 0) {
          console.log('🔍 Pattern matches:');
          for (const m of patterns.slice(0, 3)) {
            const bar = '█'.repeat(Math.round(m.confidence * 10)) + '░'.repeat(10 - Math.round(m.confidence * 10));
            console.log(`  ${(m.pattern as string).padEnd(25)} ${bar} ${(m.confidence * 100).toFixed(0)}%`);
            console.log(`  ${''.padEnd(25)} matched: ${m.matchedOn.slice(0, 3).join(', ')}`);
          }
        }

        // Deep analysis
        console.log('\n🤖 Running deep analysis...');
        const report = await analyzeThreat({
          scenarioId: 'manual',
          scenarioName: filePath,
          scenarioDesc: 'User-submitted contract for analysis',
          contractCode: code,
        });

        console.log(`\n📋 Threat Report`);
        console.log(`   Pattern:    ${report.attackPattern}`);
        console.log(`   Severity:   ${report.severity}`);
        console.log(`   Confidence: ${(report.confidence * 100).toFixed(0)}%`);
        console.log(`   AI Model:  ${report.aiModel}`);
        console.log(`\n   ${report.summary.slice(0, 300)}`);
        if (report.recommendations.length > 0) {
          console.log('\n💡 Recommendations:');
          for (const r of report.recommendations.slice(0, 3)) {
            console.log(`   - ${r}`);
          }
        }
      } catch (err) {
        console.error(`Failed: ${err}`);
        process.exit(1);
      }
      break;
    }

    case 'submit': {
      const filePath = args[1];
      if (!filePath) {
        console.error('Usage: threat-lab submit <submission.json>');
        process.exit(1);
      }
      console.log(`\n📤 Submitting findings from ${filePath}...`);
      const result = await submitFromFile(filePath);
      if (result.success) {
        console.log(`\n✅ Submission accepted`);
        console.log(`   Report: ${result.reportId}`);
        console.log(`   Score:  ${result.score?.toFixed(2)}`);
        if (result.findings) console.log(`   Findings: ${result.findings.join(', ')}`);
      } else {
        console.error(`\n❌ Rejected: ${result.error}`);
        process.exit(1);
      }
      break;
    }

    case 'patterns': {
      const patterns = [
        { id: 'reentrancy',           desc: 'Recursive external calls before state updates',           severity: 'critical' },
        { id: 'oracle-manipulation', desc: 'Flash loan price oracle attacks',                       severity: 'high'     },
        { id: 'flash-loan-attack',    desc: 'Uncollateralized borrow + arbitrage in one tx',         severity: 'medium'   },
        { id: 'access-control',       desc: 'Missing/incorrect permission checks',                   severity: 'critical' },
        { id: 'front-running',        desc: 'Transaction order exploitation (MEV)',                  severity: 'medium'   },
        { id: 'sandwich-attack',      desc: 'Front-run + back-run sandwich combo',                  severity: 'medium'   },
        { id: 'integer-overflow',      desc: 'Arithmetic without Safemath/unchecked',               severity: 'high'     },
        { id: 'delegatecall-injection', desc: 'Storage corruption via delegatecall',                severity: 'critical' },
        { id: 'permit-front-run',     desc: 'EIP712 permit signature replay',                        severity: 'medium'   },
      ];
      console.log('\n📚 Known attack patterns:\n');
      for (const p of patterns) {
        const sev = p.severity === 'critical' ? '🔴' : p.severity === 'high' ? '🟠' : '🟡';
        console.log(`  ${sev} ${p.id.padEnd(25)} ${p.desc}`);
      }
      console.log();
      break;
    }

    case 'library': {
      const subcommand = args[1];
      if (subcommand === 'search') {
        const pattern = args[2] as import('./schemas.js').AttackPattern | undefined;
        const results = await searchLibrary({
          pattern: pattern as import('./schemas.js').AttackPattern | undefined,
          keyword: args.includes('--kw') ? args[args.indexOf('--kw') + 1] : undefined,
          limit: 10,
        });
        if (results.length === 0) {
          console.log('\n🔍 No results found.\n');
        } else {
          console.log(`\n🔍 Found ${results.length} entries:\n`);
          for (const r of results) {
            console.log(`  ${r.attackPattern.padEnd(25)} [${r.severity.padEnd(10)}] ${r.scenarioName}`);
            console.log(`  ${''.padEnd(4)} ${r.summary.slice(0, 80)}...`);
            console.log(`  ${''.padEnd(4)} confidence: ${(r.confidence * 100).toFixed(0)}% | views: ${r.viewCount} | cited: ${r.citationCount}`);
            console.log();
          }
        }
      } else {
        // Show library stats
        const stats = await getLibraryStats();
        console.log(`\n📚 Pattern Library Stats`);
        console.log(`   Total entries: ${stats.totalEntries}`);
        console.log(`   Avg confidence: ${(stats.avgConfidence * 100).toFixed(0)}%`);
        if (stats.newestEntry) console.log(`   Newest: ${stats.newestEntry}`);
        if (Object.keys(stats.byPattern).length > 0) {
          console.log('\n   By pattern:');
          for (const [pattern, count] of Object.entries(stats.byPattern)) {
            console.log(`     ${(pattern as string).padEnd(25)} ${count}`);
          }
        }
        if (Object.keys(stats.bySeverity).length > 0) {
          console.log('\n   By severity:');
          for (const [sev, count] of Object.entries(stats.bySeverity)) {
            console.log(`     ${(sev as string).padEnd(25)} ${count}`);
          }
        }
        console.log();
      }
      break;
    }

    case 'export': {
      const data = await exportLibrary();
      const outPath = `library-${Date.now()}.json`;
      const { writeFile } = await import('fs/promises');
      await writeFile(outPath, data);
      console.log(`\n📦 Library exported to ${outPath} (${(data.length / 1024).toFixed(1)} KB)\n`);
      break;
    }

    case 'status': {
      const anvil = await isAnvilRunning();
      console.log('\n🔧 Threat Lab Status');
      console.log(`   Anvil: ${anvil ? '🟢 running on http://127.0.0.1:8545' : '🔴 not running (run: anvil)'}`);
      const stats = await getLibraryStats();
      console.log(`   Library: ${stats.totalEntries} entries`);
      const scenarios = listScenarios();
      console.log(`   Scenarios: ${scenarios.length} available`);
      console.log();
      break;
    }

    case 'audit': {
      const targetPath = args[1] ?? '.';
      const includeDev = !args.includes('--no-dev');
      const withSocket = !args.includes('--no-socket');
      const withNpm = !args.includes('--no-npm');

      console.log(`\n🔍 Dependency Audit — ${targetPath}`);
      console.log(`   npm audit: ${withNpm ? 'enabled' : 'disabled'}`);
      console.log(`   Socket.dev: ${withSocket ? 'enabled' : 'disabled'}`);
      console.log(`   include dev deps: ${includeDev}`);

      try {
        const result = await auditDependencies({
          projectPath: targetPath,
          includeDev,
          socketDev: withSocket,
          runNpmAudit: withNpm,
        });

        // Exit code reflects threat level
        if (result.summary.threatLevel === 'critical' || result.summary.threatLevel === 'high') {
          process.exit(1);
        }
      } catch (err) {
        console.error(`\n❌ Audit failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
      break;
    }

    case 'scan': {
      const targetPath = args[1] ?? '.';
      const quick = args.includes('--quick');
      const noDeps = args.includes('--no-deps');
      const noSim = args.includes('--no-sim');
      const noIntel = args.includes('--no-intel');
      const deep = args.includes('--deep');
      const network = args.includes('--network') ? args[args.indexOf('--network') + 1] : 'anvil';

      console.log(`\n🔬 Unified Security Scan — ${targetPath}`);
      console.log(`   Static analysis:   always on (signature patterns + AI deep-read)`);
      console.log(`   Dependency audit: ${noDeps ? 'OFF (--no-deps)' : 'OSV + npm advisories + Socket.dev'}`);
      console.log(`   Threat intel:    ${noIntel ? 'OFF (--no-intel)' : 'Brave Search + GH advisories, 14-day window'}`);
      console.log(`   Exploit sim:     ${quick || noSim ? 'OFF (--quick / --no-sim)' : `Anvil deployment + AI analysis`}`);
      console.log(`   Deep research:   ${deep ? 'ON (modelab multi-model + patch generation)' : 'OFF (use --deep to enable)'}`);
      console.log(`   Network:         ${network}`);

      if (deep && !process.env.BANKR_API_KEY) {
        console.error(`\n❌ --deep requires BANKR_API_KEY to be set`);
        process.exit(1);
      }

      try {
        await scanTarget({ target: targetPath, quick, noDeps, noSim, noIntel, network, deep });
      } catch (err) {
        console.error(`\n❌ Scan failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
      break;
    }

    default: {
      console.log(`
🔬 Threat Lab CLI — AI-powered security research platform

Usage:
  threat-lab list                          List available scenarios
  threat-lab run <scenario-id>            Execute scenario + AI analysis + library
  threat-lab run reentrancy-101 --network anvil
  threat-lab analyze <contract.sol>        Analyze a Solidity file (AI only)
  threat-lab scan <path>                  Unified scan: static + deps + intel + exploit sim
  threat-lab scan <path> --quick          Skip exploit simulation (faster)
  threat-lab scan <path> --no-deps        Skip dependency audit
  threat-lab scan <path> --no-intel       Skip live threat intel (Layer 2b)
  threat-lab scan <path> --deep           Run deep research on flagged findings (modelab)
  threat-lab audit <path>                 Dependency audit only (npm + OSV + Socket.dev)
  threat-lab audit ./ --no-socket         Skip Socket.dev (no API key)
  threat-lab submit <submission.json>     Submit a finding
  threat-lab library                      Show library stats
  threat-lab library search <pattern>    Search pattern library
  threat-lab patterns                    Show known attack patterns
  threat-lab export                      Export library to JSON
  threat-lab status                      Check Anvil / network status

Quick start:
  threat-lab status          # Check Anvil is running
  threat-lab list            # See available scenarios
  threat-lab scan .          # Full unified scan (all 4 layers)
  threat-lab scan . --quick  # Fast scan (skip exploit simulation)
  threat-lab scan . --deep   # Full scan + modelab deep research + patch generation
  threat-lab audit .         # Dependency audit only
  threat-lab run reentrancy-101  # Execute + analyze + add to library

Environment variables:
  BANKR_API_KEY              Required for AI analysis and deep research
  BRAVE_SEARCH_API_KEY       Required for live threat intel (get at brave.com/search/api)
  GITHUB_TOKEN               Optional, for GitHub Security Advisories (faster, higher rate limit)
  SOCKET_DEV_API_KEY         Optional, for malicious package detection (get at socket.dev)
`);
      break;
    }
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
