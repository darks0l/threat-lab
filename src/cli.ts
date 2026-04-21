#!/usr/bin/env node
/**
 * threat-lab CLI — Security research platform for AI-powered exploit analysis.
 *
 * Usage:
 *   threat-lab list                           # List available scenarios
 *   threat-lab run <scenario-id>             # Run a scenario locally (Anvil)
 *   threat-lab analyze <contract.sol>         # Analyze a contract file
 *   threat-lab submit <submission.json>      # Submit findings
 *   threat-lab patterns                      # Show known attack patterns
 */

import { listScenarios, getScenario } from './scenarios.js';
import { analyzeThreat } from './analyzer.js';
import { detectPatterns } from './patternDetector.js';
import { submitFromFile } from './api.js';
import { readFile } from 'fs/promises';

const args = process.argv.slice(2);
const command = args[0];

async function main() {
  switch (command) {
    case 'list': {
      const scenarios = listScenarios();
      console.log(`\n🔬 Threat Lab — ${scenarios.length} scenarios available\n`);
      for (const s of scenarios) {
        console.log(`  ${s.id.padEnd(30)} [${s.severity.padEnd(10)}] ${s.name}`);
        console.log(`  ${''.padEnd(30)} ${s.description.slice(0, 60)}...`);
        console.log(`  ${''.padEnd(30)} difficulty: ${s.difficulty} | pattern: ${s.pattern}`);
        console.log();
      }
      break;
    }

    case 'run': {
      const scenarioId = args[1];
      if (!scenarioId) {
        console.error('Usage: threat-lab run <scenario-id>');
        process.exit(1);
      }
      const scenario = getScenario(scenarioId);
      if (!scenario) {
        console.error(`Unknown scenario: ${scenarioId}`);
        console.error('Run "threat-lab list" to see available scenarios.');
        process.exit(1);
      }
      console.log(`\n⚡ Running scenario: ${scenario.name}`);
      console.log(`   Pattern: ${scenario.pattern} | Severity: ${scenario.severity}`);
      console.log(`   ${scenario.description}\n`);
      console.log('Steps:');
      for (const step of scenario.exploitSteps) {
        console.log(`  [${step.step}] ${step.action.toUpperCase().padEnd(12)} ${step.description}`);
      }
      console.log(`\n✅ Expected outcome: ${scenario.expectedOutcome}`);
      console.log('\n📝 To run this on Anvil: threat-lab deploy:anvil --scenario', scenarioId);
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
        const patterns = detectPatterns(code);
        if (patterns.length > 0) {
          console.log('🔍 Pattern matches:');
          for (const m of patterns.slice(0, 3)) {
            console.log(`  ${(m.pattern as string).padEnd(25)} ${(m.confidence * 100).toFixed(0).padStart(3)}% confidence`);
            console.log(`  ${''.padEnd(25)} matched: ${m.matchedOn.slice(0, 3).join(', ')}`);
          }
        } else {
          console.log('No known patterns detected. Running full AI analysis...');
          const report = await analyzeThreat({
            scenarioId: 'manual',
            scenarioName: 'Manual analysis',
            scenarioDesc: 'User-submitted contract for analysis',
            contractCode: code,
          });
          console.log(`\n📋 Threat Report (${report.attackPattern})`);
          console.log(`   Severity: ${report.severity} | Confidence: ${(report.confidence * 100).toFixed(0)}%`);
          console.log(`   ${report.summary.slice(0, 200)}`);
          if (report.recommendations.length > 0) {
            console.log('\n💡 Recommendations:');
            for (const r of report.recommendations.slice(0, 3)) {
              console.log(`   - ${r}`);
            }
          }
        }
      } catch (err) {
        console.error(`Failed to read file: ${err}`);
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
        console.log(`   Report ID: ${result.reportId}`);
        console.log(`   Score: ${result.score?.toFixed(2)}`);
        if (result.findings) {
          console.log(`   Findings: ${result.findings.join(', ')}`);
        }
      } else {
        console.error(`\n❌ Submission rejected: ${result.error}`);
        process.exit(1);
      }
      break;
    }

    case 'patterns': {
      const patterns = [
        { id: 'reentrancy', desc: 'Recursive external calls before state updates', severity: 'critical' },
        { id: 'oracle-manipulation', desc: 'Flash loan price oracle attacks', severity: 'high' },
        { id: 'flash-loan-attack', desc: 'Uncollateralized borrow + arbitrage', severity: 'medium' },
        { id: 'access-control', desc: 'Missing/incorrect permission checks', severity: 'critical' },
        { id: 'front-running', desc: 'Transaction order exploitation (MEV)', severity: 'medium' },
        { id: 'sandwich-attack', desc: 'Front-run + back-run sandwich combo', severity: 'medium' },
        { id: 'integer-overflow', desc: 'Arithmetic without Safemath/unchecked', severity: 'high' },
        { id: 'delegatecall-injection', desc: 'Storage corruption via delegatecall', severity: 'critical' },
        { id: 'permit-front-run', desc: 'EIP712 permit signature replay', severity: 'medium' },
      ];
      console.log('\n📚 Known attack patterns:\n');
      for (const p of patterns) {
        console.log(`  ${p.id.padEnd(25)} [${p.severity.padEnd(10)}] ${p.desc}`);
      }
      console.log();
      break;
    }

    default: {
      console.log(`
🔬 Threat Lab CLI — AI-powered security research platform

Usage:
  threat-lab list                          List available scenarios
  threat-lab run <scenario-id>             Preview a scenario
  threat-lab analyze <contract.sol>        Analyze a Solidity file
  threat-lab submit <submission.json>      Submit a finding
  threat-lab patterns                      Show known attack patterns

Examples:
  threat-lab list
  threat-lab run reentrancy-101
  threat-lab analyze ./contracts/MyVault.sol
  threat-lab submit ./my-finding.json
`);
      break;
    }
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
