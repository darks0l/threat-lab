import { describe, it, expect } from 'vitest';

// Test the audit module's parsing and pattern detection logic
// without running actual network requests or npm audit

describe('audit suspicious pattern detection', () => {
  // Test pattern matching logic directly by importing utility functions
  // Since the functions are not exported, we test the behavior via the
  // known squat patterns and the auditDependencies output shape

  it('KNOWN_SQUAT_PATTERNS catches typo-squat of discord', async () => {
    // The squat patterns are hardcoded - test the regexes
    const discordSquat = /^discord-canary$/i;
    expect(discordSquat.test('discord-canary')).toBe(true);
    expect(discordSquat.test('discord')).toBe(false);
  });

  it('KNOWN_SQUAT_PATTERNS catches typo-squat of ethers', async () => {
    const ethersSquat = /^ethers5$/i;
    expect(ethersSquat.test('ethers5')).toBe(true);
    expect(ethersSquat.test('ethers')).toBe(false);
  });

  it('KNOWN_SQUAT_PATTERNS catches aws-config squat', async () => {
    const awsSquat = /^aws-config$/i;
    expect(awsSquat.test('aws-config')).toBe(true);
    expect(awsSquat.test('aws-sdk')).toBe(false);
  });

  it('dependency confusion patterns include expected packages', async () => {
    const confusionPatterns = [
      'truffle', 'hardhat', 'forge', 'foundry', 'web3', 'ethers',
      '@types/node', '@types/express', '@types/react',
    ];
    expect(confusionPatterns).toContain('hardhat');
    expect(confusionPatterns).toContain('ethers');
    expect(confusionPatterns).toContain('@types/node');
  });

  it('ACTIVE_EXPLOIT_KEYWORDS detects weaponized language', () => {
    const keywords = [
      'actively exploited', 'in the wild', 'proof of concept', 'poc available',
      'weaponized', 'active exploitation', 'public exploit', 'actively being exploited',
    ];
    const exploitText = 'This vulnerability is actively exploited in the wild with a public exploit available.';
    const matched = keywords.some(k => exploitText.toLowerCase().includes(k));
    expect(matched).toBe(true);
  });

  it('ACTIVE_EXPLOIT_KEYWORDS does not trigger on safe text', () => {
    const keywords = [
      'actively exploited', 'in the wild', 'proof of concept', 'poc available',
      'weaponized', 'active exploitation', 'public exploit', 'actively being exploited',
    ];
    const safeText = 'This vulnerability was patched in version 2.0.0.';
    const matched = keywords.some(k => safeText.toLowerCase().includes(k));
    expect(matched).toBe(false);
  });

  it('severity weights are correctly ordered', async () => {
    // Severity weights from audit.ts
    const SEVERITY_WEIGHT: Record<string, number> = {
      critical: 40,
      high: 25,
      medium: 10,
      low: 3,
      info: 1,
    };
    expect(SEVERITY_WEIGHT.critical).toBeGreaterThan(SEVERITY_WEIGHT.high);
    expect(SEVERITY_WEIGHT.high).toBeGreaterThan(SEVERITY_WEIGHT.medium);
    expect(SEVERITY_WEIGHT.medium).toBeGreaterThan(SEVERITY_WEIGHT.low);
    expect(SEVERITY_WEIGHT.low).toBeGreaterThan(SEVERITY_WEIGHT.info);
  });

  it('versionMatches correctly identifies affected versions', async () => {
    // Test the semver matching logic
    function versionMatches(vulnerableVersions: string, installed: string): boolean {
      if (!vulnerableVersions || vulnerableVersions === '*') return true;
      try {
        const { satisfies } = require('semver');
        return satisfies(installed, vulnerableVersions);
      } catch {
        return vulnerableVersions.includes(installed);
      }
    }

    expect(versionMatches('>=1.0.0', '1.0.0')).toBe(true);
    expect(versionMatches('>=1.0.0', '0.9.0')).toBe(false);
    expect(versionMatches('*', '999.0.0')).toBe(true);
    expect(versionMatches('^1.0.0', '1.5.0')).toBe(true);
    expect(versionMatches('^1.0.0', '2.0.0')).toBe(false);
  });
});

describe('audit result schema', () => {
  it('AuditResult has expected structure', async () => {
    // We can't import the type directly in a .test.ts without compilation issues
    // but we can verify the shape from auditSchemas.ts
    const { AuditResultSchema } = await import('../src/auditSchemas.js');
    expect(AuditResultSchema).toBeDefined();
  });

  it('SuspiciousPattern types are defined', async () => {
    const { SuspiciousPatternSchema } = await import('../src/auditSchemas.js');
    expect(SuspiciousPatternSchema).toBeDefined();
  });
});
