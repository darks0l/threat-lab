import { describe, it, expect, beforeEach } from 'vitest';
import { randomUUID } from 'crypto';
import type { ThreatReport, AttackPattern } from '../src/schemas.js';

const LIBRARY_TEST_DIR = './library-test';

// Mock the library to use test directory
import * as library from '../src/library.js';

// Override the library dir for tests by mocking the module
// Since we can't easily override module-level constants, we'll test the public API
// and verify via side effects

describe('library', () => {
  describe('searchLibrary', () => {
    it('returns array type', async () => {
      const results = await library.searchLibrary({});
      expect(Array.isArray(results)).toBe(true);
    });

    it('filters by attack pattern', async () => {
      const results = await library.searchLibrary({ pattern: 'reentrancy' });
      for (const entry of results) {
        expect(entry.attackPattern).toBe('reentrancy');
      }
    });

    it('filters by severity', async () => {
      const results = await library.searchLibrary({ severity: 'critical' });
      for (const entry of results) {
        expect(entry.severity).toBe('critical');
      }
    });

    it('filters by keyword', async () => {
      const results = await library.searchLibrary({ keyword: 'reentrancy' });
      expect(Array.isArray(results)).toBe(true);
      // Results should be empty or contain reentrancy-related entries
    });

    it('filters by minimum confidence', async () => {
      const results = await library.searchLibrary({ minConfidence: 0.9 });
      for (const entry of results) {
        expect(entry.confidence).toBeGreaterThanOrEqual(0.9);
      }
    });

    it('respects limit parameter', async () => {
      const results = await library.searchLibrary({ limit: 3 });
      expect(results.length).toBeLessThanOrEqual(3);
    });
  });

  describe('getLibraryStats', () => {
    it('returns expected shape', async () => {
      const stats = await library.getLibraryStats();
      expect(stats).toHaveProperty('totalEntries');
      expect(stats).toHaveProperty('byPattern');
      expect(stats).toHaveProperty('bySeverity');
      expect(stats).toHaveProperty('avgConfidence');
      expect(typeof stats.totalEntries).toBe('number');
      expect(typeof stats.avgConfidence).toBe('number');
    });

    it('avgConfidence is between 0 and 1', async () => {
      const stats = await library.getLibraryStats();
      if (stats.totalEntries > 0) {
        expect(stats.avgConfidence).toBeGreaterThanOrEqual(0);
        expect(stats.avgConfidence).toBeLessThanOrEqual(1);
      }
    });

    it('byPattern counts sum to totalEntries', async () => {
      const stats = await library.getLibraryStats();
      const patternSum = Object.values(stats.byPattern).reduce((s, n) => s + n, 0);
      expect(patternSum).toBe(stats.totalEntries);
    });
  });

  describe('findSimilar', () => {
    it('returns array', async () => {
      const results = await library.findSimilar('reentrancy');
      expect(Array.isArray(results)).toBe(true);
    });

    it('entries match the requested pattern', async () => {
      const results = await library.findSimilar('reentrancy');
      for (const entry of results) {
        expect(entry.attackPattern).toBe('reentrancy');
      }
    });

    it('respects limit', async () => {
      const results = await library.findSimilar('reentrancy', 2);
      expect(results.length).toBeLessThanOrEqual(2);
    });
  });

  describe('getPatternCounts', () => {
    it('returns record of AttackPattern to number', async () => {
      const counts = await library.getPatternCounts();
      expect(typeof counts).toBe('object');
      for (const [pattern, count] of Object.entries(counts)) {
        expect(['reentrancy', 'oracle-manipulation', 'flash-loan-attack', 'access-control',
          'front-running', 'sandwich-attack', 'integer-overflow', 'delegatecall-injection',
          'permit-front-run', 'liquidation-attack', 'unknown'].includes(pattern)).toBe(true);
        expect(typeof count).toBe('number');
        expect(count).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe('exportLibrary', () => {
    it('returns valid JSON string', async () => {
      const data = await library.exportLibrary();
      expect(typeof data).toBe('string');
      expect(() => JSON.parse(data)).not.toThrow();
    });

    it('exported JSON has expected top-level fields', async () => {
      const data = await library.exportLibrary();
      const parsed = JSON.parse(data);
      expect(parsed).toHaveProperty('version');
      expect(parsed).toHaveProperty('exportedAt');
      expect(parsed).toHaveProperty('totalEntries');
      expect(parsed).toHaveProperty('entries');
      expect(Array.isArray(parsed.entries)).toBe(true);
    });
  });

  describe('importLibrary', () => {
    it('returns number of imported entries', async () => {
      const testExport = JSON.stringify({
        version: '1.0',
        exportedAt: new Date().toISOString(),
        totalEntries: 1,
        entries: [{
          id: 'test-import-entry',
          reportId: 'test-report',
          scenarioId: 'test-scenario',
          scenarioName: 'Test Scenario',
          attackPattern: 'reentrancy',
          severity: 'critical',
          summary: 'Test import',
          findings: [],
          recommendations: [],
          confidence: 0.9,
          submittedAt: new Date().toISOString(),
          txHashes: [],
          chainId: 1,
          viewCount: 0,
          citationCount: 0,
        }],
      });

      const count = await library.importLibrary(testExport);
      expect(typeof count).toBe('number');
    });

    it('handles invalid JSON gracefully', async () => {
      await expect(library.importLibrary('not json')).rejects.toThrow();
    });
  });

  describe('roundtrip: addToLibrary -> searchLibrary', () => {
    it('can add an entry and find it by pattern', async () => {
      const report: ThreatReport = {
        reportId: `test-${randomUUID()}`,
        scenarioId: 'test-scenario',
        attackPattern: 'reentrancy',
        severity: 'critical',
        summary: 'Test reentrancy vulnerability',
        findings: [{
          title: 'Reentrancy in withdraw',
          description: 'External call before state update',
          evidence: 'code here',
        }],
        aiModel: 'test-model',
        confidence: 0.95,
        recommendations: ['Add ReentrancyGuard'],
        createdAt: new Date().toISOString(),
      };

      const entry = await library.addToLibrary(report, {
        submittedBy: 'test-suite',
        txHashes: ['0xtest'],
        chainId: 1,
      });

      expect(entry.id).toBeDefined();
      expect(entry.attackPattern).toBe('reentrancy');
      expect(entry.severity).toBe('critical');

      const found = await library.searchLibrary({
        pattern: 'reentrancy',
        keyword: 'Test reentrancy',
      });

      const byId = found.find(e => e.id === entry.id);
      expect(byId).toBeDefined();
    });
  });
});
