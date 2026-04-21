import { describe, it, expect } from 'vitest';
import { getScenario, listScenarios } from '../src/scenarios.js';

describe('scenarios', () => {
  describe('listScenarios', () => {
    it('returns at least 6 scenarios', () => {
      const scenarios = listScenarios();
      expect(scenarios.length).toBeGreaterThanOrEqual(6);
    });

    it('each scenario has required fields', () => {
      const scenarios = listScenarios();
      for (const s of scenarios) {
        expect(s.id).toBeDefined();
        expect(s.name).toBeDefined();
        expect(s.description).toBeDefined();
        expect(s.pattern).toBeDefined();
        expect(s.severity).toBeDefined();
        expect(s.exploitSteps).toBeInstanceOf(Array);
        expect(s.exploitSteps.length).toBeGreaterThan(0);
        expect(s.expectedOutcome).toBeDefined();
        expect(s.difficulty).toBeDefined();
        expect(s.createdAt).toBeDefined();
      }
    });

    it('each step has required fields', () => {
      const scenarios = listScenarios();
      for (const s of scenarios) {
        for (const step of s.exploitSteps) {
          expect(step.step).toBeGreaterThan(0);
          expect(step.action).toBeDefined();
          expect(step.description).toBeDefined();
          // Valid actions
          expect(['deploy', 'call', 'send', 'flash-loan', 'swap', 'manipulate', 'fund', 'log']).toContain(step.action);
        }
      }
    });

    it('includes all expected scenario IDs', () => {
      const ids = listScenarios().map(s => s.id);
      expect(ids).toContain('reentrancy-101');
      expect(ids).toContain('oracle-manipulation-101');
      expect(ids).toContain('flash-loan-101');
      expect(ids).toContain('sandwich-attack-101');
      expect(ids).toContain('governance-attack-101');
      expect(ids).toContain('liquidation-attack-101');
    });
  });

  describe('getScenario', () => {
    it('returns scenario by ID', () => {
      const s = getScenario('reentrancy-101');
      expect(s).toBeDefined();
      expect(s?.name).toContain('Reentrancy');
    });

    it('returns undefined for unknown ID', () => {
      const s = getScenario('nonexistent-999');
      expect(s).toBeUndefined();
    });
  });
});