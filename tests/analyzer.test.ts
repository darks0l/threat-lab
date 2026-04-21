import { describe, it, expect, vi } from 'vitest';
import { analyzeThreat } from '../src/analyzer.js';

describe('analyzer', () => {
  describe('detectPatternBySignature (via analyzeThreat)', () => {
    it('detects reentrancy in vulnerable contract code', async () => {
      const code = `
        function withdraw(uint amount) external {
          require(balances[msg.sender] >= amount);
          (bool s,) = msg.sender.call{value: amount}("");
          require(s);
          balances[msg.sender] -= amount;
        }
      `;
      // Without BANKR_API_KEY, falls back to signature detection
      const report = await analyzeThreat({
        scenarioId: 'test-reentrancy',
        scenarioName: 'Reentrancy Test',
        scenarioDesc: 'Test reentrancy detection',
        contractCode: code,
      });
      expect(report.attackPattern).toBe('reentrancy');
      expect(report.confidence).toBeGreaterThan(0);
      expect(report.findings.length).toBeGreaterThan(0);
    });

    it('detects oracle manipulation in code', async () => {
      const code = `
        function getPrice() external returns (uint256) {
          (uint256 r0, uint256 r1,) = IUniswapV2Pair(pair).getReserves();
          price = (r1 * 1e18) / r0;
          return price;
        }
      `;
      const report = await analyzeThreat({
        scenarioId: 'test-oracle',
        scenarioName: 'Oracle Test',
        scenarioDesc: 'Test oracle detection',
        contractCode: code,
      });
      expect(report.attackPattern).toBe('oracle-manipulation');
    });

    it('detects flash loan attack in code', async () => {
      const code = `
        function executeAttack() external {
          IFlashLoanLender lender = IFlashLoanLender(VAULT);
          lender.flashLoan(address(this), tokens, amounts, "");
        }
      `;
      const report = await analyzeThreat({
        scenarioId: 'test-flash',
        scenarioName: 'Flash Loan Test',
        scenarioDesc: 'Test flash loan detection',
        contractCode: code,
      });
      expect(report.attackPattern).toBe('flash-loan-attack');
    });

    it('detects access control issues', async () => {
      const code = `
        contract Vuln {
          function adminAction() external {
            // No onlyOwner modifier — anyone can call
            treasury.transfer(msg.sender, amount);
          }
        }
      `;
      const report = await analyzeThreat({
        scenarioId: 'test-access',
        scenarioName: 'Access Control Test',
        scenarioDesc: 'Test access control detection',
        contractCode: code,
      });
      expect(report.attackPattern).toBe('access-control');
    });

    it('returns unknown for benign code', async () => {
      const code = `
        contract SimpleStorage {
          uint256 public value;
          function set(uint256 v) external { value = v; }
          function get() external view returns (uint256) { return value; }
        }
      `;
      const report = await analyzeThreat({
        scenarioId: 'test-benign',
        scenarioName: 'Benign Test',
        scenarioDesc: 'No vulnerability here',
        contractCode: code,
      });
      expect(report.attackPattern).toBe('unknown');
      expect(report.severity).toBe('medium'); // unknown defaults to medium
    });

    it('generates a valid report structure', async () => {
      const report = await analyzeThreat({
        scenarioId: 'test-structure',
        scenarioName: 'Structure Test',
        scenarioDesc: 'Test report structure',
        contractCode: 'contract X {}',
      });
      expect(report.reportId).toBeDefined();
      expect(report.scenarioId).toBe('test-structure');
      expect(report.severity).toBeDefined();
      expect(report.summary).toBeDefined();
      expect(report.findings).toBeInstanceOf(Array);
      expect(report.recommendations).toBeInstanceOf(Array);
      expect(report.createdAt).toBeDefined();
    });

    it('includes recommendations even without AI', async () => {
      const report = await analyzeThreat({
        scenarioId: 'test-recs',
        scenarioName: 'Recs Test',
        scenarioDesc: 'Test recommendations',
        contractCode: 'function withdraw() external { msg.sender.call{value: 1}(""); }',
      });
      expect(report.recommendations.length).toBeGreaterThan(0);
    });
  });
});