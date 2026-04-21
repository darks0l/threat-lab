/**
 * Threat Lab Runner — full orchestrator.
 * execute() → analyze() → library() → report
 */

import { executeScenario, isAnvilRunning } from './executor.js';
import { analyzeWithModelab, getBestAnalysis } from './modelabIntegration.js';
import { addToLibrary, getLibraryStats, searchLibrary } from './library.js';
import { getScenario } from './scenarios.js';
import type { ExecutionResult } from './executor.js';
import type { ThreatReport } from './schemas.js';
import type { ModelabAnalysisResult } from './modelabIntegration.js';

export interface RunResult {
  success: boolean;
  scenarioId: string;
  executionResult?: ExecutionResult;
  analysisResults?: ModelabAnalysisResult[];
  libraryEntry?: Awaited<ReturnType<typeof addToLibrary>>;
  error?: string;
}

const CONTRACT_CODE_MAP: Record<string, string> = {
  'ReentrancyVault': `
contract ReentrancyVault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}`,
  'OracleManipulation': `
contract OracleManipulation {
    address public pair;
    uint256 public price;
    function getPrice() external returns (uint256) {
        (uint256 r0, uint256 r1,) = IUniswapV2Pair(pair).getReserves();
        price = (r1 * 1e18) / r0;
        return price;
    }
}`,
  'FlashLoanAttacker': `
contract FlashLoanAttacker {
    function executeAttack(AttackParams calldata params) external {
        IFlashLoanLender lender = IFlashLoanLender(0xBA12222222228d8Ba445958a90aD4EeFC7D8cE2A);
        lender.flashLoan(address(this), tokens, amounts, "");
    }
    receive() external payable {}
}`,
};

const DEFAULT_CONTRACT_CODE = `
contract VulnerableContract {
    // Generic vulnerable pattern
    function vulnerable() external {
        // External call before state update — classic reentrancy
        (bool s,) = msg.sender.call{value: 0}("");
        require(s);
        // State never updated — exploit possible
    }
}
`;

/**
 * Full threat lab run: execute → analyze → add to library.
 */
export async function runThreatLab(
  scenarioId: string,
  options: {
    network?: string;
    models?: string[];
    submitToLibrary?: boolean;
    submittedBy?: string;
  } = {},
): Promise<RunResult> {
  const {
    network = 'anvil',
    models = ['claude-sonnet-4-6'],
    submitToLibrary = true,
    submittedBy,
  } = options;

  console.log(`\n${'='.repeat(60)}`);
  console.log(`🔬 THREAT LAB — Full Analysis Run`);
  console.log(`${'='.repeat(60)}`);
  console.log(`   Scenario: ${scenarioId}`);
  console.log(`   Network: ${network}`);
  console.log(`   Models: ${models.join(', ')}`);
  console.log(`   Library: ${submitToLibrary ? 'enabled' : 'disabled'}`);
  console.log('');

  // 1. Load scenario
  const scenario = getScenario(scenarioId);
  if (!scenario) {
    return { success: false, scenarioId, error: `Unknown scenario: ${scenarioId}` };
  }

  // 2. Check Anvil
  if (network === 'anvil') {
    const running = await isAnvilRunning();
    if (!running) {
      return {
        success: false,
        scenarioId,
        error: 'Anvil is not running. Start it with: anvil OR foundry node',
      };
    }
  }

  // 3. Execute the scenario
  let executionResult: ExecutionResult;
  try {
    executionResult = await executeScenario(scenario, { network });
    console.log(`\n📊 Execution complete:`);
    console.log(`   Steps: ${executionResult.steps.length}`);
    console.log(`   Txs: ${executionResult.allTxHashes.length}`);
    console.log(`   Duration: ${(executionResult.durationMs / 1000).toFixed(2)}s`);
  } catch (err) {
    return {
      success: false,
      scenarioId,
      error: `Execution failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  // 4. Get traces for analysis
  const traces = executionResult.allTxHashes.map(hash =>
    `tx: ${hash} | block: ${executionResult.startBlock}-${executionResult.endBlock}`
  );

  // 5. Run AI analysis
  const contractCode = CONTRACT_CODE_MAP[scenario.templateContract ?? ''] ?? DEFAULT_CONTRACT_CODE;
  let analysisResults: Awaited<ReturnType<typeof analyzeWithModelab>> = [];
  let bestReport: ThreatReport | null = null;

  try {
    analysisResults = await analyzeWithModelab({
      scenarioId,
      scenarioName: scenario.name,
      txTraces: traces,
      contractCode,
      models,
    });

    if (analysisResults.length > 0) {
      const best = getBestAnalysis(analysisResults);
      bestReport = best.report;
      console.log(`\n🏆 Best analysis: ${best.model} — ${bestReport.attackPattern} (${(bestReport.confidence * 100).toFixed(0)}% conf)`);
    }
  } catch (err) {
    console.warn(`\n⚠️  Analysis failed: ${err instanceof Error ? err.message : err}`);
    // Still add to library even if analysis failed
  }

  // 6. Add to library
  if (submitToLibrary && bestReport) {
    try {
      const entry = await addToLibrary(bestReport, {
        submittedBy,
        txHashes: executionResult.allTxHashes,
        chainId: executionResult.network === 'anvil' ? 31337 : 84532,
      });
      console.log(`\n📚 Library updated with ${entry.id}`);
    } catch (err) {
      console.warn(`⚠️  Library update failed: ${err}`);
    }
  }

  // 7. Print final report
  if (bestReport) {
    printReport(bestReport, scenario.name);
  }

  return {
    success: true,
    scenarioId,
    executionResult,
    analysisResults,
    libraryEntry: undefined,
  };
}

function printReport(report: ThreatReport, scenarioName: string): void {
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`📋 THREAT REPORT — ${scenarioName}`);
  console.log(`${'─'.repeat(60)}`);
  console.log(`   Pattern:   ${report.attackPattern}`);
  console.log(`   Severity:  ${report.severity}`);
  console.log(`   Confidence: ${(report.confidence * 100).toFixed(0)}%`);
  console.log(`   AI Model:  ${report.aiModel}`);
  console.log('');
  console.log(`   Summary:`);
  console.log(`   ${report.summary.slice(0, 200)}`);
  if (report.recommendations.length > 0) {
    console.log('');
    console.log(`   Recommendations:`);
    for (const rec of report.recommendations.slice(0, 3)) {
      console.log(`   - ${rec}`);
    }
  }
  console.log(`${'─'.repeat(60)}\n`);
}
