/**
 * Threat Lab Runner — full orchestrator.
 * execute() → analyze() → library() → report
 */
import { addToLibrary } from './library.js';
import type { ExecutionResult } from './executor.js';
import type { ModelabAnalysisResult } from './modelabIntegration.js';
export interface RunResult {
    success: boolean;
    scenarioId: string;
    executionResult?: ExecutionResult;
    analysisResults?: ModelabAnalysisResult[];
    libraryEntry?: Awaited<ReturnType<typeof addToLibrary>>;
    error?: string;
}
/**
 * Full threat lab run: execute → analyze → add to library.
 */
export declare function runThreatLab(scenarioId: string, options?: {
    network?: string;
    models?: string[];
    submitToLibrary?: boolean;
    submittedBy?: string;
}): Promise<RunResult>;
//# sourceMappingURL=runner.d.ts.map