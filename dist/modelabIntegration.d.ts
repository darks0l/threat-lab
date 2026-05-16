/**
 * Modelab Integration — multi-model AI analysis of exploit traces.
 * Routes each scenario through modelab's research orchestrator for
 * multi-model analysis, quality scoring, and structured threat reports.
 *
 * Falls back to direct LLM calls if modelab is unavailable.
 */
import type { ThreatReport } from './schemas.js';
export interface ModelabAnalysisResult {
    model: string;
    report: ThreatReport;
    rawResponse: string;
    durationMs: number;
}
export interface AnalyzeWithModelabOptions {
    scenarioId: string;
    scenarioName: string;
    txTraces: string[];
    contractCode: string;
    models?: string[];
    minConfidence?: number;
    chainId?: number;
}
export declare function analyzeWithModelab(options: AnalyzeWithModelabOptions): Promise<ModelabAnalysisResult[]>;
export declare function getBestAnalysis(results: ModelabAnalysisResult[]): ModelabAnalysisResult;
//# sourceMappingURL=modelabIntegration.d.ts.map