/**
 * AI-powered threat analysis engine.
 * Sends exploit traces to Bankr gateway for LLM analysis,
 * returns structured threat reports.
 */
import type { ThreatReport } from './schemas.js';
export interface AnalysisInput {
    scenarioId: string;
    scenarioName: string;
    scenarioDesc: string;
    txTrace?: string;
    contractCode: string;
    chainId?: number;
    model?: string;
}
/**
 * Analyze contract code or transaction trace using Bankr LLM gateway.
 * Falls back to signature-based detection if LLM unavailable.
 */
export declare function analyzeThreat(input: AnalysisInput): Promise<ThreatReport>;
//# sourceMappingURL=analyzer.d.ts.map