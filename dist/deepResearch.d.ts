/**
 * Threat Lab - Deep Research via modelab
 *
 * When a finding is flagged (static/deps/sim), this module can be invoked
 * to run the finding through modelab's iterative multi-model research
 * pipeline for:
 *
 * 1. Root cause analysis - multi-model perspective on the vulnerability
 * 2. Impact assessment - how severe is this really?
 * 3. Patch generation - concrete, validated fix proposals
 * 4. Exploit scenario - how would an attacker actually use this?
 *
 * Usage: threat-lab scan . --deep
 *
 * Requires BANKR_API_KEY (for the underlying LLM calls).
 * modelab routes requests through the Bankr LLM gateway.
 */
export interface DeepResearchFinding {
    category: 'static' | 'deps' | 'sim';
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    title: string;
    description: string;
    packageName?: string;
    contractFile?: string;
    evidence?: string;
}
export interface DeepResearchResult {
    finding: DeepResearchFinding;
    rootCause: string;
    impactAssessment: string;
    exploitScenario: string;
    proposedFix: PatchFix | null;
    modelsUsed: string[];
    totalCost: number;
    durationMs: number;
}
export interface PatchFix {
    title: string;
    description: string;
    code: string;
    diff: string;
    confidence: number;
    validation: string;
    references: string[];
}
export interface DeepResearchOptions {
    finding: DeepResearchFinding;
    contractCode?: string;
    models?: string[];
}
export declare function runDeepResearch(options: DeepResearchOptions): Promise<DeepResearchResult>;
export interface DeepResearchBatchOptions {
    findings: DeepResearchFinding[];
    contractCode?: string;
    models?: string[];
    maxFindings?: number;
}
export declare function runDeepResearchBatch(options: DeepResearchBatchOptions): Promise<DeepResearchResult[]>;
export declare function formatDeepResearchReport(results: DeepResearchResult[]): string;
//# sourceMappingURL=deepResearch.d.ts.map