/**
 * Submission API endpoint — receives findings JSON, validates, and stores.
 * In MVP: just validates and logs. Can be extended to store to DB/IPFS.
 */
export interface SubmitResult {
    success: boolean;
    submissionId?: string;
    reportId?: string;
    score?: number;
    error?: string;
    findings?: string[];
}
/**
 * Receive and process a threat finding submission.
 * Validates → analyzes with AI → scores → stores.
 */
export declare function submitFinding(payload: unknown, library?: {
    reportId: string;
    attackPattern: string;
    summary: string;
    confidence: number;
}[]): Promise<SubmitResult>;
/**
 * Submit findings from the CLI — takes a submission JSON file path.
 */
export declare function submitFromFile(filePath: string): Promise<SubmitResult>;
//# sourceMappingURL=api.d.ts.map