/**
 * Pattern Library — persistent, IPFS-ready storage for threat findings.
 * The library grows smarter with every submission.
 */
import type { ThreatReport, AttackPattern } from './schemas.js';
export interface LibraryEntry {
    id: string;
    reportId: string;
    scenarioId: string;
    scenarioName: string;
    attackPattern: AttackPattern;
    severity: string;
    summary: string;
    findings: Array<{
        title: string;
        description: string;
        evidence: string;
    }>;
    recommendations: string[];
    confidence: number;
    submittedBy?: string;
    submittedAt: string;
    txHashes: string[];
    chainId: number;
    ipfsCid?: string;
    viewCount: number;
    citationCount: number;
}
/**
 * Add a new submission to the pattern library.
 */
export declare function addToLibrary(report: ThreatReport, metadata: {
    submittedBy?: string;
    txHashes?: string[];
    chainId?: number;
}): Promise<LibraryEntry>;
/**
 * Search the library by pattern, severity, or keyword.
 */
export declare function searchLibrary(query: {
    pattern?: AttackPattern;
    severity?: string;
    keyword?: string;
    minConfidence?: number;
    limit?: number;
}): Promise<LibraryEntry[]>;
/**
 * Get similar entries from the library based on attack pattern.
 */
export declare function findSimilar(pattern: AttackPattern, limit?: number): Promise<LibraryEntry[]>;
/**
 * Get the full library stats.
 */
export declare function getLibraryStats(): Promise<{
    totalEntries: number;
    byPattern: Record<string, number>;
    bySeverity: Record<string, number>;
    avgConfidence: number;
    newestEntry: string | null;
}>;
/**
 * Get all unique attack patterns in the library.
 */
export declare function getPatternCounts(): Promise<Record<AttackPattern, number>>;
/**
 * Get the full list of all entries.
 */
export declare function getLibrary(): Promise<LibraryEntry[]>;
/**
 * Increment the view count for an entry.
 */
export declare function trackView(id: string): Promise<void>;
/**
 * Export the full library as a single JSON blob (IPFS-ready).
 */
export declare function exportLibrary(): Promise<string>;
/**
 * Import entries from a previous export.
 */
export declare function importLibrary(jsonData: string): Promise<number>;
//# sourceMappingURL=library.d.ts.map