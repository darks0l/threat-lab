/**
 * Threat Lab — Live Threat Intelligence
 *
 * Layer 2b of the unified scan: after checking static vulnerability databases,
 * this module does live web searches to catch:
 * - 0-days not yet in CVE/OSV databases
 * - Active discussions on X/Twitter
 * - GitHub Security Advisories published recently
 * - Security blog posts about recent discoveries
 *
 * Uses Brave Search API + GitHub Security Advisories API.
 * Requires BRAVE_SEARCH_API_KEY environment variable.
 */
export interface ThreatIntelResult {
    packageName: string;
    packageVersion: string;
    searches: SearchResult[];
    overallSeverity: 'critical' | 'high' | 'medium' | 'low' | 'none';
    hasActiveExploit: boolean;
    summary: string;
    recommendations: string[];
}
export interface SearchResult {
    source: 'twitter' | 'github-advisory' | 'security-blog' | 'general';
    query: string;
    resultCount: number;
    findings: WebFinding[];
    freshestDate: string | null;
}
export interface WebFinding {
    title: string;
    url: string;
    date: string | null;
    snippet: string;
    source: string;
    isAlert: boolean;
}
export interface ThreatIntelOptions {
    packages: Array<{
        name: string;
        version: string;
    }>;
    braveApiKey?: string;
    ghToken?: string;
    daysLookback?: number;
}
/**
 * For each package, run live searches across multiple sources.
 * Returns per-package threat intelligence results.
 */
export declare function runThreatIntel(options: ThreatIntelOptions): Promise<ThreatIntelResult[]>;
//# sourceMappingURL=threatIntel.d.ts.map