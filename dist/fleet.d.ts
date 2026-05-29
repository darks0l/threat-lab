import { type ScanResult } from './scanner.js';
import { type ThreatIntelResult } from './threatIntel.js';
import type { Severity } from './schemas.js';
export interface FleetRepo {
    id: string;
    path: string;
    label: string;
    addedAt: string;
    lastScannedAt?: string;
}
export interface RepoDependency {
    name: string;
    version: string;
    kind: 'dependencies' | 'devDependencies' | 'optionalDependencies';
}
export interface RepoScanSummary {
    repo: FleetRepo;
    packages: RepoDependency[];
    solidityFileCount: number;
    scanResults: ScanResult[];
    dependencyThreatLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
    dependencyScore: number;
    threatIntel: ThreatIntelResult[];
    overallSeverity: Severity;
    threatScore: number;
    activeThreatCount: number;
    correlatedThreatCount: number;
    advisoriesCount: number;
    vulnerabilitiesCount: number;
    scannedAt: string;
    errors: string[];
}
export interface FleetExposure {
    packageName: string;
    repoCount: number;
    repos: Array<{
        label: string;
        path: string;
        version: string;
        kind: RepoDependency['kind'];
    }>;
}
export interface ThreatStateItem {
    id: string;
    key: string;
    packageName: string;
    title: string;
    url: string;
    severity: Severity;
    activeExploit: boolean;
    correlated: boolean;
    firstSeen: string;
    lastSeen: string;
    repos: string[];
    repoLabels: string[];
    sightings: number;
}
export interface ThreatStateDelta {
    newItems: ThreatStateItem[];
    escalatedItems: ThreatStateItem[];
    totalTracked: number;
}
export interface FleetScanSummary {
    scannedAt: string;
    repoCount: number;
    repos: RepoScanSummary[];
    exposures: FleetExposure[];
    threatDelta: ThreatStateDelta;
}
export interface FleetScanOptions {
    cwd?: string;
    targets?: string[];
    quick?: boolean;
    noDeps?: boolean;
    noIntel?: boolean;
    noSim?: boolean;
    network?: string;
    outputPath?: string;
}
export declare function addFleetRepos(paths: string[], cwd?: string): Promise<FleetRepo[]>;
export declare function listFleetRepos(cwd?: string): Promise<FleetRepo[]>;
export declare function scanFleet(options?: FleetScanOptions): Promise<FleetScanSummary>;
export declare function formatFleetSummary(summary: FleetScanSummary): string;
//# sourceMappingURL=fleet.d.ts.map