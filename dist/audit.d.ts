/**
 * Threat Lab — Dependency Audit Engine
 *
 * Scans npm projects for:
 * - Known vulnerabilities (npm audit --json)
 * - Malicious packages (Socket.dev API)
 * - Suspicious patterns (postinstall scripts, typo-squats, etc.)
 * - Supply chain risk indicators
 */
import type { AuditResult } from './auditSchemas.js';
export interface AuditOptions {
    projectPath: string;
    includeDev?: boolean;
    socketDev?: boolean;
    socketDevKey?: string;
    runNpmAudit?: boolean;
}
/**
 * Run a full dependency audit on a project.
 * Checks npm vulnerabilities, Socket.dev for malicious packages,
 * and detects suspicious supply chain patterns.
 */
export declare function auditDependencies(options: AuditOptions): Promise<AuditResult>;
//# sourceMappingURL=audit.d.ts.map