import { z } from 'zod';

// ── Audit Result Schemas ─────────────────────────────────────────────────────

export const VulnerabilitySeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type VulnerabilitySeverity = z.infer<typeof VulnerabilitySeveritySchema>;

export const AdvisorySchema = z.object({
  id: z.number(),
  module_name: z.string(),
  severity: z.string(),
  title: z.string(),
  url: z.string().optional(),
  findings: z.array(z.object({
    version: z.string(),
    isTransitive: z.boolean().optional(),
  })).optional(),
});
export type Advisory = z.infer<typeof AdvisorySchema>;

export const NpmAuditSummarySchema = z.object({
  info: z.number(),
  low: z.number(),
  moderate: z.number(),
  high: z.number(),
  critical: z.number(),
});
export type NpmAuditSummary = z.infer<typeof NpmAuditSummarySchema>;

export const NpmAuditResultSchema = z.object({
  auditReportVersion: z.string(),
  vulnerabilities: z.record(AdvisorySchema),
  metadata: z.object({
    vulnerabilities: NpmAuditSummarySchema,
    dependencies: z.number(),
    devDependencies: z.number(),
    optionalDependencies: z.number(),
    totalDependencies: z.number(),
  }),
});
export type NpmAuditResult = z.infer<typeof NpmAuditResultSchema>;

// ── Socket.dev Schemas ────────────────────────────────────────────────────────

export const SocketAnalysisSchema = z.object({
  name: z.string(),
  version: z.string(),
  hasMaliciousCode: z.boolean(),
  isArchived: z.boolean(),
  description: z.string().optional(),
  publishers: z.array(z.object({
    userId: z.string(),
    username: z.string(),
    email: z.string().optional(),
  })).optional(),
  score: z.object({
    total: z.number().optional(),
    的危险: z.number().optional(), // "risk" in Chinese, API may vary
  }).optional(),
  additionalInfo: z.object({
    installedVersion: z.string().optional(),
    latestVersion: z.string().optional(),
    highImpactFolder: z.boolean().optional(),
    hasInstallScripts: z.boolean().optional(),
    hasNoPackageJSON: z.boolean().optional(),
    hasLargeExpandos: z.boolean().optional(),
    hasTypoSquats: z.boolean().optional(),
    hasDependencyConfusion: z.boolean().optional(),
    hasSandboxEscapes: z.boolean().optional(),
    hasNativeSnippets: z.boolean().optional(),
    shellCompletionFile: z.boolean().optional(),
    hasTelemetryScript: z.boolean().optional(),
  }).optional(),
  issues: z.array(z.object({
    type: z.string(),
    severity: z.string(),
    message: z.string(),
    handle: z.string().optional(),
  })).optional(),
});
export type SocketAnalysis = z.infer<typeof SocketAnalysisSchema>;

// ── Suspicious Pattern Detection ─────────────────────────────────────────────

export const SuspiciousPatternSchema = z.object({
  type: z.enum(['postinstall-exec', 'recently-published', 'large-filesystem-access', 'external-url-fetch', 'typo-squat', 'dependency-confusion', 'native-code', 'suspicious-publisher', 'high-risk-install', 'no-readme', 'sandbox-escape', 'telemetry']),
  severity: VulnerabilitySeveritySchema,
  packageName: z.string(),
  description: z.string(),
  evidence: z.string().optional(),
  recommendation: z.string(),
});
export type SuspiciousPattern = z.infer<typeof SuspiciousPatternSchema>;

// ── Combined Audit Result ─────────────────────────────────────────────────────

export const AuditVulnerabilitySchema = z.object({
  id: z.number(),
  moduleName: z.string(),
  severity: VulnerabilitySeveritySchema,
  title: z.string(),
  url: z.string().optional(),
  affectedVersions: z.array(z.string()),
  isTransitive: z.boolean(),
  via: z.string().optional(),
});
export type AuditVulnerability = z.infer<typeof AuditVulnerabilitySchema>;

export const DependencyAuditResultSchema = z.object({
  packageName: z.string(),
  packageVersion: z.string(),
  severity: VulnerabilitySeveritySchema,
  title: z.string(),
  url: z.string().optional(),
  via: z.string().optional(),
});
export type DependencyAuditResult = z.infer<typeof DependencyAuditResultSchema>;

// ── OSINT / Web Search Schemas ────────────────────────────────────────────────

export const OsintFindingSchema = z.object({
  packageName: z.string(),
  packageVersion: z.string(),
  severity: VulnerabilitySeveritySchema,
  title: z.string(),
  description: z.string().optional(),
  publishedDate: z.string().optional(),
  permalink: z.string().optional(),
  references: z.array(z.string()).default([]),
  isActive: z.boolean().default(false),
});
export type OsintFinding = z.infer<typeof OsintFindingSchema>;

export const OsintResultSchema = z.object({
  checkedPackages: z.number(),
  findings: z.array(OsintFindingSchema),
  activeExploits: z.array(z.object({
    packageName: z.string(),
    title: z.string(),
    severity: VulnerabilitySeveritySchema,
    permalink: z.string(),
  })),
});
export type OsintResult = z.infer<typeof OsintResultSchema>;

// ── Audit Result ─────────────────────────────────────────────────────────────

export const AuditResultSchema = z.object({
  projectPath: z.string(),
  auditPerformedAt: z.string(),
  npmAudit: z.object({
    version: z.string(),
    totalVulnerabilities: z.number(),
    breakdown: z.object({
      critical: z.number(),
      high: z.number(),
      medium: z.number(),
      low: z.number(),
      info: z.number(),
    }),
    vulnerabilities: z.array(AuditVulnerabilitySchema),
  }).nullable(),
  socketDev: z.object({
    checkedPackages: z.number(),
    maliciousDetections: z.array(z.object({
      packageName: z.string(),
      version: z.string(),
      description: z.string().optional(),
    })),
    highRiskPackages: z.array(z.object({
      packageName: z.string(),
      version: z.string(),
      riskTypes: z.array(z.string()),
      description: z.string(),
    })),
  }).nullable(),
  osint: z.object({
    checkedPackages: z.number(),
    findings: z.array(OsintFindingSchema),
    activeExploits: z.array(z.object({
      packageName: z.string(),
      title: z.string(),
      severity: VulnerabilitySeveritySchema,
      permalink: z.string(),
    })),
  }).nullable(),
  suspiciousPatterns: z.array(SuspiciousPatternSchema),
  npmAuditErrors: z.array(z.string()).default([]),
  dependencyCount: z.object({
    total: z.number(),
    dev: z.number(),
    optional: z.number(),
  }),
  summary: z.object({
    threatLevel: z.enum(['critical', 'high', 'medium', 'low', 'safe']),
    score: z.number().min(0).max(100),
    vulnerablePackages: z.number(),
    suspiciousPackages: z.number(),
    totalFlags: z.number(),
    criticalActions: z.array(z.string()),
  }),
});
export type AuditResult = z.infer<typeof AuditResultSchema>;
