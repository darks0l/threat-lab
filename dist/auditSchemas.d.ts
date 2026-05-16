import { z } from 'zod';
export declare const VulnerabilitySeveritySchema: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
export type VulnerabilitySeverity = z.infer<typeof VulnerabilitySeveritySchema>;
export declare const AdvisorySchema: z.ZodObject<{
    id: z.ZodNumber;
    module_name: z.ZodString;
    severity: z.ZodString;
    title: z.ZodString;
    url: z.ZodOptional<z.ZodString>;
    findings: z.ZodOptional<z.ZodArray<z.ZodObject<{
        version: z.ZodString;
        isTransitive: z.ZodOptional<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        version: string;
        isTransitive?: boolean | undefined;
    }, {
        version: string;
        isTransitive?: boolean | undefined;
    }>, "many">>;
}, "strip", z.ZodTypeAny, {
    id: number;
    severity: string;
    title: string;
    module_name: string;
    findings?: {
        version: string;
        isTransitive?: boolean | undefined;
    }[] | undefined;
    url?: string | undefined;
}, {
    id: number;
    severity: string;
    title: string;
    module_name: string;
    findings?: {
        version: string;
        isTransitive?: boolean | undefined;
    }[] | undefined;
    url?: string | undefined;
}>;
export type Advisory = z.infer<typeof AdvisorySchema>;
export declare const NpmAuditSummarySchema: z.ZodObject<{
    info: z.ZodNumber;
    low: z.ZodNumber;
    moderate: z.ZodNumber;
    high: z.ZodNumber;
    critical: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    critical: number;
    high: number;
    low: number;
    info: number;
    moderate: number;
}, {
    critical: number;
    high: number;
    low: number;
    info: number;
    moderate: number;
}>;
export type NpmAuditSummary = z.infer<typeof NpmAuditSummarySchema>;
export declare const NpmAuditResultSchema: z.ZodObject<{
    auditReportVersion: z.ZodString;
    vulnerabilities: z.ZodRecord<z.ZodString, z.ZodObject<{
        id: z.ZodNumber;
        module_name: z.ZodString;
        severity: z.ZodString;
        title: z.ZodString;
        url: z.ZodOptional<z.ZodString>;
        findings: z.ZodOptional<z.ZodArray<z.ZodObject<{
            version: z.ZodString;
            isTransitive: z.ZodOptional<z.ZodBoolean>;
        }, "strip", z.ZodTypeAny, {
            version: string;
            isTransitive?: boolean | undefined;
        }, {
            version: string;
            isTransitive?: boolean | undefined;
        }>, "many">>;
    }, "strip", z.ZodTypeAny, {
        id: number;
        severity: string;
        title: string;
        module_name: string;
        findings?: {
            version: string;
            isTransitive?: boolean | undefined;
        }[] | undefined;
        url?: string | undefined;
    }, {
        id: number;
        severity: string;
        title: string;
        module_name: string;
        findings?: {
            version: string;
            isTransitive?: boolean | undefined;
        }[] | undefined;
        url?: string | undefined;
    }>>;
    metadata: z.ZodObject<{
        vulnerabilities: z.ZodObject<{
            info: z.ZodNumber;
            low: z.ZodNumber;
            moderate: z.ZodNumber;
            high: z.ZodNumber;
            critical: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            critical: number;
            high: number;
            low: number;
            info: number;
            moderate: number;
        }, {
            critical: number;
            high: number;
            low: number;
            info: number;
            moderate: number;
        }>;
        dependencies: z.ZodNumber;
        devDependencies: z.ZodNumber;
        optionalDependencies: z.ZodNumber;
        totalDependencies: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        vulnerabilities: {
            critical: number;
            high: number;
            low: number;
            info: number;
            moderate: number;
        };
        dependencies: number;
        devDependencies: number;
        optionalDependencies: number;
        totalDependencies: number;
    }, {
        vulnerabilities: {
            critical: number;
            high: number;
            low: number;
            info: number;
            moderate: number;
        };
        dependencies: number;
        devDependencies: number;
        optionalDependencies: number;
        totalDependencies: number;
    }>;
}, "strip", z.ZodTypeAny, {
    auditReportVersion: string;
    vulnerabilities: Record<string, {
        id: number;
        severity: string;
        title: string;
        module_name: string;
        findings?: {
            version: string;
            isTransitive?: boolean | undefined;
        }[] | undefined;
        url?: string | undefined;
    }>;
    metadata: {
        vulnerabilities: {
            critical: number;
            high: number;
            low: number;
            info: number;
            moderate: number;
        };
        dependencies: number;
        devDependencies: number;
        optionalDependencies: number;
        totalDependencies: number;
    };
}, {
    auditReportVersion: string;
    vulnerabilities: Record<string, {
        id: number;
        severity: string;
        title: string;
        module_name: string;
        findings?: {
            version: string;
            isTransitive?: boolean | undefined;
        }[] | undefined;
        url?: string | undefined;
    }>;
    metadata: {
        vulnerabilities: {
            critical: number;
            high: number;
            low: number;
            info: number;
            moderate: number;
        };
        dependencies: number;
        devDependencies: number;
        optionalDependencies: number;
        totalDependencies: number;
    };
}>;
export type NpmAuditResult = z.infer<typeof NpmAuditResultSchema>;
export declare const SocketAnalysisSchema: z.ZodObject<{
    name: z.ZodString;
    version: z.ZodString;
    hasMaliciousCode: z.ZodBoolean;
    isArchived: z.ZodBoolean;
    description: z.ZodOptional<z.ZodString>;
    publishers: z.ZodOptional<z.ZodArray<z.ZodObject<{
        userId: z.ZodString;
        username: z.ZodString;
        email: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        userId: string;
        username: string;
        email?: string | undefined;
    }, {
        userId: string;
        username: string;
        email?: string | undefined;
    }>, "many">>;
    score: z.ZodOptional<z.ZodObject<{
        total: z.ZodOptional<z.ZodNumber>;
        的危险: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        total?: number | undefined;
        的危险?: number | undefined;
    }, {
        total?: number | undefined;
        的危险?: number | undefined;
    }>>;
    additionalInfo: z.ZodOptional<z.ZodObject<{
        installedVersion: z.ZodOptional<z.ZodString>;
        latestVersion: z.ZodOptional<z.ZodString>;
        highImpactFolder: z.ZodOptional<z.ZodBoolean>;
        hasInstallScripts: z.ZodOptional<z.ZodBoolean>;
        hasNoPackageJSON: z.ZodOptional<z.ZodBoolean>;
        hasLargeExpandos: z.ZodOptional<z.ZodBoolean>;
        hasTypoSquats: z.ZodOptional<z.ZodBoolean>;
        hasDependencyConfusion: z.ZodOptional<z.ZodBoolean>;
        hasSandboxEscapes: z.ZodOptional<z.ZodBoolean>;
        hasNativeSnippets: z.ZodOptional<z.ZodBoolean>;
        shellCompletionFile: z.ZodOptional<z.ZodBoolean>;
        hasTelemetryScript: z.ZodOptional<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        installedVersion?: string | undefined;
        latestVersion?: string | undefined;
        highImpactFolder?: boolean | undefined;
        hasInstallScripts?: boolean | undefined;
        hasNoPackageJSON?: boolean | undefined;
        hasLargeExpandos?: boolean | undefined;
        hasTypoSquats?: boolean | undefined;
        hasDependencyConfusion?: boolean | undefined;
        hasSandboxEscapes?: boolean | undefined;
        hasNativeSnippets?: boolean | undefined;
        shellCompletionFile?: boolean | undefined;
        hasTelemetryScript?: boolean | undefined;
    }, {
        installedVersion?: string | undefined;
        latestVersion?: string | undefined;
        highImpactFolder?: boolean | undefined;
        hasInstallScripts?: boolean | undefined;
        hasNoPackageJSON?: boolean | undefined;
        hasLargeExpandos?: boolean | undefined;
        hasTypoSquats?: boolean | undefined;
        hasDependencyConfusion?: boolean | undefined;
        hasSandboxEscapes?: boolean | undefined;
        hasNativeSnippets?: boolean | undefined;
        shellCompletionFile?: boolean | undefined;
        hasTelemetryScript?: boolean | undefined;
    }>>;
    issues: z.ZodOptional<z.ZodArray<z.ZodObject<{
        type: z.ZodString;
        severity: z.ZodString;
        message: z.ZodString;
        handle: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        message: string;
        type: string;
        severity: string;
        handle?: string | undefined;
    }, {
        message: string;
        type: string;
        severity: string;
        handle?: string | undefined;
    }>, "many">>;
}, "strip", z.ZodTypeAny, {
    name: string;
    version: string;
    hasMaliciousCode: boolean;
    isArchived: boolean;
    issues?: {
        message: string;
        type: string;
        severity: string;
        handle?: string | undefined;
    }[] | undefined;
    description?: string | undefined;
    score?: {
        total?: number | undefined;
        的危险?: number | undefined;
    } | undefined;
    publishers?: {
        userId: string;
        username: string;
        email?: string | undefined;
    }[] | undefined;
    additionalInfo?: {
        installedVersion?: string | undefined;
        latestVersion?: string | undefined;
        highImpactFolder?: boolean | undefined;
        hasInstallScripts?: boolean | undefined;
        hasNoPackageJSON?: boolean | undefined;
        hasLargeExpandos?: boolean | undefined;
        hasTypoSquats?: boolean | undefined;
        hasDependencyConfusion?: boolean | undefined;
        hasSandboxEscapes?: boolean | undefined;
        hasNativeSnippets?: boolean | undefined;
        shellCompletionFile?: boolean | undefined;
        hasTelemetryScript?: boolean | undefined;
    } | undefined;
}, {
    name: string;
    version: string;
    hasMaliciousCode: boolean;
    isArchived: boolean;
    issues?: {
        message: string;
        type: string;
        severity: string;
        handle?: string | undefined;
    }[] | undefined;
    description?: string | undefined;
    score?: {
        total?: number | undefined;
        的危险?: number | undefined;
    } | undefined;
    publishers?: {
        userId: string;
        username: string;
        email?: string | undefined;
    }[] | undefined;
    additionalInfo?: {
        installedVersion?: string | undefined;
        latestVersion?: string | undefined;
        highImpactFolder?: boolean | undefined;
        hasInstallScripts?: boolean | undefined;
        hasNoPackageJSON?: boolean | undefined;
        hasLargeExpandos?: boolean | undefined;
        hasTypoSquats?: boolean | undefined;
        hasDependencyConfusion?: boolean | undefined;
        hasSandboxEscapes?: boolean | undefined;
        hasNativeSnippets?: boolean | undefined;
        shellCompletionFile?: boolean | undefined;
        hasTelemetryScript?: boolean | undefined;
    } | undefined;
}>;
export type SocketAnalysis = z.infer<typeof SocketAnalysisSchema>;
export declare const SuspiciousPatternSchema: z.ZodObject<{
    type: z.ZodEnum<["postinstall-exec", "recently-published", "large-filesystem-access", "external-url-fetch", "typo-squat", "dependency-confusion", "native-code", "suspicious-publisher", "high-risk-install", "no-readme", "sandbox-escape", "telemetry"]>;
    severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
    packageName: z.ZodString;
    description: z.ZodString;
    evidence: z.ZodOptional<z.ZodString>;
    recommendation: z.ZodString;
}, "strip", z.ZodTypeAny, {
    type: "postinstall-exec" | "recently-published" | "large-filesystem-access" | "external-url-fetch" | "typo-squat" | "dependency-confusion" | "native-code" | "suspicious-publisher" | "high-risk-install" | "no-readme" | "sandbox-escape" | "telemetry";
    severity: "critical" | "high" | "medium" | "low" | "info";
    description: string;
    packageName: string;
    recommendation: string;
    evidence?: string | undefined;
}, {
    type: "postinstall-exec" | "recently-published" | "large-filesystem-access" | "external-url-fetch" | "typo-squat" | "dependency-confusion" | "native-code" | "suspicious-publisher" | "high-risk-install" | "no-readme" | "sandbox-escape" | "telemetry";
    severity: "critical" | "high" | "medium" | "low" | "info";
    description: string;
    packageName: string;
    recommendation: string;
    evidence?: string | undefined;
}>;
export type SuspiciousPattern = z.infer<typeof SuspiciousPatternSchema>;
export declare const AuditVulnerabilitySchema: z.ZodObject<{
    id: z.ZodNumber;
    moduleName: z.ZodString;
    severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
    title: z.ZodString;
    url: z.ZodOptional<z.ZodString>;
    affectedVersions: z.ZodArray<z.ZodString, "many">;
    isTransitive: z.ZodBoolean;
    via: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    id: number;
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    isTransitive: boolean;
    moduleName: string;
    affectedVersions: string[];
    url?: string | undefined;
    via?: string | undefined;
}, {
    id: number;
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    isTransitive: boolean;
    moduleName: string;
    affectedVersions: string[];
    url?: string | undefined;
    via?: string | undefined;
}>;
export type AuditVulnerability = z.infer<typeof AuditVulnerabilitySchema>;
export declare const DependencyAuditResultSchema: z.ZodObject<{
    packageName: z.ZodString;
    packageVersion: z.ZodString;
    severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
    title: z.ZodString;
    url: z.ZodOptional<z.ZodString>;
    via: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    packageName: string;
    packageVersion: string;
    url?: string | undefined;
    via?: string | undefined;
}, {
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    packageName: string;
    packageVersion: string;
    url?: string | undefined;
    via?: string | undefined;
}>;
export type DependencyAuditResult = z.infer<typeof DependencyAuditResultSchema>;
export declare const OsintFindingSchema: z.ZodObject<{
    packageName: z.ZodString;
    packageVersion: z.ZodString;
    severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
    title: z.ZodString;
    description: z.ZodOptional<z.ZodString>;
    publishedDate: z.ZodOptional<z.ZodString>;
    permalink: z.ZodOptional<z.ZodString>;
    references: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
    isActive: z.ZodDefault<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    packageName: string;
    packageVersion: string;
    references: string[];
    isActive: boolean;
    description?: string | undefined;
    publishedDate?: string | undefined;
    permalink?: string | undefined;
}, {
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    packageName: string;
    packageVersion: string;
    description?: string | undefined;
    publishedDate?: string | undefined;
    permalink?: string | undefined;
    references?: string[] | undefined;
    isActive?: boolean | undefined;
}>;
export type OsintFinding = z.infer<typeof OsintFindingSchema>;
export declare const OsintResultSchema: z.ZodObject<{
    checkedPackages: z.ZodNumber;
    findings: z.ZodArray<z.ZodObject<{
        packageName: z.ZodString;
        packageVersion: z.ZodString;
        severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
        title: z.ZodString;
        description: z.ZodOptional<z.ZodString>;
        publishedDate: z.ZodOptional<z.ZodString>;
        permalink: z.ZodOptional<z.ZodString>;
        references: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
        isActive: z.ZodDefault<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        severity: "critical" | "high" | "medium" | "low" | "info";
        title: string;
        packageName: string;
        packageVersion: string;
        references: string[];
        isActive: boolean;
        description?: string | undefined;
        publishedDate?: string | undefined;
        permalink?: string | undefined;
    }, {
        severity: "critical" | "high" | "medium" | "low" | "info";
        title: string;
        packageName: string;
        packageVersion: string;
        description?: string | undefined;
        publishedDate?: string | undefined;
        permalink?: string | undefined;
        references?: string[] | undefined;
        isActive?: boolean | undefined;
    }>, "many">;
    activeExploits: z.ZodArray<z.ZodObject<{
        packageName: z.ZodString;
        title: z.ZodString;
        severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
        permalink: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        severity: "critical" | "high" | "medium" | "low" | "info";
        title: string;
        packageName: string;
        permalink: string;
    }, {
        severity: "critical" | "high" | "medium" | "low" | "info";
        title: string;
        packageName: string;
        permalink: string;
    }>, "many">;
}, "strip", z.ZodTypeAny, {
    findings: {
        severity: "critical" | "high" | "medium" | "low" | "info";
        title: string;
        packageName: string;
        packageVersion: string;
        references: string[];
        isActive: boolean;
        description?: string | undefined;
        publishedDate?: string | undefined;
        permalink?: string | undefined;
    }[];
    checkedPackages: number;
    activeExploits: {
        severity: "critical" | "high" | "medium" | "low" | "info";
        title: string;
        packageName: string;
        permalink: string;
    }[];
}, {
    findings: {
        severity: "critical" | "high" | "medium" | "low" | "info";
        title: string;
        packageName: string;
        packageVersion: string;
        description?: string | undefined;
        publishedDate?: string | undefined;
        permalink?: string | undefined;
        references?: string[] | undefined;
        isActive?: boolean | undefined;
    }[];
    checkedPackages: number;
    activeExploits: {
        severity: "critical" | "high" | "medium" | "low" | "info";
        title: string;
        packageName: string;
        permalink: string;
    }[];
}>;
export type OsintResult = z.infer<typeof OsintResultSchema>;
export declare const AuditResultSchema: z.ZodObject<{
    projectPath: z.ZodString;
    auditPerformedAt: z.ZodString;
    npmAudit: z.ZodNullable<z.ZodObject<{
        version: z.ZodString;
        totalVulnerabilities: z.ZodNumber;
        breakdown: z.ZodObject<{
            critical: z.ZodNumber;
            high: z.ZodNumber;
            medium: z.ZodNumber;
            low: z.ZodNumber;
            info: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            critical: number;
            high: number;
            medium: number;
            low: number;
            info: number;
        }, {
            critical: number;
            high: number;
            medium: number;
            low: number;
            info: number;
        }>;
        vulnerabilities: z.ZodArray<z.ZodObject<{
            id: z.ZodNumber;
            moduleName: z.ZodString;
            severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
            title: z.ZodString;
            url: z.ZodOptional<z.ZodString>;
            affectedVersions: z.ZodArray<z.ZodString, "many">;
            isTransitive: z.ZodBoolean;
            via: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            id: number;
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            isTransitive: boolean;
            moduleName: string;
            affectedVersions: string[];
            url?: string | undefined;
            via?: string | undefined;
        }, {
            id: number;
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            isTransitive: boolean;
            moduleName: string;
            affectedVersions: string[];
            url?: string | undefined;
            via?: string | undefined;
        }>, "many">;
    }, "strip", z.ZodTypeAny, {
        version: string;
        vulnerabilities: {
            id: number;
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            isTransitive: boolean;
            moduleName: string;
            affectedVersions: string[];
            url?: string | undefined;
            via?: string | undefined;
        }[];
        totalVulnerabilities: number;
        breakdown: {
            critical: number;
            high: number;
            medium: number;
            low: number;
            info: number;
        };
    }, {
        version: string;
        vulnerabilities: {
            id: number;
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            isTransitive: boolean;
            moduleName: string;
            affectedVersions: string[];
            url?: string | undefined;
            via?: string | undefined;
        }[];
        totalVulnerabilities: number;
        breakdown: {
            critical: number;
            high: number;
            medium: number;
            low: number;
            info: number;
        };
    }>>;
    socketDev: z.ZodNullable<z.ZodObject<{
        checkedPackages: z.ZodNumber;
        maliciousDetections: z.ZodArray<z.ZodObject<{
            packageName: z.ZodString;
            version: z.ZodString;
            description: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            version: string;
            packageName: string;
            description?: string | undefined;
        }, {
            version: string;
            packageName: string;
            description?: string | undefined;
        }>, "many">;
        highRiskPackages: z.ZodArray<z.ZodObject<{
            packageName: z.ZodString;
            version: z.ZodString;
            riskTypes: z.ZodArray<z.ZodString, "many">;
            description: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            description: string;
            version: string;
            packageName: string;
            riskTypes: string[];
        }, {
            description: string;
            version: string;
            packageName: string;
            riskTypes: string[];
        }>, "many">;
    }, "strip", z.ZodTypeAny, {
        checkedPackages: number;
        maliciousDetections: {
            version: string;
            packageName: string;
            description?: string | undefined;
        }[];
        highRiskPackages: {
            description: string;
            version: string;
            packageName: string;
            riskTypes: string[];
        }[];
    }, {
        checkedPackages: number;
        maliciousDetections: {
            version: string;
            packageName: string;
            description?: string | undefined;
        }[];
        highRiskPackages: {
            description: string;
            version: string;
            packageName: string;
            riskTypes: string[];
        }[];
    }>>;
    osint: z.ZodNullable<z.ZodObject<{
        checkedPackages: z.ZodNumber;
        findings: z.ZodArray<z.ZodObject<{
            packageName: z.ZodString;
            packageVersion: z.ZodString;
            severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
            title: z.ZodString;
            description: z.ZodOptional<z.ZodString>;
            publishedDate: z.ZodOptional<z.ZodString>;
            permalink: z.ZodOptional<z.ZodString>;
            references: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
            isActive: z.ZodDefault<z.ZodBoolean>;
        }, "strip", z.ZodTypeAny, {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            packageVersion: string;
            references: string[];
            isActive: boolean;
            description?: string | undefined;
            publishedDate?: string | undefined;
            permalink?: string | undefined;
        }, {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            packageVersion: string;
            description?: string | undefined;
            publishedDate?: string | undefined;
            permalink?: string | undefined;
            references?: string[] | undefined;
            isActive?: boolean | undefined;
        }>, "many">;
        activeExploits: z.ZodArray<z.ZodObject<{
            packageName: z.ZodString;
            title: z.ZodString;
            severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
            permalink: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            permalink: string;
        }, {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            permalink: string;
        }>, "many">;
    }, "strip", z.ZodTypeAny, {
        findings: {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            packageVersion: string;
            references: string[];
            isActive: boolean;
            description?: string | undefined;
            publishedDate?: string | undefined;
            permalink?: string | undefined;
        }[];
        checkedPackages: number;
        activeExploits: {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            permalink: string;
        }[];
    }, {
        findings: {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            packageVersion: string;
            description?: string | undefined;
            publishedDate?: string | undefined;
            permalink?: string | undefined;
            references?: string[] | undefined;
            isActive?: boolean | undefined;
        }[];
        checkedPackages: number;
        activeExploits: {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            permalink: string;
        }[];
    }>>;
    suspiciousPatterns: z.ZodArray<z.ZodObject<{
        type: z.ZodEnum<["postinstall-exec", "recently-published", "large-filesystem-access", "external-url-fetch", "typo-squat", "dependency-confusion", "native-code", "suspicious-publisher", "high-risk-install", "no-readme", "sandbox-escape", "telemetry"]>;
        severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
        packageName: z.ZodString;
        description: z.ZodString;
        evidence: z.ZodOptional<z.ZodString>;
        recommendation: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        type: "postinstall-exec" | "recently-published" | "large-filesystem-access" | "external-url-fetch" | "typo-squat" | "dependency-confusion" | "native-code" | "suspicious-publisher" | "high-risk-install" | "no-readme" | "sandbox-escape" | "telemetry";
        severity: "critical" | "high" | "medium" | "low" | "info";
        description: string;
        packageName: string;
        recommendation: string;
        evidence?: string | undefined;
    }, {
        type: "postinstall-exec" | "recently-published" | "large-filesystem-access" | "external-url-fetch" | "typo-squat" | "dependency-confusion" | "native-code" | "suspicious-publisher" | "high-risk-install" | "no-readme" | "sandbox-escape" | "telemetry";
        severity: "critical" | "high" | "medium" | "low" | "info";
        description: string;
        packageName: string;
        recommendation: string;
        evidence?: string | undefined;
    }>, "many">;
    npmAuditErrors: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
    dependencyCount: z.ZodObject<{
        total: z.ZodNumber;
        dev: z.ZodNumber;
        optional: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        total: number;
        dev: number;
        optional: number;
    }, {
        total: number;
        dev: number;
        optional: number;
    }>;
    summary: z.ZodObject<{
        threatLevel: z.ZodEnum<["critical", "high", "medium", "low", "safe"]>;
        score: z.ZodNumber;
        vulnerablePackages: z.ZodNumber;
        suspiciousPackages: z.ZodNumber;
        totalFlags: z.ZodNumber;
        criticalActions: z.ZodArray<z.ZodString, "many">;
    }, "strip", z.ZodTypeAny, {
        score: number;
        threatLevel: "critical" | "high" | "medium" | "low" | "safe";
        vulnerablePackages: number;
        suspiciousPackages: number;
        totalFlags: number;
        criticalActions: string[];
    }, {
        score: number;
        threatLevel: "critical" | "high" | "medium" | "low" | "safe";
        vulnerablePackages: number;
        suspiciousPackages: number;
        totalFlags: number;
        criticalActions: string[];
    }>;
}, "strip", z.ZodTypeAny, {
    summary: {
        score: number;
        threatLevel: "critical" | "high" | "medium" | "low" | "safe";
        vulnerablePackages: number;
        suspiciousPackages: number;
        totalFlags: number;
        criticalActions: string[];
    };
    projectPath: string;
    auditPerformedAt: string;
    npmAudit: {
        version: string;
        vulnerabilities: {
            id: number;
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            isTransitive: boolean;
            moduleName: string;
            affectedVersions: string[];
            url?: string | undefined;
            via?: string | undefined;
        }[];
        totalVulnerabilities: number;
        breakdown: {
            critical: number;
            high: number;
            medium: number;
            low: number;
            info: number;
        };
    } | null;
    socketDev: {
        checkedPackages: number;
        maliciousDetections: {
            version: string;
            packageName: string;
            description?: string | undefined;
        }[];
        highRiskPackages: {
            description: string;
            version: string;
            packageName: string;
            riskTypes: string[];
        }[];
    } | null;
    osint: {
        findings: {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            packageVersion: string;
            references: string[];
            isActive: boolean;
            description?: string | undefined;
            publishedDate?: string | undefined;
            permalink?: string | undefined;
        }[];
        checkedPackages: number;
        activeExploits: {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            permalink: string;
        }[];
    } | null;
    suspiciousPatterns: {
        type: "postinstall-exec" | "recently-published" | "large-filesystem-access" | "external-url-fetch" | "typo-squat" | "dependency-confusion" | "native-code" | "suspicious-publisher" | "high-risk-install" | "no-readme" | "sandbox-escape" | "telemetry";
        severity: "critical" | "high" | "medium" | "low" | "info";
        description: string;
        packageName: string;
        recommendation: string;
        evidence?: string | undefined;
    }[];
    npmAuditErrors: string[];
    dependencyCount: {
        total: number;
        dev: number;
        optional: number;
    };
}, {
    summary: {
        score: number;
        threatLevel: "critical" | "high" | "medium" | "low" | "safe";
        vulnerablePackages: number;
        suspiciousPackages: number;
        totalFlags: number;
        criticalActions: string[];
    };
    projectPath: string;
    auditPerformedAt: string;
    npmAudit: {
        version: string;
        vulnerabilities: {
            id: number;
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            isTransitive: boolean;
            moduleName: string;
            affectedVersions: string[];
            url?: string | undefined;
            via?: string | undefined;
        }[];
        totalVulnerabilities: number;
        breakdown: {
            critical: number;
            high: number;
            medium: number;
            low: number;
            info: number;
        };
    } | null;
    socketDev: {
        checkedPackages: number;
        maliciousDetections: {
            version: string;
            packageName: string;
            description?: string | undefined;
        }[];
        highRiskPackages: {
            description: string;
            version: string;
            packageName: string;
            riskTypes: string[];
        }[];
    } | null;
    osint: {
        findings: {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            packageVersion: string;
            description?: string | undefined;
            publishedDate?: string | undefined;
            permalink?: string | undefined;
            references?: string[] | undefined;
            isActive?: boolean | undefined;
        }[];
        checkedPackages: number;
        activeExploits: {
            severity: "critical" | "high" | "medium" | "low" | "info";
            title: string;
            packageName: string;
            permalink: string;
        }[];
    } | null;
    suspiciousPatterns: {
        type: "postinstall-exec" | "recently-published" | "large-filesystem-access" | "external-url-fetch" | "typo-squat" | "dependency-confusion" | "native-code" | "suspicious-publisher" | "high-risk-install" | "no-readme" | "sandbox-escape" | "telemetry";
        severity: "critical" | "high" | "medium" | "low" | "info";
        description: string;
        packageName: string;
        recommendation: string;
        evidence?: string | undefined;
    }[];
    dependencyCount: {
        total: number;
        dev: number;
        optional: number;
    };
    npmAuditErrors?: string[] | undefined;
}>;
export type AuditResult = z.infer<typeof AuditResultSchema>;
//# sourceMappingURL=auditSchemas.d.ts.map