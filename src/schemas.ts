import { z } from 'zod';

// ── Attack Pattern Registry ───────────────────────────────────────────────────

export const AttackPatternSchema = z.enum([
  'reentrancy',
  'oracle-manipulation',
  'flash-loan-attack',
  'access-control',
  'front-running',
  'sandwich-attack',
  'integer-overflow',
  'delegatecall-injection',
  'permit-front-run',
  'liquidation-attack',
  'unknown',
]);
export type AttackPattern = z.infer<typeof AttackPatternSchema>;

// ── Severity ──────────────────────────────────────────────────────────────────

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'informational']);
export type Severity = z.infer<typeof SeveritySchema>;

// ── Finding ──────────────────────────────────────────────────────────────────

export const FindingSchema = z.object({
  id: z.string().uuid(),
  scenarioId: z.string(),
  attackPattern: AttackPatternSchema,
  severity: SeveritySchema,
  title: z.string(),
  description: z.string(),
  cvssScore: z.number().min(0).max(10).optional(),
  affectedContracts: z.array(z.string()),
  txHash: z.string().optional(),
  chainId: z.number(),
  blockNumber: z.number().optional(),
  aiModel: z.string().optional(),
  aiAnalysis: z.string(),
  rawTrace: z.string().optional(),
  submittedBy: z.string().optional(),
  submittedAt: z.string().datetime(),
  tags: z.array(z.string()).default([]),
});
export type Finding = z.infer<typeof FindingSchema>;

// ── Scenario ──────────────────────────────────────────────────────────────────

export const ScenarioSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  pattern: AttackPatternSchema,
  severity: SeveritySchema,
  templateContract: z.string().optional(), // Solidity contract name
  deployParams: z.record(z.unknown()).optional(),
  exploitSteps: z.array(z.object({
    step: z.number(),
    action: z.enum(['deploy', 'call', 'send', 'flash-loan', 'swap', 'manipulate', 'fund', 'log']),
    target: z.string().optional(),
    method: z.string().optional(),
    args: z.array(z.unknown()).optional(),
    value: z.string().optional(),
    description: z.string(),
  })),
  expectedOutcome: z.string(),
  difficulty: z.enum(['beginner', 'intermediate', 'advanced']),
  createdAt: z.string().datetime(),
  tags: z.array(z.string()).default([]),
});
export type Scenario = z.infer<typeof ScenarioSchema>;

// ── Submission ────────────────────────────────────────────────────────────────

export const SubmissionSchema = z.object({
  version: z.literal('1.0'),
  scenario: z.string(), // scenario id
  chainId: z.number(),
  attackerAddress: z.string(),
  victimAddress: z.string().optional(),
  txHash: z.string(),
  blockNumber: z.number(),
  findings: z.array(FindingSchema),
  aiSummary: z.string(),
  submittedBy: z.string().optional(),
  timestamp: z.string().datetime(),
});
export type Submission = z.infer<typeof SubmissionSchema>;

// ── Threat Report ────────────────────────────────────────────────────────────

export const ThreatReportSchema = z.object({
  reportId: z.string().uuid(),
  scenarioId: z.string(),
  attackPattern: AttackPatternSchema,
  severity: SeveritySchema,
  summary: z.string(),
  findings: z.array(z.object({
    title: z.string(),
    description: z.string(),
    evidence: z.string(),
  })),
  aiModel: z.string(),
  confidence: z.number().min(0).max(1),
  recommendations: z.array(z.string()),
  createdAt: z.string().datetime(),
});
export type ThreatReport = z.infer<typeof ThreatReportSchema>;
