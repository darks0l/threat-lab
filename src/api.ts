/**
 * Submission API endpoint — receives findings JSON, validates, and stores.
 * In MVP: just validates and logs. Can be extended to store to DB/IPFS.
 */

import { SubmissionSchema, type Submission } from './schemas.js';
import { analyzeThreat } from './analyzer.js';
import { scoreSubmission } from './patternDetector.js';
import { getScenario } from './scenarios.js';

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
export async function submitFinding(
  payload: unknown,
  library: { reportId: string; attackPattern: string; summary: string; confidence: number }[] = [],
): Promise<SubmitResult> {
  // Validate the submission payload
  const parseResult = SubmissionSchema.safeParse(payload);
  if (!parseResult.success) {
    return {
      success: false,
      error: `Invalid submission: ${parseResult.error.issues.map((e: { path: (string | number)[]; message: string }) => `${e.path.join('.')}: ${e.message}`).join('; ')}`,
    };
  }

  const submission = parseResult.data;

  // Look up the scenario
  const scenario = getScenario(submission.scenario);
  if (!scenario) {
    return { success: false, error: `Unknown scenario: ${submission.scenario}` };
  }

  // Run AI analysis on the raw trace or contract code
  const report = await analyzeThreat({
    scenarioId: scenario.id,
    scenarioName: scenario.name,
    scenarioDesc: scenario.description,
    txTrace: submission.findings[0]?.rawTrace,
    contractCode: scenario.exploitSteps.map(s => s.description).join('\n'),
    chainId: submission.chainId,
  });

  // Score the submission based on how much it adds to the library
  const score = scoreSubmission(report, library.map(l => ({
    ...report,
    reportId: l.reportId,
    attackPattern: l.attackPattern as typeof report.attackPattern,
  })));

  return {
    success: true,
    submissionId: submission.scenario,
    reportId: report.reportId,
    score,
    findings: report.findings.map(f => f.title),
  };
}

/**
 * Submit findings from the CLI — takes a submission JSON file path.
 */
export async function submitFromFile(filePath: string): Promise<SubmitResult> {
  const fs = await import('fs/promises');
  const raw = await fs.readFile(filePath, 'utf-8');
  const payload = JSON.parse(raw);
  return submitFinding(payload);
}
