/**
 * Shared attack pattern signatures — single source of truth.
 * Used by both analyzer.ts (regex-based) and patternDetector.ts (keyword-based).
 *
 * DO NOT duplicate these in other files. Import from here.
 */
import type { AttackPattern } from './schemas.js';
export declare const PATTERN_REGEX: Record<AttackPattern, RegExp[]>;
export declare const PATTERN_KEYWORDS: Record<AttackPattern, string[]>;
export declare const PATTERN_SIGNATURES: Record<AttackPattern, string[]>;
export declare function inferPattern(text: string): AttackPattern;
//# sourceMappingURL=patternSignatures.d.ts.map