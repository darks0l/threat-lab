import type { Scenario } from './schemas.js';
/**
 * Built-in attack scenarios — real on-chain execution on Anvil or Base Sepolia.
 * Each scenario includes concrete exploit steps ready to run via the executor.
 */
export declare const SCENARIOS: Scenario[];
export declare function getScenario(id: string): Scenario | undefined;
export declare function listScenarios(): Scenario[];
//# sourceMappingURL=scenarios.d.ts.map