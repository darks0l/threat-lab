/**
 * Scenario Executor — deploys contracts and runs exploit steps on a live network.
 * Captures transaction traces for AI analysis.
 */
import { ethers } from 'ethers';
export interface DeployResult {
    contractName: string;
    address: string;
    txHash: string;
    blockNumber: number;
}
export interface StepResult {
    step: number;
    action: string;
    description: string;
    success: boolean;
    txHash?: string;
    blockNumber?: number;
    returnData?: string;
    error?: string;
    gasUsed?: bigint;
}
export interface ExecutionResult {
    scenarioId: string;
    network: string;
    deployedContracts: DeployResult[];
    steps: StepResult[];
    allTxHashes: string[];
    startBlock: number;
    endBlock: number;
    durationMs: number;
}
export interface NetworkConfig {
    name: string;
    rpcUrl: string;
    deployerPk: string;
    chainId: number;
}
export declare function getNetworkConfig(network: string): NetworkConfig;
interface Artifact {
    bytecode: string;
    abi: ethers.InterfaceAbi;
}
export declare function loadArtifact(name: string): Promise<Artifact>;
export interface ExecutorOptions {
    network?: string;
}
export declare function executeScenario(scenario: {
    id: string;
    name: string;
    templateContract?: string;
    exploitSteps: Array<{
        step: number;
        action: string;
        target?: string;
        method?: string;
        args?: unknown[];
        value?: string;
        description: string;
    }>;
}, options?: ExecutorOptions): Promise<ExecutionResult>;
export declare function isAnvilRunning(): Promise<boolean>;
export declare function getTxTrace(txHash: string, rpcUrl: string): Promise<string>;
export {};
//# sourceMappingURL=executor.d.ts.map