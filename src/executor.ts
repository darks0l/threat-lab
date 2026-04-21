/**
 * Scenario Executor — deploys contracts and runs exploit steps on a live network.
 * Captures transaction traces for AI analysis.
 */

import { ethers } from 'ethers';
import { readFile } from 'fs/promises';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

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

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Network config ────────────────────────────────────────────────────────────

export interface NetworkConfig {
  name: string;
  rpcUrl: string;
  deployerPk: string;
  chainId: number;
}

const DEFAULT_ANVIL_RPC = 'http://127.0.0.1:8545';
const ANVIL_DEPLOYER_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcaeefd6143c56ff38'; // Anvil #0

export function getNetworkConfig(network: string): NetworkConfig {
  switch (network) {
    case 'anvil':
    case 'local':
      return {
        name: 'anvil',
        rpcUrl: process.env.ANVIL_RPC ?? DEFAULT_ANVIL_RPC,
        deployerPk: process.env.DEPLOYER_PRIVATE_KEY ?? ANVIL_DEPLOYER_PK,
        chainId: 31337,
      };
    case 'base-sepolia':
      return {
        name: 'base-sepolia',
        rpcUrl: process.env.BASE_SEPOLIA_RPC ?? 'https://sepolia.base.org',
        deployerPk: process.env.DEPLOYER_PRIVATE_KEY ?? '',
        chainId: 84532,
      };
    case 'sepolia':
      return {
        name: 'sepolia',
        rpcUrl: process.env.SEPOLIA_RPC ?? 'https://rpc.sepolia.org',
        deployerPk: process.env.DEPLOYER_PRIVATE_KEY ?? '',
        chainId: 11155111,
      };
    default:
      throw new Error(`Unknown network: ${network}`);
  }
}

// ── Contract deployment ───────────────────────────────────────────────────────

async function loadArtifact(name: string): Promise<{ bytecode: string; abi: ethers.InterfaceAbi }> {
  const artifactPath = resolve(__dirname, '..', 'out', `${name}.sol`, `${name}.json`);
  try {
    const raw = JSON.parse(await readFile(artifactPath, 'utf-8'));
    return { bytecode: raw.bytecode, abi: raw.abi as ethers.InterfaceAbi };
  } catch {
    const altPath = resolve(__dirname, '..', 'out', `${name}.json`);
    const raw = JSON.parse(await readFile(altPath, 'utf-8'));
    return { bytecode: raw.bytecode, abi: raw.abi as ethers.InterfaceAbi };
  }
}

async function deployContract(
  name: string,
  args: unknown[],
  signer: ethers.Signer,
): Promise<DeployResult> {
  const artifact = await loadArtifact(name);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const tx = await factory.deploy(...args);
  const deployed = await tx.waitForDeployment();
  const addr = await deployed.getAddress();
  const receipt = tx.deploymentTransaction()!.wait();
  return {
    contractName: name,
    address: addr,
    txHash: tx.deploymentTransaction()!.hash,
    blockNumber: (await receipt)?.blockNumber ?? 0,
  };
}

// ── Step execution ────────────────────────────────────────────────────────────

async function executeStep(
  step: {
    step: number;
    action: string;
    target?: string;
    method?: string;
    args?: unknown[];
    value?: string;
    description: string;
  },
  contracts: Map<string, { address: string; abi: ethers.InterfaceAbi }>,
  signer: ethers.Signer,
): Promise<StepResult> {
  const result: StepResult = {
    step: step.step,
    action: step.action,
    description: step.description,
    success: false,
  };

  try {
    switch (step.action) {
      case 'deploy': {
        const artifact = await loadArtifact(step.target ?? '');
        const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
        const tx = await factory.deploy();
        const deployed = await tx.waitForDeployment();
        const addr = await deployed.getAddress();
        result.txHash = tx.deploymentTransaction()!.hash;
        result.blockNumber = (await tx.deploymentTransaction()!.wait())?.blockNumber;
        result.success = true;
        result.returnData = addr;
        console.log(`  [${step.step}] Deployed ${step.target} at ${addr}`);
        break;
      }

      case 'call': {
        const contract = contracts.get(step.target ?? '');
        if (!contract) throw new Error(`Contract not found: ${step.target}`);
        const c = new ethers.Contract(contract.address, contract.abi, signer);
        const tx = await (c as ethers.Contract)[step.method ?? ''](...(step.args ?? []));
        const receipt = await tx.wait();
        result.txHash = tx.hash;
        result.blockNumber = receipt?.blockNumber;
        result.gasUsed = receipt?.gasUsed;
        result.success = true;
        console.log(`  [${step.step}] ${step.target}.${step.method}() -> ${tx.hash}`);
        break;
      }

      case 'send': {
        const contract = contracts.get(step.target ?? '');
        if (!contract) throw new Error(`Contract not found: ${step.target}`);
        const value = step.value ? ethers.parseEther(step.value.replace(' ETH', '')) : 0n;
        const c = new ethers.Contract(contract.address, contract.abi, signer);
        const tx = await (c as ethers.Contract)[step.method ?? ''](...(step.args ?? []), { value });
        const receipt = await tx.wait();
        result.txHash = tx.hash;
        result.blockNumber = receipt?.blockNumber;
        result.gasUsed = receipt?.gasUsed;
        result.success = true;
        console.log(`  [${step.step}] Sent ${step.value} to ${step.target}.${step.method}() -> ${tx.hash}`);
        break;
      }

      case 'flash-loan':
      case 'swap':
      case 'manipulate': {
        console.log(`  [${step.step}] ${step.action}: ${step.description} (mocked)`);
        result.success = true;
        result.returnData = `${step.action}-mocked`;
        break;
      }

      case 'fund': {
        const value = step.value ? ethers.parseEther(step.value.replace(' ETH', '')) : 0n;
        const tx = await signer.sendTransaction({ to: step.target, value });
        await tx.wait();
        result.txHash = tx.hash;
        result.success = true;
        console.log(`  [${step.step}] Funded ${step.target} with ${step.value}`);
        break;
      }

      default:
        result.error = `Unknown action: ${step.action}`;
        console.warn(`  [${step.step}] Unknown action: ${step.action}`);
    }
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    result.success = false;
    console.error(`  [${step.step}] Error: ${result.error}`);
  }

  return result;
}

// ── Main executor ─────────────────────────────────────────────────────────────

export interface ExecutorOptions {
  network?: string;
  buildFirst?: boolean;
}

const CONTRACT_ARTIFACTS: Record<string, { name: string; ctorArgs?: unknown[] }> = {
  'ReentrancyVault': { name: 'ReentrancyVault' },
  'OracleManipulation': { name: 'OracleManipulation', ctorArgs: ['0x0000000000000000000000000000000000000000', '0x0000000000000000000000000000000000000000', '0x0000000000000000000000000000000000000000'] },
  'FlashLoanAttacker': { name: 'FlashLoanAttacker' },
};

export async function executeScenario(
  scenario: {
    id: string;
    name: string;
    templateContract: string;
    exploitSteps: Array<{
      step: number;
      action: string;
      target?: string;
      method?: string;
      args?: unknown[];
      value?: string;
      description: string;
    }>;
  },
  options: ExecutorOptions = {},
): Promise<ExecutionResult> {
  const networkName = options.network ?? 'anvil';
  const config = getNetworkConfig(networkName);

  console.log(`\n⚡ Executing: ${scenario.name}`);
  console.log(`   Network: ${networkName} | RPC: ${config.rpcUrl}`);

  const provider = new ethers.JsonRpcProvider(config.rpcUrl);
  const signer = new ethers.Wallet(config.deployerPk, provider);

  const startBlock = await provider.getBlockNumber();
  const startTime = Date.now();
  const deployedContracts = new Map<string, { address: string; abi: ethers.InterfaceAbi }>();
  const steps: StepResult[] = [];
  const allTxHashes: string[] = [];

  // Fund deployer on local network
  if (networkName === 'anvil') {
    const anvilFunder = new ethers.Wallet(ANVIL_DEPLOYER_PK, provider);
    const balance = await provider.getBalance(signer.address);
    if (balance < ethers.parseEther('10')) {
      const fundTx = await anvilFunder.sendTransaction({ to: signer.address, value: ethers.parseEther('100') });
      await fundTx.wait();
    }
  }

  // Deploy the main contract(s)
  const artifactInfo = CONTRACT_ARTIFACTS[scenario.templateContract];
  if (artifactInfo) {
    try {
      const result = await deployContract(artifactInfo.name, artifactInfo.ctorArgs ?? [], signer);
      const artifact = await loadArtifact(artifactInfo.name);
      deployedContracts.set(scenario.templateContract, { address: result.address, abi: artifact.abi });
      steps.push({
        step: 0,
        action: 'deploy',
        description: `Deployed ${scenario.templateContract}`,
        success: true,
        txHash: result.txHash,
        blockNumber: result.blockNumber,
        returnData: result.address,
      });
      allTxHashes.push(result.txHash);
    } catch (err) {
      steps.push({
        step: 0,
        action: 'deploy',
        description: `Failed to deploy ${scenario.templateContract}`,
        success: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // Run each exploit step
  for (const step of scenario.exploitSteps) {
    const stepResult = await executeStep(step, deployedContracts, signer);
    steps.push(stepResult);
    if (stepResult.txHash) allTxHashes.push(stepResult.txHash);
  }

  const endBlock = await provider.getBlockNumber();
  const durationMs = Date.now() - startTime;

  console.log(`\n📋 Captured ${allTxHashes.length} transactions`);
  for (const hash of allTxHashes.slice(0, 5)) {
    try {
      const receipt = await provider.getTransactionReceipt(hash);
      if (receipt) {
        console.log(`   ${hash.slice(0, 18)}... | gas: ${receipt.gasUsed.toString()} | status: ${receipt.status}`);
      }
    } catch { /* skip */ }
  }

  await provider.destroy();

  return {
    scenarioId: scenario.id,
    network: networkName,
    deployedContracts: Array.from(deployedContracts.entries()).map(([name, data]) => ({
      contractName: name,
      address: data.address,
      txHash: steps.find(s => s.returnData === data.address)?.txHash ?? '',
      blockNumber: steps.find(s => s.returnData === data.address)?.blockNumber ?? 0,
    })),
    steps,
    allTxHashes,
    startBlock,
    endBlock,
    durationMs,
  };
}

export async function isAnvilRunning(): Promise<boolean> {
  try {
    // Use a simple HTTP check with AbortController timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const response = await fetch(DEFAULT_ANVIL_RPC, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!response.ok) return false;
    const data = await response.json() as { result?: string };
    return data.result !== undefined;
  } catch {
    return false;
  }
}

export async function getTxTrace(txHash: string, rpcUrl: string): Promise<string> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  try {
    const trace = await provider.send('debug_traceTransaction', [txHash]);
    return JSON.stringify(trace, null, 2);
  } catch {
    const receipt = await provider.getTransactionReceipt(txHash);
    return JSON.stringify({
      txHash,
      gasUsed: receipt?.gasUsed.toString(),
      status: receipt?.status,
      logs: receipt?.logs.map(l => ({ address: l.address, topics: l.topics, data: l.data })),
    }, null, 2);
  } finally {
    await provider.destroy();
  }
}
