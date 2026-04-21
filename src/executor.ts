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
// Default Anvil deployer — 10,000 ETH pre-funded
const ANVIL_DEPLOYER_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
// Anvil account #1 — use if default account's nonce state is stale
const ANVIL_ACCOUNT_1_PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae67c7e8726530508362d3a8';
const ANVIL_ACCOUNT_1 = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';

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
    case 'base-sepolia': {
      const pk = process.env.DEPLOYER_PRIVATE_KEY ?? '';
      if (!pk) {
        throw new Error('DEPLOYER_PRIVATE_KEY is not set. Set it in .env to deploy to base-sepolia.');
      }
      return {
        name: 'base-sepolia',
        rpcUrl: process.env.BASE_SEPOLIA_RPC ?? 'https://sepolia.base.org',
        deployerPk: pk,
        chainId: 84532,
      };
    }
    case 'sepolia': {
      const pk = process.env.DEPLOYER_PRIVATE_KEY ?? '';
      if (!pk) {
        throw new Error('DEPLOYER_PRIVATE_KEY is not set. Set it in .env to deploy to sepolia.');
      }
      return {
        name: 'sepolia',
        rpcUrl: process.env.SEPOLIA_RPC ?? 'https://rpc.sepolia.org',
        deployerPk: pk,
        chainId: 11155111,
      };
    }
    default:
      throw new Error(`Unknown network: ${network}`);
  }
}

// ── Contract artifact loading ─────────────────────────────────────────────────

interface Artifact {
  bytecode: string;
  abi: ethers.InterfaceAbi;
}

async function loadArtifact(name: string): Promise<Artifact> {
  const paths = [
    resolve(__dirname, '..', 'out', `${name}.sol`, `${name}.json`),
    resolve(__dirname, '..', 'out', `${name}.json`),
  ];

  for (const artifactPath of paths) {
    try {
      const raw = JSON.parse(await readFile(artifactPath, 'utf-8'));
      if (raw.bytecode && raw.abi) {
        return { bytecode: raw.bytecode, abi: raw.abi as ethers.InterfaceAbi };
      }
    } catch { /* try next */ }
  }

  throw new Error(`Artifact not found for: ${name}. Run 'forge build' first.`);
}

// ── Contract deployment ───────────────────────────────────────────────────────

async function deployContract(
  name: string,
  args: unknown[],
  wallet: ethers.Wallet,
  provider: ethers.JsonRpcProvider,
): Promise<{ address: string; txHash: string; blockNumber: number }> {
  const artifact = await loadArtifact(name);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);
  try {
    const contract = await factory.deploy(...(args ?? [])) as ethers.Contract;
    const address = await contract.getAddress();
    const deployTx = contract.deploymentTransaction();
    const receipt = deployTx ? await deployTx.wait() : null;
    await mineBlock(provider);
    return {
      address,
      txHash: deployTx?.hash ?? '',
      blockNumber: receipt?.blockNumber ?? 0,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [DEPLOY ERROR] ${name}: ${msg}`);
    throw err;
  }
}

// ── Step execution ───────────────────────────────────────────────────────────

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
  wallet: ethers.Wallet,
  provider: ethers.JsonRpcProvider,
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
        const contractName = step.target ?? 'UNKNOWN';
        // Resolve placeholders like {CONTRACT_NAME} to actual deployed contract addresses
        const resolvedArgs = (step.args ?? []).map(arg => {
          if (typeof arg === 'string' && arg.startsWith('{') && arg.endsWith('}')) {
            const key = arg.slice(1, -1);
            const entry = Array.from(contracts.entries()).find(([k]) => k.toLowerCase() === key.toLowerCase());
            if (!entry) {
              console.error(`  [DEBUG] Available contracts: ${Array.from(contracts.keys()).join(', ')}`);
              throw new Error(`Placeholder {${key}} not found in deployed contracts`);
            }
            return entry[1].address;
          }
          return arg;
        });
        const deployed = await deployContract(contractName, resolvedArgs, wallet, provider);
        const artifact = await loadArtifact(contractName);

        contracts.set(contractName, { address: deployed.address, abi: artifact.abi });
        contracts.set(deployed.address.toLowerCase(), { address: deployed.address, abi: artifact.abi });

        result.txHash = deployed.txHash;
        result.blockNumber = deployed.blockNumber;
        result.success = true;
        result.returnData = deployed.address;
        console.log(`  [${step.step}] Deployed ${contractName} at ${deployed.address}`);
        break;
      }

      case 'call': {
        const found = Array.from(contracts.entries()).find(([k]) => k.toLowerCase() === (step.target ?? '').toLowerCase());
        const contract = found?.[1];
        if (!contract) throw new Error(`Contract not found: ${step.target}`);
        const c = new ethers.Contract(contract.address, contract.abi, wallet);
        // Use sendTransaction for state-changing calls (attack, withdraw, etc.)
        // Use staticCall only for view/pure reads when blockTag is explicitly 'latest'
        const isViewRead = (step.args ?? []).includes('latest') ||
          (step.method ?? '').startsWith('get') ||
          (step.method ?? '').startsWith('balance');
        let returnData: unknown;
        if (isViewRead) {
          returnData = await (c as any)[step.method ?? ''].staticCall(...(step.args ?? []), { blockTag: 'latest' });
        } else {
          const nonce = await provider.getTransactionCount(wallet.address, 'pending');
          const tx = await (c as any)[step.method ?? ''](...(step.args ?? []), { nonce });
          const receipt = await tx.wait();
          await mineBlock(provider);
          returnData = receipt?.status === 1 ? 'tx_success' : 'tx_failed';
          result.txHash = tx.hash;
          result.blockNumber = receipt?.blockNumber;
          result.gasUsed = receipt?.gasUsed;
        }
        result.returnData = returnData?.toString() ?? '';
        result.success = true;
        console.log(`  [${step.step}] ${step.target}.${step.method}() -> ${returnData}`);
        break;
      }

      case 'send': {
        const contract = contracts.get(step.target ?? '') ?? contracts.get(step.target?.toLowerCase() ?? '');
        if (!contract) throw new Error(`Contract not found: ${step.target}`);
        const value = step.value ? ethers.parseEther(step.value.replace(/ ETH|ether/gi, '').trim()) : 0n;
        const c = new ethers.Contract(contract.address, contract.abi, wallet);
        const nonce = await provider.getTransactionCount(wallet.address, 'latest');
        const tx = await (c as ethers.Contract)[step.method ?? ''](...(step.args ?? []), { value, nonce });
        const receipt = await tx.wait();
        await mineBlock(provider);
        result.txHash = tx.hash;
        result.blockNumber = receipt?.blockNumber;
        result.gasUsed = receipt?.gasUsed;
        result.success = true;
        console.log(`  [${step.step}] ${step.target}.${step.method}() [value=${step.value ?? '0'}] -> ${tx.hash}`);
        break;
      }

      case 'flash-loan':
      case 'swap':
      case 'manipulate': {
        console.log(`  [${step.step}] ${step.action}: ${step.description} (simulated)`);
        result.success = true;
        result.returnData = `${step.action}-simulated`;
        break;
      }

      case 'fund': {
        const value = step.value ? ethers.parseEther(step.value.replace(/ ETH|ether/gi, '').trim()) : 0n;
        const toAddress = step.target
          ? (contracts.get(step.target)?.address ?? step.target)
          : wallet.address;
        const tx = await wallet.sendTransaction({ to: toAddress, value });
        await tx.wait();
        await mineBlock(provider);
        result.txHash = tx.hash;
        result.success = true;
        console.log(`  [${step.step}] Funded ${toAddress} with ${step.value ?? '0 ETH'}`);
        break;
      }

      case 'log': {
        console.log(`  [${step.step}] ${step.description}`);
        result.success = true;
        result.returnData = step.description;
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
}

export async function executeScenario(
  scenario: {
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
  },
  options: ExecutorOptions = {},
): Promise<ExecutionResult> {
  const networkName = options.network ?? 'anvil';
  const config = getNetworkConfig(networkName);

  console.log(`\n⚡ Executing: ${scenario.name}`);
  console.log(`   Network: ${networkName} | RPC: ${config.rpcUrl}`);

  const provider = new ethers.JsonRpcProvider(config.rpcUrl);
  const wallet = new ethers.Wallet(config.deployerPk, provider);

  const startBlock = await provider.getBlockNumber();
  const startTime = Date.now();
  const deployedContracts = new Map<string, { address: string; abi: ethers.InterfaceAbi }>();
  const steps: StepResult[] = [];
  const allTxHashes: string[] = [];

  // Anvil #0 is pre-funded with 10000 ETH — no funding needed

  // Run each exploit step
  for (const step of scenario.exploitSteps) {
    const stepResult = await executeStep(step, deployedContracts, wallet, provider);
    steps.push(stepResult);
    if (stepResult.txHash) allTxHashes.push(stepResult.txHash);
  }

  const endBlock = await provider.getBlockNumber();
  const durationMs = Date.now() - startTime;

  console.log(`\n📋 Captured ${allTxHashes.length} transaction(s)`);

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

// Mine a new block on Anvil to finalize pending transactions and reset nonce state
async function mineBlock(provider: ethers.JsonRpcProvider): Promise<void> {
  try {
    await provider.send('evm_mine', []);
    // Force ethers provider to refresh internal block state
    await provider.getBlockNumber();
  } catch { /* already mined */ }
}

// Deploy a contract and return the deployment receipt
async function deployAndWait(
  factory: ethers.ContractFactory,
  args: unknown[],
  nonce: number,
): Promise<{ address: string; receipt: ethers.TransactionReceipt; txHash: string }> {
  // Build the unsigned deploy tx
  const deployTxReq = factory.getDeployTransaction(...(args ?? []));
  // Cast runner to Wallet to access signTransaction
  const runner = factory.runner as ethers.Wallet;
  const signed = await runner.signTransaction!({ ...deployTxReq, nonce });
  const broadcasted = await runner.provider!.broadcastTransaction(signed);
  const receipt = await broadcasted.wait();
  return {
    address: receipt!.contractAddress!,
    receipt: receipt!,
    txHash: broadcasted.hash,
  };
}

export async function isAnvilRunning(): Promise<boolean> {
  try {
    const provider = new ethers.JsonRpcProvider(DEFAULT_ANVIL_RPC);
    const blockNumber = await provider.getBlockNumber();
    await provider.destroy();
    return blockNumber >= 0;
  } catch {
    return false;
  }
}

export async function getTxTrace(txHash: string, rpcUrl: string): Promise<string> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  try {
    // Only call debug_traceTransaction on chains that support it (Anvil, Hardhat)
    try {
      const trace = await provider.send('debug_traceTransaction', [txHash]);
      return JSON.stringify(trace, null, 2);
    } catch {
      // Fallback to receipt + logs on chains without debug_traceTransaction
    }
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
