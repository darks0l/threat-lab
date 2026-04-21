/**
 * Deploy scenarios to Anvil (local) or Base Sepolia.
 * Usage: ts-node scripts/deploy.ts --network anvil --scenario reentrancy-101
 */

import { ethers } from 'ethers';
import { readFile } from 'fs/promises';
import { resolve } from 'path';

const args = process.argv.slice(2);
const network = args[args.indexOf('--network') + 1] ?? 'anvil';
const scenarioId = args[args.indexOf('--scenario') + 1];

// ── Network config ────────────────────────────────────────────────────────────

const NETWORKS: Record<string, { url: string; deployer: string }> = {
  anvil: {
    url: 'http://127.0.0.1:8545',
    deployer: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', // Anvil default
  },
  'base-sepolia': {
    url: process.env.BASE_SEPOLIA_RPC ?? 'https://sepolia.base.org',
    deployer: process.env.DEPLOYER_ADDRESS ?? '',
  },
};

const networkConfig = NETWORKS[network];
if (!networkConfig) {
  console.error(`Unknown network: ${network}`);
  console.error('Available:', Object.keys(NETWORKS).join(', '));
  process.exit(1);
}

// ── Contract artifacts ────────────────────────────────────────────────────────

const CONTRACTS: Record<string, string[]> = {
  'ReentrancyVault': ['ReentrancyVault.sol', 'ReentrancyVault'],
  'OracleManipulation': ['OracleManipulation.sol', 'OracleManipulation'],
  'FlashLoanAttacker': ['FlashLoanAttacker.sol', 'FlashLoanAttacker'],
};

async function deployContract(name: string, deployer: ethers.Signer): Promise<string> {
  const [sourceFile, contractName] = CONTRACTS[name] ?? ['', name];
  const artifactPath = resolve(import.meta.dirname, `../out/${contractName}.sol/${contractName}.json`);

  let artifact: { bytecode: string; abi: unknown[] };
  try {
    artifact = JSON.parse(await readFile(artifactPath, 'utf-8'));
  } catch {
    console.warn(`[${name}] Artifact not found at ${artifactPath} — run 'forge build' first`);
    console.warn(`[${name}] Skipping deploy (will be available after forge build)`);
    return '';
  }

  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, deployer);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  console.log(`✅ ${name} deployed at ${address}`);
  return address;
}

async function main() {
  console.log(`\n🔧 Threat Lab Deployer`);
  console.log(`   Network: ${network}`);
  console.log(`   RPC: ${networkConfig.url}\n`);

  // Load deployer
  const provider = new ethers.JsonRpcProvider(networkConfig.url);
  let deployer: ethers.Signer;

  if (network === 'anvil') {
    const wallet = ethers.Wallet.createRandom().connect(provider);
    // Fund the wallet from Anvil's default deployer
    const funder = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcaeefd6143c56ff38', provider);
    const tx = await funder.sendTransaction({ to: wallet.address, value: ethers.parseEther('100') });
    await tx.wait();
    deployer = wallet;
    console.log(`   Deployer: ${wallet.address} (100 ETH funded from Anvil default)\n`);
  } else {
    const pk = process.env.DEPLOYER_PRIVATE_KEY;
    if (!pk) {
      console.error('DEPLOYER_PRIVATE_KEY not set');
      process.exit(1);
    }
    deployer = new ethers.Wallet(pk, provider);
    console.log(`   Deployer: ${deployer.address}\n`);
  }

  // Deploy all contracts
  const deployed: Record<string, string> = {};
  for (const name of Object.keys(CONTRACTS)) {
    const address = await deployContract(name, deployer);
    if (address) deployed[name] = address;
  }

  // Save deployment addresses
  const output = {
    network,
    timestamp: new Date().toISOString(),
    deployer: await deployer.getAddress(),
    contracts: deployed,
  };

  console.log('\n📦 Deployment summary:');
  for (const [name, address] of Object.entries(deployed)) {
    console.log(`   ${name}: ${address}`);
  }

  const { writeFile, mkdir } = await import('fs/promises');
  const outDir = resolve(import.meta.dirname, '..');
  await mkdir(outDir, { recursive: true });
  await writeFile(resolve(outDir, `.deploy-${network}.json`), JSON.stringify(output, null, 2));
  console.log(`\n✅ Saved deployment to .deploy-${network}.json`);
}

main().catch(err => {
  console.error('Deploy failed:', err);
  process.exit(1);
});
