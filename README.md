# 🔬 Threat Lab

> AI-powered security research platform — deploy exploit scenarios, get AI analysis, build the collective pattern library.

**The threat landscape is a moving target.** MEV bots, flash loan attacks, oracle manipulation — by the time a new exploit pattern is understood well enough to defend against, dozens of protocols have already been hit. The window between "detected" and "exploited" is milliseconds. The window between "exploited" and "patched" is weeks.

Threat Lab is the research infrastructure for that gap. Instead of waiting for the next attack to happen on mainnet, security researchers deploy realistic exploit scenarios in a sandboxed environment, get AI-powered analysis of the attack mechanics, and submit findings to a growing pattern library. The platform gets smarter with every submission.

---

## How it works

```
┌─────────────┐     ┌──────────────┐     ┌────────────┐     ┌──────────────┐
│  Scenario   │────▶│   Execute    │────▶│  Analyze   │────▶│   Library    │
│  Library    │     │ (Anvil/Sepolia)│     │(multi-model)│     │  (grows)     │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                           │                    │
                           ▼                    ▼
                    Real tx traces       Threat Report
                    + gas analysis      + recommendations
```

1. **Choose a scenario** — pre-built exploit templates or your own
2. **Execute it** — deploy contracts to Anvil or Base Sepolia, run exploit steps, capture real tx traces
3. **Get AI analysis** — multi-model analysis via Bankr LLM gateway produces structured threat reports
4. **Submit to library** — findings are stored permanently, searchable, citable
5. **Pattern library compounds** — every submission makes future analysis smarter

---

## Quick start

```bash
# Check status
npx threat-lab status

# List scenarios + library
npx threat-lab list

# Unified scan — all 3 layers in one pass (recommended)
npx threat-lab scan .              # full: static + deps + exploit sim
npx threat-lab scan . --quick       # fast: static + deps (no Anvil needed)
npx threat-lab scan ./contracts --no-deps   # contract only: static + exploit sim

# Analyze a Solidity file directly (static analysis only)
npx threat-lab analyze ./contracts/MyVault.sol

# Dependency audit only (npm + OSV + Socket.dev)
npx threat-lab audit .
npx threat-lab audit ./ --no-socket   # skip Socket.dev (no API key)

# Execute a scenario (requires Anvil running)
npx threat-lab run reentrancy-101 --network anvil

# Search the pattern library
npx threat-lab library search reentrancy

# View library stats
npx threat-lab library

# Export library (IPFS-ready)
npx threat-lab export
```

---

## Scenarios

| ID | Pattern | Severity | Difficulty |
|----|----------|----------|------------|
| `reentrancy-101` | Reentrancy vault drain | Critical | Beginner |
| `oracle-manipulation-101` | Uniswap V2 oracle manipulation | High | Intermediate |
| `flash-loan-101` | Flash loan arbitrage | Medium | Beginner |
| `sandwich-attack-101` | AMM sandwich attack | High | Intermediate |
| `governance-attack-101` | DAO governance flash loan takeover | Critical | Advanced |
| `liquidation-attack-101` | Aave V2 oracle liquidation attack | High | Advanced |

---

## Architecture

```
threat-lab/
├── src/
│   ├── schemas.ts           # Zod schemas for all entities
│   ├── scenarios.ts         # Built-in attack scenario library
│   ├── executor.ts          # Deploy contracts + run exploit steps
│   ├── runner.ts            # Full orchestrator: execute → analyze → library
│   ├── modelabIntegration.ts # Multi-model AI analysis via Bankr gateway
│   ├── analyzer.ts          # AI analysis engine (signature + LLM)
│   ├── patternDetector.ts    # Pattern matching against known signatures
│   ├── library.ts           # Persistent pattern library (IPFS-ready)
│   ├── scanner.ts           # Unified scan orchestrator (static + deps + sim)
│   ├── audit.ts             # Dependency audit (OSV + npm + Socket.dev)
│   ├── auditSchemas.ts      # Zod schemas for audit result types
│   ├── api.ts               # Submission endpoint handler
│   └── cli.ts               # Full CLI (scan/audit/run/analyze/library/export)
├── contracts/              # Exploitable Solidity contract templates
│   ├── ReentrancyVault.sol
│   ├── OracleManipulation.sol
│   ├── FlashLoanAttacker.sol
│   └── *.sol                # Additional scenario contracts
├── library/                # Pattern library storage (created at runtime)
│   ├── index.json           # Library index
│   └── reports/             # Individual threat reports
├── scripts/
│   └── deploy.ts            # Deploy scenarios to Anvil / Base Sepolia
├── test/                   # Foundry/Forge tests
└── foundry.toml            # Forge configuration
```

---

## The execution loop

```
threat-lab run reentrancy-101

⚡ Executing: Reentrancy Vault Drain
   Network: anvil | RPC: http://127.0.0.1:8545

  [0] Deployed ReentrancyVault at 0x5FbDB2315678afecb367f032d93F642f54180a3E
  [1] Funded vault with 10 ETH
  [2] Deployed Attacker contract
  [3] Executed attack(10 ETH) -> recursive withdrawal confirmed

📋 Captured 4 transactions

🧠 Running modelab analysis for: Reentrancy Vault Drain
   Models: claude-sonnet-4-6
  ✅ claude-sonnet-4-6: reentrancy (80% confidence) — 1420ms

🏆 Best analysis: claude-sonnet-4-6 — reentrancy (80% conf)

📚 Added to pattern library:
   ID: a1b2c3d4-...
   Pattern: reentrancy | Severity: critical
   Library size: 7 entries

────────────────────────────────────────────────────────────
📋 THREAT REPORT — Reentrancy Vault Drain
   Pattern:   reentrancy
   Severity:   critical
   Confidence: 80%
   AI Model:  claude-sonnet-4-6

   Recommendations:
   - Implement CEI pattern (Checks-Effects-Interactions)
   - Add ReentrancyGuard from OpenZeppelin
   - Use pull-based withdrawal pattern instead of push
────────────────────────────────────────────────────────────
```

---

## Pattern library

The library currently recognizes:

- `reentrancy` — external calls before state updates
- `oracle-manipulation` — spot price oracle attacks
- `flash-loan-attack` — uncollateralized borrow + arbitrage
- `access-control` — missing permission checks
- `front-running` — MEV transaction order exploitation
- `sandwich-attack` — front-run + back-run combo
- `integer-overflow` — unchecked arithmetic
- `delegatecall-injection` — storage corruption via delegatecall
- `permit-front-run` — EIP712 signature replay
- `governance-attack` — flash loan DAO takeover
- `liquidation-attack` — oracle-manipulated liquidation exploit

Every submission expands the library. New patterns can be added by submitting a new scenario.

---

## Environment variables

```bash
# Bankr LLM gateway (required for AI analysis)
BANKR_API_KEY=your_bankr_api_key
BANKR_API_URL=https://gateway.bankr.gg/v1/chat/completions

# Anvil (defaults to http://127.0.0.1:8545)
ANVIL_RPC=http://127.0.0.1:8545

# Base Sepolia deployment
BASE_SEPOLIA_RPC=https://sepolia.base.org
DEPLOYER_PRIVATE_KEY=0x...
```

---

## The unified scan — all 3 layers in one command

```
npx threat-lab scan .

🔬 Threat Lab — Scanning .
   Static analysis:   always on (signature patterns + AI deep-read)
   Dependency audit: ON (npm + OSV.dev + Socket.dev)
   Exploit sim:      ON (Anvil)

  🟠 contracts/MyVault.sol [score: 72] [exploit sim: liquidation-attack]
  🔴 contracts/GovToken.sol [score: 89] [exploit sim: governance-attack]
  🟢 contracts/SafeMath.sol [score: 3]

   Overall Threat: HIGH | Score: 80/100 | 3 files
```

The unified `scan` command runs three independent passes in parallel per file:

**Layer 1 — Static Analysis** *(always on)*
Signature pattern matching against all known attack patterns + Bankr AI deep-read of contract code. Scans every `.sol` file in the target path recursively.

**Layer 2 — Dependency Audit** *(if `node_modules` present)*
Queries OSV.dev, npm Security Advisories, and Socket.dev for known vulnerabilities and malicious packages. Active exploits (CVEs described as "actively exploited") are flagged at highest priority.

**Layer 3 — Exploit Simulation** *(if Anvil running + contract matched to scenario)*
Matches your contract to a built-in scenario by code signature, deploys it to Anvil, executes the attack, and runs the transaction trace through AI for a verdict.

Reports are saved to `threat-reports/<file>.<pattern>.md` and `threat-reports/simulation/<scenario>.json`.

## Building

```bash
npm install
npm run build        # TypeScript compilation
forge build          # Solidity contracts (requires Foundry)
npm test             # Run SDK tests
```

---

## Deploying scenarios

```bash
# Local Anvil (recommended for testing)
forge build && npx threat-lab run reentrancy-101 --network anvil

# Base Sepolia (requires DEPLOYER_PRIVATE_KEY)
npx threat-lab run reentrancy-101 --network base-sepolia
```

---

Built with teeth. 🌑

