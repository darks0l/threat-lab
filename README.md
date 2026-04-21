# 🔬 Threat Lab

> AI-powered security research platform — deploy exploit scenarios, get AI analysis, build the collective pattern library.

**The threat landscape is a moving target.** MEV bots, flash loan attacks, oracle manipulation — by the time a new exploit pattern is understood well enough to defend against, dozens of protocols have already been hit. The window between "detected" and "exploited" is milliseconds. The window between "exploited" and "patched" is weeks.

Threat Lab is the research infrastructure for that gap. Instead of waiting for the next attack to happen on mainnet, security researchers deploy realistic exploit scenarios in a sandboxed environment, get AI-powered analysis of the attack mechanics, and submit findings to a growing pattern library. The platform gets smarter with every submission.

---

## How it works

```
┌─────────────┐     ┌──────────────┐     ┌────────────┐     ┌──────────────┐
│  Scenario   │────▶│   Deploy     │────▶│  Execute   │────▶│  AI Analysis │
│  Library    │     │  (Anvil/     │     │  Exploit   │     │  (Bankr LLM  │
│             │     │  Sepolia)    │     │  Steps     │     │   Gateway)   │
└─────────────┘     └──────────────┘     └────────────┘     └──────────────┘
                                                                    │
                                                                    ▼
                                              ┌──────────────┐     ┌──────────────┐
                                              │   Pattern    │◀────│   Submit     │
                                              │   Library    │     │  Findings    │
                                              │   (grows)    │     │              │
                                              └──────────────┘     └──────────────┘
```

1. **Choose a scenario** — pre-built exploit templates or your own
2. **Deploy it** — to a local Anvil chain or Base Sepolia testnet
3. **Execute the exploit** — run the attack steps, capture the trace
4. **Get AI analysis** — Bankr LLM gateway breaks down exactly what happened
5. **Submit findings** — your submission expands the pattern library

---

## Quick start

```bash
# List available scenarios
npx threat-lab list

# Run a scenario locally
npx threat-lab run reentrancy-101

# Analyze a contract
npx threat-lab analyze ./contracts/ReentrancyVault.sol

# Submit findings
npx threat-lab submit ./my-finding.json
```

---

## Scenarios

| ID | Pattern | Severity | Difficulty |
|----|----------|----------|------------|
| `reentrancy-101` | Reentrancy vault drain | Critical | Beginner |
| `oracle-manipulation-101` | Uniswap V2 oracle manipulation | High | Intermediate |
| `flash-loan-101` | Flash loan arbitrage | Medium | Beginner |

---

## Architecture

```
threat-lab/
├── contracts/           # Exploitable Solidity contract templates
│   ├── ReentrancyVault.sol
│   ├── OracleManipulation.sol
│   └── FlashLoanAttacker.sol
├── src/
│   ├── schemas.ts      # Zod schemas for findings/submissions
│   ├── scenarios.ts    # Built-in attack scenario library
│   ├── analyzer.ts     # AI analysis via Bankr LLM gateway
│   ├── patternDetector.ts  # Signature-based pattern matching
│   ├── api.ts          # Submission endpoint handler
│   └── cli.ts          # threat-lab CLI
├── scripts/
│   └── deploy.ts       # Deploy scenarios to Anvil / Base Sepolia
├── test/               # Foundry/Forge tests
└── foundry.toml        # Forge configuration
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

Every submission that gets confirmed expands the library. New patterns can be added by submitting a new scenario.

---

## Building

```bash
npm install
npm run build        # TypeScript compilation
forge build          # Solidity contracts (requires Foundry)
npm test             # Run SDK tests
```

---

## Deploying contracts

```bash
# Local Anvil
forge build && ts-node scripts/deploy.ts --network anvil

# Base Sepolia (requires DEPLOYER_PRIVATE_KEY)
forge build && ts-node scripts/deploy.ts --network base-sepolia --scenario reentrancy-101
```

---

Built with teeth. 🌑

