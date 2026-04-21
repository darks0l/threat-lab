# Threat Lab — Submission Guide

The pattern library grows through community submissions. Every validated submission makes the collective smarter.

---

## How It Works

```
You find a real exploit (or document one)
  → Build a submission JSON file
  → Open a PR to darks0l/threat-lab
  → Maintainer reviews manually
  → On merge: your finding is in the collective library
```

The library is distributed via GitHub. When your submission merges, every user pulling `threat-lab` gets your finding automatically.

---

## Submission Workflow

### Step 1 — Find or document a threat

Use `threat-lab scan` on your own contracts, or document a known exploit from mainnet.

If scanning locally:
```bash
npx threat-lab scan ./contracts --quick
```

### Step 2 — Build your submission JSON

Create a file in `library/reports/` named after your finding:

```
library/reports/
  my-finding-YYYY-MM-DD.json
```

The file must conform to the `SubmissionSchema` (version `1.0`):

```json
{
  "version": "1.0",
  "scenario": "reentrancy-101",
  "chainId": 8453,
  "attackerAddress": "0xYourAttackerAddress",
  "victimAddress": "0xTargetContractAddress",
  "txHash": "0xTransactionHash",
  "blockNumber": 12345678,
  "findings": [
    {
      "id": "generate-a-uuid-v4",
      "scenarioId": "reentrancy-101",
      "attackPattern": "reentrancy",
      "severity": "critical",
      "title": "Re-entrancy in withdraw function",
      "description": "External call to untrusted recipient before state update. Allows recursive withdrawals draining the vault.",
      "affectedContracts": ["0xTargetContract"],
      "txHash": "0xTransactionHash",
      "chainId": 8453,
      "blockNumber": 12345678,
      "aiModel": "optional-model-name",
      "aiAnalysis": "Detailed explanation of how the attack works, what state was read incorrectly, and how the attacker extracted funds.",
      "submittedAt": "2026-04-21T00:00:00Z",
      "tags": ["yield-vault", "erc777"]
    }
  ],
  "aiSummary": "A brief (1-2 sentence) plain-language summary of the exploit.",
  "submittedBy": "your-github-handle",
  "timestamp": "2026-04-21T00:00:00Z"
}
```

### Step 3 — Validate locally

```bash
npx threat-lab submit library/reports/my-finding-YYYY-MM-DD.json
```

This validates the JSON against the schema and adds it to your local library index. Fix any errors before opening a PR.

### Step 4 — Open a Pull Request

1. Fork `darks0l/threat-lab`
2. Add your JSON file to `library/reports/`
3. Commit + push + open a PR

**PR title format:** `[submission] <attack-pattern> — <short-title>`

Example:
```
[submission] reentrancy — Cream Finance vault drain 2026
```

---

## Review Criteria

All submissions are reviewed manually by a maintainer before merging. Review focuses on:

### Must pass (rejection if missing)
- **Real vulnerability** — the submission describes a genuine, reproducible smart contract flaw. Do not submit false positives, hypotheticals without code, or POCs that don't actually exploit the described issue.
- **Sufficient evidence** — tx hash + contract address + AI analysis must be present. A finding without a transaction trace or contract code is not mergeable.
- **Not a honeypot** — submissions describing attacker-controlled trap contracts designed to drain whitehat researchers are rejected.
- **Attack pattern correct** — the `attackPattern` field must match the actual vulnerability type. Mismatched patterns corrupt the library.

### Should pass (approval likely)
- **Severity appropriate** — critical/high severity backed by actual fund loss or immediate risk. Low/medium submissions still welcome but should clearly justify the rating.
- **Novel contribution** — the finding adds new information not already in the library (different contract type, new variant of a known pattern, or documented real-world event).
- **Clean analysis** — AI analysis explains the root cause clearly, not just surface symptoms.

### Nice to have (not required)
- CVSS score (`cvssScore` field)
- Multiple findings in a single submission (different attack vectors on the same protocol)
- Links to onchain data, Dune dashboards, or published incident reports
- Patch recommendations (`recommendations` in the report output)

---

## Attack Patterns

Valid `attackPattern` values:

| Pattern | Description |
|---|---|
| `reentrancy` | External calls before state updates; recursive call attacks |
| `oracle-manipulation` | Spot price oracle attacks; Uniswap saw manipulation |
| `flash-loan-attack` | Flash loan amplified economic attacks |
| `access-control` | Missing/incorrect AccessControl, ownership bugs |
| `front-running` | MEV front-running of sensitive transactions |
| `sandwich-attack` | Front-run + back-run sandwich on DEX swaps |
| `integer-overflow` | Arithmetic bugs from overflow/underflow |
| `delegatecall-injection` | Malicious delegatecall target; library injection |
| `permit-front-run` | Permit signature front-running on DEXes |
| `liquidation-attack` | Oracle manipulation for underwater liquidations |
| `unknown` | None of the above — describe clearly in analysis |

---

## Common Rejection Reasons

1. **No transaction hash** — without an onchain anchor, there's no way to verify the attack happened
2. **Hypothetical only** — "this could be exploited" without actual exploitation
3. **Wrong attack pattern** — `reentrancy` used for what is actually `access-control`
4. **Copy-paste existing entries** — resubmitting already-documented exploits
5. **AI analysis missing or shallow** — "the contract has a bug" with no root cause explanation

---

## Questions?

Open an issue on [github.com/darks0l/threat-lab](https://github.com/darks0l/threat-lab) or reach out via the DARKSOL Discord.
