# Pattern Library Submission Guide

The Threat Lab pattern library is a permanent, growing record of real exploit patterns. Every submission makes the platform smarter.

---

## How to Submit a Finding

### Via CLI

```bash
# Generate a submission file from a run
threat-lab run reentrancy-101 --network anvil

# The run output will show the report ID
# Submit it to the library:
threat-lab submit submission.json
```

### Via API

```bash
curl -X POST https://your-threat-lab-instance.com/api/submit \
  -H "Content-Type: application/json" \
  -d @submission.json
```

---

## Submission Format

A valid submission JSON file:

```json
{
  "version": "1.0",
  "scenario": "reentrancy-101",
  "chainId": 1,
  "attackerAddress": "0x...",
  "victimAddress": "0x...",
  "txHash": "0x...",
  "blockNumber": 12345678,
  "findings": [
    {
      "id": "uuid-here",
      "scenarioId": "reentrancy-101",
      "attackPattern": "reentrancy",
      "severity": "critical",
      "title": "Reentrancy in withdraw function",
      "description": "...",
      "affectedContracts": ["0x..."],
      "txHash": "0x...",
      "chainId": 1,
      "aiModel": "claude-sonnet-4-6",
      "aiAnalysis": "...",
      "submittedAt": "2026-04-21T00:00:00.000Z",
      "tags": ["web3", "solidity", "reentrancy"]
    }
  ],
  "aiSummary": "...",
  "submittedBy": "your-name or org",
  "timestamp": "2026-04-21T00:00:00.000Z"
}
```

---

## What Gets Stored

- **Attack pattern** — categorized from the 11 known patterns
- **Severity** — critical / high / medium / low / informational
- **AI analysis** — multi-model threat report
- **Recommendations** — prevention steps
- **On-chain evidence** — transaction hashes, block numbers, contract addresses
- **Pattern library grows** — future scans use this data for smarter detection

---

## Attack Patterns

| Pattern | Description | Severity |
|---|---|---|
| `reentrancy` | Recursive external calls before state update | critical |
| `oracle-manipulation` | Flash loan price oracle attacks | high |
| `flash-loan-attack` | Uncollateralized borrow + arbitrage | medium |
| `access-control` | Missing/incorrect permission checks | critical |
| `front-running` | Transaction order exploitation (MEV) | medium |
| `sandwich-attack` | Front-run + back-run combo | medium |
| `integer-overflow` | Arithmetic without Safemath/unchecked | high |
| `delegatecall-injection` | Storage corruption via delegatecall | critical |
| `permit-front-run` | EIP712 permit signature replay | medium |
| `liquidation-attack` | Oracle manipulation for unfair liquidation | high |
| `unknown` | Novel pattern not yet categorized | varies |

---

## Quality Standards

**Good submissions include:**
- Real transaction hashes (not mocked)
- Actual contract addresses
- Multi-model AI analysis confirmation
- Specific prevention recommendations

**Submissions may be rejected if:**
- No on-chain evidence (all mocked)
- Severity doesn't match the actual risk
- Duplicate of an existing high-confidence entry
- No meaningful analysis provided

---

## Exporting the Library

```bash
# Export full library as JSON
threat-lab export

# Import into another instance
threat-lab library import library-export.json
```

The library export is IPFS-ready. Pin it to preserve the collective knowledge permanently.
