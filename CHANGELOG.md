# Changelog

All notable changes to this project are documented in this file.

## v0.4.0 — 2026-05-20

- feat: add `watch <path>` monitor mode with interval-based rescans, diffing, snapshot output, and escalation alerts
- feat: reuse project-level dependency audit + threat-intel passes across all scanned Solidity files for faster unified scans
- feat: correlate live threat intel against declared project dependencies and dependency-audit signals before escalating alerts
- feat: add structured security-gate summaries for `scan --fail-on <severity>` with per-category counts
- fix: suppress duplicate structured findings and duplicate watch alerts in monitor cycles
- fix: downgrade weak, uncorrelated exploit chatter so reports stop over-warning on background noise
- docs: refresh README around unified scan/watch workflows and current package positioning
- test: expand scanner coverage for watch mode, correlated intel, weak-signal suppression, and gate summaries

## v0.3.1 — 2026-05-15

- feat: add `scan --compare <baseline.json>` report diffing for saved scan artifacts
- feat: add `scan --fail-on <severity>` security gates for CI/release enforcement
- test: cover scan diffing and severity-threshold helpers
- docs: document baseline comparisons and security-gate usage

## v0.3.0 — 2026-05-10

- feat: first polished npm/GitHub release pass for Threat Lab
- feat: ships unified scan/audit/run/library CLI flow for exploit research and pattern capture
- feat: includes real Solidity scenario contracts, pattern library plumbing, and multi-model analysis integration
- docs: adds release changelog and refreshes package metadata for publish readiness

## v0.2.0 — 2026-05-10

- feat: runner reads actual `.sol` files
- feat: `--json` output support
- feat: `--version` flag
- feat: `.env.example`
- test: 89 tests passing
