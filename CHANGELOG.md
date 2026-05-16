# Changelog

All notable changes to this project are documented in this file.

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
