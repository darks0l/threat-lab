# Changelog

All notable changes to this project are documented in this file.

## v0.4.2 — 2026-05-29

- feat: add `monitor add|list|scan` commands for multi-repo fleet monitoring
- feat: persist fleet registry, last fleet scan, and deduped threat memory under `.threat-lab/`
- feat: build cross-repo dependency exposure maps so shared package blast radius is visible
- feat: track package-level threat sightings across scans with first-seen / last-seen / repo exposure state
- docs: add fleet monitor usage and persistent threat-state documentation

## v0.4.1 — 2026-05-29

- feat: export unified scan results as SARIF 2.1.0 for GitHub code scanning and CI security pipelines
- feat: add a reusable composite GitHub Action wrapper via `action.yml`
- fix: auto-create nested output directories for `scan --output` targets
- docs: add wrapper usage, SARIF workflow examples, and version-pinned action guidance
- chore: align package metadata / lockfile versioning for the new release

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
