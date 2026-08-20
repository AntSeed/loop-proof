# Wash-Trading Proof Coverage Report

## Status

- Scan period: Base blocks `44,471,575` through `49,936,173` exclusive.
- Approved report root: `0x9c78028391a4ba30c63fd823955b3e13552397047ca496bac1cc317c782e3fc7`.
- Findings planned and executed: **42 of 42**.
- Execution mode: **development** (`RISC0_DEV_MODE=1`).
- Production-valid proofs: **0**. Development receipts cannot be submitted onchain.

## Volume Coverage

| Policy | Findings | Report-classified volume | Authenticated compact-proof volume | Coverage |
| --- | ---: | ---: | ---: | ---: |
| P0 closed loop | 1 | 33,554.340699 USDC | 1,006.698680 USDC | 3.00% |
| P1 coordinated control | 17 | 108,688.801163 USDC | 17,001.841545 USDC | 15.64% |
| P0 reciprocal | 24 | 11,924.872200 USDC | 241.400000 USDC | 2.02% |
| Cohort policies combined | 18 | 142,243.141862 USDC | 18,008.540225 USDC | 12.66% |

The compact proofs authenticate **18,249.940225 unique USDC** across **13,123 unique settlement logs** after deduplicating selected evidence across all claims.

There is no sound single global coverage percentage for v1. Cohort and reciprocal report volumes can contain the same settlements, so their `154,168.014062 USDC` arithmetic sum is not a deduplicated denominator. Presenting `18,249.940225 / 154,168.014062` as global coverage would understate or overstate coverage depending on the overlap.

## What Was Proved

Every finding successfully executed its compact guest predicate and authenticated its selected receipts or transactions against Base block roots. Each proof also checked membership in the governance-approved report root and the claim dependency root.

The result is a conservative enforcement statement: every report finding has enough authenticated onchain evidence to satisfy its compact penalty predicate. It is not a proof that every settlement contributing to the full report-classified volume was individually authenticated inside the zkVM.

## Execution Cost

- Total zkVM cycles across 42 development executions: `12,259,737,600`.
- Total user cycles: `11,336,504,197`.
- Largest claim: `0x6d4741d976aa07cff99655ff88bb427fb28c38a1af8633f09af962a00dbe8b91` at `1,289,224,192` total cycles.
- Evidence object references: `13,376`.
- Unique Base blocks: `13,092` (`12,596` checkpoint-range targets plus `496` historical blocks).
- AggregateVerifier checkpoint windows: `7,321`.

## Artifacts

- Proof bundle: `/tmp/proof-bundle-v1.json`
- Proof plan: `/tmp/proof-plan-v1.json`
- Consolidated development results: `/tmp/proof-results-v1.json`
- Machine-readable coverage report: `/tmp/proof-coverage-v1.json`
- Per-claim results and logs: `/tmp/wash-proof-results-20260819/`

## Production Gap

To submit penalties, an operator must generate production receipts for both current image IDs, approve and configure the report root and image IDs in the registry, submit the required historical/checkpoint state proofs, dry-run all calls on a Base fork, and then explicitly run the submission command with `--submit`.

The v1 design deliberately trusts the approved report root for completeness-dependent facts. No fraud-proof challenge system is required for the compact enforcement claims, but governance approval of a wrong or incomplete report root remains a trust risk.
