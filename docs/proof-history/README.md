# Seller proof list history

## Uniform 30% development replay — September 5, 2026

- Frozen inputs: `2026-09-05-alpha-return-30-development-replay.json`.
- Completed results: `2026-09-05-alpha-return-30-development-result.json`.
- All 54 sellers passed the attested 30% guest and all 54 passed local Anvil
  submission tests. V is 146,692.697298 USDC; T is 190,205.878768 USDC.
  Development success does not resolve the production blockers below.
- Workflow: `../development-replay.md`.
- Fresh artifacts and live progress: `/Users/alex/Documents/code/antseed-org/loop-proof/out/vt30-development-replay-2026-09-05/summary.json`.
- Local submission results: the same output directory's `anvil/summary.json`.
- The manifest requests all 54 supported sellers under the attested 30% guest,
  including four expanded return witnesses previously verified only natively.
- Completion must be read from these summaries; the manifest is not a result.
- This is development-only validation of the existing predicate. The AIP-4
  attribution/calibration/denominator findings remain unresolved. Old archives
  and previous run statuses below remain unchanged.

## Joint V and R expansion at 50% — September 5, 2026

- Results: `2026-09-05-alpha-return-50-joint-search.json`.
- Prompt-Forge and NoaxAI were scanned across all three identified USDC funding
  cohorts each, with refreshed intermediary traces and a longer-path graph search.
- Additional settlement candidates were found, but buyer-ledger-selected volume
  and qualifying return credit did not increase. Neither remaining seller reached
  50% at its existing V. Smaller candidates were not adopted.
- Old results and the active guest were preserved. No new proofs or submissions
  were made; this result does not establish global impossibility.

## Fixed-volume 50% evidence search — September 5, 2026

- Results: `2026-09-05-alpha-return-50-fixed-volume-search.json`.
- Only the six supported sellers below 50% were searched. Existing V/T and
  the other 48 sellers were preserved; their archived artifact hashes rechecked.
- ClaudeNode, StrataCode, Argus AI and surplus-provider now have authenticated
  returns passing native verification and an independent 50% check at unchanged V.
- Prompt-Forge and NoaxAI remain below 50%. No settlement volume was trimmed
  to make their ratios pass. The search is not exhaustive.
- The active guest is still 30%; this run produced no new 50% guest proofs,
  network submissions or contract submissions. Old proof lists remain intact.
- Reusable workflow: `../fixed-volume-return-search.md`.

Changing the return threshold creates a new policy and guest verification key.
It does not replace the old seller list or make old proof bytes valid for the
new key. These are development proofs, not prover-network submissions.

## Archived 50% baseline — September 5, 2026

- List: `2026-09-05-alpha-return-50.json` in this directory.
- 55 attempted sellers: 48 development-verified artifacts and 7 rejected sellers.
- Selected wash volume: 109,628.858655 USDC.
- Alpha return: 5,000 bps.
- Guest vkey: `0x00927080e32e3a180eb47f209908519abc780cf84d1e3d4a95000310fa2f4c32`.
- Full local archive: `/Users/alex/Documents/code/antseed-org/loop-proof/out/proof-history/alpha-return-50-2026-09-05`.

The archive contains copied development artifacts, seller input witnesses,
reproducible guest/attestation, the source base commit and uncommitted patch.
The list records SHA-256 hashes of all 48 development artifact files. Neither
the old 20% outputs nor the original 50% outputs were overwritten.

## Active 30% policy — September 5, 2026

- Alpha return: 3,000 bps, defined in `predicate/src/lib.rs`.
- Guest vkey: `0x0028d499469d8bdb345427dccf15bbbf3f1c582625a0a5690e7ac3576ef6ed99`.
- Reproducible guest: `/Users/alex/Documents/code/antseed-org/loop-proof/out/vt30-reproducible-2026-09-05`.
- New candidate outputs: `/Users/alex/Documents/code/antseed-org/loop-proof/out/vt30-2026-09-05/usdc-candidates`.
- Finished list: `2026-09-05-alpha-return-30-candidates.json` in this directory.
- Four of four candidates passed native verification and the new guest's
  development/mock proof verification: 16,126.074805 USDC selected wash volume.
- This is the four-candidate run, not a regenerated 30% batch of all 55 original
  sellers. No prover-network or contract submission was made in this run.

### Expanded original sellers — validated

- Prompt-Forge and NoaxAI both passed native verification, execution of the new
  30% guest and development/mock proof verification with expanded return evidence.
- Their full original wash volumes were preserved: 11,156.194466 and
  9,781.569372 USDC respectively, totaling 20,937.763838 USDC. Authenticated
  return coverage is 30.8133% and 33.6113%; no settlements were trimmed.
- Results: `2026-09-05-alpha-return-30-expanded-originals.json`.
- Full reconciled list: `2026-09-05-alpha-return-30-status.json`.
- Verified evidence meeting the 30% return floor now supports 146,692.697298
  USDC across 54 sellers: 48 previously verified with the stricter 50% guest,
  plus six verified with the new 30% guest. The six new-guest artifacts cover
  37,063.838643 USDC. The other 48 still need regeneration for a uniform 30%
  guest batch; their old proof bytes cannot be submitted under the new key.
- Five prior period-end binding failures remain excluded and were not rerun.
  The old 50% list is unchanged, and all 48 archived artifact hashes were checked.
- Full output: `/Users/alex/Documents/code/antseed-org/loop-proof/out/vt30-2026-09-05/expanded-original-sellers/REPORT.md`.

Read `validation-current-summary.json` or `REPORT.md` in the new output
directory for finished candidate outcomes. The original `validation-summary.json`
preserves the first attempt, including two materializer format failures that
were fixed and revalidated. A draft bundle is not a validated proof. Original draft
candidate amounts remain recorded separately from ledger-selected amounts.

Do not sum successive claims for the same seller: stronger evidence replaces
the seller's selected wash volume, rather than adding overlapping settlements.
Keep this history and its large local artifact archive when cleaning build
outputs. The source-tree lists are small; large proof artifacts are not included
in Git. Until reviewed and committed, the new history files remain local changes.
