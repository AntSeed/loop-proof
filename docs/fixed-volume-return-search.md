# Search for 50% returns without reducing proven volume

This workflow upgrades return evidence only for supported sellers whose current
return ratio is below the search target. The target defaults to 5,000 basis
points. It does **not** change the active guest policy, guest key, old proof
lists, settlements, funding, buyer ledgers, or authenticated period-end total.

The objective is `R >= ceil(V * targetBps / 10000)` at the **existing V**.
Finding more settlement receipts is not a substitute for finding more returns.
Existing proofs from a guest with an equal or higher return floor are skipped;
excluded sellers are not reintroduced. Missing return measurements are reported
rather than assumed to qualify.

## Search

Run from the proof repository. Paths below are placeholders for your files:

```sh
node scripts/search-fixed-volume-returns.mjs \
  --status /absolute/path/to/verified-status.json \
  --manifest /absolute/path/to/search-manifest.json \
  --trace-dir /absolute/path/to/raw/traces \
  --target-bps 5000 \
  --out-dir /absolute/path/to/NEW-search-directory
```

The status uses the existing proof-history seller format. Each manifest seller
contains `seller`, `sellerInput`, and `baselineReturns`, plus optional
`candidateSources` and `traceOverrides` (address-to-file mapping). Seller inputs
use the current single-evidence schema. Baseline returns can be an existing
selected plan or a `{paths: [{hops: [...]}]}` document. Additional candidate
sources may also use `{edges, paths}` graphs with edge-ID path references.

The search checks baseline artifact hashes and V/T, fixes the settlement volume,
and considers both baseline-preserving augmentation and a fresh greedy return
selection. It never keeps a selection with less return credit than the baseline.
Paths must connect the same seller and funder, fall within the period, respect
the path window and hop-retention rules, and use distinct transfers.

Outputs distinguish `candidate-target-met-needs-authentication` from
`candidate-shortfall`. A shortfall is **not** proof that no additional evidence
exists: cached discovery and greedy selection are not exhaustive. Fresh cached
discovery handles direct, two-hop and three-hop returns; supplied candidate
graphs can contain paths up to the predicate's nine-transfer limit.

## Refresh missing traces

```sh
node scripts/refresh-return-search-traces.mjs \
  --summary /absolute/path/to/search/summary.json \
  --manifest /absolute/path/to/search-manifest.json \
  --out-dir /absolute/path/to/NEW-trace-directory
```

This requires `BASE_RPC_URL` with Alchemy's read-only asset-transfer API. It
refreshes only sellers still short of the target, their funder inbound transfers,
and missing relay traces, bounded to the original block period. The default cap
is 30 pages per directional query; `--max-pages` can change it. Truncated or
failed requests are explicitly recorded, never described as complete history.
Run the search again in a new directory with the emitted `manifest.json`.

## Authenticate successful candidates

```sh
cargo build --release -p loop-host --bin wash-trading-expand-returns
node scripts/authenticate-fixed-volume-returns.mjs \
  --summary /absolute/path/to/search/summary.json \
  --binary /absolute/path/to/target/release/wash-trading-expand-returns \
  --out-dir /absolute/path/to/NEW-authentication-directory
```

Optional repeated `--seller ADDRESS` flags restrict authentication to selected
successful candidates, for example newly discovered successes after a refresh.
`BASE_RPC_URL` is required. Receipt metadata is checked first; the Rust helper
then authenticates inclusion proofs and runs `verify_seller` on the original and
expanded inputs. It checks the target against authenticated return credit and
requires unchanged V/T, settlements, fundings, buyers and ledgers. Only return
paths and the block evidence needed for those paths are expanded.

`native-verified-at-target` is **not** a new 50% guest proof. The output explicitly
records the active predicate floor, independently checked target, and absence
of guest execution. Building a 50% guest and generating its development/network
proofs remain separate steps. No command here submits a transaction or a prover
network request. Existing proof bytes must not be relabeled as 50% proofs.

All run directories must be new. Preserve the status, manifest, source evidence,
and prior run directories when retrying or expanding a search.

## Joint settlement and return expansion

`search-joint-wash-volume.mjs` expands both candidate settlements and returns for
the remaining `shortfall` sellers in the fixed-volume history. It evaluates every
identified positive USDC funding cohort separately, rather than pooling capital
or returns from different funders. The existing V is an adoption floor: a smaller
candidate is retained only as a diagnostic, never used to replace the baseline.

```sh
node scripts/search-joint-wash-volume.mjs \
  --history docs/proof-history/2026-09-05-alpha-return-50-fixed-volume-search.json \
  --manifest /absolute/path/to/refreshed/manifest.json \
  --baseline-bundle /absolute/path/to/proof-bundle.json \
  --scan-dir /absolute/path/to/scan \
  --target-bps 5000 \
  --max-graph-steps 20000000 --max-return-candidates 250000 \
  --out-dir /absolute/path/to/NEW-joint-search-directory
```

The return graph loads two relay frontiers and can follow simple paths of up to
nine transfers through the loaded graph. It reports missing traces and search
limits. Even an untruncated run is not a global impossibility proof or a claim
of globally optimal return selection. The refresh script accepts additional
`--relay ADDRESS` values and an optional `--from-block` inside the original
period, to investigate an observed intermediary over the relevant activity range.

The planner's joint-search mode ranks larger V before lower proof cost and uses
an explicit return target; the active guest default and existing checkpoint
policy are unchanged. Joint searches authenticate draft metadata afresh rather
than reuse policy-bound planner checkpoints. Results separate:

- All discovered post-funding settlement candidates.
- Ledger-selected volume before applying return coverage.
- Candidate volume satisfying the 50% return target.
- Whether that candidate preserves or improves the existing V.

Candidate plans are marked `analysisOnly` and `nativeVerified: false`. Passing
these planning checks is not a proof. Any eligible larger/same-volume candidate
still requires inclusion proofs, native verification, and the appropriate guest
proof before submission. A failed search preserves the original evidence.
