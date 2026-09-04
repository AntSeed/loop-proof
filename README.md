# antseed-loop-proof

Reference implementation of **AIP-4: Proof-Carrying Wash-Trading Enforcement**
— the zkVM guests, the conserved-value-loop predicate library, and the host
tooling that materializes raw Base evidence into guest witnesses.

A finding against a seller is never attested; it is **proven**. A guest
program re-verifies raw Base evidence — receipts, transactions, and contract
state, each authenticated by Merkle-Patricia proofs against block headers —
and checks a fixed mechanical predicate. The guest's verification key **is**
the rule: the historical `AntseedWashTradingRegistry` (AntSeed monorepo)
verifies one recursive SP1 aggregate and permanently records the complete
approved snapshot. The aggregate guest authenticates the fixed manifest of
claims, seller volumes, and evidence-block hashes. Ongoing submissions are a
separate future registry design.
No committee, no multisig, no challenge
window, no company API, no scheduled infrastructure.

## What the predicates prove

Both predicates prove a **conserved value loop**, not the existence of
transfers. Because claim submission is permissionless and the record is
permanent, the claimant is assumed adversarial: a predicate satisfiable by
sprinkling a few dollars around an honest seller would be a weapon. Three
magnitudes must therefore be bound together at comparable scale:

Predicate version 8 removes native funding from closed-loop proofs. Existing
native-funded plans, witnesses, proofs, and closed-loop guest vkeys are not
valid for this rule version and must not be submitted to a production registry.

- **FUND** — USDC activity the funder initiated for the buyer cohort. Funding
  must satisfy `Σ FUND ≥ α_fund · Σ SETTLE`; native funding is rejected because
  ETH value cannot establish conservation of USDC settlement volume;
- **SETTLE** — `ChannelSettled` volume from those buyers to the subject,
  each strictly after its buyer's funding;
- **RETURN** — value flowing back seller → funder, per-hop retention ≥
  `ρ_hop`, end-to-end within `T_path` (`Σ RETURN ≥ α_return · Σ SETTLE`);
- **LEDGER** — per-buyer attribution through the protocol's own accounting:
  `Deposits.buyers[b].balance` proven at the period end must reconcile
  with the funder-attributed capital
  (`balance_end + settledₑᵥ ≤ funded · (1 + ε_ledger)`).

  *Note:* the deployed `AntseedDeposits` keeps a net `balance`, not a
  lifetime-cumulative deposit counter, so this balance-delta reconciliation
  is the strongest end-state witness form of AIP-4's attribution requirement
  implementable against deployed state. Unseen outflows (spend to other
  sellers, withdrawals) only make the check *stricter* for the claimed
  buyers' inflow, and looser measurement never flags anyone by itself —
  the RETURN and coverage legs still bind.

**There are no volume floors and no minimum cohort size.** Every parameter
is a ratio or an evidence-shape bound. A floor in a public immutable rule
tells an operator how finely to slice; ratios have no edge to sit under, and
splitting fabricated volume across identities *raises* each identity's
proven ratio.

Each child journal commits the seller address and suspected wash volume derived
from authenticated settlement evidence. The seller aggregate unions settlement
IDs across claims, deduplicates overlaps, and rejects conflicting amounts for
the same settlement. A later proof can replace a seller result only when it
proves a strictly greater wash-trading volume.

### Storage-layout binding

The guest derives the buyer-ledger storage slot itself; slots are never part of
the witness:

| binding | contract | slot |
|---|---|---|
| `buyers[buyer].balance` | Deposits `0x0F7a…9fD2` | `keccak(buyer ‖ 9)` |

## Layout

```
core/               MPT/receipt/transaction/state-proof primitives (zkVM-agnostic)
predicate/          P0_CLOSED_LOOP + P0_RECIPROCAL predicates, journal, native tests
program/closed-loop SP1 guest (standalone crate, needs the SP1 toolchain)
program/reciprocal  SP1 guest
program/aggregator  recursive SP1 guest; emits the registry ABI
host/               witness materializer, prover driver, live layout cross-check
cases/              example case descriptions
scripts/            reproducible guest builds
```

## Usage

```bash
# native predicate + evidence-authentication tests (no zkVM toolchain needed)
cargo test

# materialize an ad-hoc closed-loop case (archive RPC required for the
# period-end ledger proofs)
cargo run -p loop-host -- fetch --case cases/<case>.json --out fixture.json [--expect-reject]

# reproducible guest builds + vkey derivation (SP1 toolchain + Docker)
scripts/build-guests.sh

# produce one seller-focused Groth16 aggregate (one child is still wrapped)
cargo run -p loop-host --features sp1 --bin wash-trading-aggregate -- \
  --seller 0x... \
  --aggregator-elf program/aggregator/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/aggregator-guest \
  --closed-loop-elf program/closed-loop/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/closed-loop-guest \
  --reciprocal-elf program/reciprocal/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/reciprocal-guest \
  --child closed-loop:fixture.json --output seller-proof.json

# execute the checked-in synthetic closed-loop and reciprocal fixtures with
# SP1's mock prover and emit one local-development artifact per seller
node scripts/generate-development-proofs.mjs \
  --output-dir out/development-proof-artifacts/sellers
```

The generator rebuilds all three guest ELFs by default. Pass
`--skip-guest-build` only for a fast repeat run against already-built ELFs.

Development artifacts are explicitly marked `securityMode: development` and
must only be submitted to the digest-pinned local verifier used by the AntSeed
Anvil E2E. They are not production proofs and are rejected by production
proving workflows.

To execute every claim in an approved historical report, use the fail-closed
batch generator. It rejects subset plans and prints the final unique suspected
USDC volume only after every approved claim is represented in the aggregate:

```bash
node scripts/generate-approved-development-proofs.mjs \
  --bundle /path/to/proof-bundle.json \
  --plan /path/to/proof-plan.json \
  --snapshot-lock /path/to/snapshot-lock.json \
  --artifact-dir out/approved-development-proofs
```

Pass `--witness-only` to stop after every canonical witness has been
materialized and verified by the native guest predicate. This mode does not
build SP1 proofs, contact a prover network, or produce submission calldata:

```bash
node scripts/generate-approved-development-proofs.mjs \
  --bundle /path/to/proof-bundle.json \
  --plan /path/to/proof-plan.json \
  --snapshot-lock /path/to/snapshot-lock.json \
  --artifact-dir out/approved-development-witnesses \
  --witness-only
```

The approved development runner also writes
`submit-historical-aggregate-calldata.json` and
`block-authentication-chunks.json`. The first records the aggregate program ID,
vkey, public values, proof bytes, and calldata for
`submitHistoricalAggregate(bytes,bytes)`. The second contains every canonical
block reference grouped into fixed 100-reference chunks with Merkle proofs
against the root committed by SP1. After the aggregate is staged, anyone can
authenticate chunks in any order against Chainlink BlockhashStore and call
`finalizeHistoricalResult` once all references are present. Seller records and
ratios are unavailable before finalization.

`summary.json` distinguishes complete source evidence from enforcement output:
`uniqueSettlementVolumeRaw` totals deduplicated settlements represented by all
approved claims, while `aggregate.provenWashVolumeRaw` is the authoritative
on-chain total after greatest-ratio selection for sellers appearing in multiple
claims.

After proving, reconcile verified child artifacts back into discovery states
and emit the final investigated-seller table:

```bash
node scripts/reconcile-development-proof-results.mjs \
  --discovery /path/to/discovery/p0-loop-candidates.json \
  --bundle /path/to/proof/closed-loop-approved-bundle.json \
  --children out/approved-development-proofs/children \
  --aggregate out/approved-development-proofs/aggregate-proof.json \
  --diagnostics /path/to/proof/candidate-diagnostics.json \
  --output out/approved-development-proofs/validation-report.json
```

The current approved report is one historical period, not independently
epoch-sliced claims. Child and aggregate journals commit only that fixed block
range; they do not derive or publish reward epochs.

Case files in `cases/` describe a claim's participants (seller, funder,
buyers, return paths). `--expect-reject` asserts that the predicate
correctly rejects the evidence — use it for honest-seller test vectors
where the conserved-loop shape is absent.

Block evidence is checkpointed atomically after every successful RPC fetch in
`cache/block-evidence-v1/`. Re-running the same case resumes from those files,
and progress reports separate cache hits from RPC fetches. Set
`LOOP_EVIDENCE_CACHE_DIR` to place the checkpoint outside the repository; the
cache key includes the block number and exact receipt/transaction targets, so
evidence from a different selection is never reused.

`scripts/build-case.py` reads each buyer's Deposits balance at the period-end
block and selects funding that satisfies the P0 ledger inequality per buyer
before topping up the aggregate 90% funding requirement.

## Production batch pipeline

Production proving starts from the approved detection bundle and never from an
operator-maintained case list. The planner authenticates every dependency,
requires its selected settlement volume to equal the bundle's approved analysis
metrics, and emits `antseed-wash-trading-proof-plan` v2. Claim IDs emitted by
the guests additionally bind the complete authenticated witness, so two
different evidence selections cannot occupy the same on-chain claim ID.

```bash
# 1. Authenticate and plan the exact approved claim set.
node scripts/plan-wash-trading-proofs.mjs \
  --bundle proof-bundle.json \
  --out proof-plan.json \
  --rpc-url "$BASE_RPC_URL"

# 2. Build all three guests twice in isolated snapshots and compare ELFs/vkeys.
node scripts/build-guests-reproducibly.mjs --work-dir ../guest-repro-builds --out guest-build-attestation.json
node scripts/verify-guest-build-attestation.mjs guest-build-attestation.json

# 3. Run the smallest seller as a paid canary. The guarded runner checks the
# deposited PROVE balance and all three vkeys, binds a marketplace max-price
# cap into the approved quote, runs a no-spend preflight, and requires a second
# explicit confirmation before sending any paid request.
BASE_RPC_URL="$BASE_RPC_URL" scripts/run-production-proofs-safe.sh canary

# 4. After validating the canary artifact, resume the same checkpoint directory
# and produce the remaining children and seller aggregates.
BASE_RPC_URL="$BASE_RPC_URL" scripts/run-production-proofs-safe.sh full
```

The default canary is the smallest current seller proof: one child and 202
authenticated block references. Set `WASH_TRADING_CANARY_SELLER` to select a
different approved seller. Completed production children and seller aggregates
are validated and reused, so interruption or a later full run does not repay for
finished proofs. `WASH_TRADING_CHILD_CONCURRENCY` and
`WASH_TRADING_SELLER_CONCURRENCY` default to `1`; raise them only after the
canary succeeds.

`wash-trading-materialize-p0` consumes each claim's exact `selectedEvidence`.
It authenticates the selected receipt and transaction tries, adds mandatory
period-end `Deposits.buyers[*].balance` proofs with no opening-balance credit,
and natively verifies the final witness before it is passed to SP1.
Reciprocal claims also include
pair-internal protocol deposits selected by the planner.

Each `antseed-wash-trading-seller-proof` artifact contains one registry-ready
`publicValues` blob and one Groth16 `proofBytes` blob. Public values contain the
fixed period, pinned child vkeys, seller identity, deduplicated wash volume,
evidence digest, and block-authentication commitment.
Child proofs and settlement IDs remain private to the recursive aggregate.

Before production submission, run the coverage report and the AntSeed
repository's volume verifier. The signed analysis baseline, current planner,
refetched authenticated receipts, host metrics, and journal wash volumes must
all agree exactly.

## Rule identity

`PREDICATE_VERSION`, every α/β/ρ/ε parameter, the
contract addresses and storage-slot bindings are constants in
`predicate/src/lib.rs`. Changing any of them changes the child vkey and
therefore the rule. The historical registry pins the seller aggregator and
both child vkeys, and accepts only strictly stronger results for a seller. Current
parameter values are **calibration placeholders** — final values are fixed
by the companion wash-trading detection AIP before a registry is bound to a
live policy.

Guest builds are dockerized (`scripts/build-guests.sh`) so any party can
independently re-derive the pinned vkeys from source.

## Unified historical snapshot

Do not merge claims from separate scans. Freeze one cutoff, run one exhaustive
all-seller scan, and reuse earlier trace artifacts only as immutable prefixes:

```bash
cd /path/to/analyses/wash-trading
pnpm run wash-trading:scan -- \
  --discover-p0 \
  --seed-scan /path/to/original-scan \
  --seed-scan /path/to/noax-scan \
  --to 2026-08-31T00:00:00Z \
  --output /path/to/unified-scan \
  --rpc-url "$BASE_RPC_URL"
```

The scanner refreshes Antscan's indexed seller universe, evaluates every seller,
requires zero incomplete discovery entries, and writes `proof/proof-coverage.json`.
Existing complete traces are reused; traces ending before the cutoff fetch only a
one-second-overlapping suffix and canonically deduplicate transfers.

Build one authenticated bundle and proof plan from that scan:

```bash
cd /path/to/loop-proof
node scripts/build-unified-historical-snapshot.mjs \
  --scan-dir /path/to/unified-scan \
  --out-dir out/unified-historical \
  --rpc-url "$BASE_RPC_URL"
```

This writes `proof-bundle.json`, `proof-plan.json`, and `snapshot-lock.json`.
The lock commits the scan sources, complete seller universe, frozen timestamp and
block cutoff, policy version, report root, proof plan, claim/seller counts, and
full proven wash volume.

Generate every development witness and the single development aggregate:

```bash
node scripts/generate-approved-development-proofs.mjs \
  --bundle out/unified-historical/proof-bundle.json \
  --plan out/unified-historical/proof-plan.json \
  --snapshot-lock out/unified-historical/snapshot-lock.json \
  --artifact-dir out/unified-historical/development
```

This is local development proving only. It does not submit paid production proofs
or deploy the historical registry.
