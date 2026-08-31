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

- **FUND** — activity the funder initiated for the buyer cohort, attributed by
  recovered transaction signer. USDC funding must satisfy
  `Σ FUND ≥ α_fund · Σ SETTLE`; native funding proves common seeding and
  ordering without comparing ETH and USDC units;
- **SETTLE** — `ChannelSettled` volume from those buyers to the subject,
  each strictly after its buyer's funding;
- **RETURN** — value flowing back seller → funder, per-hop retention ≥
  `ρ_hop`, end-to-end within `T_path` (`Σ RETURN ≥ α_return · Σ SETTLE`);
- **LEDGER** — for USDC-funded cohorts, per-buyer attribution through the protocol's own accounting:
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

The journal commits each seller address and the suspected wash volume derived
from authenticated settlement evidence. It deliberately does not prove or
publish a total-volume denominator or an ERC-8004 agent ID.

### Storage-layout bindings (verified against deployed bytecode)

The guest derives every proven storage slot itself; slots are never part of
the witness. Verified live on Base mainnet (`loop-host verify-layout`):

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

# live cross-check of pinned storage-layout constants against Base
cargo run -p loop-host -- verify-layout <seller_address> [seller_address ...]
cargo test -p loop-host -- --ignored     # same check as a test

# materialize an ad-hoc closed-loop case (archive RPC required for the
# period-end ledger proofs)
cargo run -p loop-host -- fetch --case cases/<case>.json --out fixture.json [--expect-reject]

# reproducible guest builds + vkey derivation (SP1 toolchain + Docker)
scripts/build-guests.sh

# produce one Groth16 aggregate (one child is still aggregated)
cargo run -p loop-host --features sp1 --bin wash-trading-aggregate -- \
  --aggregator-elf program/aggregator/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/aggregator-guest \
  --closed-loop-elf program/closed-loop/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/closed-loop-guest \
  --reciprocal-elf program/reciprocal/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/reciprocal-guest \
  --manifest historical-manifest.json \
  --child closed-loop:fixture.json --output aggregate-proof.json

# execute the checked-in synthetic closed-loop and reciprocal fixtures with
# SP1's mock prover and emit one local-development aggregate artifact
node scripts/generate-development-proofs.mjs \
  --output out/development-aggregate-proof.json
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
  --artifact-dir out/approved-development-proofs
```

The approved development runner also writes
`submit-historical-aggregate-calldata.json`. It records the aggregate program ID, vkey,
public values, proof bytes, and calldata for the immutable historical
registry's `submitHistoricalAggregate(bytes,bytes)` entrypoint. The registry
pins the aggregate vkey at deployment, so the program ID remains artifact
metadata and is not repeated in calldata.

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

# 3. Generate the immutable historical manifest.
node scripts/generate-historical-manifest.mjs \
  --bundle proof-bundle.json \
  --output historical-manifest.json

# 4. Quote and approve proving cost, then make compressed child proofs and one
# Groth16 aggregate. RPCs need eth_getProof at the historical period end.
node scripts/prove-approved-batch.mjs \
  --plan proof-plan.json \
  --manifest historical-manifest.json \
  --artifact-dir proof-artifacts \
  --closed-loop-elf target/guests/closed-loop/elf \
  --reciprocal-elf target/guests/reciprocal/elf \
  --aggregator-elf target/guests/aggregator/elf \
  --cost-quote proof-cost.json \
  --approve-cost-digest 0x... \
  --confirm-production-proving
```

`wash-trading-materialize-p0` consumes each claim's exact `selectedEvidence`.
It authenticates the selected receipt and transaction tries, adds mandatory
period-end `Deposits.buyers[*].balance` proofs with no opening-balance credit,
and natively verifies the final witness before it is passed to SP1.
Reciprocal claims also include
pair-internal protocol deposits selected by the planner.

The final `antseed-wash-trading-aggregate-proof` artifact contains exactly one
registry-ready `publicValues` blob and one Groth16 `proofBytes` blob. Public
values contain the report root, manifest digest, fixed period, exact claim and
seller counts, sorted seller volumes, total proven wash volume, and the number
of private manifest block references. No per-child on-chain submission exists.

Before production submission, run the coverage report and the AntSeed
repository's volume verifier. The signed analysis baseline, current planner,
refetched authenticated receipts, host metrics, and journal wash volumes must
all agree exactly.

## Rule identity

`PREDICATE_VERSION`, every α/β/ρ/ε parameter, the
contract addresses and storage-slot bindings are constants in
`predicate/src/lib.rs`. Changing any of them changes the child vkey and
therefore the rule. This historical registry pins one aggregator vkey and
accepts one complete result. Any ongoing proof system is deployed separately. Current
parameter values are **calibration placeholders** — final values are fixed
by the companion wash-trading detection AIP before a registry is bound to a
live policy.

Guest builds are dockerized (`scripts/build-guests.sh`) so any party can
independently re-derive the pinned vkeys from source.
