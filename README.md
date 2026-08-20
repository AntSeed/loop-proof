# AntSeed Seller-Penalty Proof

This workspace contains the RISC Zero proof used by AntSeed's wash-trading
**enforcement** path. It proves one seller claim and can additionally reproduce
the exact settlement totals of an approved seller-report snapshot. It does not
prove or enforce every finding in the analytics report in
`../analyses/wash-trading`.

## Enforcement rule

The pinned guest proves all of the following:

1. The proof uses Base chain ID `8453`, Base USDC, the deployed AntSeed
   Channels contract, and the deployed AntSeed Deposits contract.
2. Authentic USDC receipts show a direct or relay path from the seller to one
   funder. Each relay forwards at least 98% within 43,200 Base blocks.
3. That funder authentically funded at least **three distinct buyers**. Each
   proven buyer received at least 1 USDC.
4. Authentic `ChannelSettled` receipts show those buyers later settled with
   the same seller. Every settlement must occur strictly after that buyer's
   proven funding.
5. The sum of the included post-funding settlement deltas is at least
   **1,000 USDC**.
6. No onchain log may be counted twice.
7. Every receipt is included in the receipts trie of its supplied Base header.
8. Every settlement in the approved seller-report snapshot is authenticated,
   unique, canonically ordered, and inside the fixed report period.
9. The authenticated snapshot reproduces its exact total volume, suspected
   volume, suspected-buyer count, and deterministic evidence root.
10. The proven common-funder cohort represents at least 50% of the approved
    report total. The registry pins both the report ID and evidence root.

If the proof and all referenced Base block hashes are accepted onchain, the
seller receives a fixed `9,000 BPS` reduction in **future seller points**.
Buyers receive no penalty.

The exact constants and logic live in `core/src/lib.rs`. The compiled guest
image ID is the versioned rule: changing a threshold or check changes the image
ID that the registry must pin.

## Public journal

The guest commits an ABI-encoded `SellerPenaltyJournal` containing:

- predicate version, Base chain ID, and pinned contract addresses;
- seller and funder;
- linked-buyer and relay-hop counts;
- fixed penalty BPS;
- proven seller outflow, total buyer funding, and suspicious volume;
- approved-report total and suspected volumes, suspected-buyer count, period,
  report ID, and deterministic evidence root;
- earliest funding and latest settlement blocks;
- every referenced `(block number, block hash)`.

The journal intentionally does not publish buyer addresses. The proof checks
that they are distinct, funded, and linked to the seller's settlements without
expanding permanent onchain state.

## Data integrity

There are two independent integrity checks:

1. **Inside the zkVM:** each referenced receipt has a Merkle-Patricia inclusion
   proof against the `receiptsRoot` in its supplied Base header. The guest then
   parses the authenticated USDC, `Deposited`, and `ChannelSettled` logs.
2. **In the registry:** every `(number, hash)` committed by the guest must be
   accepted by `IBaseAnalysisStateOracle.isCanonicalBlock`.

The second check is necessary because a valid receipt proof only proves that a
receipt belongs to the supplied header. The state oracle proves that the header
is actually a canonical finalized Base header. Historical `blockhash()` cannot
solve this because the EVM exposes only the latest 256 block hashes. A
blockhash keeper also cannot authenticate old blocks unless it was already
checkpointing them at the time.

`checkpoint/` implements that production path without an AntSeed L1 contract:

1. Steel authenticates Ethereum state through an Ethereum beacon root exposed
   by Base's EIP-4788 predeploy.
2. The checkpoint guest proves that Base's Ethereum AnchorStateRegistry accepts
   an AggregateVerifier game and reads one of its 30-block intermediate roots.
3. The guest checks the OP output-root preimage and a contiguous Base header
   chain from that checkpoint back to the requested evidence blocks.
4. `AntseedBaseCheckpointOracle` validates the Steel commitment on Base and
   permanently stores only those exact `(number, hash)` pairs.

RPC and Beacon API responses are witnesses, not trust assumptions. Invalid
responses fail inside Steel or the checkpoint guest.

## Why this path has no fraud-proof challenge

The common-funder enforcement evidence is monotonic:

- every included fact is authenticated;
- adding valid evidence can only strengthen or preserve the result;
- omitting evidence can only reduce the buyer count or proven volume;
- reduced evidence can only make the penalty harder to obtain.

A prover therefore cannot create a common-funder link by hiding unfavorable
data. The full-report mode additionally prevents a prover from substituting a
smaller report snapshot: deployment pins the approved report ID and evidence
root, and the guest must reproduce the exact pinned totals from authenticated
receipts.

This design deliberately trusts the governance-approved report snapshot. It
does not prove that the offchain report discovery process found every event on
Base. A permissionless completeness claim would still need either complete
event enumeration inside ZK or a challenge/fraud-proof mechanism.

## What is not proven

This proof does **not** establish:

- complete seller, buyer, transfer, or settlement activity;
- that the selected funder was the first or primary funder;
- that the proven buyers are all of the seller's buyers;
- that the approved report snapshot contains every historical settlement;
- the absence of organic buyers or legitimate activity;
- the report's ≥99% buyer classification rule from every buyer's activity with
  other sellers; the approved snapshot supplies that fixed classification;
- the full multi-seller P0/P1 analytics report;
- that every dishonest seller is detected.

Those completeness-dependent claims may still be useful in the separate
analytics/reporting system, but they do not control rewards.

## Enforcement scope

- Seller future points are reduced by 90% after proof acceptance.
- Buyer points are unchanged.
- Existing locked rewards are unchanged.
- No clawback or confiscation occurs.
- Exact proof replay is a no-op, and later proofs cannot increase the fixed
  penalty.

## Layout

- `core/` — input types, receipt authentication, predicate, and ABI journal.
- `methods/guest/` — RISC Zero guest entrypoint.
- `host/` — Base RPC evidence builder plus native, dry-run, and proving CLI.
- `enforcement-core/` — shared report-root, dependency, receipt, and transaction predicate logic.
- `cohort-methods/` — P0 closed-loop and P1 coordinated-control guest image.
- `reciprocal-methods/` — P0 reciprocal-pair guest image.
- `scripts/` — deterministic bundle planner.
- `checkpoint/` — isolated Steel-based Base checkpoint proof workspace.
- `cases/flash.json` — a three-buyer Base mainnet evidence request.
- `cases/flash-full-report.json` — the approved Flash snapshot request: all
  seller settlements plus the report's 55-buyer ≥99%-seller-share cohort.

The former full-analysis and challenge packages are not members of this
enforcement workspace. The JavaScript scanner in `../analyses/wash-trading`
remains a separate reporting tool.

## Run

Requires Rust 1.88 and the RISC Zero toolchain.

Copy `.env.example` to `.env` and set `BASE_RPC_URL`. The host reads that URL
first and falls back to public Base RPCs.

```bash
cargo build --release

# Discover all bounded settlements, select the exact minimum checkpoint
# windows, fetch only selected receipt proofs, and write both manifests.
./target/release/loop-host fetch \
  --case cases/flash.json \
  --out cases/flash-fixture.json \
  --selection-out cases/flash-selection.json

# Native validation plus zkVM execution, without producing a proof.
./target/release/loop-host run cases/flash-fixture.json

# Fast development receipt with real guest cycle counts.
RISC0_DEV_MODE=1 ./target/release/loop-host run \
  cases/flash-fixture.json --prove

# Real proof.
./target/release/loop-host run cases/flash-fixture.json --prove
```

The host prints user cycles, total cycles, segment count, journal SHA-256, and
the ABI journal bytes required by `submitSellerPenalty`. Cycle cost scales
primarily with the number and size of authenticated receipt proof paths.

### Full Flash report development proof

The full-report case reproduces the published Flash seller row, not the whole
multi-seller report. Generated fixture, selection, cache, and journal files are
ignored because the fixture is 480 MB and can be rebuilt from Base RPC data.

```bash
./target/release/loop-host fetch \
  --case cases/flash-full-report.json \
  --out cases/flash-full-report-fixture.json \
  --selection-out cases/flash-full-report-selection.json

# Development receipt only. RISC Zero prints an explicit warning that this is
# not a valid production proof.
RISC0_DEV_MODE=1 ./target/release/loop-host run \
  cases/flash-full-report-fixture.json \
  --prove \
  --journal-out cases/flash-full-report-journal.hex
```

The reproducible 2026-08-19 development run produced:

- 43,586 authenticated Flash settlements across 39,722 Base blocks;
- 44,847.928171 USDC exact approved-report total;
- 42,748.838506 USDC attributed to the report's 55 suspected buyers;
- 33,490.027681 USDC post-funding qualified volume across 38 linked buyers;
- report evidence root
  `0x8a0ce40f96615b8e93a0de20d7ac4b5a47ef96b688093cc48c863c948ad91c21`;
- journal SHA-256
  `0xf44a443d31a0418faa7d0e37f6c7a756af317da90b6f03c02e69d1f119d27d6c`;
- v3 seller image ID
  `0x0fb2461a755f36b945d5a82d26716c0e513452bca3f9d73e990bcf133d01e91a`;
- 29,295,611,813 user cycles and 31,979,995,136 total cycles across
  30,499 segments in 294.83 seconds;
- a 2,543,040-byte ABI journal.

The run used `RISC0_DEV_MODE=1`; it exercised and verified the real guest image
but intentionally produced no secure production proof.

### Base checkpoint dry run

The checkpoint workspace uses Rust 1.94 and pins Steel to commit
`f6fc6297c938d7acc0563337da136d034c3cb67b`.

```bash
cd checkpoint

# Resolve every selected 30-block window to an ASR-valid type-621 game at
# finalized Ethereum state. This only writes a proof plan.
cargo run --release -p checkpoint-host --bin checkpoint-plan -- \
  --selection ../cases/flash-selection.json \
  --out ../cases/flash-checkpoint-plan.json

# Live Ethereum/Base preflight plus zkVM execution. Defaults to one target
# 28 blocks behind the checkpoint.
cargo run --release -p checkpoint-host -- \
  --journal-out ../../antseed/packages/contracts/test/fixtures/checkpoint-journal.hex

# Development Groth16-shaped receipt; this is not a production-secure proof.
RISC0_DEV_MODE=1 cargo run --release -p checkpoint-host -- --prove
```

Each proof covers target blocks in one 30-block AggregateVerifier checkpoint
window. Generate multiple proofs for evidence spread across multiple windows.
The Base EIP-4788 history is approximately 4h33m, so a permissionless keeper
must call `archiveBeaconRoot(timestamp)` before a needed root expires. Missing
that call only prevents a penalty and therefore causes overpayment, never an
unsupported underpayment.

The current checkpoint image ID is
`e719072a9e3c7645903268b7e01079b5ea7704612b680d9401964b83a83e643e`.
A live 29-header run measured 7,923,466 user cycles and 9,568,256 padded
cycles. This cost is separate from the seller receipt proof and can be reused
for every seller proof that references the stored block hashes.
The two-block oracle storage path measured 91,338 execution gas with a mock
verifier; production total gas must add the real RISC Zero verifier and
transaction calldata.

### Current Base mainnet selection

`loop-host fetch` scans only the case's required `[start_block,
end_block_exclusive)` period and excludes blocks before AggregateVerifier
coverage. It first decodes settlement deltas from `eth_getLogs` as selection
hints, then runs an exact deterministic optimizer over protocol-aligned
30-block windows. Full receipts and Merkle proofs are fetched only for the
selected evidence, and the unchanged native predicate reauthenticates the
selected volume before either output file is accepted.

For the current `cases/flash.json` period, the live 2026-08-19 result is:

- 2,850 eligible settlement candidates across 3 buyers;
- 69 selected settlement receipts proving 1,000.701075 USDC;
- 70 referenced Base blocks in 49 total checkpoint windows;
- 40 ASR-valid AggregateVerifier games in the finalized checkpoint plan;
- an 838 KB optimized fixture, down from the former 11 MB fixture.

The earlier planning estimate was 573 windows. Live exact optimization found a
strictly better valid result: **49**. The unchanged native predicate and zkVM
guest both accept it, and the checkpoint planner resolves all 49 windows at
finalized Ethereum state. Artificially retaining 573 windows would violate the
minimum-window objective.

### Previous Base mainnet measurement

The former first-settlements fixture was fetched through `BASE_RPC_URL` and executed
with RISC Zero 3.0 in development proving mode on 2026-08-19:

- 3 linked buyers;
- 1,002 authenticated settlement receipts;
- 1,008 referenced Base blocks;
- 11 MB input fixture;
- 1,243.599300 USDC proven post-funding volume;
- **574,196,479 user cycles**;
- **623,378,432 total cycles** across 595 segments;
- 5.52 seconds for the local development receipt (not a secure proof).

This is roughly 195× the old 2.94M-cycle, three-settlement spike. The increase
comes from proving enough individual low-value settlement events to cross the
1,000-USDC threshold, not from searching the full analytics dataset.

The same fixture also produces 1,008 block references in the public journal.
A Foundry test using 1,008 references and a simple mapping-backed mock oracle
measured **1,771,484 execution gas** for `submitSellerPenalty`. This excludes
transaction intrinsic/calldata gas and uses a cheap mock verifier and oracle;
it is not a production gas quote. The real cost depends on how finalized Base
canonicality is authenticated. Before production, benchmark the exact calldata
against the real verifier/oracle or replace per-block calls with an audited
batch/range commitment that authenticates all referenced headers with one
bounded onchain check. Do not remove canonical-header authentication to save
gas.

## Production checklist

- Deploy and audit `AntseedBaseCheckpointOracle` and operate redundant
  permissionless beacon-root archivers.
- Build the guest reproducibly and pin its exact image ID.
- Generate a final representative fixture and record zkVM cycles/proof size.
- Verify Rust/Solidity ABI compatibility for the generated journal.
- Audit the guest, registry, points policy, and deployment wiring.
- Monitor verifier gas, checkpoint submission gas, and archive liveness.
- Reduce receipt count through an authenticated onchain aggregate or storage
  proof if the 574M-cycle representative proof is operationally unacceptable;
  never replace it with an unauthenticated indexer total.
- Keep the reporting scanner operationally separate from enforcement.

## Report-matched batch enforcement

The compact enforcement path starts from the scanner's immutable
`proof-bundle-v1.json`. The bundle's report root is the governance trust anchor
for period-completeness facts; the guests authenticate the selected positive
onchain evidence and its membership in that root.

```bash
node scripts/plan-wash-trading-proofs.mjs \
  --bundle proof-bundle-v1.json \
  --out proof-plan-v1.json \
  --rpc-url "$ANTSEED_BASE_RPC_URL"

cargo run -p loop-host --bin wash-trading-prove -- \
  --plan proof-plan-v1.json \
  --out proof-results-v1.json \
  --prove

node scripts/report-wash-trading-proof-coverage.mjs \
  --bundle proof-bundle-v1.json \
  --plan proof-plan-v1.json \
  --results proof-results-v1.json \
  --out proof-coverage-v1.json
```

The planner resolves every dependency against Base, requires settlements inside
the fixed report period, and routes block authentication through either the
AggregateVerifier checkpoint range or the historical backfill range. It
minimizes state-proof groups before receipt count and witness size. Closed-loop evidence priority is
`DIRECT_SELLER_FUNDER`, then `DIRECT_SELLER_BUYER`, then three valid relay
paths. Reciprocal plans use exactly 100 unique settlements in both directions.

The coverage report keeps report-root-classified volume separate from the
unique settlement volume actually authenticated by compact enforcement proofs.
It also reports cohort and reciprocal totals separately because the two policy
classes can refer to the same settlement and cannot be summed as a global
deduplicated wash-trading total.

Use `RISC0_DEV_MODE=1` only for the development coverage gate. The resulting
manifest is marked `development` and the contract submission script rejects it.
Production proving must produce Groth16-compatible seals before submission.

### Security artifact invalidation

The compact guests now require one approved funder for the entire cohort,
authenticate the transaction behind every receipt-backed dependency, bind exact
parties/channel/amount/period fields, reject duplicate dependency leaves and
zero-value settlements, and reject zero-value or value-amplifying relay paths.
These checks change both compact guest image IDs. Rebuild and pin the new cohort
and reciprocal image IDs, then regenerate the proof plan, proof results, seals,
coverage report, and submission manifest. Any artifact produced by an earlier
compact image—including previously generated `proof-plan-v1.json` and
`proof-results-v1.json` files—must not be submitted.
