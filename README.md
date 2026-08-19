# AntSeed Seller-Penalty Proof

This workspace contains the RISC Zero proof used by AntSeed's wash-trading
**enforcement** path. It proves one conservative, positive-evidence statement
about one seller. It does not prove or enforce the full analytics report in
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

## Why fraud proofs are not required

The enforcement rule uses only **monotonic positive evidence**:

- every included fact is authenticated;
- adding valid evidence can only strengthen or preserve the result;
- omitting evidence can only reduce the buyer count or proven volume;
- reduced evidence can only make the penalty harder to obtain.

A prover therefore cannot create a false penalty by hiding unfavorable data.
They can only fail to penalize a seller that might deserve a penalty. That
false-negative direction is acceptable for this policy; false-positive seller
penalties are not.

This is why enforcement no longer has an evidence root, findings root,
candidate proposal, 14-day challenge window, revisions, watcher requirement,
fraud-proof guest, or finding-materialization step.

## What is not proven

This proof does **not** establish:

- complete seller, buyer, transfer, or settlement activity;
- that the selected funder was the first or primary funder;
- that the proven buyers are all of the seller's buyers;
- any percentage of the seller's total volume;
- the absence of organic buyers or legitimate activity;
- the full P0/P1 analytics report;
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
- `checkpoint/` — isolated Steel-based Base checkpoint proof workspace.
- `cases/flash.json` — a three-buyer Base mainnet evidence request.

The former full-analysis and challenge packages are not members of this
enforcement workspace. The JavaScript scanner in `../analyses/wash-trading`
remains a separate reporting tool.

## Run

Requires Rust 1.88 and the RISC Zero toolchain.

Copy `.env.example` to `.env` and set `BASE_RPC_URL`. The host reads that URL
first and falls back to public Base RPCs.

```bash
cargo build --release

# Fetch receipt proofs for the configured seller/funder/buyer cohort.
./target/release/loop-host fetch \
  --case cases/flash.json \
  --out cases/flash-fixture.json

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

### Base checkpoint dry run

The checkpoint workspace uses Rust 1.94 and pins Steel to commit
`f6fc6297c938d7acc0563337da136d034c3cb67b`.

```bash
cd checkpoint

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

### Current Base mainnet measurement

The `cases/flash.json` fixture was fetched through `BASE_RPC_URL` and executed
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
