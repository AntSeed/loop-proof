# AntSeed Wash-Trading Proofs — Predicate v3

This workspace contains the three RISC Zero predicates used by AntSeed's
wash-trading enforcement path:

1. **P0 closed cycle** — a common funder bootstraps buyers, those buyers settle
   with one seller, and value later returns outward from that seller.
2. **P0 reciprocal** — one normalized address pair repeatedly settles in both
   directions.
3. **P1 coordinated control** — a common-funder cohort contributes at least
   half of one seller's complete frozen-period volume.

Each proof is self-contained. Enforcement does **not** trust an analytics
report root, report leaf, dependency root, mutable funder allowlist, or generic
router attribution. There is one seal and one journal per seller case or
reciprocal pair; there is no multi-case zk proof.

The authoritative predicate implementation is
[`enforcement-core/src/lib.rs`](enforcement-core/src/lib.rs). The three guest
entrypoints are:

- [`closed-cycle-methods/guest/src/main.rs`](closed-cycle-methods/guest/src/main.rs)
- [`reciprocal-methods/guest/src/main.rs`](reciprocal-methods/guest/src/main.rs)
- [`coordinated-control-methods/guest/src/main.rs`](coordinated-control-methods/guest/src/main.rs)

The onchain registry is
[`../antseed/packages/contracts/integrity/AntseedWashTradingRegistry.sol`](../antseed/packages/contracts/integrity/AntseedWashTradingRegistry.sol).

## Fixed Scope and Constants

| Item | Predicate-v3 value |
|---|---:|
| Base chain ID | `8453` |
| Predicate version | `3` |
| Included settlement blocks | `44,471,575` through `49,936,172` |
| Journal period | `[44,471,575, 49,936,173)` |
| Start state boundary | `44,471,574` |
| End state boundary | `49,936,172` |
| Seller/buyer penalty | `9,000 BPS` reduction |
| Minimum common-funder cohort | `3` distinct buyers |
| Maximum linked/penalized buyers | `160` |
| Maximum journal block references | `256` |
| Minimum cohort volume | `1,000 USDC` |
| Minimum USDC funding per buyer | `1 USDC` |
| Minimum native funding per buyer | `0.00005 ETH` |

All USDC values use the token's six-decimal raw units. Threshold comparisons
are integer comparisons with checked unsigned arithmetic; there is no decimal
rounding.

## Common Authentication Guarantees

Every accepted guest execution proves all of the following common facts.

### Canonical Base data

- The witness declares Base chain ID `8453`.
- Every supplied block number is unique, and the journal contains the supplied
  `(blockNumber, blockHash)` pairs sorted by block number.
- Every referenced receipt is verified against the supplied header's
  `receiptsRoot` with a Merkle-Patricia proof.
- Every referenced transaction is verified against the supplied header's
  `transactionsRoot` with a Merkle-Patricia proof.
- P0 witnesses use only authenticated receipts and transactions; they do not
  require historical `eth_getProof` support.
- P1 EIP-1186 account and storage proofs are verified against the authenticated
  header's `stateRoot` and account `storageRoot`.
- P1 account and storage non-inclusion/zero proofs are supported, but malformed
  non-inclusion witnesses are rejected.
- Duplicate P1 account or storage proofs, duplicate receipt or transaction
  indexes, and duplicate proof block numbers are rejected.
- Onchain, the registry independently requires every journal block reference
  to satisfy `IBaseAnalysisStateOracle.isCanonicalBlock(number, hash)`.

A valid receipt, transaction, or storage proof only authenticates data against
its supplied Base header. The state-oracle check is what binds that header to
canonical finalized Base history. The checkpoint implementation is documented
in [`checkpoint/README.md`](checkpoint/README.md).

### Pinned contracts and P1 storage layouts

The guests accept only the following deployed contract addresses. P1 also pins
runtime code hashes for contracts whose historical state it reads:

| Contract | Address | Authentication |
|---|---|---|
| Base USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | Transfer logs are authenticated by address/topic/data shape |
| AntSeed Channels | `0xBA66d3b4fbCf472F6F11D6F9F96aaCE96516F09d` | `0x9d8c726d151e2257e2b4e50f46dcf0bc7c976786585ee3b902be55bd431f1ed8` |
| AntSeed Deposits | `0x0F7a3a8f4Da01637d1202bb5443fcF7F88F99fD2` | `0x41f0965f0300d0ce16e2a5824ae52fecf4321f4083e62abfa309e64414f95955` |
| Old emissions | `0x36877fBa8Fa333aa46a1c57b66D132E4995C86b5` | `0x5991d7a7f4d33f70e29ad71421820d37c8ae04eb99a720184b99a2b7d231876e` |
| New emissions | `0xF13bE52c4A3afC6AE29536f073588d01A0564088` | `0x534c9513b91440044e12ad087f414f8ae0b59fd7cba3d892e1a522296bfcf464` |

P1-only pinned storage derivations are:

- `AntseedDeposits.buyers` mapping slot `9`; `firstChannelAt` is struct
  offset `3`.
- `AntseedChannels.channels` mapping slot `9`; buyer is offset `0`, seller is
  offset `1`, and the packed `deposit/settled` word is offset `2`, with
  `settled` in the upper 128 bits.
- Old emissions `userSellerPoints` mapping slot `10` and `userBuyerPoints`
  mapping slot `11`.
- New emissions `userSellerPoints` mapping slot `14` and `userBuyerPoints`
  mapping slot `15`.
- Seller and buyer counter evidence must cover both emissions contracts and
  every epoch `0` through `18` exactly once for the requested subject.

The observed first new-emissions pointer block is `45,937,736`. Predicate v3
does not trust the pointer as a volume oracle: it authenticates and sums the
boundary deltas from both pinned emissions contracts directly.

### Funder identity and funding

For cohort predicates, linked buyers must be nonzero, strictly sorted, unique,
and between `3` and `160` entries. The seller and exact funder must be nonzero;
a seller may be its own funder. One funding witness must exist for every linked
buyer and no unrelated or duplicate buyer funding witness is accepted.

For P0, a receipt/transaction witness proves only positive funding before the
selected seller settlements. Direct USDC and protocol-deposit funding require
the authenticated transaction signer to equal the funder. Native funding
requires the same signer match plus a successful receipt for the authenticated
transaction. Smart-account attribution is unsupported on this receipt-only
path. P0 does not claim that the selected transfer is the buyer's first funder
or predates the buyer's first-ever channel.

P1 retains the stronger historical-state timing rule below and therefore still
requires an archive RPC with historical `eth_getProof` support.

For every linked buyer, the proof authenticates
`AntseedDeposits.buyers[buyer].firstChannelAt` at block `49,936,172` and proves
that the selected funding block timestamp is strictly earlier than that first
channel timestamp. Funding may predate the frozen settlement period.

Supported funding forms are:

#### EOA USDC funding

- A successful Base USDC `Transfer` log has exact
  `from = funder`, `to = buyer`, and `amount >= 1 USDC`.
- The transaction containing that log is authenticated.
- The recovered transaction signer equals the funder.
- The funder account has the empty-code hash at that funding block.

#### EIP-7702 USDC funding

- The same successful USDC `Transfer` requirements apply.
- The authenticated funder account contains a 23-byte EIP-7702 delegation
  designator beginning `0xef0100`.
- The account code hash equals the supplied delegation designator's hash.
- The recovered transaction signer equals the funder address.

#### Pinned smart-account USDC funding

Only these two smart-account funder addresses are supported:

- `0xee7ae85f2fe2239e27d9c1e23fffe168d63b4055`
- `0x17fe9197970454875df742a74b74ed5f984b645a`

For them, the proof requires:

- A successful Base USDC `Transfer` with exact
  `from = smart account`, `to = buyer`, and `amount >= 1 USDC`.
- Proxy runtime code hash
  `0x22bcbefe2dacbb6289d731af9eabb98fdfb6480f4c59c9b2f45f574f008ef68f`.
- ERC-1967 implementation address
  `0xd206ac7fef53d83ed4563e770b28dba90d0d9ec8`.
- Implementation runtime code hash
  `0x491c065559650e64988c11ac6fb90a72bec27afa3b112a4962fded431a603352`.
- The pinned owner slot decodes to a nonzero owner.
- The pinned plugin-count slot is zero.

The smart-account address—not its owner—is the funder identity. Predicate v3
does not merge the owner and smart-account addresses into one funder.

#### Native ETH funding

- The authenticated transaction has exact `to = buyer` and
  `value >= 0.00005 ETH`.
- Its receipt is authenticated and successful. Transaction inclusion without a
  successful receipt is insufficient because a reverted transaction transfers
  no ETH.
- The receipt and transaction must be the same transaction in the same block.
- The recovered signer is authenticated as the EOA or EIP-7702 funder.

Native ETH funding is intentionally **not** supported for smart-contract
funders. A top-level Ethereum transaction cannot originate from a contract
account, and predicate v3 does not authenticate internal native-value call
traces.

## P0 Closed-Cycle Guarantee

An accepted closed-cycle proof guarantees all of the following.

### Funding and settlement phase

- One exact funder funded the complete linked-buyer cohort under the common
  funding rules above.
- At least three distinct linked buyers have authenticated settlements with
  the exact seller.
- Every selected settlement is a successful `ChannelSettled` receipt emitted
  by the pinned Channels contract.
- The event's exact buyer is in the linked cohort, its seller equals the claim
  seller, and its settlement delta is nonzero.
- Every selected settlement block is inside
  `[44,471,575, 49,936,173)`.
- Every settlement block timestamp is strictly later than that buyer's funding
  block timestamp.
- No settlement log is counted twice.
- Selected settlement deltas total at least `1,000 USDC` using checked
  `uint128` arithmetic.

### Threshold ordering

Selected settlements are deterministically ordered by
`(blockNumber, transactionIndex, logIndex)`. The proof records the exact event
where the selected cumulative volume first reaches `1,000 USDC`. Closure
evidence must occur strictly after that event in the same ordering.

### Direct closure

A direct closure proves one successful Base USDC transfer:

- `from = seller`;
- `to = exact funder` or `to = one linked buyer`;
- `amount >= 1 USDC`;
- the transfer is inside the fixed period; and
- the transfer occurs strictly after the threshold-crossing settlement.

The direction is seller-outward only. `funder -> seller` and
`buyer -> seller` do not count as closure.

### Relay closure

A relay closure proves at least three paths. Each path contains three distinct,
successful Base USDC transfer logs with this exact shape:

`seller -> relay 1 -> relay 2 -> exact funder`

For every path:

- the seller payment occurs after the threshold crossing;
- all three transfers are in strict chain order and inside the fixed period;
- no transfer log is reused in any relay path;
- the final receipt occurs no more than `86,400` seconds after the seller
  payment;
- the seller payment is at least `1 USDC`;
- the relay-forward amount differs from the seller payment by at most
  `0.001 USDC`;
- the final amount is nonzero and no greater than either the seller payment or
  relay-forward amount; and
- the final funder receipt either loses no more than `1 USDC` or preserves at
  least `98%` of the seller payment.

Predicate v3 prevents transfer-log reuse; it does not require relay addresses
to be distinct within one path or across different paths.

### Closed-cycle journal and penalties

The closed-cycle guest commits:

- predicate version and deterministic claim ID;
- fixed period;
- seller and exact funder;
- cohort hash and cohort count;
- authenticated qualified volume;
- closure kind and path count;
- fixed `9,000 BPS` penalty;
- sorted, unique canonical Base block references.

The seller is marked P0 and receives the future seller-points penalty. P0 is
seller-only: the journal contains no buyer counters or buyer penalties.

## P0 Reciprocal Guarantee

An accepted reciprocal proof guarantees all of the following.

- The subjects are nonzero and normalized as `addressA < addressB`.
- Every selected settlement is a successful, authenticated
  `ChannelSettled` event emitted by the pinned Channels contract.
- Every event is exactly either `addressA -> addressB` or
  `addressB -> addressA`; unrelated buyers or sellers are rejected.
- Every settlement lies inside the fixed period and has a nonzero delta.
- No settlement log is counted twice.
- The selected evidence contains at least `100` total settlements.
- It contains at least `10` settlements from A to B and at least `10` from B
  to A.
- It contains at least `10 USDC` from A to B and at least `10 USDC` from B to
  A.
- The smaller directional volume is at least `80%` of the larger directional
  volume, using exact integer arithmetic.

The reciprocal guest commits the normalized pair, both directional settlement
counts, both directional volumes, fixed period and penalty, deterministic claim
ID, and canonical block references.

Both addresses are marked P0 and receive the future seller-points penalty. The
P0 journal contains no buyer counters or buyer penalties.

## P1 Coordinated-Control Guarantee

An accepted coordinated-control proof guarantees all of the following.

### Common funder

- One exact funder funded every buyer in a sorted, unique cohort of at least
  three buyers under the common funding rules above.
- ETH and USDC evidence may coexist only because every funding witness is
  checked against that same exact funder address.
- A smart account and its owner remain separate funder identities.

### Cohort channel volume

- Every selected `channelId` is unique.
- At the end boundary, authenticated channel storage has the exact linked buyer
  and exact claim seller.
- The proof reads the channel's packed `settled` value at both state boundaries.
- The channel contribution is
  `settled(end block 49,936,172) - settled(start block 44,471,574)`.
- Underflow is rejected and all channel/buyer/cohort additions use checked
  arithmetic.
- The sum of selected channel deltas is at least `1,000 USDC`.

P1 uses cumulative channel-state deltas rather than settlement receipts because
ordering and closure timing are not part of this predicate.

### Complete seller-period volume

- The seller's `userSellerPoints` values are authenticated at both state
  boundaries for every epoch `0–18` in both pinned emissions contracts.
- Each per-slot delta must be nonnegative and fit `uint128`.
- All 38 deltas are added with checked arithmetic to produce the exact
  `sellerPeriodVolume` used by the predicate.
- The authenticated cohort volume satisfies
  `cohortVolume * 2 >= sellerPeriodVolume`.
- Equality at exactly `50%` passes; one raw USDC unit below the comparison
  fails.

The new emissions contract may be absent at the start boundary; that is
authenticated as zero. The old emissions contract must exist at the start
boundary, and both pinned contracts must exist with the expected code hashes at
the end boundary.

### P1 journal and penalties

The P1 guest commits seller, exact funder, cohort hash/count, qualified cohort
volume, exact seller-period volume, qualifying buyer penalties, fixed period
and penalty, deterministic claim ID, and canonical block references.

No return payment or closure evidence is required for P1. The seller receives
the future seller penalty. A linked buyer receives the future buyer penalty
only when authenticated target-seller channel volume is at least `99%` of that
buyer's complete frozen-period `userBuyerPoints` delta.

## Deterministic Claims and Public Journals

For cohort predicates:

```text
cohortHash = keccak256(abi.encode(sortedLinkedBuyers))

claimId = keccak256(abi.encode(
  chainId,
  proofType,
  periodStartBlock,
  periodEndBlockExclusive,
  seller,
  exactFunder,
  cohortHash
))
```

For reciprocal predicates:

```text
claimId = keccak256(abi.encode(
  chainId,
  reciprocalProofType,
  periodStartBlock,
  periodEndBlockExclusive,
  normalizedAddressA,
  normalizedAddressB
))
```

The Rust guest computes the claim ID, and the Solidity registry recomputes it
from the decoded journal. A proof for one predicate, period, subject, funder, or
cohort cannot be replayed as a different claim.

All journals use ABI encoding and include:

- `predicateVersion = 3`;
- the deterministic `claimId`;
- fixed period start and end-exclusive blocks;
- `penaltyBps = 9_000`;
- a sorted, unique `penalizedBuyers` array capped at `160` for P1 only; and
- sorted, unique `(number, blockHash)` references capped at `256`.

The journal ABI definitions live beside the Rust journals in
[`enforcement-core/src/lib.rs`](enforcement-core/src/lib.rs). Solidity decoding
and invariant checks live in
[`../antseed/packages/contracts/integrity/AntseedWashTradingRegistry.sol`](../antseed/packages/contracts/integrity/AntseedWashTradingRegistry.sol).

## Onchain Enforcement Effect

The registry exposes exactly three proof submission functions:

```solidity
submitClosedCycleProof(bytes seal, bytes journalData)
submitReciprocalProof(bytes seal, bytes journalData)
submitCoordinatedControlProof(bytes seal, bytes journalData)
```

Before changing penalties, the registry:

1. verifies the seal against the corresponding immutable image ID;
2. hashes and decodes the journal;
3. recomputes the deterministic claim ID;
4. checks predicate version, fixed period, thresholds, penalty, array caps,
   sorting, uniqueness, and journal-specific invariants; and
5. checks every block reference against the Base state oracle.

Claim IDs are idempotent. Seller and P1 buyer penalties are monotonic and use
`max(previousPenalty, 9_000)`, so separate proofs never add multiple 9,000-BPS
penalties together. P0 proof bits are recorded independently from the points
penalty, so a later P0 proof still marks a seller that an earlier P1 proof had
already penalized.

[`../antseed/packages/contracts/policies/AntseedWashTradingPointsPolicy.sol`](../antseed/packages/contracts/policies/AntseedWashTradingPointsPolicy.sol)
returns seller and buyer penalties to the points-policy registry. A 9,000-BPS
reduction leaves 10% of otherwise calculated future points. Previously accrued
points, locked rewards, and historical reward state are not confiscated or
redirected. The separate composite reward policy holds P0 sellers and sellers
submitted in its immutable deployment-time inactivity snapshot while preserving
ownership of the locked balance. Later settlements cannot clear either block.

Emergency policy removal remains available through the existing points-policy
registry. There is no claim-level owner override or mutable enforcement
allowlist in the wash-trading registry.

## What Predicate v3 Does Not Prove

These limitations are intentional and security-relevant:

- It does not prove that an analytics report is complete or correct.
- It does not trust or consume a report root, report leaf, dependency root, or
  approved-address array.
- P0 proves a sufficient authenticated set of settlements meeting its
  thresholds; it does not claim that every seller settlement is enumerated.
- P0 funding proves a positive funding event before the selected settlements;
  it does not prove the buyer's first funder or funding before the buyer's
  first-ever channel.
- P1 is the predicate that authenticates the seller's complete frozen-period
  counter delta for the 50% comparison.
- CoW, routers, aggregators, and generic unpinned contract funders are not attributed.
  Such cases remain `analysis-only-router-attribution` and cannot enter a
  production submission manifest.
- It does not equate a smart account with its owner.
- It does not authenticate smart-account internal native ETH transfers.
- It does not infer common control from exchange deposits, shared relayers,
  IP addresses, offchain identities, or behavioral similarity.
- It does not claw back past points or rewards.
- It does not batch multiple seller cases into one zk proof.
- It does not make an untrusted Base header canonical; canonicality is supplied
  by the separately verified state oracle.

## Proof and Submission Flow

Materialize a P0 witness from a proof plan using an ordinary Base RPC. This path
reads receipt and transaction tries only and never calls `eth_getProof`:

```bash
cd loop-proof

BASE_RPC_URL="$BASE_RPC_URL" \
  cargo run --release -p loop-host --bin wash-trading-materialize-p0 -- \
  --plan /absolute/path/to/proof-plan.json \
  --claim-id 0xClaimId \
  --output cases/p0-witness-v3.json
```

Materialize a P1 coordinated-control witness from the frozen scan with a Base
archive RPC that supports historical `eth_getProof` at both fixed state
boundaries:

```bash
cd loop-proof

BASE_ARCHIVE_RPC_URL="$ARCHIVE_BASE_RPC_URL" \
  cargo run --release -p loop-host --bin wash-trading-materialize -- \
  --scan-dir /absolute/path/to/scan \
  --seller 0xSeller \
  --output cases/p1-witness-v3.json
```

Use `--funders 0xFunderA,0xFunderB` to restrict materialization to specific
exact funders. Without it, the materializer chooses threshold-sufficient
cohorts deterministically. Every included funder must fund at least three
selected buyers. Native funding and protocol deposits are supported; a
seller may be its own exact funder. The materializer authenticates receipt,
transaction, account, channel, deposit, and emissions-counter proofs and runs
native predicate verification before writing the package.

`BASE_RPC_URL` remains the primary endpoint for blocks, transactions, receipts,
and logs. State-witness calls try `BASE_RPC_URL` first, then fall back to
`BASE_ARCHIVE_RPC_URL` when the primary endpoint does not cover the requested
historical block. This keeps the existing RPC for high-volume and in-range
reads while limiting archive-node usage to missing witness data. Without
`BASE_ARCHIVE_RPC_URL`, a primary endpoint whose proof index starts after the
fixed boundary fails the initial archive preflight and cannot produce a valid
witness.

The predicate-v3 prover accepts one self-contained witness package per
invocation:

```bash
cd loop-proof

cargo run -p loop-host --bin wash-trading-prove -- \
  --input proof-witness-v3.json \
  --output proof-result-v3.json
```

The witness package must have:

- `version: 3`;
- `kind: "antseed-wash-trading-proof-witness"`;
- `enforceable: true`; and
- exactly one `proofType` and corresponding predicate input.

Use `--prove` to produce a receipt. Production proving additionally requires
both `--production` and `RISC0_DEV_MODE=0`:

```bash
RISC0_DEV_MODE=0 cargo run --release -p loop-host --bin wash-trading-prove -- \
  --input proof-witness-v3.json \
  --output proof-result-v3.json \
  --prove \
  --production
```

The host rejects `enforceable=false` router-attribution cases. It executes the
same predicate natively and inside the zkVM and rejects any journal-byte
mismatch.

Submit production results sequentially with the resumable script:

```bash
cd ../antseed/packages/contracts

node scripts/submit-wash-trading-proofs.mjs \
  --manifest /absolute/path/proof-result-v3.json \
  --registry 0xRegistryAddress \
  --rpc-url "$ANTSEED_BASE_RPC_URL" \
  --dry-run

node scripts/submit-wash-trading-proofs.mjs \
  --manifest /absolute/path/proof-result-v3.json \
  --registry 0xRegistryAddress \
  --rpc-url "$ANTSEED_BASE_RPC_URL" \
  --submit
```

The submission script refuses manifests marked as development, non-Base RPC
networks, wrong image IDs, malformed claim IDs, noncanonical arrays, missing
seals, analysis-only entries, and journal-digest mismatches. The production
verifier remains the authority on seal validity. The script persists successful
transaction receipts for resume. A failed case can be retried; an unrelated
case can be submitted independently with its own result manifest.

## Case Classification

Analysis classifies cases as:

- `proof-ready` — eligible for predicate-v3 production proving;
- `analysis-only-router-attribution` — retained in analytics but refused by
  production proving and submission; or
- `fails-predicate` — does not meet the predicate thresholds.

The current coverage report is
[`reports/wash-trading-proof-coverage-2026-08-19.md`](reports/wash-trading-proof-coverage-2026-08-19.md).
The current production-ready inventory is 39 independent proofs: one closed
cycle, 24 reciprocal pairs, and 14 coordinated-control cohorts.

## Source Map

| Responsibility | File |
|---|---|
| Predicate constants, witnesses, state/receipt proofs, thresholds, journals | [`enforcement-core/src/lib.rs`](enforcement-core/src/lib.rs) |
| Closed-cycle guest | [`closed-cycle-methods/guest/src/main.rs`](closed-cycle-methods/guest/src/main.rs) |
| Reciprocal guest | [`reciprocal-methods/guest/src/main.rs`](reciprocal-methods/guest/src/main.rs) |
| Coordinated-control guest | [`coordinated-control-methods/guest/src/main.rs`](coordinated-control-methods/guest/src/main.rs) |
| P1 scan-to-witness materializer | [`host/src/bin/wash-trading-materialize.rs`](host/src/bin/wash-trading-materialize.rs) |
| Witness execution and proof packaging | [`host/src/bin/wash-trading-prove.rs`](host/src/bin/wash-trading-prove.rs) |
| EIP-1186 RPC fetching | [`host/src/rpc.rs`](host/src/rpc.rs) |
| Deterministic funder selection | [`host/src/selection.rs`](host/src/selection.rs) |
| Onchain registry | [`../antseed/packages/contracts/integrity/AntseedWashTradingRegistry.sol`](../antseed/packages/contracts/integrity/AntseedWashTradingRegistry.sol) |
| Points policy | [`../antseed/packages/contracts/policies/AntseedWashTradingPointsPolicy.sol`](../antseed/packages/contracts/policies/AntseedWashTradingPointsPolicy.sol) |
| Deployment | [`../antseed/packages/contracts/script/DeployWashTradingEnforcement.s.sol`](../antseed/packages/contracts/script/DeployWashTradingEnforcement.s.sol) |
| Production submission | [`../antseed/packages/contracts/scripts/submit-wash-trading-proofs.mjs`](../antseed/packages/contracts/scripts/submit-wash-trading-proofs.mjs) |
| Analysis classification | [`../analyses/wash-trading/scripts/wash-trading/proof-coverage.mjs`](../analyses/wash-trading/scripts/wash-trading/proof-coverage.mjs) |

## Validation

Run the proof workspace tests:

```bash
cd loop-proof
cargo test --workspace
cargo fmt --all --check
```

Run the enforcement contract tests:

```bash
cd ../antseed/packages/contracts
forge test --match-path 'test/AntseedWashTrading*.t.sol'
forge test
node --test scripts/submit-wash-trading-proofs.test.mjs
```

Run the proof-planning and coverage tests:

```bash
cd ../../../loop-proof
node --test scripts/*.test.mjs

cd ../analyses
node --test wash-trading/scripts/wash-trading/proof-coverage.test.mjs
```

## Production Acceptance Still Required

Code and local tests do not replace production proof acceptance. Before Base
submission:

- materialize every referenced historical Base block in the state oracle;
- generate all intended receipts with `RISC0_DEV_MODE=0`;
- benchmark the largest 147-buyer witness under native and zkVM execution;
- dry-run every submission against a Base fork;
- obtain at least one successful production receipt for each image ID; and
- submit claims sequentially through the resumable script.

Development receipts and analysis-only router cases are never submit-ready.
