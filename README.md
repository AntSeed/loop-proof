# AntSeed P0 Proofs

This repository builds and runs the two Succinct SP1 predicates used by the immutable seller reward gate:

- `P0_CLOSED_LOOP`
- `P0_RECIPROCAL`

## Guarantees

### Closed Loop

The guest authenticates funding transactions or receipts, successful `ChannelSettled` receipts, and seller-outward closure transfers against committed Base transaction and receipt roots. It requires:

- one authenticated funder;
- at least three funded buyers;
- positive funding before each selected settlement;
- at least 1,000 USDC settled after funding; and
- direct, relay, or authenticated self-funded closure.

Receipt-only native funding is accepted only when the recovered transaction signer is the funder. The proof establishes positive funding before the selected settlements; it does not claim to establish a buyer's first-ever funder.

### Reciprocal

The guest authenticates successful settlements for one exact normalized wallet pair. It requires:

- at least 100 combined settlements;
- at least 10 settlements in each direction;
- at least 10 USDC in each direction; and
- at least 80% directional volume reciprocity.

Both wallets are recorded as P0.

### Minimal Public Journals

The pinned SP1 program vkey is authoritative for all predicate constants, thresholds,
claim construction, and evidence semantics. The closed-loop public journal
contains only the seller and canonical block references. The reciprocal journal
contains only the normalized pair and canonical block references. Claim IDs and
measured volumes remain in the off-chain proof manifest for release auditing;
Solidity does not duplicate the guest's predicate logic.

### Canonical Blocks

Every committed Base header is checked by the on-chain canonical Base block oracle. Seller proofs need ordinary block, transaction, and receipt RPC methods; they do not call historical `eth_getProof`.

## Repository Layout

- `enforcement-core/`: shared P0 verification and journal ABI.
- `closed-cycle-methods/`: closed-loop SP1 guest program.
- `reciprocal-methods/`: reciprocal SP1 guest program.
- `host/`: real-data materialization, execution, and proving binaries.
- `scripts/`: proof planning and coverage reporting.
- `core/`: receipt and trie verification shared by the P0 guests.
- `checkpoint/`: separate canonical-block-oracle maintenance workspace; it is not a seller predicate.

## Build and Test

```bash
cargo fmt --all --check
cargo test --workspace
cargo check -p loop-host --bins
node --test scripts/*.test.mjs
```

## Real-Data Flow

```bash
node scripts/plan-wash-trading-proofs.mjs \
  --bundle proof-bundle.json \
  --out proof-plan.json \
  --rpc-url "$BASE_RPC_URL"

cargo run --release -p loop-host --bin wash-trading-materialize-p0 -- \
  --plan proof-plan.json \
  --claim-id 0x... \
  --output proof-witness.json

cargo run --release -p loop-host --bin wash-trading-prove -- \
  --input proof-witness.json \
  --output proof-results.json
```

Add `--prove --production` to produce SP1 Groth16 proof bytes for Solidity. Use `SP1_PROVER=network` with `NETWORK_PRIVATE_KEY` for Succinct Network or `SP1_PROVER=cpu` for local proving; `mock` and `light` are rejected for production. Development execution results are rejected by the production submission script. The separate `submit-development-proof-local.mjs` utility accepts exactly one development execution result and a loopback RPC URL for Anvil-only E2E testing.

Network proving also requires `SP1_NETWORK_MAX_COMPRESSED_BASE_FEE_PROVE_WEI`,
`SP1_NETWORK_MAX_GROTH16_BASE_FEE_PROVE_WEI`, and
`SP1_NETWORK_MAX_PRICE_PER_PGU_PROVE_WEI`. The host reads the live auction before
every request, rejects fees above either approved ceiling, rejects an account that
cannot cover the live base fee, and passes the approved price-per-PGU ceiling into
the signed request. The SDK still simulates the exact witness locally so the request
uses its measured PGU rather than a loose manual gas limit.

The current report inventory contains 26 P0 proofs: two closed-loop sellers and 24 reciprocal pairs.
The measured workload, live market estimate, enforced approval envelope, and
local CPU/electricity estimate are recorded in
[`reports/SP1_PROOF_MARKET_READINESS.md`](reports/SP1_PROOF_MARKET_READINESS.md).

Before production proving, query the live Succinct auction without submitting a proof:

```bash
cargo run --release -p loop-host --bin sp1-network-readiness \
  > sp1-network-readiness.json
```

The command requires `NETWORK_PRIVATE_KEY`, all three network fee caps, and
`SP1_NETWORK_REQUIRED_BALANCE_PROVE_WEI`. It reports the account balance plus the
current compressed and Groth16 base fees and maximum price per PGU, and exits
unless every approval and funding gate passes. It is read-only. For a measured proof with `G` prover gas units, the market ceiling is
`baseFeeProveWei + G * maxPricePerPguProveWei`. Convert the result from 18-decimal
PROVE and then apply the current PROVE/USD price when preparing the aggregate
cost quote.

Development execution results include both `instructionCount` and
`proverGasUnits`, allowing every materialized P0 witness to be priced before a
network proof request is submitted.

## Deployment Security Flow

The deployment pipeline intentionally separates evidence selection, canonical
state population, proof generation, and proof submission. The canonical state
plan is a one-time prerequisite for teaching the Base oracle the exact block
hashes referenced by the 26 seller proofs. It does not select settlements,
change predicate thresholds, or participate in volume arithmetic.

The required order is:

1. Generate the 26-claim proof plan.
2. Capture and Ed25519-sign the exact settlement/volume baseline.
3. Prove the fixed 16,384-header epochs as SP1 compressed proofs and wrap one recursive history-accumulator proof in Groth16.
4. Generate one strict `antseed-base-state-plan` v1 for accumulator submission
   and exact block-hash materialization.
5. Validate and apply that state plan on an Anvil Base fork. A complete rerun
   must send zero transactions.
6. Materialize and prove the 26 P0 witnesses.
7. Refetch every baseline receipt and produce a clean final volume report that
   equals the baseline, planner sums, host verification, and receipt delta sums.
8. Dry-run proof submission, then build the signed release manifest.

Any changed claim identity, funder/cohort, settlement transaction/log, or raw
volume is a blocking exception. The pipeline never silently substitutes new
evidence. The fixed predicate constants remain unchanged.

### Volume baseline

```bash
openssl genpkey -algorithm Ed25519 -out baseline-key.pem
openssl pkey -in baseline-key.pem -pubout -out baseline.pub.pem

node ../antseed/packages/contracts/scripts/verify-proof-volumes.mjs capture \
  --bundle proof-bundle.json \
  --plan proof-plan.json \
  --rpc-url "$BASE_RPC_URL" \
  --signing-key baseline-key.pem \
  --out volume-baseline.json
```

`capture` requires exactly 26 claims for deployment and authenticates the
exact successful `ChannelSettled` log in every receipt. Volume is the event's
`delta` word, not its cumulative amount.

### Proving cost approval

Build one aggregate cost quote from current provider prices. Production batch
commands require the exact printed digest as an explicit approval:

```bash
node scripts/proving-cost-quote.mjs \
  --accumulator-manifest checkpoint/history-artifacts/manifest.json \
  --proof-plan proof-plan.json \
  --epoch-unit-usd 0.00 \
  --aggregate-unit-usd 0.00 \
  --p0-unit-usd 0.00 \
  --provider PROVIDER_NAME \
  --expires-at 2026-08-22T00:00:00Z \
  --out proving-cost-quote.json
```

Replace the example zeroes with real quoted maximum unit costs. No production
proving command should run until the aggregate amount and digest are approved.
The proof host's mandatory network ceilings are an independent final guardrail;
set them from the same approved quote before invoking the batch.

### Production batch and final volume gate

```bash
node scripts/prove-p0-plan.mjs \
  --plan proof-plan.json \
  --artifact-dir p0-proof-artifacts \
  --cost-quote proving-cost-quote.json \
  --approve-cost-digest 0x... \
  --confirm-production-proving

node ../antseed/packages/contracts/scripts/verify-proof-volumes.mjs verify \
  --bundle proof-bundle.json \
  --plan proof-plan.json \
  --results p0-proof-artifacts/proof-results.json \
  --baseline volume-baseline.json \
  --trusted-public-key baseline.pub.pem \
  --rpc-url "$BASE_RPC_URL" \
  --report final-volume-report.json
```

Production proof submission additionally requires the baseline public key and
checks every journal block reference against the registry's configured state
oracle before simulation or broadcast.
