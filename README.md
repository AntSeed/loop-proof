# AntSeed P0 Proofs

This repository builds and runs the two RISC Zero predicates used by the immutable seller reward gate:

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

The pinned guest image is authoritative for all predicate constants, thresholds,
claim construction, and evidence semantics. The closed-loop public journal
contains only the seller and canonical block references. The reciprocal journal
contains only the normalized pair and canonical block references. Claim IDs and
measured volumes remain in the off-chain proof manifest for release auditing;
Solidity does not duplicate the guest's predicate logic.

### Canonical Blocks

Every committed Base header is checked by the on-chain canonical Base block oracle. Seller proofs need ordinary block, transaction, and receipt RPC methods; they do not call historical `eth_getProof`.

## Repository Layout

- `enforcement-core/`: shared P0 verification and journal ABI.
- `closed-cycle-methods/`: closed-loop RISC Zero guest image.
- `reciprocal-methods/`: reciprocal RISC Zero guest image.
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

Add `--prove` for a proof receipt and `--production` for a production prover run. Production submission requires a production Groth16 receipt; development results are rejected by the production submission script. The separate `submit-development-proof-local.mjs` utility accepts exactly one development receipt and a loopback RPC URL for Anvil-only E2E testing.

The current report inventory contains 26 P0 proofs: two closed-loop sellers and 24 reciprocal pairs.

## Deployment Security Flow

The deployment pipeline intentionally separates evidence selection, canonical
state population, proof generation, and proof submission. The canonical state
plan is a one-time prerequisite for teaching the Base oracle the exact block
hashes referenced by the 26 seller proofs. It does not select settlements,
change predicate thresholds, or participate in volume arithmetic.

The required order is:

1. Generate the 26-claim proof plan.
2. Capture and Ed25519-sign the exact settlement/volume baseline.
3. Generate checkpoint proofs and all 112 historical chunk proofs.
4. Generate and merge strict `antseed-base-state-plan` v1 files for checkpoint
   submission, historical backfill, and required block materialization.
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
  --checkpoint-plan checkpoint-plan.json \
  --proof-plan proof-plan.json \
  --checkpoint-unit-usd 0.00 \
  --historical-unit-usd 0.00 \
  --p0-unit-usd 0.00 \
  --provider PROVIDER_NAME \
  --expires-at 2026-08-22T00:00:00Z \
  --out proving-cost-quote.json
```

Replace the example zeroes with real quoted maximum unit costs. No production
proving command should run until the aggregate amount and digest are approved.

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
