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

Add `--prove` for a proof receipt and `--production` for a production prover run. Production submission requires a production Groth16 receipt; development results are rejected by the submission script.

The current report inventory contains 26 P0 proofs: two closed-loop sellers and 24 reciprocal pairs.
