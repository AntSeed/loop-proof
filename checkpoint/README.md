# Base Checkpoint Proof

This isolated RISC Zero workspace authenticates historical Base block hashes
without deploying an AntSeed contract on Ethereum.

The host reads a finalized Ethereum state through Steel, queries Base's
Ethereum `AnchorStateRegistry` at `0x909f...4E72`, and proves that it accepts a
game of AggregateVerifier type `621`. The guest reads a 30-block intermediate
output root from that game, verifies the Base output-root preimage, and checks
a contiguous Base header chain back to the requested target blocks.

The ABI journal is submitted on Base to
`AntseedBaseCheckpointOracle.submitCheckpoint`. The oracle verifies the RISC
Zero seal and validates Steel's beacon commitment against Base's EIP-4788
predeploy. It then stores exact canonical block hashes for the seller-penalty
registry.

## Security direction

- A fabricated or non-canonical block cannot be stored.
- An existing block number cannot be overwritten with a conflicting hash.
- Missing a proof or beacon-root archive can only leave a seller unpenalized.
- No checkpoint proof can directly reduce buyer rewards.
- No RPC or Beacon API is trusted; both only provide proof witnesses.

## Environment

The host reads `../.env` when run from this directory:

```dotenv
BASE_RPC_URL=https://base-mainnet.g.alchemy.com/v2/YOUR_KEY
L1_RPC_URL=https://ethereum-rpc.publicnode.com
BEACON_API_URL=https://ethereum-beacon-api.publicnode.com
```

## Commands

```bash
cargo test -p checkpoint-core

# Read-only planning: resolve selected windows at finalized Ethereum state.
jq '.checkpointSelection' ../out/proof-plan.json > ../out/checkpoint-selection.json
cargo run --release -p checkpoint-host --bin checkpoint-plan -- \
  --selection ../out/checkpoint-selection.json \
  --out ../out/checkpoint-plan.json

cargo run --release -p checkpoint-host -- --journal-out checkpoint-journal.hex
RISC0_DEV_MODE=1 cargo run --release -p checkpoint-host -- \
  --prove --seal-out checkpoint-seal.hex
```

`checkpoint-plan` validates the selection manifest, discovers type-621 games,
checks each game's start and interval configuration, requires ASR acceptance at
one finalized Ethereum block, and writes the game, intermediate-root index,
checkpoint block, and sorted target blocks for every proof. It does not produce
proofs or submit transactions.

The default `checkpoint-host` game/index remains a stable known-valid Base
AggregateVerifier fixture. Production automation must consume the generated
plan and archive each Steel beacon root before Base's EIP-4788 retention window
expires.

## Historical deployment backfill

`checkpoint-history` bridges the pre-AggregateVerifier AntSeed range
`44,469,557..46,302,990` to the authenticated checkpoint at block
`46,302,990`. It uses 112 independent, resumable chunks in newest-to-oldest
order. Each chunk contains at most 16,384 canonical Base headers and commits to
a fixed-depth positional Merkle root, so only seller-evidence blocks need to be
materialized onchain.

```bash
cd checkpoint

# Fetch all 112 witnesses. Use --chunks 0 for the newest chunk only.
# Completed pages are cached atomically, so rerunning resumes an interrupted
# chunk. Raise --request-interval-ms when the provider returns HTTP 429.
cargo run --release -p checkpoint-host --bin checkpoint-history -- \
  --artifact-dir history-artifacts fetch \
  --concurrency 4 --page-size 512 --request-interval-ms 250

# Execute locally, record cycle counts, and enforce the 1B-cycle limit.
cargo run --release -p checkpoint-host --bin checkpoint-history -- \
  --artifact-dir history-artifacts dry-run

# Paid proving is impossible without both explicit price and confirmation.
cargo run --release -p checkpoint-host --bin checkpoint-history -- \
  --artifact-dir history-artifacts prove \
  --max-price "0.01 USD" --confirm-paid-proving

# Produce calldata only; this command never broadcasts transactions.
cargo run --release -p checkpoint-host --bin checkpoint-history -- \
  --artifact-dir history-artifacts tx-plan \
  --oracle 0x...

# Materialize only historical blocks referenced by an accepted current witness.
cargo run --release -p checkpoint-host --bin checkpoint-history -- \
  --artifact-dir history-artifacts materialize-plan \
  --oracle 0x... --seller-fixture ../out/proof-witness.json
```

Every fetch, dry run, and proof transition is persisted in `manifest.json`.
Partial fetches additionally persist canonical RLP header pages beside the
manifest; their numbering, encoding, and parent links are revalidated before
every resume. The manifest records the input SHA-256, image ID, expected
journal digest, cycle count, Boundless request ID, seal, and journal. A resumed
command rejects changed inputs or journals. Paid proving additionally requires
`BOUNDLESS_REQUESTOR_KEY` and a configured Pinata, S3, or GCS uploader.

The Base deployment requires `HISTORICAL_CHUNK_IMAGE_ID` alongside the existing
checkpoint and seller image IDs. Production flow first submits the existing
checkpoint proof for block `46,302,990`, calls `beginHistoricalBackfill`, then
submits the 112 chunk proofs newest-to-oldest. No command broadcasts deployment
or submissions automatically.

The current pinned historical-chunk image ID is
`c1cc15f700032158b03f782aaa7aa23f02851ab6f6a0ba8452beb504eecf0475`.

The 16,384-header geometry was measured after routing both canonical-header and
Merkle hashing through RISC Zero's Keccak coprocessor. A full synthetic chunk
with production-shaped post-Cancun headers produced a 10,748,564-byte input,
712,438,437 user cycles, and 786,563,072 padded RV32 cycles across 751 segments.
The guest journal exactly matched native validation. The same benchmark before
accelerated header hashing required 2,584,739,840 padded cycles, so the
accelerated path is required to satisfy the 1-billion-cycle admission limit.

## Current measurement

A live Base mainnet run on 2026-08-19 authenticated a target 28 blocks behind
the checkpoint (29 contiguous headers total):

- guest image ID
  `e719072a9e3c7645903268b7e01079b5ea7704612b680d9401964b83a83e643e`;
- 7,923,466 user cycles;
- 9,568,256 padded total cycles across 10 segments;
- about 356 ms for a local development receipt.

The Base oracle's two-block submission path measured 91,338 EVM execution gas
with a mock verifier. This excludes intrinsic/calldata gas and the production
RISC Zero verifier call. The deployed oracle runtime is 3,443 bytes.

Development receipts are structurally useful for E2E tests but are not secure
production proofs. A production Groth16 proof still requires a real local or
remote RISC Zero prover.
