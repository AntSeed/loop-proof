# antseed-loop-proof

Reference implementation of **AIP-4: Proof-Carrying Wash-Trading Enforcement**:
the direct SP1 seller guest, conserved-value-loop predicates, and host tooling
that materializes raw Base evidence into proof witnesses.

A seller result is proven directly from one raw evidence bundle. One SP1 execution
verifies either a closed-loop bundle or a reciprocal bundle, rejects duplicate
settlement IDs, authenticates every referenced block, proves the seller's total settled volume
from the channels contract's own cumulative counter at the period end, and
commits one schema-1 seller journal for the registry. There are no recursive
child proofs and no seller-aggregator guest.

This repository is proof infrastructure, not a mainnet security approval. A
production deployment still requires independently reviewed predicate
parameters, reproducible guest builds, real Groth16 proofs, the matching
concrete SP1 verifier, and canonical block authentication.

## What is proven

Both predicates prove a **conserved USDC value loop**, not merely transfers:

- **FUND**: authenticated USDC funding covers the required share of settlement
  volume. Native-token funding is rejected by predicate version 8.
- **SETTLE**: authenticated `ChannelSettled` records bind exact buyers, sellers,
  settlement IDs, amounts, and ordering after funding.
- **RETURN**: authenticated seller-to-funder paths meet per-hop retention,
  end-to-end amount, and time bounds.
- **LEDGER**: authenticated period-end `Deposits.buyers[buyer].balance` storage
  proofs reconcile the selected funding and settlement activity.
- **TOTAL**: an authenticated period-end storage proof of
  `AntseedChannels._agentStats[sellerAgentId].totalVolumeUsdc` commits the
  seller's complete settled volume for the period (the period starts at
  protocol genesis, so the end counter is the period total). The journal's
  `provenWashVolume / totalSellerVolume` is therefore a lower-bound share
  with a complete, non-selectable denominator.

The direct seller verifier preserves the raw receipt, transaction, and storage
Merkle-Patricia checks performed by `verify_closed_loop` and
`verify_reciprocal`. It additionally enforces one seller, period, and evidence
bundle, unique settlement IDs, checked
volume arithmetic, deterministic evidence digests, and deterministic block
authentication roots.

There are no absolute volume floors or minimum cohort sizes. Predicate
parameters are ratios or evidence-shape bounds.

## Layout

```text
core/             Receipt, transaction, state, and MPT verification primitives
predicate/        Closed-loop, reciprocal, and direct seller verification
program/seller/   Single SP1 guest; emits the schema-1 registry journal
host/             Witness materializer and direct seller prover
scripts/          Historical orchestration, attestations, quotes, and calldata
```

## Local validation

```bash
# Native predicate and evidence-authentication tests
cargo test --workspace

# Build the only SP1 guest
scripts/build-guests.sh

# Generate synthetic direct development proofs
node scripts/generate-development-proofs.mjs
```

Produce one direct seller artifact from an existing evidence witness:

```bash
cargo run --release -p loop-host --features sp1 --bin wash-trading-prove-seller -- \
  --development \
  --seller 0x... \
  --seller-elf program/seller/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/seller-guest \
  --evidence closed-loop:/path/to/closed-loop.witness.json \
  --seller-witness /path/to/seller-witness.json \
  --output /path/to/seller-proof.json
```

Use `--evidence reciprocal:/path/to/reciprocal.witness.json` instead for a
reciprocal bundle. Exactly one `--evidence` is required; legacy `--claim` and
repeated evidence arguments are rejected. A bundle can contain many buyers,
settlements, and return paths, but there is no cross-bundle seller aggregation.
Batch tools reject multiple approved bundles for the same seller rather than
silently picking one. A reciprocal bundle may produce a separate proof for each
of its two sellers.

The guest input has one `evidence` object, not a `claims` array. Old seller input
JSON is rejected, even if its array has only one entry. Seller artifacts carry
`evidenceFormat: "single-bundle-v1"`; `claimCount: 1` and the singleton
`sourceClaimIds` array remain provenance metadata for downstream tools. Rebuild
the guest and regenerate seller inputs and proofs with its new program vkey;
old seller proof caches cannot be reused. This input simplification does not
change the current schema-1 on-chain journal ABI. Raw closed-loop and reciprocal
witness files remain reusable.

Set `BASE_RPC_URL` (or comma-separated `BASE_RPC_URLS`) to an archive RPC for
the period-end staking and channels storage proofs. For offline replay, pass
`--total-volume-witness /path/to/boundary.json` instead. This is the
`total_volume` object in the saved seller witness; no start-boundary
proof is requested. Artifacts and seller summaries expose `totalSellerVolumeRaw`
alongside `provenWashVolumeRaw`, both in USDC base units (six decimals).

Available modes are:

- `--witness-only`: runs complete native verification and writes the
  seller witness without initializing SP1 or a prover network.
- `--execute-only`: additionally executes the seller guest and verifies its
  public values against native verification.
- `--development`: executes the guest and creates a development proof artifact
  accepted only by the local mock verifier integration. It reuses the checked
  execution's public values to create and verify the SDK mock proof instead of
  executing the same guest a second time.
- `--production`: requests a real network Groth16 proof and requires
  `--confirm-production`, explicit price/time limits, a funded prover identity,
  and a resumable request checkpoint.

Development proof bytes are not production cryptographic evidence.

## Unified historical dataset

Freeze one scan and build one authenticated bundle, plan, and snapshot lock:

```bash
node scripts/build-unified-historical-snapshot.mjs \
  --scan-dir /path/to/unified-scan \
  --out-dir out/unified-historical \
  --rpc-url "$BASE_RPC_URL"
```

Materialize every approved claim and natively verify every direct seller proof
input without a prover-network request:

```bash
node scripts/generate-approved-development-proofs.mjs \
  --bundle out/unified-historical/proof-bundle.json \
  --plan out/unified-historical/proof-plan.json \
  --snapshot-lock out/unified-historical/snapshot-lock.json \
  --artifact-dir out/unified-historical/development \
  --witness-only
```

The summary fails unless every approved claim maps to every affected seller and
the sum of the 55 direct seller journals equals the approved unique settlement
volume. Cached claim witnesses avoid re-fetching claim evidence, but the seller
prover still needs the period-end total-volume storage proofs. All development
modes keep `proverNetworkSubmitted` set to `false`.

The paid batch orchestrator natively preflights every selected seller before
submitting any network request, including in `--preflight-only` mode. Failures
are recorded under `native-preflight/summary.json` and stop the entire selected
batch before spending. Cost-quote approval and reproducible-guest checks still
apply; a passing development artifact alone does not authorize paid proving.
For an offline paid preflight and submission, pass `--total-volume-witness-dir`
with one `<seller>.json` period-end boundary witness per selected seller; the
same boundary file is used for both native preflight and the paid proof input.

`prove-approved-historical-development.mjs` attempts every seller even if one
fails, writes `sellerFailures` and `complete` in its summary, and exits nonzero
for an incomplete run. An unstaked-at-period-end seller is a finding, not an
automatically excluded claim. Cached artifacts without a positive authenticated
total are stale and must be regenerated.

To report actual return coverage from the verified claim witnesses:

```bash
cargo run --release -p wash-predicate --example report_return_coverage -- /path/to/witnesses > return-coverage.json
```

For transfer-return closed loops, coverage is the sum of each return path's
minimum hop amount divided by the claim's selected settled volume. The fixed
`ALPHA_RETURN_BPS` floor remains 2000 (20%); it is not the wash share `V/T`.
Self-funded loops close by identity, and reciprocal claims do not use this
alpha-return test. Neither is assigned a fabricated measured return percentage.

To execute or development-prove existing historical witnesses:

```bash
node scripts/prove-approved-historical-development.mjs \
  --bundle out/unified-historical/proof-bundle.json \
  --witness-dir out/unified-historical/development \
  --artifact-dir out/volume-only-historical-development \
  --execute-only
```

Large sellers may require substantial SP1 execution time and memory. Use the
smallest seller first before scheduling the complete set.

## Reproducible guest identity

Build the seller guest twice in isolated source snapshots and compare ELF
digests before deriving its vkey:

```bash
node scripts/build-guests-reproducibly.mjs \
  --work-dir ../guest-repro-builds \
  --out guest-build-attestation.json
node scripts/verify-guest-build-attestation.mjs guest-build-attestation.json
```

Attestation version 4 contains exactly one guest entry: `seller`.

## Production proving

Production requests are intentionally guarded and resumable:

```bash
scripts/run-production-proofs-safe.sh canary
scripts/run-production-proofs-safe.sh full
```

The runner:

1. verifies the reproducible seller guest attestation;
2. obtains a live Succinct price recommendation without submitting work;
3. writes a digest-pinned cost quote for one proof per selected seller;
4. validates all witnesses and stable run configuration with a no-spend pass;
5. checks the funded prover account and expected seller vkey;
6. requires a second exact confirmation before any paid request; and
7. resumes each seller from its request checkpoint after interruption.

Do not run production mode merely to validate the implementation. The complete
native dataset check and representative SP1 execution are free of paid proof
requests.

## Registry submission artifacts

Each version-3 `antseed-wash-trading-seller-proof` contains registry-ready
`publicValues`, `proofBytes`, and gas-bounded block-authentication chunks.

```bash
node scripts/generate-aggregate-calldata.mjs \
  --seller-proof seller-proof.json \
  --output stage-seller-calldata.json

node scripts/generate-block-authentication-chunks.mjs \
  --seller-proof seller-proof.json \
  --output block-authentication-chunks.json
```

The first artifact encodes `stageSellerProof(bytes,bytes)`. The second flattens
and validates the seller proof's ordered block references and preserves each
Merkle proof needed by `authenticateBlockReferences` before finalization.

## Rule identity

`PREDICATE_VERSION`, ratio parameters, contract addresses, and storage-slot
bindings are constants in `predicate/src/lib.rs`. Any semantic change alters
the seller ELF and therefore its program vkey. The schema-1 registry pins that
single seller vkey and the concrete SP1 verifier release.
