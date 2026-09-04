# antseed-loop-proof

Reference implementation of **AIP-4: Proof-Carrying Wash-Trading Enforcement**:
the direct SP1 seller guest, conserved-value-loop predicates, and host tooling
that materializes raw Base evidence into proof witnesses.

A seller result is proven directly from raw evidence. One SP1 execution
re-verifies every included closed-loop and reciprocal claim, unions settlement
IDs, rejects conflicts and overlaps, authenticates every referenced block, and
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

The direct seller verifier preserves the raw receipt, transaction, and storage
Merkle-Patricia checks performed by `verify_closed_loop` and
`verify_reciprocal`. It additionally enforces one seller and period, unique
claim IDs, settlement-ID deduplication, conflicting-amount rejection, checked
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

Produce one direct seller artifact from existing claim witnesses:

```bash
cargo run --release -p loop-host --features sp1 --bin wash-trading-prove-seller -- \
  --development \
  --seller 0x... \
  --seller-elf program/seller/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/seller-guest \
  --claim closed-loop:/path/to/closed-loop.witness.json \
  --claim reciprocal:/path/to/reciprocal.witness.json \
  --seller-witness /path/to/combined-seller-witness.json \
  --output /path/to/seller-proof.json
```

Available modes are:

- `--witness-only`: runs complete native verification and writes the combined
  seller witness without initializing SP1 or a prover network.
- `--execute-only`: additionally executes the seller guest and verifies its
  public values against native verification.
- `--development`: executes the guest and creates a development proof artifact
  accepted only by the local mock verifier integration.
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
volume. No RPC is used when current witness-cache files already exist, and
`proverNetworkSubmitted` remains `false`.

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
