# Base History Accumulator

This workspace proves the Base block hashes required by the wash-trading evidence proofs without trusting an archive RPC or an OP Stack output proposal.

## Security model

1. Each epoch guest receives exactly 16,384 canonical RLP Base headers.
2. It checks block numbers and every `parentHash` link, then commits a fixed-depth Merkle root over `(blockNumber, blockHash)` leaves.
3. The accumulator guest recursively verifies every SP1 compressed epoch proof, checks that the epoch public values are contiguous, and commits their ordered MMR root.
4. `AntseedBaseCheckpointOracle` verifies the wrapped SP1 Groth16 proof and checks its final Base block hash directly against Base's EIP-2935 history-storage contract.
5. A block is usable by an evidence proof only after `materializeHistoricalBlocks` verifies both its 14-level epoch branch and its MMR mountain proof and stores the exact `(blockNumber, blockHash)` pair.

The on-chain root is immutable in V1. It covers full epochs only, starting at Base block `44,469,557`, and must cover through block `49,936,172`.

## Build

```bash
cd loop-proof/checkpoint
cargo build --release -p checkpoint-host
```

Generate deployment metadata with `cargo run --release -p checkpoint-host -- program-metadata --out program-metadata.json`. Pin `programs.historyEpoch.recursionVKey` and `programs.accumulator.programVKey` in the oracle constructor.

## Production proof flow

Set `BASE_RPC_URL` to an archive-capable Base RPC. The fetcher performs concurrent header requests and persists one witness per epoch.

```bash
cd loop-proof/checkpoint
mkdir -p history-artifacts

cargo run --release -p checkpoint-host -- \
  plan --rpc-url "$BASE_RPC_URL" --out history-artifacts/manifest.json

cargo run --release -p checkpoint-host -- \
  fetch --rpc-url "$BASE_RPC_URL" \
  --manifest history-artifacts/manifest.json \
  --artifact-dir history-artifacts \
  --concurrency 32

cargo run --release -p checkpoint-host -- \
  prove-epochs \
  --manifest history-artifacts/manifest.json \
  --artifact-dir history-artifacts

cargo run --release -p checkpoint-host -- \
  aggregate \
  --manifest history-artifacts/manifest.json \
  --artifact-dir history-artifacts
```

Epoch proofs are resumable SP1 compressed proofs. Only the final recursive accumulator proof is wrapped in Groth16 for Solidity verification.

The aligned anchor must still be inside EIP-2935's 8,191-block window when submitted. If it expires during proving, rerun `plan` into the same manifest, then rerun `fetch`, `prove-epochs`, and `aggregate`. Cached epochs are validated and reused; only newly added epochs are fetched and proved.

## Deploy the oracle

```bash
cd antseed/packages/contracts
export SP1_VERIFIER=0x397A5f7f3dBd538f23DE225B51f532c34448dA9B
export HISTORY_EPOCH_RECURSION_VKEY=0x...
export HISTORY_ACCUMULATOR_PROGRAM_VKEY=0x...

forge script script/DeployBaseHistoricalAccumulatorOracle.s.sol \
  --rpc-url "$BASE_RPC_URL" --broadcast --verify
```

This is a fresh deployment. Do not point production registries at an older checkpoint-oracle deployment.

## Build and validate calldata

The proof planner emits every required block in `accumulatorSelection.materialization_block_numbers`.

```bash
BLOCKS=$(jq -r '.accumulatorSelection.materialization_block_numbers | join(",")' ../out/proof-plan.json)

cargo run --release -p checkpoint-host -- \
  state-plan \
  --manifest history-artifacts/manifest.json \
  --artifact-dir history-artifacts \
  --oracle "$BASE_STATE_ORACLE" \
  --blocks "$BLOCKS" \
  --batch-size 16 \
  --out history-artifacts/state-plan.json

node ../../antseed/packages/contracts/scripts/apply-base-state-plan.mjs \
  --plan history-artifacts/state-plan.json \
  --rpc-url "$BASE_RPC_URL" \
  --validate-only
```

For an Anvil fork, use `--fork-submit`. For Base mainnet, first record the printed plan digest, then use `--submit --confirm-plan-digest 0x...` with `SUBMITTER_PRIVATE_KEY` set. The executor is resumable and checks the exact accumulator end block, epoch count, MMR root, public-values digest, and every materialized `canonicalBlockHashes(blockNumber)` value after inclusion. State-plan generation requires the final accumulator proof to be SP1 Groth16.

## Preflight checks

Validate accumulator logic and generate the exact deployment vkeys before starting expensive proofs:

```bash
cargo test -p history-core -p checkpoint-core
cargo run --release -p checkpoint-host -- \
  program-metadata --out target/program-metadata.json
```

Set `SP1_PROVER=network` with `NETWORK_PRIVATE_KEY` for Succinct Network, or `SP1_PROVER=cpu` for local proving. Light or mock execution is rejected by `prove-epochs` and `aggregate` and can never be included in a production state plan. Network proving additionally requires mode-specific `SP1_NETWORK_MAX_COMPRESSED_BASE_FEE_PROVE_WEI` and `SP1_NETWORK_MAX_GROTH16_BASE_FEE_PROVE_WEI` ceilings plus `SP1_NETWORK_MAX_PRICE_PER_PGU_PROVE_WEI`; each request reads the live auction, checks the funded balance and approved ceilings, and signs the approved price-per-PGU cap. SP1's local simulation supplies the exact PGU limit for each witness.

Measure fetched epoch workloads locally without creating proofs:

```bash
cargo run --release -p checkpoint-host -- \
  measure-epochs \
  --manifest history-artifacts/manifest.json \
  --artifact-dir history-artifacts \
  --out history-artifacts/measurements.json
```

Exercise the full recursive guest path without writing release-eligible proof
artifacts by using a current manifest and at least the first fetched epoch:

```bash
cargo run --release -p checkpoint-host -- \
  smoke-recursive \
  --manifest history-artifacts/manifest.json \
  --artifact-dir history-artifacts \
  --out history-artifacts/recursive-smoke.json
```

The smoke report is explicitly marked `insecure-mock`; production `prove-epochs`
and `aggregate` still require cryptographically verifiable SP1 proofs.
