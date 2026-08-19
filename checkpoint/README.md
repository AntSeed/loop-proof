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
cargo run --release -p checkpoint-host -- --journal-out checkpoint-journal.hex
RISC0_DEV_MODE=1 cargo run --release -p checkpoint-host -- \
  --prove --seal-out checkpoint-seal.hex
```

The default game/index is a stable known-valid Base AggregateVerifier fixture.
Production automation should discover the newest ASR-valid AggregateVerifier
game, select the intermediate root following each evidence block, and archive
the Steel beacon root before Base's EIP-4788 retention window expires.

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
