# Wash-Trading Proof Dry Run — 2026-08-20

## Source

- Scan: `/Users/alex/.antseed/forensics/wash-trading/scans/2026-08-13T22-54-53-096Z`
- Period: Base blocks `44,471,575` through `49,936,172`
- State boundaries: blocks `44,471,574` and `49,936,172`
- Generated inventory: `/Users/alex/Documents/code/antseed-org/analyses/wash-trading/proof-coverage.json`

## Hardened Predicate-v2 Coverage

- Findings: `42` (`18` seller findings and `24` reciprocal pairs).
- Proof-ready: `39` (`1` closed cycle, `14` coordinated control, and `24` reciprocal pairs).
- Fails predicate: `3` seller findings.
- Proof-ready seller volume: `148,229.538173 USDC`.
- All seller-finding volume: `162,637.578608 USDC`.
- Seller-volume coverage: `91.1410139%`.
- Seller volume below the agreed proof thresholds: `14,408.040435 USDC`.
- Reciprocal gross volume is overlapping evidence and is not added to seller volume.

Multi-funder P1 evidence is accepted only when every included exact funder funded at least three selected buyers before their first channels. This prevents unrelated one-off buyer funders from being combined into a false coordinated-control claim. Three additional seller findings pass this hardened rule; three still fail the fixed `1,000 USDC` or `50%` threshold.

Seller-funded buyers are supported. For CatGPT (`0xb629449e487740c5fb86d7c4ddd51709d692dab4`), the predicate binds the seller as the exact funder and authenticates both the USDC `Transfer` into `AntseedDeposits` and the matching `Deposited(buyer, amount)` event in the same successful receipt.

## Legacy zkVM Baseline

The preserved authenticated Flash fixture was executed with:

```bash
cargo run --release -p loop-host --bin loop-host -- run cases/flash-full-report-fixture.json
```

Results:

- Native receipt verification: passed.
- RISC Zero guest execution without proof generation: passed.
- Authenticated settlements: `43,586` across `39,722` Base blocks.
- Report total: `44,847.928171 USDC`.
- Report suspected volume: `42,748.838506 USDC`.
- Qualified post-funding volume: `33,490.027681 USDC`.
- Journal SHA-256: `0xf44a443d31a0418faa7d0e37f6c7a756af317da90b6f03c02e69d1f119d27d6c`.

This proves the historical receipt pipeline and legacy guest execute, but it is not a predicate-v2 proof and cannot be submitted to the new registry.

## Predicate-v2 Materializer Dry Run

The new materializer is:

- `/Users/alex/Documents/code/antseed-org/loop-proof/host/src/bin/wash-trading-materialize.rs`

It now:

- selects threshold-sufficient P1 buyer/channel evidence;
- supports one or multiple exact funder cohorts;
- requires at least three selected buyers per included funder;
- supports successful native funding and authenticated protocol deposits;
- fetches transaction and receipt trie proofs;
- fetches chunked EIP-1186 storage witnesses;
- builds channel and emissions counter references; and
- runs native predicate verification before writing a v2 witness package.

The compact P1 case `0x5cd4413f15d664afbdab2fc4273c56e215aa08f1` reached historical transaction/receipt materialization. The run then failed at the required archive-state preflight:

```text
archive RPC preflight failed at the fixed state-start block
eth_getProof: no state found for block number 44471574
```

Alchemy does support Base `eth_getProof`, but its versioned proof store does
not currently cover the full frozen period. Calling `debug_proofsSyncStatus`
with the configured token returned:

```text
earliest: 48,930,390
latest:   50,226,401
```

An explicit proof request at the end boundary block `49,936,172` succeeded
with nine account-proof nodes. The required start boundary block `44,471,574`
is `4,458,816` blocks earlier than Alchemy's current proof index and returned
`no state found`. An earlier `latest` request also failed while the indexed tip
was changing; explicit in-range block requests confirmed that Base proof
support itself is working.

The materializer now uses two RPC roles:

- `BASE_RPC_URL` remains the primary endpoint for blocks, transactions,
  receipts, and logs.
- State-witness requests try `BASE_RPC_URL` first and fall back to
  `BASE_ARCHIVE_RPC_URL` only when the primary proof index does not cover the
  requested block.
- If no archive variable is configured, the start-boundary preflight fails
  safely because that block is outside Alchemy's current indexed range.

### Endpoint capability sweep

The exact `eth_getProof` request was tested at block `44,471,574` against the
configured endpoint and the public Base endpoints exposed by Base.org,
Alchemy, PublicNode, Blast, 1RPC, dRPC, GetBlock, Tatum, BlockPI, BlockReq,
bloXroute, Nodies, OMNIA, OnFinality, Pocket, Polkachu, Sentio, Tenderly,
thirdweb, Blockmachine, LeoRPC, Uniblock, and the QuickNode documentation demo.

- None of the public endpoints returned the historical account proof.
- Most enforce a recent-proof window or prune the historical trie state.
- PublicNode requires a personal archive token.
- The QuickNode documentation demo exposes `eth_getProof` but limits it to a
  recent 10,000-block range.
- Dwellir advertises a Base archive endpoint, but its shared public credential
  returned HTTP `429 Too Many Requests` on repeated checks.
- QuickNode documents Base `eth_getProof`, but explicitly limits the method to
  the most recent 10,000 Base blocks, so it cannot serve the fixed start
  boundary.
- Chainstack documents Base `eth_getProof`, bills historical calls as archive
  requests, and is listed by Base as supporting archive queries across the
  entire Base Mainnet history. A personal endpoint still must pass the exact
  boundary request.
- ChainNodes documents historical Base `eth_getProof` and advertises archival
  data, but the tested personal endpoint routed to an upstream that was roughly
  2.1 million blocks behind the end boundary and returned no usable start-state
  proof.
- PublicNode classifies the fixed-boundary request as archive access and
  requires a personal token. Dwellir advertises a Base archive endpoint, but
  its shared public credential returned HTTP `429 Too Many Requests`.

Because the canonical EIP-1186 proofs could not be fetched, no v2 witness was written and the new coordinated-control guest could not honestly be executed on the historical case. Fabricating or bypassing these proofs would invalidate the onchain security model.

## Plan B

The recommended fallback is a temporary personal Base archive endpoint. It is
needed only while materializing and caching the v2 witness packages; subsequent
native verification, zk proving, registry dry runs, and submissions work from
the saved witness and do not require ongoing archive access.

Provider candidates, in order of confidence from published capabilities and
the exact endpoint checks:

1. Chainstack Base archive node.
2. PublicNode personal archive token or an Allnodes hosted Base archive node.
3. Dwellir personal Base archive endpoint.
4. A repaired or rerouted ChainNodes Base archive endpoint.
5. A self-hosted Base archive node or snapshot, which is operationally much
   heavier and is not recommended for this one-time proof generation.

Before running the materializer, the candidate endpoint must return a nonempty
`result.accountProof` for contract
`0xBA66d3b4fbCf472F6F11D6F9F96aaCE96516F09d` at block `0x2a69516`.

Using `eth_getStorageAt` instead is not an acceptable fallback because it
returns a value without the Merkle path tying that value to the block's
`stateRoot`. A receipt-only redesign would require proving completeness across
roughly 5.46 million Base blocks and is substantially larger and riskier than
temporarily obtaining archive access.

## Next Acceptance Command

With an archive endpoint configured:

```bash
cd /Users/alex/Documents/code/antseed-org/loop-proof

BASE_ARCHIVE_RPC_URL="$ARCHIVE_BASE_RPC_URL" \
  cargo run --release -p loop-host --bin wash-trading-materialize -- \
  --scan-dir /Users/alex/.antseed/forensics/wash-trading/scans/2026-08-13T22-54-53-096Z \
  --seller 0x5cd4413f15d664afbdab2fc4273c56e215aa08f1 \
  --output cases/p1-5cd441-v2-witness.json

RISC0_DEV_MODE=1 cargo run --release -p loop-host --bin wash-trading-prove -- \
  --input cases/p1-5cd441-v2-witness.json \
  --output cases/p1-5cd441-v2-result.json \
  --prove
```

Production proving still requires `RISC0_DEV_MODE=0`, the production image IDs, canonical block-oracle materialization, and a Base-fork submission dry run.
