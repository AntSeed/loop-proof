# AntSeed Loop-Proof Spike

Proof-of-concept for **proof-carrying wash-trading findings** on AntSeed: a
RISC Zero guest that proves, from raw Base chain data only, that a seller
funded a buyer (directly or through a chain of forwarding hops) and that the
buyer subsequently settled volume back to that same seller.

The proven statement ("the loop"):

```
seller ──USDC──▶ hop₁ ──▶ … ──▶ funder ──USDC──▶ buyer
   ▲                                                │
   └────────── ChannelSettled volume ◀──────────────┘
                 (strictly after funding)
```

No AntScan, no Blockscout, no trusted indexer: every event is authenticated by
recomputing the block's receipts root from the full receipt set and hashing
the header. The journal commits the `(number, hash)` of every block relied on;
on-chain, a registry checks those hashes are canonical and verifies the seal
against the pinned image ID. The image ID **is** the rule — changing any
threshold in `core/src/lib.rs` produces a different ID.

## Layout

- `core/` — shared types + the predicate (`loop_core::verify`). Runs natively
  and in the guest. Pinned rule constants at the top of `lib.rs`.
- `methods/guest/` — zkVM entrypoint (reads input, verifies, commits journal).
- `host/` — CLI: fetches evidence from Base RPC, re-encodes receipts to their
  exact trie-value form (validated against `receiptsRoot` before anything is
  trusted), runs the executor/prover.
- `cases/flash.json` — the real test vector: seller "Flash"
  (`0x0329c5d3…9b2c`), the network's one CRITICAL finding in the 2026-08 scan.
  3-hop payout chain → funder `0xd0b2…0b76` → buyer funding → settlements.

## Run

Requires Rust ≥1.88 and the RISC Zero toolchain (`rzup install`).

```bash
cargo build --release

# fetch evidence from public Base RPCs and build the fixture
./target/release/loop-host fetch --case cases/flash.json --out cases/flash-fixture.json

# execute in the zkVM (no proof, prints journal)
./target/release/loop-host run cases/flash-fixture.json

# dev-mode "proof" with real cycle counts (instant)
RISC0_DEV_MODE=1 ./target/release/loop-host run cases/flash-fixture.json --prove

# real STARK proof
./target/release/loop-host run cases/flash-fixture.json --prove
```

## Spike results (2026-08-18, Base mainnet data)

- Fixture: 7 blocks, 8 receipts with MPT inclusion proofs (3 hops + 1 funding
  transfer + 3 sample settlements), 55 KB.
- Guest: **2.94M user cycles** (3.3M total, 4 segments). The first iteration
  carried whole-block receipt sets instead of per-receipt proof paths and cost
  272M cycles — the MPT switch is an 83× reduction.
- Dev-mode proof: ~0.1 s. **Real STARK: 714 s on an Apple-Silicon Mac
  (CPU path)** — verified against the guest image ID, journal correct.
  A CUDA GPU or the Boundless market turns this into seconds-to-a-minute;
  the remaining CPU cost is prover backend, not guest size.
- Soundness checks: a tampered receipt byte and a mislabeled funding log are
  both rejected (no proof can be produced).

## Known simplifications (spike scope)

- **Funding shape B** (seller/funder deposits directly for the buyer via
  `AntseedDeposits.deposit(buyer, …)`) is implemented in the predicate but the
  host only fetches shape A. Verified to exist on-chain (20 × $10.00 seed
  deposits by the Flash funder).
- Whole-block receipt sets instead of per-receipt MPT proofs. Simpler and
  sound; MPT proof paths would cut cycles substantially for large blocks.
- Keccak is unaccelerated. The `sha3-keccak` feature of `alloy-primitives`
  plus RISC Zero's patched `sha3` crate should reduce cycles significantly.
- The journal's `block_refs` are self-declared; canonicality is the on-chain
  registry's job (checkpointer contract), out of scope here.
- Hop windows use block numbers, funding materiality is $1, forward share is
  98% — all deliberately pinned constants, versioned via `PREDICATE_VERSION`.
