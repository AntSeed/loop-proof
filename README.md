# antseed-loop-proof

Reference implementation of **AIP-4: Proof-Carrying Wash-Trading Enforcement**
— the zkVM guests, the conserved-value-loop predicate library, and the host
tooling that materializes raw Base evidence into guest witnesses.

A finding against a seller is never attested; it is **proven**. A guest
program re-verifies raw Base evidence — receipts, transactions, and contract
state, each authenticated by Merkle-Patricia proofs against block headers —
and checks a fixed mechanical predicate. The guest's verification key **is**
the rule: the on-chain `AntseedWashTradingRegistry` (AntSeed monorepo)
verifies the SP1 proof, authenticates every journal block hash against the
public [Chainlink BlockhashStore]
(`0x78b69899C8cD252126cBB1A50171ec37286C3877` on Base), and permanently
records the proven wash ratio. No committee, no multisig, no challenge
window, no company API, no scheduled infrastructure.

[Chainlink BlockhashStore]: https://docs.chain.link/vrf/v2-5/overview/subscription

## What the predicates prove

Both predicates prove a **conserved value loop**, not the existence of
transfers. Because claim submission is permissionless and the record is
permanent, the claimant is assumed adversarial: a predicate satisfiable by
sprinkling a few dollars around an honest seller would be a weapon. Three
magnitudes must therefore be bound together at comparable scale:

- **FUND** — capital the funder injected into the buyer cohort, attributed by
  recovered transaction signer (`Σ FUND ≥ α_fund · Σ SETTLE`);
- **SETTLE** — `ChannelSettled` volume from those buyers to the subject,
  each strictly after its buyer's funding;
- **RETURN** — value flowing back seller → funder, per-hop retention ≥
  `ρ_hop`, end-to-end within `T_path` (`Σ RETURN ≥ α_return · Σ SETTLE`);
- **LEDGER** — per-buyer attribution through the protocol's own accounting:
  `Deposits.buyers[b].balance` proven at both period bounds must reconcile
  with the funder-attributed capital
  (`balance_end + settledₑᵥ ≤ balance_start + funded · (1 + ε_ledger)`).

  *Note:* the deployed `AntseedDeposits` keeps a net `balance`, not a
  lifetime-cumulative deposit counter, so this balance-delta reconciliation
  is the strongest O(1)-witness form of AIP-4's attribution requirement
  implementable against deployed state. Unseen outflows (spend to other
  sellers, withdrawals) only make the check *stricter* for the claimed
  buyers' inflow, and looser measurement never flags anyone by itself —
  the RETURN and coverage legs still bind.

**There are no volume floors and no minimum cohort size.** Every parameter
is a ratio or an evidence-shape bound. A floor in a public immutable rule
tells an operator how finely to slice; ratios have no edge to sit under, and
splitting fabricated volume across identities *raises* each identity's
proven ratio.

The journal additionally commits the subject's own settled volume — read
inside the proof from `AntseedChannels.AgentStats.totalVolumeUsdc` at the
period-end block via storage proof — so the enforcement ratio
`washVolume / settledVolume` is fixed at proving time and cannot be diluted
by volume accumulated afterwards.

### Storage-layout bindings (verified against deployed bytecode)

The guest derives every proven storage slot itself; slots are never part of
the witness. Verified live on Base mainnet (`loop-host verify-layout`):

| binding | contract | slot |
|---|---|---|
| `_agentStats[id].totalVolumeUsdc` | Channels `0xBA66…F09d` | `keccak(id ‖ 11) + 1` |
| `sellerAgentId[seller]` | Staking `0x3652…c8e6` | `keccak(seller ‖ 4)` |
| `buyers[buyer].balance` | Deposits `0x0F7a…9fD2` | `keccak(buyer ‖ 9)` |

## Layout

```
core/               MPT/receipt/transaction/state-proof primitives (zkVM-agnostic)
predicate/          P0_CLOSED_LOOP + P0_RECIPROCAL predicates, journal, native tests
program/closed-loop SP1 guest (standalone crate, needs the SP1 toolchain)
program/reciprocal  SP1 guest
host/               witness materializer, prover driver, live layout cross-check
cases/              example case descriptions
scripts/            reproducible guest builds
```

## Usage

```bash
# native predicate + evidence-authentication tests (no zkVM toolchain needed)
cargo test

# live cross-check of pinned storage-layout constants against Base
cargo run -p loop-host -- verify-layout <seller_address> [seller_address ...]
cargo test -p loop-host -- --ignored     # same check as a test

# materialize evidence for a claim (archive RPC required for the two
# period-boundary state proofs; set BASE_RPC_URLS=<archive>,...)
cargo run -p loop-host -- fetch --case cases/<case>.json --out fixture.json [--expect-reject]

# reproducible guest builds + vkey derivation (SP1 toolchain + Docker)
scripts/build-guests.sh

# execute / prove
cargo run -p loop-host --features sp1 -- run fixture.json --prove --elf target/guests/closed-loop/<elf>
```

Case files in `cases/` describe a claim's participants (seller, funder,
buyers, return paths). `--expect-reject` asserts that the predicate
correctly rejects the evidence — use it for honest-seller test vectors
where the conserved-loop shape is absent.

## Rule identity

`PREDICATE_VERSION`, the enforcement period, every α/β/ρ/ε parameter, the
contract addresses, and the storage-slot bindings are constants in
`predicate/src/lib.rs`. Changing any of them changes both guest vkeys and
therefore the rule; a new rule is a new registry deployment. Current
parameter values are **calibration placeholders** — final values are fixed
by the companion wash-trading detection AIP before a registry is bound to a
live policy.

Guest builds are dockerized (`scripts/build-guests.sh`) so any party can
independently re-derive the pinned vkeys from source.
