//! AIP-4 conserved-value-loop predicates.
//!
//! A finding is a proof-carrying claim: this library re-verifies raw Base
//! evidence (receipts, transactions, and state, authenticated by
//! Merkle-Patricia proofs against block headers) and checks a fixed
//! mechanical predicate over it. The guest binary's verification key IS the
//! rule: changing any constant in this crate produces a different vkey and
//! therefore a different rule requiring a new registry.
//!
//! Both predicates prove the same thing — a conserved value loop. Fabricated
//! volume is volume settled with capital that the same party put in and got
//! back. Three magnitudes are bound together at comparable scale: capital
//! injected (`FUND`), volume settled (`SETTLE`), capital returned (`RETURN`),
//! with attribution of the buyers' funding through the protocol's own
//! accounting (`LEDGER`). Transfers between related wallets are never
//! sufficient by themselves.
//!
//! Every parameter is a ratio or a bound on evidence shape — never a
//! magnitude of volume. There is no volume floor and no minimum cohort size:
//! a single funded buyer in a conserved circuit is already a proven loop, and
//! any absolute floor in a public immutable rule would only tell an operator
//! how finely to slice its activity to stay beneath it.

use alloy_primitives::{address, keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

pub mod closed_loop;
pub mod journal;
pub mod reciprocal;
pub mod resolver;
pub mod stats;

pub use closed_loop::{verify_closed_loop, ClosedLoopInput};
pub use journal::{SubjectRecord, WashJournal};
pub use reciprocal::{verify_reciprocal, ReciprocalInput};

// ─── Rule identity ────────────────────────────────────────────────────────

pub const PREDICATE_VERSION: u32 = 2;
pub const CLOSED_LOOP_PREDICATE_ID: u8 = 1;
pub const RECIPROCAL_PREDICATE_ID: u8 = 2;
pub const BASE_CHAIN_ID: u64 = 8_453;

// ─── Enforcement period (fixed per rule; a new period is a new registry) ──

pub const PERIOD_START_BLOCK: u64 = 44_471_575;
/// Inclusive end block. The `LEDGER` witness and the `AgentStats` settled
/// volume are read here, fixing every claim's ratio at proving time.
pub const PERIOD_END_BLOCK: u64 = 49_936_172;
/// The pre-period state boundary the ledger's start side is read at.
pub const PERIOD_LEDGER_START_BLOCK: u64 = PERIOD_START_BLOCK - 1;

// ─── Predicate parameters ─────────────────────────────────────────────────
//
// PLACEHOLDER CALIBRATION: final values are fixed by the companion
// wash-trading detection AIP before any registry deployment. All are ratios
// (bps) or evidence-shape bounds — deliberately never volume magnitudes.

/// FUND must cover at least this share of the settled volume it fabricates.
pub const ALPHA_FUND_BPS: u64 = 9_000;
/// RETURN must carry at least this share of the settled volume back to the
/// funder.
pub const ALPHA_RETURN_BPS: u64 = 3_000;
/// Each return hop must forward at least this share of what it received.
/// Set low to accommodate real intermediary chains that batch or round
/// transfer amounts (observed: conduit forwards round-number amounts,
/// retaining 29-60 % per hop). False-positive resistance comes from the
/// compound effect: 28 % per hop over three hops is 2.2 %, so a random
/// chain cannot reach α_return on legitimate traffic.
pub const RHO_HOP_BPS: u64 = 2_800;
/// Tolerance on the per-buyer ledger reconciliation, as a share of the
/// funder-attributed amount (a ratio, so no absolute slack to hide inside).
pub const EPSILON_LEDGER_BPS: u64 = 500;
/// Reciprocal predicate: min/max directional volume ratio.
pub const BETA_RECIPROCAL_BPS: u64 = 8_000;
/// Reciprocal predicate: the pair must have financed at least this share of
/// its combined settled volume out of receipts from each other.
pub const ALPHA_SELF_BPS: u64 = 9_000;

/// End-to-end wall-clock bound on one return path (72 h). Intermediary
/// chains observed in production batch over 1-2 days; the bound must
/// accommodate the full hop chain without becoming so wide that unrelated
/// transfers qualify.
pub const T_PATH_SECONDS: u64 = 259_200;
/// Witness-sizing bound on intermediate return hops. Set well above observed
/// laundering topologies so it is never the binding constraint: what
/// qualifies a path is per-hop retention and the end-to-end total, not the
/// number of addresses it visits.
pub const H_MAX_INTERMEDIATE_HOPS: usize = 8;

// Witness-sizing limits (shape bounds, not thresholds).
pub const MAX_BUYERS: usize = 256;
pub const MAX_BLOCK_REFS: usize = 40_000;
pub const MAX_RETURN_PATHS: usize = 512;

// ─── Deployed contracts the evidence binds to (Base mainnet) ──────────────

pub const USDC_ADDRESS: Address = address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
pub const CHANNELS_ADDRESS: Address = address!("BA66d3b4fbCf472F6F11D6F9F96aaCE96516F09d");
pub const DEPOSITS_ADDRESS: Address = address!("0F7a3a8f4Da01637d1202bb5443fcF7F88F99fD2");
pub const STAKING_ADDRESS: Address = address!("3652E6B22919bd322A25723B94BB207602E5c8e6");

// ─── Storage layout bindings (verified against deployed bytecode) ─────────
//
// The guest derives every proven slot from these constants and the subject
// addresses; slots are never part of the witness, so a prover cannot point a
// proof at a different contract or field. Verified live against Base mainnet
// (`loop-host verify-layout <seller>`): e.g. for any agent id N,
// `_agentStats[N].totalVolumeUsdc` at keccak256(N ‖ 11) + 1 equals
// `getAgentStats(N).totalVolumeUsdc`.

/// `AntseedChannels.mapping(uint256 => AgentStats) private _agentStats`.
pub const CHANNELS_AGENT_STATS_SLOT: u64 = 11;
/// `AgentStats { uint64 channelCount; uint64 ghostCount; uint256
/// totalVolumeUsdc; uint64 lastSettledAt }` — the two u64s pack into the
/// first slot, so `totalVolumeUsdc` is at offset 1.
pub const AGENT_STATS_TOTAL_VOLUME_OFFSET: u64 = 1;
/// `AntseedStaking.mapping(address => uint256) public sellerAgentId`.
pub const STAKING_SELLER_AGENT_ID_SLOT: u64 = 4;
/// `AntseedDeposits.mapping(address => BuyerAccount) public buyers`.
pub const DEPOSITS_BUYERS_SLOT: u64 = 9;
/// `BuyerAccount.balance` is the struct's first field.
pub const BUYER_ACCOUNT_BALANCE_OFFSET: u64 = 0;

// ─── Evidence references ──────────────────────────────────────────────────

use alloy_consensus::Header;
use loop_core::{ReceiptProof, StorageProof, TransactionProof};

/// One referenced block: consensus header plus the inclusion-proven receipts
/// and transactions the claim touches.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceBlock {
    pub header: Header,
    pub receipts: Vec<ReceiptProof>,
    pub transactions: Vec<TransactionProof>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LogRef {
    pub block: usize,
    pub receipt: usize,
    pub log: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ReceiptRef {
    pub block: usize,
    pub receipt: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TransactionRef {
    pub block: usize,
    pub transaction: usize,
}

/// One authenticated storage read at a specific evidence block. The guest
/// derives the account address and slot; only the proof nodes travel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateRead {
    pub block: usize,
    pub proof: StorageProof,
}

/// `FUND` evidence: capital from the funder crediting one buyer. Every form
/// is attributed by recovering the funding transaction's signer — log topics
/// alone never attribute.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FundingKind {
    /// Direct USDC transfer funder → buyer.
    Usdc { transfer: LogRef },
    /// `Deposits.deposit(buyer, …)`: USDC transfer funder → Deposits paired
    /// with `Deposited(buyer, amount)` in the same receipt.
    ProtocolDeposit { transfer: LogRef, deposited: LogRef },
    /// Native transfer funder → buyer. Establishes funding order and shape
    /// only: native value is a different unit and never counts toward the
    /// USDC coverage or ledger sums.
    Native { transaction: TransactionRef, receipt: ReceiptRef },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FundingEvidence {
    pub buyer: Address,
    pub kind: FundingKind,
}

/// One `RETURN` path: a chain of USDC transfers seller → … → funder.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReturnPath {
    pub transfers: Vec<LogRef>,
}

/// `LEDGER` witness for one buyer: `Deposits.buyers[buyer].balance` proven
/// at both period bounds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuyerLedger {
    /// Read at `PERIOD_LEDGER_START_BLOCK`.
    pub start: StateRead,
    /// Read at `PERIOD_END_BLOCK`.
    pub end: StateRead,
}

/// Denominator witness for one subject: `Staking.sellerAgentId[subject]` and,
/// when the agent id is non-zero, `Channels._agentStats[id].totalVolumeUsdc`,
/// both at `PERIOD_END_BLOCK`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SellerStatsWitness {
    pub agent_id_read: StateRead,
    /// Required iff the proven agent id is non-zero.
    pub stats_read: Option<StateRead>,
}

// ─── Claim identifiers ────────────────────────────────────────────────────

alloy_sol_types::sol! {
    struct SolClosedLoopClaimId {
        uint256 chainId;
        uint8 predicateId;
        uint32 predicateVersion;
        uint64 periodStartBlock;
        uint64 periodEndBlock;
        address seller;
        address funder;
        bytes32 cohortHash;
    }
    struct SolReciprocalClaimId {
        uint256 chainId;
        uint8 predicateId;
        uint32 predicateVersion;
        uint64 periodStartBlock;
        uint64 periodEndBlock;
        address addressA;
        address addressB;
    }
}

pub fn cohort_hash(buyers: &[Address]) -> B256 {
    keccak256(buyers.to_vec().abi_encode())
}

pub fn closed_loop_claim_id(seller: Address, funder: Address, cohort: B256) -> B256 {
    keccak256(
        SolClosedLoopClaimId {
            chainId: U256::from(BASE_CHAIN_ID),
            predicateId: CLOSED_LOOP_PREDICATE_ID,
            predicateVersion: PREDICATE_VERSION,
            periodStartBlock: PERIOD_START_BLOCK,
            periodEndBlock: PERIOD_END_BLOCK,
            seller,
            funder,
            cohortHash: cohort,
        }
        .abi_encode(),
    )
}

pub fn reciprocal_claim_id(address_a: Address, address_b: Address) -> B256 {
    keccak256(
        SolReciprocalClaimId {
            chainId: U256::from(BASE_CHAIN_ID),
            predicateId: RECIPROCAL_PREDICATE_ID,
            predicateVersion: PREDICATE_VERSION,
            periodStartBlock: PERIOD_START_BLOCK,
            periodEndBlock: PERIOD_END_BLOCK,
            addressA: address_a,
            addressB: address_b,
        }
        .abi_encode(),
    )
}

// ─── Shared validation ────────────────────────────────────────────────────

pub(crate) fn validate_chain(chain_id: u64) -> Result<(), String> {
    if chain_id != BASE_CHAIN_ID {
        return Err("unrecognized chain".into());
    }
    Ok(())
}

pub(crate) fn validate_sorted_unique_addresses(
    values: &[Address],
    minimum: usize,
    maximum: usize,
    label: &str,
) -> Result<(), String> {
    if values.len() < minimum || values.len() > maximum {
        return Err(format!("{label}: invalid length"));
    }
    let mut previous = None;
    for value in values {
        if *value == Address::ZERO || previous.is_some_and(|prior| prior >= *value) {
            return Err(format!("{label}: values must be nonzero, sorted, and unique"));
        }
        previous = Some(*value);
    }
    Ok(())
}

/// Authenticate every evidence block: unique numbers within the witness
/// window, receipt and transaction inclusion proofs, unique per-block proof
/// indexes. Returns the sorted `(number, hash)` refs the journal commits.
pub(crate) fn authenticate_blocks(blocks: &[EvidenceBlock]) -> Result<Vec<(u64, B256)>, String> {
    use std::collections::BTreeSet;
    if blocks.is_empty() || blocks.len() > MAX_BLOCK_REFS {
        return Err("invalid block evidence count".into());
    }
    let mut numbers = BTreeSet::new();
    let mut refs = Vec::with_capacity(blocks.len());
    for block in blocks {
        let number = block.header.number;
        if !(PERIOD_LEDGER_START_BLOCK..=PERIOD_END_BLOCK).contains(&number) {
            return Err(format!("block {number} outside the witness window"));
        }
        if !numbers.insert(number) {
            return Err("duplicate block evidence".into());
        }
        let mut receipt_indexes = BTreeSet::new();
        for receipt in &block.receipts {
            if !receipt_indexes.insert(receipt.tx_index) {
                return Err("duplicate receipt proof".into());
            }
            loop_core::verify_receipt_inclusion(&block.header, receipt)?;
        }
        let mut transaction_indexes = BTreeSet::new();
        for transaction in &block.transactions {
            if !transaction_indexes.insert(transaction.tx_index) {
                return Err("duplicate transaction proof".into());
            }
            loop_core::verify_transaction_inclusion(&block.header, transaction)?;
        }
        refs.push((number, block.header.hash_slow()));
    }
    refs.sort_unstable_by_key(|value| value.0);
    Ok(refs)
}

/// Event evidence must sit inside the enforcement period proper (the
/// pre-period ledger boundary block carries state only, never events).
pub(crate) fn ensure_event_in_period(block: u64, label: &str) -> Result<(), String> {
    if !(PERIOD_START_BLOCK..=PERIOD_END_BLOCK).contains(&block) {
        return Err(format!("{label} is outside the fixed enforcement period"));
    }
    Ok(())
}

pub(crate) fn topic_address(topic: B256) -> Address {
    Address::from_slice(&topic.as_slice()[12..])
}

/// `numerator * 10_000 >= total * ratio_bps`, overflow-free.
pub(crate) fn meets_ratio(numerator: u128, total: u128, ratio_bps: u64) -> bool {
    U256::from(numerator) * U256::from(10_000u64) >= U256::from(total) * U256::from(ratio_bps)
}
