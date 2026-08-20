use alloy_consensus::{transaction::SignerRecoverable, Header, Transaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{address, b256, keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolValue;
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use loop_core::{
    receipt_log, receipt_success, trie_index_key, verify_receipt_inclusion, ReceiptProof,
    CHANNEL_SETTLED_TOPIC, TRANSFER_TOPIC,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PREDICATE_VERSION: u32 = 3;
pub const BASE_CHAIN_ID: u64 = 8_453;
pub const PERIOD_START_BLOCK: u64 = 44_471_575;
pub const PERIOD_END_BLOCK_EXCLUSIVE: u64 = 49_936_173;
pub const STATE_START_BLOCK: u64 = PERIOD_START_BLOCK - 1;
pub const STATE_END_BLOCK: u64 = PERIOD_END_BLOCK_EXCLUSIVE - 1;
pub const EMISSIONS_CUTOVER_BLOCK: u64 = 45_937_736;
pub const PENALTY_BPS: u16 = 9_000;
pub const MAX_BUYERS: usize = 160;
pub const MAX_FUNDERS: usize = 160;
pub const MAX_BLOCK_REFS: usize = 256;
pub const MINIMUM_BUYERS: usize = 3;
pub const MINIMUM_VOLUME_RAW: u128 = 1_000_000_000;
pub const MINIMUM_USDC_FUNDING_RAW: u128 = 1_000_000;
pub const MINIMUM_NATIVE_FUNDING_WEI: u128 = 50_000_000_000_000;
pub const MINIMUM_CLOSURE_RAW: u128 = 1_000_000;
pub const MINIMUM_RECIPROCAL_SETTLEMENTS: u32 = 100;
pub const MINIMUM_RECIPROCAL_DIRECTION_SETTLEMENTS: u32 = 10;
pub const MINIMUM_RECIPROCAL_DIRECTION_VOLUME_RAW: u128 = 10_000_000;
pub const MINIMUM_RECIPROCAL_VOLUME_BPS: u128 = 8_000;
pub const MAX_RELAY_SECONDS: u64 = 86_400;
pub const MAX_RELAY_EARLY_DELTA_RAW: u128 = 1_000;
pub const MIN_RELAY_RETAINED_BPS: u128 = 9_800;
pub const MAX_RELAY_LOSS_RAW: u128 = 1_000_000;

pub const USDC_ADDRESS: Address = address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
pub const CHANNELS_ADDRESS: Address = address!("BA66d3b4fbCf472F6F11D6F9F96aaCE96516F09d");
pub const DEPOSITS_ADDRESS: Address = address!("0F7a3a8f4Da01637d1202bb5443fcF7F88F99fD2");
pub const OLD_EMISSIONS_ADDRESS: Address = address!("36877fBa8Fa333aa46a1c57b66D132E4995C86b5");
pub const NEW_EMISSIONS_ADDRESS: Address = address!("F13bE52c4A3afC6AE29536f073588d01A0564088");
pub const SMART_ACCOUNT_IMPLEMENTATION: Address =
    address!("d206ac7fef53d83ed4563e770b28dba90d0d9ec8");
pub const SUPPORTED_SMART_ACCOUNT_A: Address = address!("ee7ae85f2fe2239e27d9c1e23fffe168d63b4055");
pub const SUPPORTED_SMART_ACCOUNT_B: Address = address!("17fe9197970454875df742a74b74ed5f984b645a");

pub const DEPOSITS_CODE_HASH: B256 =
    b256!("41f0965f0300d0ce16e2a5824ae52fecf4321f4083e62abfa309e64414f95955");
pub const CHANNELS_CODE_HASH: B256 =
    b256!("9d8c726d151e2257e2b4e50f46dcf0bc7c976786585ee3b902be55bd431f1ed8");
pub const OLD_EMISSIONS_CODE_HASH: B256 =
    b256!("5991d7a7f4d33f70e29ad71421820d37c8ae04eb99a720184b99a2b7d231876e");
pub const NEW_EMISSIONS_CODE_HASH: B256 =
    b256!("534c9513b91440044e12ad087f414f8ae0b59fd7cba3d892e1a522296bfcf464");
pub const SMART_ACCOUNT_PROXY_CODE_HASH: B256 =
    b256!("22bcbefe2dacbb6289d731af9eabb98fdfb6480f4c59c9b2f45f574f008ef68f");
pub const SMART_ACCOUNT_IMPLEMENTATION_CODE_HASH: B256 =
    b256!("491c065559650e64988c11ac6fb90a72bec27afa3b112a4962fded431a603352");

pub const DEPOSITS_BUYERS_SLOT: u64 = 9;
pub const CHANNELS_CHANNELS_SLOT: u64 = 9;
pub const OLD_EMISSIONS_SELLER_POINTS_SLOT: u64 = 10;
pub const OLD_EMISSIONS_BUYER_POINTS_SLOT: u64 = 11;
pub const NEW_EMISSIONS_SELLER_POINTS_SLOT: u64 = 14;
pub const NEW_EMISSIONS_BUYER_POINTS_SLOT: u64 = 15;
pub const MAX_EMISSIONS_EPOCH: u64 = 18;
pub const ERC1967_IMPLEMENTATION_SLOT: B256 =
    b256!("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");
pub const SMART_ACCOUNT_PLUGIN_COUNT_SLOT: B256 =
    b256!("c6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfca");
pub const SMART_ACCOUNT_OWNER_SLOT: B256 =
    b256!("c6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfd0");
pub const DEPOSITED_TOPIC: B256 =
    b256!("2da466a7b24304f47e87fa2e1e5a81b9831ce54fec19055ce277ca2f39ba42c4");

pub const CLOSED_CYCLE_PROOF_TYPE: u8 = 1;
pub const RECIPROCAL_PROOF_TYPE: u8 = 2;
pub const COORDINATED_CONTROL_PROOF_TYPE: u8 = 3;
pub const DIRECT_CLOSURE: u8 = 1;
pub const RELAY_CLOSURE: u8 = 2;

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionProof {
    pub tx_index: u64,
    pub value: Bytes,
    pub proof: Vec<Bytes>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnforcementBlock {
    pub header: Header,
    pub receipts: Vec<ReceiptProof>,
    pub transactions: Vec<TransactionProof>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Eip1186StorageProof {
    pub slot: B256,
    pub value: U256,
    pub proof: Vec<Bytes>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Eip1186AccountProof {
    pub block: usize,
    pub address: Address,
    pub exists: bool,
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
    pub account_proof: Vec<Bytes>,
    pub storage_proofs: Vec<Eip1186StorageProof>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct StateValueRef {
    pub account: usize,
    pub slot: B256,
    pub storage: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FunderAuthentication {
    Eoa {
        account: usize,
    },
    Eip7702 {
        account: usize,
        delegation_code: Bytes,
    },
    SupportedSmartAccount {
        proxy_account: usize,
        implementation_account: usize,
        implementation_slot: StateValueRef,
        plugin_count_slot: StateValueRef,
        owner_slot: StateValueRef,
        owner: Address,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FundingKind {
    Usdc {
        transfer: LogRef,
    },
    ProtocolDeposit {
        transfer: LogRef,
        deposited: LogRef,
    },
    Native {
        transaction: TransactionRef,
        receipt: ReceiptRef,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FundingEvidence {
    pub buyer: Address,
    pub first_channel_at: StateValueRef,
    pub authentication: FunderAuthentication,
    pub kind: FundingKind,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PositiveFundingEvidence {
    pub buyer: Address,
    pub kind: FundingKind,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementEvidence {
    pub settlement: LogRef,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayPathEvidence {
    pub seller_payment: LogRef,
    pub relay_forward: LogRef,
    pub final_receipt: LogRef,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ClosureEvidence {
    Direct { transfer: LogRef },
    Relay { paths: Vec<RelayPathEvidence> },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CounterKind {
    Seller,
    Buyer,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CounterDelta {
    pub kind: CounterKind,
    pub subject: Address,
    pub contract: Address,
    pub epoch: u64,
    pub start: StateValueRef,
    pub end: StateValueRef,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChannelDelta {
    pub channel_id: B256,
    pub buyer: Address,
    pub seller: Address,
    pub start_packed_amounts: StateValueRef,
    pub end_buyer: StateValueRef,
    pub end_seller: StateValueRef,
    pub end_packed_amounts: StateValueRef,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FunderCohort {
    pub funder: Address,
    pub linked_buyers: Vec<Address>,
    pub fundings: Vec<FundingEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClosedCycleInput {
    pub chain_id: u64,
    pub seller: Address,
    pub funder: Address,
    pub linked_buyers: Vec<Address>,
    pub blocks: Vec<EnforcementBlock>,
    pub fundings: Vec<PositiveFundingEvidence>,
    pub settlements: Vec<SettlementEvidence>,
    pub closure: ClosureEvidence,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReciprocalInput {
    pub chain_id: u64,
    pub address_a: Address,
    pub address_b: Address,
    pub blocks: Vec<EnforcementBlock>,
    pub settlements: Vec<SettlementEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoordinatedControlInput {
    pub chain_id: u64,
    pub seller: Address,
    pub funding_cohorts: Vec<FunderCohort>,
    pub blocks: Vec<EnforcementBlock>,
    pub state_proofs: Vec<Eip1186AccountProof>,
    pub channels: Vec<ChannelDelta>,
    pub seller_counters: Vec<CounterDelta>,
    pub buyer_counters: Vec<CounterDelta>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClosedCycleJournal {
    pub predicate_version: u32,
    pub claim_id: B256,
    pub period_start_block: u64,
    pub period_end_block_exclusive: u64,
    pub seller: Address,
    pub funder: Address,
    pub cohort_hash: B256,
    pub cohort_count: u32,
    pub qualified_volume_raw: u128,
    pub closure_kind: u8,
    pub closure_path_count: u32,
    pub penalty_bps: u16,
    pub block_refs: Vec<(u64, B256)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReciprocalJournal {
    pub predicate_version: u32,
    pub claim_id: B256,
    pub period_start_block: u64,
    pub period_end_block_exclusive: u64,
    pub address_a: Address,
    pub address_b: Address,
    pub settlement_count_a_to_b: u32,
    pub settlement_count_b_to_a: u32,
    pub volume_a_to_b_raw: u128,
    pub volume_b_to_a_raw: u128,
    pub penalty_bps: u16,
    pub block_refs: Vec<(u64, B256)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoordinatedControlJournal {
    pub predicate_version: u32,
    pub claim_id: B256,
    pub period_start_block: u64,
    pub period_end_block_exclusive: u64,
    pub seller: Address,
    pub funder_cohort_hash: B256,
    pub funder_count: u32,
    pub cohort_hash: B256,
    pub cohort_count: u32,
    pub qualified_cohort_volume_raw: u128,
    pub seller_period_volume_raw: u128,
    pub penalty_bps: u16,
    pub penalized_buyers: Vec<Address>,
    pub block_refs: Vec<(u64, B256)>,
}

alloy_sol_types::sol! {
    struct SolBlockRef { uint64 number; bytes32 blockHash; }
    struct SolClosedCycleJournal {
        uint32 predicateVersion; bytes32 claimId; uint64 periodStartBlock; uint64 periodEndBlockExclusive;
        address seller; address funder; bytes32 cohortHash; uint32 cohortCount; uint128 qualifiedVolumeRaw;
        uint8 closureKind; uint32 closurePathCount; uint16 penaltyBps; SolBlockRef[] blockRefs;
    }
    struct SolReciprocalJournal {
        uint32 predicateVersion; bytes32 claimId; uint64 periodStartBlock; uint64 periodEndBlockExclusive;
        address addressA; address addressB; uint32 settlementCountAToB; uint32 settlementCountBToA;
        uint128 volumeAToBRaw; uint128 volumeBToARaw; uint16 penaltyBps; SolBlockRef[] blockRefs;
    }
    struct SolCoordinatedControlJournal {
        uint32 predicateVersion; bytes32 claimId; uint64 periodStartBlock; uint64 periodEndBlockExclusive;
        address seller; bytes32 funderCohortHash; uint32 funderCount; bytes32 cohortHash; uint32 cohortCount; uint128 qualifiedCohortVolumeRaw;
        uint128 sellerPeriodVolumeRaw; uint16 penaltyBps; address[] penalizedBuyers; SolBlockRef[] blockRefs;
    }
    struct SolCohortClaimId {
        uint256 chainId; uint8 proofType; uint64 periodStartBlock; uint64 periodEndBlockExclusive;
        address seller; address funder; bytes32 cohortHash;
    }
    struct SolReciprocalClaimId {
        uint256 chainId; uint8 proofType; uint64 periodStartBlock; uint64 periodEndBlockExclusive;
        address addressA; address addressB;
    }
    struct SolCoordinatedControlClaimId {
        uint256 chainId; uint8 proofType; uint64 periodStartBlock; uint64 periodEndBlockExclusive;
        address seller; bytes32 funderCohortHash; bytes32 cohortHash;
    }
    struct SolFunderCohort { address funder; address[] buyers; }
}

fn sol_block_refs(refs: &[(u64, B256)]) -> Vec<SolBlockRef> {
    refs.iter()
        .map(|(number, block_hash)| SolBlockRef {
            number: *number,
            blockHash: *block_hash,
        })
        .collect()
}

impl ClosedCycleJournal {
    pub fn abi_encode(&self) -> Vec<u8> {
        SolClosedCycleJournal {
            predicateVersion: self.predicate_version,
            claimId: self.claim_id,
            periodStartBlock: self.period_start_block,
            periodEndBlockExclusive: self.period_end_block_exclusive,
            seller: self.seller,
            funder: self.funder,
            cohortHash: self.cohort_hash,
            cohortCount: self.cohort_count,
            qualifiedVolumeRaw: self.qualified_volume_raw,
            closureKind: self.closure_kind,
            closurePathCount: self.closure_path_count,
            penaltyBps: self.penalty_bps,
            blockRefs: sol_block_refs(&self.block_refs),
        }
        .abi_encode()
    }
}

impl ReciprocalJournal {
    pub fn abi_encode(&self) -> Vec<u8> {
        SolReciprocalJournal {
            predicateVersion: self.predicate_version,
            claimId: self.claim_id,
            periodStartBlock: self.period_start_block,
            periodEndBlockExclusive: self.period_end_block_exclusive,
            addressA: self.address_a,
            addressB: self.address_b,
            settlementCountAToB: self.settlement_count_a_to_b,
            settlementCountBToA: self.settlement_count_b_to_a,
            volumeAToBRaw: self.volume_a_to_b_raw,
            volumeBToARaw: self.volume_b_to_a_raw,
            penaltyBps: self.penalty_bps,
            blockRefs: sol_block_refs(&self.block_refs),
        }
        .abi_encode()
    }
}

impl CoordinatedControlJournal {
    pub fn abi_encode(&self) -> Vec<u8> {
        SolCoordinatedControlJournal {
            predicateVersion: self.predicate_version,
            claimId: self.claim_id,
            periodStartBlock: self.period_start_block,
            periodEndBlockExclusive: self.period_end_block_exclusive,
            seller: self.seller,
            funderCohortHash: self.funder_cohort_hash,
            funderCount: self.funder_count,
            cohortHash: self.cohort_hash,
            cohortCount: self.cohort_count,
            qualifiedCohortVolumeRaw: self.qualified_cohort_volume_raw,
            sellerPeriodVolumeRaw: self.seller_period_volume_raw,
            penaltyBps: self.penalty_bps,
            penalizedBuyers: self.penalized_buyers.clone(),
            blockRefs: sol_block_refs(&self.block_refs),
        }
        .abi_encode()
    }
}

pub fn verify_closed_cycle(input: &ClosedCycleInput) -> Result<ClosedCycleJournal, String> {
    validate_common(
        input.chain_id,
        input.seller,
        input.funder,
        &input.linked_buyers,
    )?;
    let block_refs = authenticate_blocks(&input.blocks)?;
    let resolver = ChainResolver {
        blocks: &input.blocks,
    };
    let funding_times = verify_positive_fundings(
        input.funder,
        &input.linked_buyers,
        &input.fundings,
        &resolver,
    )?;
    let (qualified_volume_raw, _, crossing_key) = verify_settlements(
        input.seller,
        &input.linked_buyers,
        &funding_times,
        &input.settlements,
        &resolver,
    )?;
    if qualified_volume_raw < MINIMUM_VOLUME_RAW {
        return Err("closed cycle: qualified volume below 1,000 USDC".into());
    }
    let (closure_kind, closure_path_count) = verify_closure(
        input.seller,
        input.funder,
        &input.linked_buyers,
        crossing_key.ok_or("closed cycle: threshold was not crossed")?,
        &input.closure,
        &resolver,
    )?;
    let cohort_hash = cohort_hash(&input.linked_buyers);
    Ok(ClosedCycleJournal {
        predicate_version: PREDICATE_VERSION,
        claim_id: cohort_claim_id(
            CLOSED_CYCLE_PROOF_TYPE,
            input.seller,
            input.funder,
            cohort_hash,
        ),
        period_start_block: PERIOD_START_BLOCK,
        period_end_block_exclusive: PERIOD_END_BLOCK_EXCLUSIVE,
        seller: input.seller,
        funder: input.funder,
        cohort_hash,
        cohort_count: input.linked_buyers.len() as u32,
        qualified_volume_raw,
        closure_kind,
        closure_path_count,
        penalty_bps: PENALTY_BPS,
        block_refs,
    })
}

pub fn verify_reciprocal(input: &ReciprocalInput) -> Result<ReciprocalJournal, String> {
    validate_chain(input.chain_id)?;
    if input.address_a == Address::ZERO
        || input.address_b == Address::ZERO
        || input.address_a >= input.address_b
    {
        return Err("reciprocal: pair must be nonzero and normalized".into());
    }
    let block_refs = authenticate_blocks(&input.blocks)?;
    let resolver = ChainResolver {
        blocks: &input.blocks,
    };
    let mut used = BTreeSet::new();
    let (mut count_ab, mut count_ba, mut volume_ab, mut volume_ba) = (0u32, 0u32, 0u128, 0u128);
    for evidence in &input.settlements {
        let key = resolver.log_key(evidence.settlement)?;
        if !used.insert(key) {
            return Err("reciprocal: duplicate settlement evidence".into());
        }
        let (_, buyer, seller, amount, block) = resolver.settlement(evidence.settlement)?;
        ensure_period_block(block, "reciprocal settlement")?;
        if amount == 0 {
            return Err("reciprocal: zero settlement".into());
        }
        if buyer == input.address_a && seller == input.address_b {
            count_ab = count_ab
                .checked_add(1)
                .ok_or("reciprocal: count overflow")?;
            volume_ab = volume_ab
                .checked_add(amount)
                .ok_or("reciprocal: volume overflow")?;
        } else if buyer == input.address_b && seller == input.address_a {
            count_ba = count_ba
                .checked_add(1)
                .ok_or("reciprocal: count overflow")?;
            volume_ba = volume_ba
                .checked_add(amount)
                .ok_or("reciprocal: volume overflow")?;
        } else {
            return Err("reciprocal: settlement does not belong to exact ordered pair".into());
        }
    }
    if !reciprocal_thresholds_satisfied(count_ab, count_ba, volume_ab, volume_ba)? {
        return Err("reciprocal: directional threshold not satisfied".into());
    }
    Ok(ReciprocalJournal {
        predicate_version: PREDICATE_VERSION,
        claim_id: reciprocal_claim_id(input.address_a, input.address_b),
        period_start_block: PERIOD_START_BLOCK,
        period_end_block_exclusive: PERIOD_END_BLOCK_EXCLUSIVE,
        address_a: input.address_a,
        address_b: input.address_b,
        settlement_count_a_to_b: count_ab,
        settlement_count_b_to_a: count_ba,
        volume_a_to_b_raw: volume_ab,
        volume_b_to_a_raw: volume_ba,
        penalty_bps: PENALTY_BPS,
        block_refs,
    })
}

fn reciprocal_thresholds_satisfied(
    count_ab: u32,
    count_ba: u32,
    volume_ab: u128,
    volume_ba: u128,
) -> Result<bool, String> {
    let total_count = count_ab
        .checked_add(count_ba)
        .ok_or("reciprocal: count overflow")?;
    let minimum_volume = volume_ab.min(volume_ba);
    let maximum_volume = volume_ab.max(volume_ba);
    let reciprocal = minimum_volume
        .checked_mul(10_000)
        .ok_or("reciprocal: ratio overflow")?
        >= maximum_volume
            .checked_mul(MINIMUM_RECIPROCAL_VOLUME_BPS)
            .ok_or("reciprocal: ratio overflow")?;
    Ok(total_count >= MINIMUM_RECIPROCAL_SETTLEMENTS
        && count_ab >= MINIMUM_RECIPROCAL_DIRECTION_SETTLEMENTS
        && count_ba >= MINIMUM_RECIPROCAL_DIRECTION_SETTLEMENTS
        && volume_ab >= MINIMUM_RECIPROCAL_DIRECTION_VOLUME_RAW
        && volume_ba >= MINIMUM_RECIPROCAL_DIRECTION_VOLUME_RAW
        && reciprocal)
}

pub fn verify_coordinated_control(
    input: &CoordinatedControlInput,
) -> Result<CoordinatedControlJournal, String> {
    validate_chain(input.chain_id)?;
    if input.seller == Address::ZERO {
        return Err("coordinated control: zero seller".into());
    }
    let linked_buyers = validate_funding_cohorts(&input.funding_cohorts)?;
    let block_refs = authenticate_blocks(&input.blocks)?;
    let state = StateResolver::authenticate(&input.blocks, &input.state_proofs)?;
    let resolver = ChainResolver {
        blocks: &input.blocks,
    };
    for cohort in &input.funding_cohorts {
        verify_state_fundings(
            cohort.funder,
            &cohort.linked_buyers,
            &cohort.fundings,
            &resolver,
            &state,
        )?;
    }
    let linked = linked_buyers.iter().copied().collect::<BTreeSet<_>>();
    let mut channel_ids = BTreeSet::new();
    let mut target_volumes = BTreeMap::<Address, u128>::new();
    let mut cohort_volume = 0u128;
    for channel in &input.channels {
        if !channel_ids.insert(channel.channel_id) {
            return Err("coordinated control: duplicate channel".into());
        }
        if channel.seller != input.seller || !linked.contains(&channel.buyer) {
            return Err("coordinated control: channel subject mismatch".into());
        }
        let base = channel_base_slot(channel.channel_id);
        let start_word = state.read_expected(
            channel.start_packed_amounts,
            STATE_START_BLOCK,
            CHANNELS_ADDRESS,
            Some(CHANNELS_CODE_HASH),
            add_slot(base, 2)?,
        )?;
        let end_buyer = state.read_expected(
            channel.end_buyer,
            STATE_END_BLOCK,
            CHANNELS_ADDRESS,
            Some(CHANNELS_CODE_HASH),
            base,
        )?;
        let end_seller = state.read_expected(
            channel.end_seller,
            STATE_END_BLOCK,
            CHANNELS_ADDRESS,
            Some(CHANNELS_CODE_HASH),
            add_slot(base, 1)?,
        )?;
        let end_word = state.read_expected(
            channel.end_packed_amounts,
            STATE_END_BLOCK,
            CHANNELS_ADDRESS,
            Some(CHANNELS_CODE_HASH),
            add_slot(base, 2)?,
        )?;
        if word_address(end_buyer) != channel.buyer || word_address(end_seller) != channel.seller {
            return Err("coordinated control: authenticated channel parties differ".into());
        }
        let delta = packed_settled(end_word)
            .checked_sub(packed_settled(start_word))
            .ok_or("coordinated control: channel underflow")?;
        cohort_volume = cohort_volume
            .checked_add(delta)
            .ok_or("coordinated control: cohort overflow")?;
        let total = target_volumes.entry(channel.buyer).or_default();
        *total = total
            .checked_add(delta)
            .ok_or("coordinated control: buyer overflow")?;
    }
    if cohort_volume < MINIMUM_VOLUME_RAW {
        return Err("coordinated control: cohort volume below 1,000 USDC".into());
    }
    let seller_period_volume = counter_total(
        CounterKind::Seller,
        input.seller,
        &input.seller_counters,
        &state,
    )?;
    if cohort_volume
        .checked_mul(2)
        .ok_or("coordinated control: ratio overflow")?
        < seller_period_volume
    {
        return Err("coordinated control: cohort is below 50 percent".into());
    }
    let penalized_buyers = qualifying_buyers(
        &linked_buyers,
        &target_volumes,
        &input.buyer_counters,
        &state,
    )?;
    let cohort_hash = cohort_hash(&linked_buyers);
    let funder_cohort_hash = funder_cohort_hash(&input.funding_cohorts);
    Ok(CoordinatedControlJournal {
        predicate_version: PREDICATE_VERSION,
        claim_id: coordinated_control_claim_id(input.seller, funder_cohort_hash, cohort_hash),
        period_start_block: PERIOD_START_BLOCK,
        period_end_block_exclusive: PERIOD_END_BLOCK_EXCLUSIVE,
        seller: input.seller,
        funder_cohort_hash,
        funder_count: input.funding_cohorts.len() as u32,
        cohort_hash,
        cohort_count: linked_buyers.len() as u32,
        qualified_cohort_volume_raw: cohort_volume,
        seller_period_volume_raw: seller_period_volume,
        penalty_bps: PENALTY_BPS,
        penalized_buyers,
        block_refs,
    })
}

fn validate_chain(chain_id: u64) -> Result<(), String> {
    if chain_id != BASE_CHAIN_ID {
        return Err("unrecognized chain".into());
    }
    Ok(())
}

fn validate_common(
    chain_id: u64,
    seller: Address,
    funder: Address,
    buyers: &[Address],
) -> Result<(), String> {
    validate_chain(chain_id)?;
    if seller == Address::ZERO || funder == Address::ZERO {
        return Err("cohort: zero seller or funder".into());
    }
    validate_sorted_unique_addresses(buyers, MINIMUM_BUYERS, MAX_BUYERS, "linked buyers")
}

fn validate_funding_cohorts(cohorts: &[FunderCohort]) -> Result<Vec<Address>, String> {
    if cohorts.is_empty() || cohorts.len() > MAX_FUNDERS {
        return Err("funding cohorts: invalid length".into());
    }
    let mut previous_funder = None;
    let mut buyers = BTreeSet::new();
    for cohort in cohorts {
        if cohort.funder == Address::ZERO
            || previous_funder.is_some_and(|previous| previous >= cohort.funder)
        {
            return Err("funding cohorts: funders must be nonzero, sorted, and unique".into());
        }
        validate_sorted_unique_addresses(
            &cohort.linked_buyers,
            MINIMUM_BUYERS,
            MAX_BUYERS,
            "funder cohort buyers",
        )?;
        for buyer in &cohort.linked_buyers {
            if !buyers.insert(*buyer) {
                return Err("funding cohorts: buyer assigned to multiple funders".into());
            }
        }
        previous_funder = Some(cohort.funder);
    }
    if buyers.len() < MINIMUM_BUYERS || buyers.len() > MAX_BUYERS {
        return Err("funding cohorts: invalid total buyer count".into());
    }
    Ok(buyers.into_iter().collect())
}

fn validate_sorted_unique_addresses(
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
            return Err(format!(
                "{label}: values must be nonzero, sorted, and unique"
            ));
        }
        previous = Some(*value);
    }
    Ok(())
}

fn authenticate_blocks(blocks: &[EnforcementBlock]) -> Result<Vec<(u64, B256)>, String> {
    if blocks.is_empty() || blocks.len() > MAX_BLOCK_REFS {
        return Err("invalid block evidence count".into());
    }
    let mut numbers = BTreeSet::new();
    let mut refs = Vec::with_capacity(blocks.len());
    for block in blocks {
        if !numbers.insert(block.header.number) {
            return Err("duplicate block evidence".into());
        }
        let mut receipt_indexes = BTreeSet::new();
        for receipt in &block.receipts {
            if !receipt_indexes.insert(receipt.tx_index) {
                return Err("duplicate receipt proof".into());
            }
            verify_receipt_inclusion(&block.header, receipt)?;
        }
        let mut transaction_indexes = BTreeSet::new();
        for transaction in &block.transactions {
            if !transaction_indexes.insert(transaction.tx_index) {
                return Err("duplicate transaction proof".into());
            }
            verify_transaction_inclusion(&block.header, transaction)?;
        }
        refs.push((block.header.number, block.header.hash_slow()));
    }
    refs.sort_unstable_by_key(|value| value.0);
    Ok(refs)
}

fn verify_transaction_inclusion(
    header: &Header,
    transaction: &TransactionProof,
) -> Result<(), String> {
    verify_proof(
        header.transactions_root,
        Nibbles::unpack(trie_index_key(transaction.tx_index)),
        Some(transaction.value.to_vec()),
        transaction.proof.iter(),
    )
    .map_err(|error| format!("transaction inclusion: {error}"))
}

struct StateResolver<'a> {
    blocks: &'a [EnforcementBlock],
    proofs: &'a [Eip1186AccountProof],
}

impl<'a> StateResolver<'a> {
    fn authenticate(
        blocks: &'a [EnforcementBlock],
        proofs: &'a [Eip1186AccountProof],
    ) -> Result<Self, String> {
        let mut accounts = BTreeSet::new();
        for proof in proofs {
            let block = blocks
                .get(proof.block)
                .ok_or("state proof block out of range")?;
            if !accounts.insert((block.header.number, proof.address)) {
                return Err("duplicate account proof".into());
            }
            let expected_account = if proof.exists {
                Some(alloy_rlp::encode(TrieAccount {
                    nonce: proof.nonce,
                    balance: proof.balance,
                    storage_root: proof.storage_root,
                    code_hash: proof.code_hash,
                }))
            } else {
                if proof.nonce != 0
                    || proof.balance != U256::ZERO
                    || proof.storage_root != EMPTY_ROOT_HASH
                    || proof.code_hash != KECCAK_EMPTY
                    || !proof.storage_proofs.is_empty()
                {
                    return Err("malformed non-inclusion account proof".into());
                }
                None
            };
            verify_proof(
                block.header.state_root,
                Nibbles::unpack(keccak256(proof.address)),
                expected_account,
                proof.account_proof.iter(),
            )
            .map_err(|error| format!("account proof: {error}"))?;
            let mut slots = BTreeSet::new();
            for storage in &proof.storage_proofs {
                if !slots.insert(storage.slot) {
                    return Err("duplicate storage slot proof".into());
                }
                let expected = if storage.value == U256::ZERO {
                    None
                } else {
                    Some(alloy_rlp::encode(storage.value))
                };
                verify_proof(
                    proof.storage_root,
                    Nibbles::unpack(keccak256(storage.slot)),
                    expected,
                    storage.proof.iter(),
                )
                .map_err(|error| format!("storage proof: {error}"))?;
            }
        }
        Ok(Self { blocks, proofs })
    }

    fn account(&self, index: usize) -> Result<&Eip1186AccountProof, String> {
        self.proofs
            .get(index)
            .ok_or("account reference out of range".into())
    }

    fn read_expected(
        &self,
        reference: StateValueRef,
        block_number: u64,
        address: Address,
        code_hash: Option<B256>,
        expected_slot: B256,
    ) -> Result<U256, String> {
        if reference.slot != expected_slot {
            return Err("wrong storage slot".into());
        }
        let account = self.account(reference.account)?;
        let block = self
            .blocks
            .get(account.block)
            .ok_or("state proof block out of range")?;
        if block.header.number != block_number || account.address != address {
            return Err("state proof subject or boundary mismatch".into());
        }
        if !account.exists {
            if reference.storage.is_some() || code_hash.is_some() {
                return Err("required account does not exist".into());
            }
            return Ok(U256::ZERO);
        }
        if code_hash.is_some_and(|expected| account.code_hash != expected) {
            return Err("wrong contract code hash".into());
        }
        let storage = account
            .storage_proofs
            .get(reference.storage.ok_or("missing storage proof reference")?)
            .ok_or("storage proof reference out of range")?;
        if storage.slot != reference.slot {
            return Err("storage proof reference points to wrong slot".into());
        }
        Ok(storage.value)
    }
}

struct ChainResolver<'a> {
    blocks: &'a [EnforcementBlock],
}

impl ChainResolver<'_> {
    fn block(&self, index: usize) -> Result<&EnforcementBlock, String> {
        self.blocks
            .get(index)
            .ok_or("block reference out of range".into())
    }

    fn receipt(&self, reference: ReceiptRef) -> Result<(&ReceiptProof, &EnforcementBlock), String> {
        let block = self.block(reference.block)?;
        Ok((
            block
                .receipts
                .get(reference.receipt)
                .ok_or("receipt reference out of range")?,
            block,
        ))
    }

    fn log(
        &self,
        reference: LogRef,
    ) -> Result<(loop_core::ParsedLog, &ReceiptProof, &EnforcementBlock), String> {
        let (receipt, block) = self.receipt(ReceiptRef {
            block: reference.block,
            receipt: reference.receipt,
        })?;
        if !receipt_success(&receipt.value)? {
            return Err("referenced receipt reverted".into());
        }
        Ok((receipt_log(&receipt.value, reference.log)?, receipt, block))
    }

    fn log_key(&self, reference: LogRef) -> Result<(u64, u64, usize), String> {
        let (_, receipt, block) = self.log(reference)?;
        Ok((block.header.number, receipt.tx_index, reference.log))
    }

    fn transaction(
        &self,
        reference: TransactionRef,
    ) -> Result<(&TransactionProof, &EnforcementBlock), String> {
        let block = self.block(reference.block)?;
        Ok((
            block
                .transactions
                .get(reference.transaction)
                .ok_or("transaction reference out of range")?,
            block,
        ))
    }

    fn transaction_for_log(&self, reference: LogRef) -> Result<TransactionRef, String> {
        let (_, receipt, block) = self.log(reference)?;
        let mut matches = block
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, transaction)| transaction.tx_index == receipt.tx_index);
        let (position, _) = matches
            .next()
            .ok_or("authenticated transaction missing for receipt")?;
        if matches.next().is_some() {
            return Err("duplicate authenticated transaction for receipt".into());
        }
        Ok(TransactionRef {
            block: reference.block,
            transaction: position,
        })
    }

    fn decoded_transaction(
        &self,
        reference: TransactionRef,
    ) -> Result<(TxEnvelope, Address, &EnforcementBlock), String> {
        let (proof, block) = self.transaction(reference)?;
        let mut bytes = proof.value.as_ref();
        let envelope = TxEnvelope::decode_2718(&mut bytes)
            .map_err(|error| format!("transaction decode: {error}"))?;
        if !bytes.is_empty() {
            return Err("transaction has trailing bytes".into());
        }
        let signer = envelope
            .recover_signer()
            .map_err(|_| "transaction signer recovery failed")?;
        Ok((envelope, signer, block))
    }

    fn usdc_transfer(&self, reference: LogRef) -> Result<(Address, Address, u128, u64), String> {
        let (log, _, block) = self.log(reference)?;
        if log.address != USDC_ADDRESS
            || log.topics.len() != 3
            || log.topics[0] != TRANSFER_TOPIC
            || log.data.len() != 32
        {
            return Err("not a USDC transfer".into());
        }
        Ok((
            topic_address(log.topics[1]),
            topic_address(log.topics[2]),
            u128::try_from(U256::from_be_slice(&log.data)).map_err(|_| "USDC amount overflow")?,
            block.header.number,
        ))
    }

    fn settlement(&self, reference: LogRef) -> Result<(B256, Address, Address, u128, u64), String> {
        let (log, _, block) = self.log(reference)?;
        if log.address != CHANNELS_ADDRESS
            || log.topics.len() != 4
            || log.topics[0] != CHANNEL_SETTLED_TOPIC
            || log.data.len() < 64
        {
            return Err("not a ChannelSettled event".into());
        }
        Ok((
            log.topics[1],
            topic_address(log.topics[2]),
            topic_address(log.topics[3]),
            u128::try_from(U256::from_be_slice(&log.data[32..64]))
                .map_err(|_| "settlement amount overflow")?,
            block.header.number,
        ))
    }

    fn protocol_deposit(&self, reference: LogRef) -> Result<(Address, u128, u64), String> {
        let (log, _, block) = self.log(reference)?;
        if log.address != DEPOSITS_ADDRESS
            || log.topics.len() != 2
            || log.topics[0] != DEPOSITED_TOPIC
            || log.data.len() != 32
        {
            return Err("not an Antseed Deposited event".into());
        }
        Ok((
            topic_address(log.topics[1]),
            u128::try_from(U256::from_be_slice(&log.data))
                .map_err(|_| "deposit amount overflow")?,
            block.header.number,
        ))
    }
}

fn verify_positive_fundings(
    funder: Address,
    linked_buyers: &[Address],
    fundings: &[PositiveFundingEvidence],
    resolver: &ChainResolver<'_>,
) -> Result<BTreeMap<Address, u64>, String> {
    if fundings.len() != linked_buyers.len() {
        return Err("funding evidence must cover each linked buyer exactly once".into());
    }
    let linked = linked_buyers.iter().copied().collect::<BTreeSet<_>>();
    let mut times = BTreeMap::new();
    for evidence in fundings {
        if !linked.contains(&evidence.buyer) || times.contains_key(&evidence.buyer) {
            return Err("duplicate or unrelated funding buyer".into());
        }
        let funding_time = match evidence.kind {
            FundingKind::Usdc { transfer } => {
                let (from, to, amount, _) = resolver.usdc_transfer(transfer)?;
                if from != funder || to != evidence.buyer || amount < MINIMUM_USDC_FUNDING_RAW {
                    return Err("invalid direct USDC funding".into());
                }
                require_transaction_signer(
                    funder,
                    resolver.transaction_for_log(transfer)?,
                    resolver,
                )?;
                resolver.block(transfer.block)?.header.timestamp
            }
            FundingKind::ProtocolDeposit {
                transfer,
                deposited,
            } => {
                if transfer.block != deposited.block || transfer.receipt != deposited.receipt {
                    return Err("protocol deposit logs must share one receipt".into());
                }
                let transfer_key = resolver.log_key(transfer)?;
                let deposited_key = resolver.log_key(deposited)?;
                let (from, to, transferred_amount, _) = resolver.usdc_transfer(transfer)?;
                let (deposit_buyer, deposited_amount, _) = resolver.protocol_deposit(deposited)?;
                if !valid_protocol_deposit(
                    transfer_key,
                    deposited_key,
                    from,
                    to,
                    transferred_amount,
                    deposit_buyer,
                    deposited_amount,
                    funder,
                    evidence.buyer,
                ) {
                    return Err("invalid protocol-deposit funding".into());
                }
                require_transaction_signer(
                    funder,
                    resolver.transaction_for_log(transfer)?,
                    resolver,
                )?;
                resolver.block(transfer.block)?.header.timestamp
            }
            FundingKind::Native {
                transaction,
                receipt,
            } => {
                let (receipt_proof, receipt_block) = resolver.receipt(receipt)?;
                if !receipt_success(&receipt_proof.value)? {
                    return Err("native funding receipt reverted".into());
                }
                let (envelope, signer, transaction_block) =
                    resolver.decoded_transaction(transaction)?;
                let (transaction_proof, _) = resolver.transaction(transaction)?;
                if receipt.block != transaction.block
                    || receipt_proof.tx_index != transaction_proof.tx_index
                    || receipt_block.header.number != transaction_block.header.number
                    || signer != funder
                    || envelope.to() != Some(evidence.buyer)
                    || envelope.value() < U256::from(MINIMUM_NATIVE_FUNDING_WEI)
                {
                    return Err("invalid native funding".into());
                }
                transaction_block.header.timestamp
            }
        };
        times.insert(evidence.buyer, funding_time);
    }
    Ok(times)
}

fn require_transaction_signer(
    funder: Address,
    transaction: TransactionRef,
    resolver: &ChainResolver<'_>,
) -> Result<(), String> {
    let (_, signer, _) = resolver.decoded_transaction(transaction)?;
    if signer != funder {
        return Err("funding transaction signer mismatch".into());
    }
    Ok(())
}

fn verify_state_fundings(
    funder: Address,
    linked_buyers: &[Address],
    fundings: &[FundingEvidence],
    resolver: &ChainResolver<'_>,
    state: &StateResolver<'_>,
) -> Result<BTreeMap<Address, u64>, String> {
    if fundings.len() != linked_buyers.len() {
        return Err("funding evidence must cover each linked buyer exactly once".into());
    }
    let linked = linked_buyers.iter().copied().collect::<BTreeSet<_>>();
    let mut times = BTreeMap::new();
    for evidence in fundings {
        if !linked.contains(&evidence.buyer) || times.contains_key(&evidence.buyer) {
            return Err("duplicate or unrelated funding buyer".into());
        }
        let first_channel = state.read_expected(
            evidence.first_channel_at,
            STATE_END_BLOCK,
            DEPOSITS_ADDRESS,
            Some(DEPOSITS_CODE_HASH),
            first_channel_slot(evidence.buyer)?,
        )?;
        let first_channel_at =
            u64::try_from(first_channel).map_err(|_| "firstChannelAt overflow")?;
        if first_channel_at == 0 {
            return Err("linked buyer has no first channel".into());
        }
        let funding_time = match evidence.kind {
            FundingKind::Usdc { transfer } => {
                let (from, to, amount, _) = resolver.usdc_transfer(transfer)?;
                if from != funder || to != evidence.buyer || amount < MINIMUM_USDC_FUNDING_RAW {
                    return Err("invalid direct USDC funding".into());
                }
                authenticate_funder(
                    funder,
                    &evidence.authentication,
                    resolver.transaction_for_log(transfer)?,
                    resolver,
                    state,
                )?;
                resolver.block(transfer.block)?.header.timestamp
            }
            FundingKind::ProtocolDeposit {
                transfer,
                deposited,
            } => {
                if transfer.block != deposited.block || transfer.receipt != deposited.receipt {
                    return Err("protocol deposit logs must share one receipt".into());
                }
                let transfer_key = resolver.log_key(transfer)?;
                let deposited_key = resolver.log_key(deposited)?;
                let (from, to, transferred_amount, _) = resolver.usdc_transfer(transfer)?;
                let (deposit_buyer, deposited_amount, _) = resolver.protocol_deposit(deposited)?;
                if !valid_protocol_deposit(
                    transfer_key,
                    deposited_key,
                    from,
                    to,
                    transferred_amount,
                    deposit_buyer,
                    deposited_amount,
                    funder,
                    evidence.buyer,
                ) {
                    return Err("invalid protocol-deposit funding".into());
                }
                authenticate_funder(
                    funder,
                    &evidence.authentication,
                    resolver.transaction_for_log(transfer)?,
                    resolver,
                    state,
                )?;
                resolver.block(transfer.block)?.header.timestamp
            }
            FundingKind::Native {
                transaction,
                receipt,
            } => {
                validate_native_funder_authentication(&evidence.authentication)?;
                let (receipt_proof, receipt_block) = resolver.receipt(receipt)?;
                if !receipt_success(&receipt_proof.value)? {
                    return Err("native funding receipt reverted".into());
                }
                let (envelope, _, transaction_block) = resolver.decoded_transaction(transaction)?;
                let (transaction_proof, _) = resolver.transaction(transaction)?;
                if receipt.block != transaction.block
                    || receipt_proof.tx_index != transaction_proof.tx_index
                    || receipt_block.header.number != transaction_block.header.number
                    || envelope.to() != Some(evidence.buyer)
                    || envelope.value() < U256::from(MINIMUM_NATIVE_FUNDING_WEI)
                {
                    return Err("invalid native funding".into());
                }
                authenticate_funder(
                    funder,
                    &evidence.authentication,
                    transaction,
                    resolver,
                    state,
                )?;
                transaction_block.header.timestamp
            }
        };
        if funding_time >= first_channel_at {
            return Err("funding is not before buyer first channel".into());
        }
        times.insert(evidence.buyer, funding_time);
    }
    Ok(times)
}

#[allow(clippy::too_many_arguments)]
fn valid_protocol_deposit(
    transfer_key: (u64, u64, usize),
    deposited_key: (u64, u64, usize),
    from: Address,
    to: Address,
    transferred_amount: u128,
    deposit_buyer: Address,
    deposited_amount: u128,
    expected_funder: Address,
    expected_buyer: Address,
) -> bool {
    transfer_key < deposited_key
        && transfer_key.0 == deposited_key.0
        && transfer_key.1 == deposited_key.1
        && from == expected_funder
        && to == DEPOSITS_ADDRESS
        && deposit_buyer == expected_buyer
        && transferred_amount == deposited_amount
        && deposited_amount >= MINIMUM_USDC_FUNDING_RAW
}

fn validate_native_funder_authentication(
    authentication: &FunderAuthentication,
) -> Result<(), String> {
    if matches!(
        authentication,
        FunderAuthentication::SupportedSmartAccount { .. }
    ) {
        return Err("native funding cannot be attributed to a smart-account transaction".into());
    }
    Ok(())
}

fn authenticate_funder(
    funder: Address,
    authentication: &FunderAuthentication,
    transaction: TransactionRef,
    resolver: &ChainResolver<'_>,
    state: &StateResolver<'_>,
) -> Result<(), String> {
    let (envelope, signer, block) = resolver.decoded_transaction(transaction)?;
    match authentication {
        FunderAuthentication::Eoa { account } => {
            require_account_at(
                state.account(*account)?,
                state.blocks,
                block.header.number,
                funder,
                KECCAK_EMPTY,
            )?;
            if signer != funder {
                return Err("EOA funding signer mismatch".into());
            }
        }
        FunderAuthentication::Eip7702 {
            account,
            delegation_code,
        } => {
            if delegation_code.len() != 23 || delegation_code[..3] != [0xef, 0x01, 0x00] {
                return Err("invalid EIP-7702 delegation code".into());
            }
            require_account_at(
                state.account(*account)?,
                state.blocks,
                block.header.number,
                funder,
                keccak256(delegation_code),
            )?;
            if signer != funder {
                return Err("EIP-7702 funding signer mismatch".into());
            }
        }
        FunderAuthentication::SupportedSmartAccount {
            proxy_account,
            implementation_account,
            implementation_slot,
            plugin_count_slot,
            owner_slot,
            owner,
        } => {
            if funder != SUPPORTED_SMART_ACCOUNT_A && funder != SUPPORTED_SMART_ACCOUNT_B {
                return Err("unsupported smart-account funder".into());
            }
            require_account_at(
                state.account(*proxy_account)?,
                state.blocks,
                block.header.number,
                funder,
                SMART_ACCOUNT_PROXY_CODE_HASH,
            )?;
            require_account_at(
                state.account(*implementation_account)?,
                state.blocks,
                block.header.number,
                SMART_ACCOUNT_IMPLEMENTATION,
                SMART_ACCOUNT_IMPLEMENTATION_CODE_HASH,
            )?;
            let implementation = state.read_expected(
                *implementation_slot,
                block.header.number,
                funder,
                Some(SMART_ACCOUNT_PROXY_CODE_HASH),
                ERC1967_IMPLEMENTATION_SLOT,
            )?;
            let plugins = state.read_expected(
                *plugin_count_slot,
                block.header.number,
                funder,
                Some(SMART_ACCOUNT_PROXY_CODE_HASH),
                SMART_ACCOUNT_PLUGIN_COUNT_SLOT,
            )?;
            let owner_word = state.read_expected(
                *owner_slot,
                block.header.number,
                funder,
                Some(SMART_ACCOUNT_PROXY_CODE_HASH),
                SMART_ACCOUNT_OWNER_SLOT,
            )?;
            if word_address(implementation) != SMART_ACCOUNT_IMPLEMENTATION
                || plugins != U256::ZERO
                || *owner == Address::ZERO
                || packed_smart_account_owner(owner_word) != *owner
            {
                return Err("smart-account implementation, owner, or plugins mismatch".into());
            }
            if envelope.to().is_none() {
                return Err("smart-account funding transaction cannot create a contract".into());
            }
        }
    }
    Ok(())
}

fn require_account_at(
    proof: &Eip1186AccountProof,
    blocks: &[EnforcementBlock],
    block_number: u64,
    address: Address,
    code_hash: B256,
) -> Result<(), String> {
    let block = blocks
        .get(proof.block)
        .ok_or("account block reference out of range")?;
    if block.header.number != block_number
        || proof.address != address
        || !proof.exists
        || proof.code_hash != code_hash
    {
        return Err("account identity or code hash mismatch".into());
    }
    Ok(())
}

fn verify_settlements(
    seller: Address,
    linked_buyers: &[Address],
    funding_times: &BTreeMap<Address, u64>,
    settlements: &[SettlementEvidence],
    resolver: &ChainResolver<'_>,
) -> Result<(u128, BTreeMap<Address, u128>, Option<(u64, u64, usize)>), String> {
    let linked = linked_buyers.iter().copied().collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(settlements.len());
    let mut used = BTreeSet::new();
    for evidence in settlements {
        let key = resolver.log_key(evidence.settlement)?;
        if !used.insert(key) {
            return Err("duplicate settlement evidence".into());
        }
        ordered.push((key, evidence.settlement));
    }
    ordered.sort_unstable_by_key(|entry| entry.0);
    let mut total = 0u128;
    let mut target_volumes = BTreeMap::<Address, u128>::new();
    let mut crossing = None;
    for (key, reference) in ordered {
        let (_, buyer, actual_seller, amount, block_number) = resolver.settlement(reference)?;
        ensure_period_block(block_number, "cohort settlement")?;
        if actual_seller != seller || !linked.contains(&buyer) || amount == 0 {
            return Err("settlement subject or amount mismatch".into());
        }
        if resolver.block(reference.block)?.header.timestamp <= funding_times[&buyer] {
            return Err("settlement is not after funding".into());
        }
        total = total
            .checked_add(amount)
            .ok_or("settlement volume overflow")?;
        let buyer_total = target_volumes.entry(buyer).or_default();
        *buyer_total = buyer_total
            .checked_add(amount)
            .ok_or("buyer settlement overflow")?;
        if crossing.is_none() && total >= MINIMUM_VOLUME_RAW {
            crossing = Some(key);
        }
    }
    if target_volumes.len() < MINIMUM_BUYERS {
        return Err("fewer than three funded buyers settled".into());
    }
    Ok((total, target_volumes, crossing))
}

fn verify_closure(
    seller: Address,
    funder: Address,
    linked_buyers: &[Address],
    crossing_key: (u64, u64, usize),
    closure: &ClosureEvidence,
    resolver: &ChainResolver<'_>,
) -> Result<(u8, u32), String> {
    match closure {
        ClosureEvidence::Direct { transfer } => {
            let key = resolver.log_key(*transfer)?;
            let (from, to, amount, block) = resolver.usdc_transfer(*transfer)?;
            ensure_period_block(block, "direct closure")?;
            if key <= crossing_key
                || from != seller
                || (to != funder && linked_buyers.binary_search(&to).is_err())
                || amount < MINIMUM_CLOSURE_RAW
            {
                return Err("invalid seller-outward direct closure".into());
            }
            Ok((DIRECT_CLOSURE, 1))
        }
        ClosureEvidence::Relay { paths } => {
            if paths.len() < 3 {
                return Err("relay closure requires at least three paths".into());
            }
            let mut used = BTreeSet::new();
            for path in paths {
                let refs = [path.seller_payment, path.relay_forward, path.final_receipt];
                let mut keys = Vec::with_capacity(3);
                for reference in refs {
                    let key = resolver.log_key(reference)?;
                    if !used.insert(key) {
                        return Err("relay closure reuses a transfer".into());
                    }
                    keys.push(key);
                }
                if keys[0] <= crossing_key || keys[0] >= keys[1] || keys[1] >= keys[2] {
                    return Err("relay path ordering mismatch".into());
                }
                let (from1, to1, amount1, block1) = resolver.usdc_transfer(path.seller_payment)?;
                let (from2, to2, amount2, block2) = resolver.usdc_transfer(path.relay_forward)?;
                let (from3, to3, amount3, block3) = resolver.usdc_transfer(path.final_receipt)?;
                ensure_period_block(block1, "relay seller payment")?;
                ensure_period_block(block2, "relay forward")?;
                ensure_period_block(block3, "relay receipt")?;
                let first_time = resolver.block(path.seller_payment.block)?.header.timestamp;
                let final_time = resolver.block(path.final_receipt.block)?.header.timestamp;
                if from1 != seller
                    || to1 != from2
                    || to2 != from3
                    || to3 != funder
                    || final_time < first_time
                    || final_time - first_time > MAX_RELAY_SECONDS
                    || !valid_relay_amounts(amount1, amount2, amount3)
                {
                    return Err("invalid relay closure path".into());
                }
            }
            Ok((RELAY_CLOSURE, paths.len() as u32))
        }
    }
}

fn valid_relay_amounts(seller_amount: u128, forwarded: u128, received: u128) -> bool {
    if seller_amount < MINIMUM_CLOSURE_RAW
        || forwarded == 0
        || received == 0
        || received > seller_amount
        || received > forwarded
    {
        return false;
    }
    seller_amount.abs_diff(forwarded) <= MAX_RELAY_EARLY_DELTA_RAW
        && (seller_amount - received <= MAX_RELAY_LOSS_RAW
            || received.saturating_mul(10_000)
                >= seller_amount.saturating_mul(MIN_RELAY_RETAINED_BPS))
}

fn qualifying_buyers(
    buyers: &[Address],
    target_volumes: &BTreeMap<Address, u128>,
    counters: &[CounterDelta],
    state: &StateResolver<'_>,
) -> Result<Vec<Address>, String> {
    let mut result = Vec::new();
    for buyer in buyers {
        let target = target_volumes.get(buyer).copied().unwrap_or(0);
        let total = counter_total(CounterKind::Buyer, *buyer, counters, state)?;
        if total == 0 {
            if target != 0 {
                return Err("buyer counter is zero despite authenticated target volume".into());
            }
            continue;
        }
        if target > total {
            return Err("target seller volume exceeds complete buyer volume".into());
        }
        if buyer_share_qualifies(target, total)? {
            result.push(*buyer);
        }
    }
    Ok(result)
}

fn buyer_share_qualifies(target: u128, total: u128) -> Result<bool, String> {
    Ok(target.checked_mul(100).ok_or("buyer share overflow")?
        >= total.checked_mul(99).ok_or("buyer share overflow")?)
}

fn counter_total(
    kind: CounterKind,
    subject: Address,
    counters: &[CounterDelta],
    state: &StateResolver<'_>,
) -> Result<u128, String> {
    let selected = counters
        .iter()
        .filter(|counter| counter.kind == kind && counter.subject == subject)
        .collect::<Vec<_>>();
    if selected.len() != 2 * (MAX_EMISSIONS_EPOCH as usize + 1) {
        return Err("counter evidence does not cover both contracts and epochs 0-18".into());
    }
    let mut identities = BTreeSet::new();
    let mut total = 0u128;
    for counter in selected {
        if counter.epoch > MAX_EMISSIONS_EPOCH
            || !identities.insert((counter.contract, counter.epoch))
            || (counter.contract != OLD_EMISSIONS_ADDRESS
                && counter.contract != NEW_EMISSIONS_ADDRESS)
        {
            return Err("duplicate or unsupported counter evidence".into());
        }
        let slot = counter_slot(kind, subject, counter.epoch, counter.contract)?;
        let code_hash = if counter.contract == OLD_EMISSIONS_ADDRESS {
            OLD_EMISSIONS_CODE_HASH
        } else {
            NEW_EMISSIONS_CODE_HASH
        };
        let start_account = state.account(counter.start.account)?;
        let start_code_hash = if start_account.exists {
            Some(code_hash)
        } else {
            None
        };
        if counter.contract == OLD_EMISSIONS_ADDRESS && start_code_hash.is_none() {
            return Err("old emissions contract missing at start boundary".into());
        }
        let start = state.read_expected(
            counter.start,
            STATE_START_BLOCK,
            counter.contract,
            start_code_hash,
            slot,
        )?;
        let end = state.read_expected(
            counter.end,
            STATE_END_BLOCK,
            counter.contract,
            Some(code_hash),
            slot,
        )?;
        let delta = u128::try_from(end.checked_sub(start).ok_or("counter underflow")?)
            .map_err(|_| "counter delta exceeds uint128")?;
        total = total
            .checked_add(delta)
            .ok_or("counter total exceeds uint128")?;
    }
    Ok(total)
}

fn ensure_period_block(block: u64, label: &str) -> Result<(), String> {
    if !(PERIOD_START_BLOCK..PERIOD_END_BLOCK_EXCLUSIVE).contains(&block) {
        return Err(format!("{label} is outside fixed period"));
    }
    Ok(())
}

pub fn cohort_hash(buyers: &[Address]) -> B256 {
    keccak256(buyers.to_vec().abi_encode())
}

pub fn funder_cohort_hash(cohorts: &[FunderCohort]) -> B256 {
    keccak256(
        cohorts
            .iter()
            .map(|cohort| SolFunderCohort {
                funder: cohort.funder,
                buyers: cohort.linked_buyers.clone(),
            })
            .collect::<Vec<_>>()
            .abi_encode(),
    )
}

pub fn cohort_claim_id(
    proof_type: u8,
    seller: Address,
    funder: Address,
    cohort_hash: B256,
) -> B256 {
    keccak256(
        SolCohortClaimId {
            chainId: U256::from(BASE_CHAIN_ID),
            proofType: proof_type,
            periodStartBlock: PERIOD_START_BLOCK,
            periodEndBlockExclusive: PERIOD_END_BLOCK_EXCLUSIVE,
            seller,
            funder,
            cohortHash: cohort_hash,
        }
        .abi_encode(),
    )
}

pub fn reciprocal_claim_id(address_a: Address, address_b: Address) -> B256 {
    keccak256(
        SolReciprocalClaimId {
            chainId: U256::from(BASE_CHAIN_ID),
            proofType: RECIPROCAL_PROOF_TYPE,
            periodStartBlock: PERIOD_START_BLOCK,
            periodEndBlockExclusive: PERIOD_END_BLOCK_EXCLUSIVE,
            addressA: address_a,
            addressB: address_b,
        }
        .abi_encode(),
    )
}

pub fn coordinated_control_claim_id(
    seller: Address,
    funder_cohort_hash: B256,
    cohort_hash: B256,
) -> B256 {
    keccak256(
        SolCoordinatedControlClaimId {
            chainId: U256::from(BASE_CHAIN_ID),
            proofType: COORDINATED_CONTROL_PROOF_TYPE,
            periodStartBlock: PERIOD_START_BLOCK,
            periodEndBlockExclusive: PERIOD_END_BLOCK_EXCLUSIVE,
            seller,
            funderCohortHash: funder_cohort_hash,
            cohortHash: cohort_hash,
        }
        .abi_encode(),
    )
}

pub fn first_channel_slot(buyer: Address) -> Result<B256, String> {
    add_slot(
        keccak256((buyer, U256::from(DEPOSITS_BUYERS_SLOT)).abi_encode()),
        3,
    )
}

pub fn channel_base_slot(channel_id: B256) -> B256 {
    keccak256((channel_id, U256::from(CHANNELS_CHANNELS_SLOT)).abi_encode())
}

pub fn counter_slot(
    kind: CounterKind,
    subject: Address,
    epoch: u64,
    contract: Address,
) -> Result<B256, String> {
    let mapping_slot = match (contract, kind) {
        (OLD_EMISSIONS_ADDRESS, CounterKind::Seller) => OLD_EMISSIONS_SELLER_POINTS_SLOT,
        (OLD_EMISSIONS_ADDRESS, CounterKind::Buyer) => OLD_EMISSIONS_BUYER_POINTS_SLOT,
        (NEW_EMISSIONS_ADDRESS, CounterKind::Seller) => NEW_EMISSIONS_SELLER_POINTS_SLOT,
        (NEW_EMISSIONS_ADDRESS, CounterKind::Buyer) => NEW_EMISSIONS_BUYER_POINTS_SLOT,
        _ => return Err("unsupported emissions contract".into()),
    };
    let outer = keccak256((subject, U256::from(mapping_slot)).abi_encode());
    Ok(keccak256((U256::from(epoch), outer).abi_encode()))
}

fn add_slot(slot: B256, offset: u64) -> Result<B256, String> {
    let value = U256::from_be_slice(slot.as_slice())
        .checked_add(U256::from(offset))
        .ok_or("storage slot overflow")?;
    Ok(B256::from(value.to_be_bytes::<32>()))
}

fn packed_settled(word: U256) -> u128 {
    u128::try_from(word >> 128).unwrap()
}
fn word_address(word: U256) -> Address {
    Address::from_slice(&word.to_be_bytes::<32>()[12..])
}
fn packed_smart_account_owner(word: U256) -> Address {
    word_address(word >> 16)
}
fn topic_address(topic: B256) -> Address {
    Address::from_slice(&topic.as_slice()[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::{proof::ProofRetainer, HashBuilder};

    #[test]
    fn relay_boundaries_are_exact() {
        assert!(valid_relay_amounts(1_000_000, 999_000, 999_000));
        assert!(!valid_relay_amounts(1_000_000, 998_999, 998_999));
        assert!(valid_relay_amounts(50_000_000, 50_001_000, 49_000_000));
        assert!(!valid_relay_amounts(50_000_000, 50_001_001, 49_000_000));
        assert!(valid_relay_amounts(100_000_000, 100_000_000, 98_000_000));
        assert!(!valid_relay_amounts(100_000_000, 100_000_000, 97_999_999));
    }

    #[test]
    fn claim_ids_bind_predicate_and_order() {
        let a = address!("0000000000000000000000000000000000000001");
        let b = address!("0000000000000000000000000000000000000002");
        let hash = cohort_hash(&[a, b]);
        assert_ne!(hash, cohort_hash(&[b, a]));
        assert_ne!(
            cohort_claim_id(CLOSED_CYCLE_PROOF_TYPE, a, b, hash),
            cohort_claim_id(COORDINATED_CONTROL_PROOF_TYPE, a, b, hash)
        );
        assert_ne!(reciprocal_claim_id(a, b), reciprocal_claim_id(b, a));
    }

    #[test]
    fn storage_slots_match_foundry_layout_rules() {
        let buyer = address!("0000000000000000000000000000000000000001");
        let base = keccak256((buyer, U256::from(DEPOSITS_BUYERS_SLOT)).abi_encode());
        assert_eq!(
            first_channel_slot(buyer).unwrap(),
            add_slot(base, 3).unwrap()
        );
        let expected = |mapping_slot| {
            let outer = keccak256((buyer, U256::from(mapping_slot)).abi_encode());
            keccak256((U256::ZERO, outer).abi_encode())
        };
        assert_eq!(
            counter_slot(CounterKind::Seller, buyer, 0, OLD_EMISSIONS_ADDRESS).unwrap(),
            expected(10)
        );
        assert_eq!(
            counter_slot(CounterKind::Buyer, buyer, 0, OLD_EMISSIONS_ADDRESS).unwrap(),
            expected(11)
        );
        assert_eq!(
            counter_slot(CounterKind::Seller, buyer, 0, NEW_EMISSIONS_ADDRESS).unwrap(),
            expected(14)
        );
        assert_eq!(
            counter_slot(CounterKind::Buyer, buyer, 0, NEW_EMISSIONS_ADDRESS).unwrap(),
            expected(15)
        );
    }

    #[test]
    fn rejects_unknown_emissions_layout() {
        assert!(counter_slot(
            CounterKind::Seller,
            address!("0000000000000000000000000000000000000001"),
            0,
            Address::ZERO,
        )
        .is_err());
    }

    #[test]
    fn rejects_smart_account_native_funding_attribution() {
        let reference = StateValueRef {
            account: 0,
            slot: B256::ZERO,
            storage: None,
        };
        let authentication = FunderAuthentication::SupportedSmartAccount {
            proxy_account: 0,
            implementation_account: 0,
            implementation_slot: reference,
            plugin_count_slot: reference,
            owner_slot: reference,
            owner: address!("0000000000000000000000000000000000000001"),
        };
        assert!(validate_native_funder_authentication(&authentication).is_err());
        assert!(
            validate_native_funder_authentication(&FunderAuthentication::Eoa { account: 0 })
                .is_ok()
        );
    }

    #[test]
    fn exact_ratio_boundaries_do_not_round() {
        assert!(1_000_000_000u128 * 2 >= 2_000_000_000u128);
        assert!(999_999_999u128 * 2 < 2_000_000_000u128);
        assert!(99u128 * 100 >= 100u128 * 99);
        assert!(98u128 * 100 < 100u128 * 99);
        assert!(buyer_share_qualifies(99, 100).unwrap());
        assert!(!buyer_share_qualifies(98, 100).unwrap());
        assert!(buyer_share_qualifies(99_000_000, 100_000_000).unwrap());
        assert!(!buyer_share_qualifies(98_999_999, 100_000_000).unwrap());
        assert!(reciprocal_thresholds_satisfied(50, 50, 50_000_000, 40_000_000).unwrap());
        assert!(!reciprocal_thresholds_satisfied(50, 50, 50_000_000, 39_999_999).unwrap());
    }

    #[test]
    fn reciprocal_receipt_witness_authenticates_and_rejects_tampering() {
        let input = reciprocal_input(1_000_000, 800_000, true);
        let journal = verify_reciprocal(&input).unwrap();
        assert_eq!(journal.settlement_count_a_to_b, 50);
        assert_eq!(journal.settlement_count_b_to_a, 50);
        assert_eq!(journal.volume_a_to_b_raw, 50_000_000);
        assert_eq!(journal.volume_b_to_a_raw, 40_000_000);

        let mut tampered_root = input.clone();
        tampered_root.blocks[0].header.receipts_root = B256::ZERO;
        assert!(verify_reciprocal(&tampered_root).is_err());

        let mut duplicate = input.clone();
        duplicate.settlements.push(duplicate.settlements[0].clone());
        assert!(verify_reciprocal(&duplicate)
            .unwrap_err()
            .contains("duplicate settlement"));

        let mut wrong_subject = input.clone();
        wrong_subject.address_b = address!("0000000000000000000000000000000000000003");
        assert!(verify_reciprocal(&wrong_subject)
            .unwrap_err()
            .contains("exact ordered pair"));

        let reverted = reciprocal_input(1_000_000, 800_000, false);
        assert!(verify_reciprocal(&reverted)
            .unwrap_err()
            .contains("referenced receipt reverted"));

        let below_ratio = reciprocal_input(1_000_000, 799_999, true);
        assert!(verify_reciprocal(&below_ratio)
            .unwrap_err()
            .contains("directional threshold"));
    }

    #[test]
    fn receipt_only_funding_requires_the_recovered_funder_signer() {
        let raw = alloy_primitives::hex::decode("01f86382210580018252089400000000000000000000000000000000000000aa0180c001a04e4f22a8bf8949e504ea441c49c09aef77d2c21559b6dec72922ce5f0bf82405a05970730d98c433bfa3a0abf720cb52020856b6b446d3bc345197d1d53198639d").unwrap();
        let block = transaction_block(Bytes::from(raw));
        let blocks = [block];
        let resolver = ChainResolver { blocks: &blocks };
        let reference = TransactionRef {
            block: 0,
            transaction: 0,
        };
        let signer = address!("19e7e376e7c213b7e7e7e46cc70a5dd086daff2a");
        assert!(require_transaction_signer(signer, reference, &resolver).is_ok());
        assert!(require_transaction_signer(
            address!("0000000000000000000000000000000000000001"),
            reference,
            &resolver
        )
        .unwrap_err()
        .contains("signer mismatch"));
    }

    #[test]
    fn closed_cycle_receipt_witness_enforces_funding_order_threshold_and_closure() {
        let input = closed_cycle_input(400_000_000);
        let journal = verify_closed_cycle(&input).unwrap();
        assert_eq!(journal.cohort_count, 3);
        assert_eq!(journal.qualified_volume_raw, 1_200_000_000);
        assert_eq!(journal.closure_kind, 1);

        let mut funding_after_settlement = input.clone();
        funding_after_settlement.blocks[0].header.timestamp = PERIOD_START_BLOCK + 100;
        assert!(verify_closed_cycle(&funding_after_settlement)
            .unwrap_err()
            .contains("settlement is not after funding"));

        let insufficient = closed_cycle_input(300_000_000);
        assert!(verify_closed_cycle(&insufficient)
            .unwrap_err()
            .contains("qualified volume below 1,000 USDC"));

        let mut duplicate = input.clone();
        duplicate.settlements.push(duplicate.settlements[0].clone());
        assert!(verify_closed_cycle(&duplicate)
            .unwrap_err()
            .contains("duplicate settlement"));

        let mut invalid_closure = input.clone();
        invalid_closure.closure = ClosureEvidence::Direct {
            transfer: invalid_closure.settlements[0].settlement,
        };
        assert!(verify_closed_cycle(&invalid_closure).is_err());

        let mut wrong_signer = input.clone();
        wrong_signer.funder = address!("0000000000000000000000000000000000000010");
        assert!(verify_closed_cycle(&wrong_signer).is_err());

        let mut tampered_receipt = input.clone();
        tampered_receipt.blocks[0].header.receipts_root = B256::ZERO;
        assert!(verify_closed_cycle(&tampered_receipt).is_err());

        let mut tampered_transaction = input.clone();
        tampered_transaction.blocks[0].header.transactions_root = B256::ZERO;
        assert!(verify_closed_cycle(&tampered_transaction).is_err());
    }

    #[test]
    fn multi_funder_cohorts_each_require_three_buyers() {
        let funder_a = address!("0000000000000000000000000000000000000010");
        let funder_b = address!("0000000000000000000000000000000000000020");
        let buyers = [
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
            address!("0000000000000000000000000000000000000004"),
            address!("0000000000000000000000000000000000000005"),
        ];
        let cohorts = vec![
            FunderCohort {
                funder: funder_a,
                linked_buyers: buyers[..3].to_vec(),
                fundings: Vec::new(),
            },
            FunderCohort {
                funder: funder_b,
                linked_buyers: buyers[3..].to_vec(),
                fundings: Vec::new(),
            },
        ];
        assert!(validate_funding_cohorts(&cohorts).is_err());
    }

    #[test]
    fn protocol_deposit_requires_exact_same_receipt_flow() {
        let funder = address!("0000000000000000000000000000000000000010");
        let buyer = address!("0000000000000000000000000000000000000001");
        let valid = |transfer_key, deposited_key, amount| {
            valid_protocol_deposit(
                transfer_key,
                deposited_key,
                funder,
                DEPOSITS_ADDRESS,
                amount,
                buyer,
                amount,
                funder,
                buyer,
            )
        };
        assert!(valid((1, 2, 3), (1, 2, 4), MINIMUM_USDC_FUNDING_RAW));
        assert!(!valid((1, 2, 4), (1, 2, 3), MINIMUM_USDC_FUNDING_RAW));
        assert!(!valid((1, 2, 3), (1, 3, 4), MINIMUM_USDC_FUNDING_RAW));
        assert!(!valid((1, 2, 3), (1, 2, 4), MINIMUM_USDC_FUNDING_RAW - 1));
        assert_eq!(keccak256("Deposited(address,uint256)"), DEPOSITED_TOPIC);
    }

    #[test]
    fn rejects_duplicate_and_malformed_account_proofs() {
        let address = address!("0000000000000000000000000000000000000001");
        let block = EnforcementBlock {
            header: Header {
                number: STATE_START_BLOCK,
                state_root: EMPTY_ROOT_HASH,
                ..Default::default()
            },
            receipts: Vec::new(),
            transactions: Vec::new(),
        };
        let missing = Eip1186AccountProof {
            block: 0,
            address,
            exists: false,
            nonce: 0,
            balance: U256::ZERO,
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
            account_proof: Vec::new(),
            storage_proofs: Vec::new(),
        };
        assert!(
            StateResolver::authenticate(&[block.clone()], &[missing.clone(), missing.clone()])
                .is_err()
        );

        let mut malformed = missing;
        malformed.exists = true;
        malformed.code_hash = DEPOSITS_CODE_HASH;
        assert!(StateResolver::authenticate(&[block], &[malformed]).is_err());
    }

    fn reciprocal_input(
        amount_a_to_b: u128,
        amount_b_to_a: u128,
        success: bool,
    ) -> ReciprocalInput {
        let address_a = address!("0000000000000000000000000000000000000001");
        let address_b = address!("0000000000000000000000000000000000000002");
        let mut blocks = Vec::new();
        let mut settlements = Vec::new();
        for index in 0..100usize {
            let (buyer, seller, amount) = if index < 50 {
                (address_a, address_b, amount_a_to_b)
            } else {
                (address_b, address_a, amount_b_to_a)
            };
            blocks.push(settlement_block(
                PERIOD_START_BLOCK + index as u64,
                buyer,
                seller,
                amount,
                success,
            ));
            settlements.push(SettlementEvidence {
                settlement: LogRef {
                    block: index,
                    receipt: 0,
                    log: 0,
                },
            });
        }
        ReciprocalInput {
            chain_id: BASE_CHAIN_ID,
            address_a,
            address_b,
            blocks,
            settlements,
        }
    }

    fn closed_cycle_input(settlement_amount: u128) -> ClosedCycleInput {
        let funder = address!("19e7e376e7c213b7e7e7e46cc70a5dd086daff2a");
        let seller = address!("00000000000000000000000000000000000000aa");
        let buyers = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
        ];
        let transaction = Bytes::from(alloy_primitives::hex::decode("01f86382210580018252089400000000000000000000000000000000000000aa0180c001a04e4f22a8bf8949e504ea441c49c09aef77d2c21559b6dec72922ce5f0bf82405a05970730d98c433bfa3a0abf720cb52020856b6b446d3bc345197d1d53198639d").unwrap());
        let mut blocks = Vec::new();
        let mut fundings = Vec::new();
        for (index, buyer) in buyers.iter().copied().enumerate() {
            blocks.push(usdc_transfer_block(
                PERIOD_START_BLOCK - 20 + index as u64,
                funder,
                buyer,
                MINIMUM_USDC_FUNDING_RAW,
                Some(transaction.clone()),
            ));
            fundings.push(PositiveFundingEvidence {
                buyer,
                kind: FundingKind::Usdc {
                    transfer: LogRef {
                        block: index,
                        receipt: 0,
                        log: 0,
                    },
                },
            });
        }
        let mut settlements = Vec::new();
        for (index, buyer) in buyers.iter().copied().enumerate() {
            blocks.push(settlement_block(
                PERIOD_START_BLOCK + index as u64,
                buyer,
                seller,
                settlement_amount,
                true,
            ));
            settlements.push(SettlementEvidence {
                settlement: LogRef {
                    block: buyers.len() + index,
                    receipt: 0,
                    log: 0,
                },
            });
        }
        blocks.push(usdc_transfer_block(
            PERIOD_START_BLOCK + 10,
            seller,
            funder,
            MINIMUM_CLOSURE_RAW,
            None,
        ));
        ClosedCycleInput {
            chain_id: BASE_CHAIN_ID,
            seller,
            funder,
            linked_buyers: buyers,
            blocks,
            fundings,
            settlements,
            closure: ClosureEvidence::Direct {
                transfer: LogRef {
                    block: 6,
                    receipt: 0,
                    log: 0,
                },
            },
        }
    }

    fn settlement_block(
        number: u64,
        buyer: Address,
        seller: Address,
        amount: u128,
        success: bool,
    ) -> EnforcementBlock {
        let mut data = [0u8; 64];
        data[48..].copy_from_slice(&amount.to_be_bytes());
        let log = rlp_list(&[
            rlp_bytes(CHANNELS_ADDRESS.as_slice()),
            rlp_list(&[
                rlp_bytes(CHANNEL_SETTLED_TOPIC.as_slice()),
                rlp_bytes(B256::ZERO.as_slice()),
                rlp_bytes(address_topic(buyer).as_slice()),
                rlp_bytes(address_topic(seller).as_slice()),
            ]),
            rlp_bytes(&data),
        ]);
        let receipt = Bytes::from(rlp_list(&[
            rlp_uint(if success { 1 } else { 0 }),
            rlp_uint(1),
            rlp_bytes(&[0u8; 256]),
            rlp_list(&[log]),
        ]));
        let (receipts_root, proof) = trie_proof(&receipt);
        EnforcementBlock {
            header: Header {
                number,
                timestamp: number,
                receipts_root,
                ..Default::default()
            },
            receipts: vec![ReceiptProof {
                tx_index: 0,
                value: receipt,
                proof,
            }],
            transactions: Vec::new(),
        }
    }

    fn usdc_transfer_block(
        number: u64,
        from: Address,
        to: Address,
        amount: u128,
        transaction: Option<Bytes>,
    ) -> EnforcementBlock {
        let mut data = [0u8; 32];
        data[16..].copy_from_slice(&amount.to_be_bytes());
        let log = rlp_list(&[
            rlp_bytes(USDC_ADDRESS.as_slice()),
            rlp_list(&[
                rlp_bytes(TRANSFER_TOPIC.as_slice()),
                rlp_bytes(address_topic(from).as_slice()),
                rlp_bytes(address_topic(to).as_slice()),
            ]),
            rlp_bytes(&data),
        ]);
        let receipt = Bytes::from(rlp_list(&[
            rlp_uint(1),
            rlp_uint(1),
            rlp_bytes(&[0u8; 256]),
            rlp_list(&[log]),
        ]));
        let (receipts_root, receipt_proof) = trie_proof(&receipt);
        let (transactions_root, transactions) = if let Some(value) = transaction {
            let (root, proof) = trie_proof(&value);
            (
                root,
                vec![TransactionProof {
                    tx_index: 0,
                    value,
                    proof,
                }],
            )
        } else {
            (B256::ZERO, Vec::new())
        };
        EnforcementBlock {
            header: Header {
                number,
                timestamp: number,
                receipts_root,
                transactions_root,
                ..Default::default()
            },
            receipts: vec![ReceiptProof {
                tx_index: 0,
                value: receipt,
                proof: receipt_proof,
            }],
            transactions,
        }
    }

    fn transaction_block(value: Bytes) -> EnforcementBlock {
        let (transactions_root, proof) = trie_proof(&value);
        EnforcementBlock {
            header: Header {
                number: PERIOD_START_BLOCK,
                transactions_root,
                ..Default::default()
            },
            receipts: Vec::new(),
            transactions: vec![TransactionProof {
                tx_index: 0,
                value,
                proof,
            }],
        }
    }

    fn trie_proof(value: &Bytes) -> (B256, Vec<Bytes>) {
        let key = Nibbles::unpack(loop_core::trie_index_key(0));
        let mut builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![key.clone()]));
        builder.add_leaf(key.clone(), value.as_ref());
        let root = builder.root();
        let proof = builder
            .take_proof_nodes()
            .matching_nodes_sorted(&key)
            .into_iter()
            .map(|(_, node)| node)
            .collect();
        (root, proof)
    }

    fn address_topic(value: Address) -> B256 {
        let mut topic = [0u8; 32];
        topic[12..].copy_from_slice(value.as_slice());
        B256::from(topic)
    }

    fn rlp_len_prefix(base: u8, len: usize) -> Vec<u8> {
        if len <= 55 {
            vec![base + len as u8]
        } else {
            let bytes = (len as u64).to_be_bytes();
            let significant = bytes
                .iter()
                .skip_while(|byte| **byte == 0)
                .copied()
                .collect::<Vec<_>>();
            let mut prefix = vec![base + 55 + significant.len() as u8];
            prefix.extend(significant);
            prefix
        }
    }

    fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            return bytes.to_vec();
        }
        [rlp_len_prefix(0x80, bytes.len()), bytes.to_vec()].concat()
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload = items.concat();
        [rlp_len_prefix(0xc0, payload.len()), payload].concat()
    }

    fn rlp_uint(value: u128) -> Vec<u8> {
        if value == 0 {
            return vec![0x80];
        }
        let bytes = value.to_be_bytes();
        rlp_bytes(
            bytes
                .iter()
                .skip_while(|byte| **byte == 0)
                .copied()
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }
}
