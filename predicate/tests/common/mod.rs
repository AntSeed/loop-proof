//! Synthetic-chain fixture builder: constructs blocks whose receipt,
//! transaction, and state tries are real Merkle-Patricia tries, so every
//! predicate test exercises the exact verification paths the guest runs.

#![allow(dead_code)]

use alloy_consensus::Header;
use alloy_primitives::{address, hex, keccak256, Address, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
use loop_core::{rlp_bytes, rlp_list, rlp_uint, ReceiptProof, StorageProof, TransactionProof};
use std::collections::BTreeMap;
use wash_predicate::{
    BuyerLedger, EvidenceBlock, FundingEvidence, FundingKind, LogRef, ReturnPath, StateRead,
    AGENT_STATS_TOTAL_VOLUME_OFFSET, BUYER_ACCOUNT_BALANCE_OFFSET, CHANNELS_ADDRESS,
    CHANNELS_AGENT_STATS_SLOT, DEPOSITS_ADDRESS, DEPOSITS_BUYERS_SLOT, PERIOD_END_BLOCK,
    PERIOD_START_BLOCK, STAKING_ADDRESS, STAKING_SELLER_AGENT_ID_SLOT, USDC_ADDRESS,
};

/// Signer-recoverable raw transaction (chain id 8453, to = SELLER, value 1
/// wei) whose recovered signer is `FUNDER`.
pub const RAW_FUNDER_TX: &str = "01f86382210580018252089400000000000000000000000000000000000000aa0180c001a04e4f22a8bf8949e504ea441c49c09aef77d2c21559b6dec72922ce5f0bf82405a05970730d98c433bfa3a0abf720cb52020856b6b446d3bc345197d1d53198639d";

pub const FUNDER: Address = address!("19e7e376e7c213b7e7e7e46cc70a5dd086daff2a");
pub const SELLER: Address = address!("00000000000000000000000000000000000000aa");
pub const RELAY: Address = address!("00000000000000000000000000000000000000cc");
pub const BUYERS: [Address; 3] = [
    address!("0000000000000000000000000000000000000001"),
    address!("0000000000000000000000000000000000000002"),
    address!("0000000000000000000000000000000000000003"),
];

pub fn address_topic(value: Address) -> B256 {
    let mut topic = [0u8; 32];
    topic[12..].copy_from_slice(value.as_slice());
    B256::from(topic)
}

// ── trie builders ───────────────────────────────────────────────────────

/// Single-leaf index trie (receipts/transactions with one entry at index 0).
pub fn index_trie_proof(value: &[u8]) -> (B256, Vec<Bytes>) {
    let key = Nibbles::unpack(loop_core::trie_index_key(0));
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![key.clone()]));
    hb.add_leaf(key.clone(), value);
    let root = hb.root();
    let proof = hb
        .take_proof_nodes()
        .matching_nodes_sorted(&key)
        .into_iter()
        .map(|(_, node)| node)
        .collect();
    (root, proof)
}

/// Hashed-key trie over arbitrary (key, value) pairs, retaining proofs for
/// `retain` keys (present or absent).
fn secure_trie(entries: &[(B256, Vec<u8>)], retain: &[B256]) -> (B256, BTreeMap<B256, Vec<Bytes>>) {
    let mut leaves: Vec<(Nibbles, &Vec<u8>)> = entries
        .iter()
        .map(|(k, v)| (Nibbles::unpack(keccak256(k)), v))
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let retained: Vec<Nibbles> = retain
        .iter()
        .map(|k| Nibbles::unpack(keccak256(k)))
        .collect();
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(retained));
    for (key, value) in &leaves {
        hb.add_leaf(key.clone(), value);
    }
    let root = hb.root();
    let nodes = hb.take_proof_nodes();
    let mut out = BTreeMap::new();
    for key in retain {
        let nib = Nibbles::unpack(keccak256(key));
        out.insert(
            *key,
            nodes
                .matching_nodes_sorted(&nib)
                .into_iter()
                .map(|(_, n)| n)
                .collect(),
        );
    }
    (root, out)
}

fn secure_trie_addr(
    entries: &[(Address, Vec<u8>)],
    retain: &[Address],
) -> (B256, BTreeMap<Address, Vec<Bytes>>) {
    let mut leaves: Vec<(Nibbles, &Vec<u8>)> = entries
        .iter()
        .map(|(a, v)| (Nibbles::unpack(keccak256(a)), v))
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let retained: Vec<Nibbles> = retain
        .iter()
        .map(|a| Nibbles::unpack(keccak256(a)))
        .collect();
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(retained));
    for (key, value) in &leaves {
        hb.add_leaf(key.clone(), value);
    }
    let root = hb.root();
    let nodes = hb.take_proof_nodes();
    let mut out = BTreeMap::new();
    for addr in retain {
        let nib = Nibbles::unpack(keccak256(addr));
        out.insert(
            *addr,
            nodes
                .matching_nodes_sorted(&nib)
                .into_iter()
                .map(|(_, n)| n)
                .collect(),
        );
    }
    (root, out)
}

fn storage_leaf(value: U256) -> Vec<u8> {
    let be = value.to_be_bytes::<32>();
    let sig: Vec<u8> = be.iter().skip_while(|b| **b == 0).cloned().collect();
    rlp_bytes(&sig)
}

// ── receipts and logs ───────────────────────────────────────────────────

pub fn log_rlp(address: Address, topics: &[B256], data: &[u8]) -> Vec<u8> {
    rlp_list(&[
        rlp_bytes(address.as_slice()),
        rlp_list(
            &topics
                .iter()
                .map(|t| rlp_bytes(t.as_slice()))
                .collect::<Vec<_>>(),
        ),
        rlp_bytes(data),
    ])
}

pub fn receipt_rlp(success: bool, logs: &[Vec<u8>]) -> Bytes {
    Bytes::from(rlp_list(&[
        rlp_uint(if success { 1 } else { 0 }),
        rlp_uint(1),
        rlp_bytes(&[0u8; 256]),
        rlp_list(logs),
    ]))
}

pub fn transfer_log(from: Address, to: Address, amount: u128) -> Vec<u8> {
    let mut data = [0u8; 32];
    data[16..].copy_from_slice(&amount.to_be_bytes());
    log_rlp(
        USDC_ADDRESS,
        &[
            loop_core::TRANSFER_TOPIC,
            address_topic(from),
            address_topic(to),
        ],
        &data,
    )
}

pub fn deposited_log(buyer: Address, amount: u128) -> Vec<u8> {
    let mut data = [0u8; 32];
    data[16..].copy_from_slice(&amount.to_be_bytes());
    log_rlp(
        DEPOSITS_ADDRESS,
        &[loop_core::DEPOSITED_TOPIC, address_topic(buyer)],
        &data,
    )
}

pub fn settled_log(buyer: Address, seller: Address, delta: u128) -> Vec<u8> {
    let mut data = [0u8; 64];
    data[48..].copy_from_slice(&delta.to_be_bytes());
    log_rlp(
        CHANNELS_ADDRESS,
        &[
            loop_core::CHANNEL_SETTLED_TOPIC,
            B256::ZERO,
            address_topic(buyer),
            address_topic(seller),
        ],
        &data,
    )
}

// ── block builders ──────────────────────────────────────────────────────

/// One block carrying a single receipt (at tx index 0) and, optionally, the
/// matching authenticated transaction.
pub fn receipt_block(
    number: u64,
    timestamp: u64,
    receipt: Bytes,
    transaction: Option<Bytes>,
) -> EvidenceBlock {
    let (receipts_root, receipt_proof) = index_trie_proof(&receipt);
    let (transactions_root, transactions) = match transaction {
        Some(value) => {
            let (root, proof) = index_trie_proof(&value);
            (
                root,
                vec![TransactionProof {
                    tx_index: 0,
                    value,
                    proof,
                }],
            )
        }
        None => (B256::ZERO, Vec::new()),
    };
    EvidenceBlock {
        header: Header {
            number,
            timestamp,
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

pub fn settlement_block(
    number: u64,
    timestamp: u64,
    buyer: Address,
    seller: Address,
    delta: u128,
    success: bool,
) -> EvidenceBlock {
    receipt_block(
        number,
        timestamp,
        receipt_rlp(success, &[settled_log(buyer, seller, delta)]),
        None,
    )
}

pub fn transfer_block(
    number: u64,
    timestamp: u64,
    from: Address,
    to: Address,
    amount: u128,
    with_funder_tx: bool,
) -> EvidenceBlock {
    receipt_block(
        number,
        timestamp,
        receipt_rlp(true, &[transfer_log(from, to, amount)]),
        with_funder_tx.then(|| Bytes::from(hex::decode(RAW_FUNDER_TX).unwrap())),
    )
}

/// Deposit receipt: Transfer(payer → Deposits) then Deposited(member).
pub fn deposit_block(
    number: u64,
    timestamp: u64,
    payer: Address,
    member: Address,
    amount: u128,
    with_funder_tx: bool,
) -> EvidenceBlock {
    receipt_block(
        number,
        timestamp,
        receipt_rlp(
            true,
            &[
                transfer_log(payer, DEPOSITS_ADDRESS, amount),
                deposited_log(member, amount),
            ],
        ),
        with_funder_tx.then(|| Bytes::from(hex::decode(RAW_FUNDER_TX).unwrap())),
    )
}

// ── state boundary blocks ───────────────────────────────────────────────

/// Contents of the world state at one boundary block.
#[derive(Clone, Default)]
pub struct StateSpec {
    /// `Deposits.buyers[addr].balance`
    pub balances: Vec<(Address, U256)>,
    /// `Staking.sellerAgentId[seller]`
    pub agent_ids: Vec<(Address, U256)>,
    /// `Channels._agentStats[agentId].totalVolumeUsdc`
    pub total_volumes: Vec<(U256, U256)>,
}

pub struct StateBlock {
    pub block: EvidenceBlock,
    proofs: BTreeMap<(Address, B256), StorageProof>,
}

impl StateBlock {
    pub fn read(&self, block_index: usize, contract: Address, slot: B256) -> StateRead {
        StateRead {
            block: block_index,
            proof: self
                .proofs
                .get(&(contract, slot))
                .unwrap_or_else(|| panic!("no retained proof for {contract} {slot}"))
                .clone(),
        }
    }

    pub fn proof(&self, contract: Address, slot: B256) -> StorageProof {
        self.proofs
            .get(&(contract, slot))
            .unwrap_or_else(|| panic!("no retained proof for {contract} {slot}"))
            .clone()
    }
}

pub fn balance_slot(buyer: Address) -> B256 {
    loop_core::slot_offset(
        loop_core::mapping_slot_address(buyer, DEPOSITS_BUYERS_SLOT),
        BUYER_ACCOUNT_BALANCE_OFFSET,
    )
}

pub fn agent_id_slot(seller: Address) -> B256 {
    loop_core::mapping_slot_address(seller, STAKING_SELLER_AGENT_ID_SLOT)
}

pub fn total_volume_slot(agent_id: U256) -> B256 {
    loop_core::slot_offset(
        loop_core::mapping_slot_u256(agent_id, CHANNELS_AGENT_STATS_SLOT),
        AGENT_STATS_TOTAL_VOLUME_OFFSET,
    )
}

/// Default agent id used by seller-proof fixtures.
pub const AGENT_ID: u64 = 53_008;

/// Every fixture seller's cumulative settled-volume counter at the period
/// end (the start-boundary counter is zero).
pub const TOTAL_VOLUME_END_COUNTER: u128 = 2_000_000_000;

/// Fixture-canonical agent id per subject address. Claim end-state blocks
/// and total-volume boundary witnesses must agree on one world state, so
/// both derive it from here.
pub fn canonical_agent_id(seller: Address) -> U256 {
    if seller == SELLER {
        U256::from(AGENT_ID)
    } else if seller == PAIR_A {
        U256::from(AGENT_ID + 1)
    } else if seller == PAIR_B {
        U256::from(AGENT_ID + 2)
    } else {
        U256::from(AGENT_ID + 9)
    }
}

/// Staking/channels state shared by every boundary block: all fixture
/// sellers staked, each with `counter` settled volume.
fn boundary_entries(counter: u128) -> (Vec<(Address, U256)>, Vec<(U256, U256)>) {
    let sellers = [SELLER, PAIR_A, PAIR_B];
    (
        sellers
            .iter()
            .map(|s| (*s, canonical_agent_id(*s)))
            .collect(),
        sellers
            .iter()
            .map(|s| (canonical_agent_id(*s), U256::from(counter)))
            .collect(),
    )
}

/// Extend a period-end state spec with the canonical staking/channels
/// entries so the end header matches total-volume boundary witnesses.
pub fn with_boundary_state(mut spec: StateSpec) -> StateSpec {
    let (agent_ids, total_volumes) = boundary_entries(TOTAL_VOLUME_END_COUNTER);
    spec.agent_ids = agent_ids;
    spec.total_volumes = total_volumes;
    spec
}

/// Build the period-end boundary witness proving the seller's total settled
/// volume (`TOTAL_VOLUME_END_COUNTER`; the period starts at protocol
/// genesis, so the end counter is the period total).
pub fn total_volume_witness(seller: Address) -> wash_predicate::seller::TotalVolumeBoundary {
    total_volume_boundary(PERIOD_END_BLOCK, 9_000, seller, TOTAL_VOLUME_END_COUNTER)
}

pub fn total_volume_boundary(
    number: u64,
    timestamp: u64,
    seller: Address,
    counter: u128,
) -> wash_predicate::seller::TotalVolumeBoundary {
    let agent = canonical_agent_id(seller);
    let (agent_ids, total_volumes) = boundary_entries(counter);
    let spec = StateSpec {
        balances: Vec::new(),
        agent_ids,
        total_volumes,
    };
    let retain = vec![
        (STAKING_ADDRESS, agent_id_slot(seller)),
        (CHANNELS_ADDRESS, total_volume_slot(agent)),
    ];
    let state = state_block(number, timestamp, &spec, &retain);
    wash_predicate::seller::TotalVolumeBoundary {
        header: state.block.header.clone(),
        agent_id: state.proof(STAKING_ADDRESS, agent_id_slot(seller)),
        total_volume: state.proof(CHANNELS_ADDRESS, total_volume_slot(agent)),
    }
}

/// Period-end boundary where the target seller is not staked: its agent-id
/// slot is absent (proves zero), so the proof must be rejected.
pub fn unstaked_total_volume_witness(
    seller: Address,
) -> wash_predicate::seller::TotalVolumeBoundary {
    let others: Vec<Address> = [SELLER, PAIR_A, PAIR_B]
        .into_iter()
        .filter(|other| *other != seller)
        .collect();
    let spec = StateSpec {
        balances: Vec::new(),
        agent_ids: others
            .iter()
            .map(|other| (*other, canonical_agent_id(*other)))
            .collect(),
        total_volumes: others
            .iter()
            .map(|other| (canonical_agent_id(*other), U256::from(1u64)))
            .collect(),
    };
    let retain = vec![
        (STAKING_ADDRESS, agent_id_slot(seller)),
        (CHANNELS_ADDRESS, total_volume_slot(U256::ZERO)),
    ];
    let state = state_block(PERIOD_END_BLOCK, 9_000, &spec, &retain);
    wash_predicate::seller::TotalVolumeBoundary {
        header: state.block.header.clone(),
        agent_id: state.proof(STAKING_ADDRESS, agent_id_slot(seller)),
        total_volume: state.proof(CHANNELS_ADDRESS, total_volume_slot(U256::ZERO)),
    }
}

/// Build a boundary block whose state trie holds the deposits account,
/// retaining storage proofs for every slot in `retain`.
pub fn state_block(
    number: u64,
    timestamp: u64,
    spec: &StateSpec,
    retain: &[(Address, B256)],
) -> StateBlock {
    let contracts = [DEPOSITS_ADDRESS, STAKING_ADDRESS, CHANNELS_ADDRESS];
    let mut storage: BTreeMap<Address, Vec<(B256, Vec<u8>)>> = BTreeMap::new();
    for (buyer, balance) in &spec.balances {
        if !balance.is_zero() {
            storage
                .entry(DEPOSITS_ADDRESS)
                .or_default()
                .push((balance_slot(*buyer), storage_leaf(*balance)));
        }
    }
    for (seller, agent_id) in &spec.agent_ids {
        if !agent_id.is_zero() {
            storage
                .entry(STAKING_ADDRESS)
                .or_default()
                .push((agent_id_slot(*seller), storage_leaf(*agent_id)));
        }
    }
    for (agent_id, volume) in &spec.total_volumes {
        if !volume.is_zero() {
            storage
                .entry(CHANNELS_ADDRESS)
                .or_default()
                .push((total_volume_slot(*agent_id), storage_leaf(*volume)));
        }
    }
    // storage tries + retained storage proofs per contract
    let mut storage_roots: BTreeMap<Address, B256> = BTreeMap::new();
    let mut storage_proofs: BTreeMap<(Address, B256), Vec<Bytes>> = BTreeMap::new();
    for contract in contracts {
        let entries = storage.get(&contract).cloned().unwrap_or_default();
        let wanted: Vec<B256> = retain
            .iter()
            .filter(|(a, _)| *a == contract)
            .map(|(_, s)| *s)
            .collect();
        if entries.is_empty() {
            storage_roots.insert(contract, loop_core::EMPTY_TRIE_ROOT);
            for slot in wanted {
                storage_proofs.insert((contract, slot), Vec::new());
            }
        } else {
            let (root, proofs) = secure_trie(&entries, &wanted);
            storage_roots.insert(contract, root);
            for (slot, proof) in proofs {
                storage_proofs.insert((contract, slot), proof);
            }
        }
    }

    // account trie
    let account_entries: Vec<(Address, Vec<u8>)> = contracts
        .iter()
        .map(|contract| {
            (
                *contract,
                rlp_list(&[
                    rlp_uint(1),
                    rlp_uint(0),
                    rlp_bytes(storage_roots[contract].as_slice()),
                    rlp_bytes(&[0u8; 32]),
                ]),
            )
        })
        .collect();
    let (state_root, account_proofs) = secure_trie_addr(&account_entries, &contracts);

    let mut proofs = BTreeMap::new();
    for (contract, slot) in retain {
        proofs.insert(
            (*contract, *slot),
            StorageProof {
                account_proof: account_proofs[contract].clone(),
                storage_proof: storage_proofs
                    .get(&(*contract, *slot))
                    .cloned()
                    .unwrap_or_default(),
            },
        );
    }

    StateBlock {
        block: EvidenceBlock {
            header: Header {
                number,
                timestamp,
                state_root,
                ..Default::default()
            },
            receipts: Vec::new(),
            transactions: Vec::new(),
        },
        proofs,
    }
}

// ── closed-loop fixture ─────────────────────────────────────────────────

pub struct LoopCfg {
    pub seller: Address,
    pub funder: Address,
    pub buyers: Vec<Address>,
    /// USDC funded per buyer (direct transfer form).
    pub funded: Vec<u128>,
    /// Settlement delta per buyer.
    pub settled: Vec<u128>,
    /// Period-end protocol balances per buyer.
    pub end_balances: Vec<u128>,
    /// Return paths: each a hop list of (to, amount); from starts at seller.
    pub return_paths: Vec<Vec<(Address, u128)>>,
}

impl Default for LoopCfg {
    fn default() -> Self {
        LoopCfg {
            seller: SELLER,
            funder: FUNDER,
            buyers: BUYERS.to_vec(),
            funded: vec![400_000_000; 3],
            settled: vec![400_000_000; 3],
            end_balances: vec![0; 3],
            // Σ settle = 1200 USDC; α_return = 3_000 bps needs ≥ 360 at the
            // funder; this path returns 1170.
            return_paths: vec![vec![(RELAY, 1_176_000_000), (FUNDER, 1_170_000_000)]],
        }
    }
}

pub fn closed_loop_input(cfg: &LoopCfg) -> wash_predicate::ClosedLoopInput {
    let mut blocks: Vec<EvidenceBlock> = Vec::new();
    let mut fundings = Vec::new();
    let mut settlements = Vec::new();
    let mut returns = Vec::new();

    // FUND: direct transfers, one block each, timestamps 1_000 + i.
    for (i, buyer) in cfg.buyers.iter().enumerate() {
        blocks.push(transfer_block(
            PERIOD_START_BLOCK + i as u64,
            1_000 + i as u64,
            cfg.funder,
            *buyer,
            cfg.funded[i],
            true,
        ));
        fundings.push(FundingEvidence {
            buyer: *buyer,
            kind: FundingKind::Usdc {
                transfer: LogRef {
                    block: blocks.len() - 1,
                    receipt: 0,
                    log: 0,
                },
            },
        });
    }

    // SETTLE: timestamps 2_000 + i.
    for (i, buyer) in cfg.buyers.iter().enumerate() {
        if cfg.settled[i] == 0 {
            continue;
        }
        blocks.push(settlement_block(
            PERIOD_START_BLOCK + 10 + i as u64,
            2_000 + i as u64,
            *buyer,
            cfg.seller,
            cfg.settled[i],
            true,
        ));
        settlements.push(LogRef {
            block: blocks.len() - 1,
            receipt: 0,
            log: 0,
        });
    }

    // RETURN: timestamps 3_000 onwards.
    let mut return_block = PERIOD_START_BLOCK + 100;
    let mut return_time = 3_000u64;
    for path in &cfg.return_paths {
        let mut refs = Vec::new();
        let mut from = cfg.seller;
        for (to, amount) in path {
            blocks.push(transfer_block(
                return_block,
                return_time,
                from,
                *to,
                *amount,
                false,
            ));
            refs.push(LogRef {
                block: blocks.len() - 1,
                receipt: 0,
                log: 0,
            });
            from = *to;
            return_block += 1;
            return_time += 10;
        }
        returns.push(ReturnPath { transfers: refs });
    }

    // LEDGER period-end block.
    let mut retain_end: Vec<(Address, B256)> = Vec::new();
    for buyer in &cfg.buyers {
        retain_end.push((DEPOSITS_ADDRESS, balance_slot(*buyer)));
    }
    let end_spec = StateSpec {
        balances: cfg
            .buyers
            .iter()
            .zip(&cfg.end_balances)
            .map(|(b, v)| (*b, U256::from(*v)))
            .collect(),
        ..Default::default()
    };
    let end_state = state_block(
        PERIOD_END_BLOCK,
        9_000,
        &with_boundary_state(end_spec),
        &retain_end,
    );
    let end_index = blocks.len();
    blocks.push(end_state.block.clone());

    let ledgers: Vec<BuyerLedger> = cfg
        .buyers
        .iter()
        .map(|buyer| BuyerLedger {
            end: end_state.read(end_index, DEPOSITS_ADDRESS, balance_slot(*buyer)),
        })
        .collect();
    wash_predicate::ClosedLoopInput {
        chain_id: wash_predicate::BASE_CHAIN_ID,
        period_start_block: PERIOD_START_BLOCK,
        period_end_block: PERIOD_END_BLOCK,
        source_claim_id: B256::from([0x11; 32]),
        seller: cfg.seller,
        funder: cfg.funder,
        buyers: cfg.buyers.clone(),
        blocks,
        fundings,
        settlements,
        returns,
        ledgers,
    }
}

// ── reciprocal fixture ──────────────────────────────────────────────────

/// Pair member A is the recoverable signer (deposits must be signer-attributed).
pub const PAIR_A: Address = FUNDER;
pub const PAIR_B: Address = address!("ffffffffffffffffffffffffffffffffffffffee");

pub struct PairCfg {
    /// Settlements with seller = A, buyer = B.
    pub a_sells: Vec<u128>,
    /// Settlements with seller = B, buyer = A.
    pub b_sells: Vec<u128>,
    /// Pair-internal deposits: (credited member, amount); payer/signer is A.
    pub deposits: Vec<(Address, u128)>,
    pub end_balances: (u128, u128),
}

impl Default for PairCfg {
    fn default() -> Self {
        PairCfg {
            a_sells: vec![250_000_000, 250_000_000],
            b_sells: vec![225_000_000, 225_000_000],
            deposits: vec![(PAIR_A, 500_000_000), (PAIR_B, 450_000_000)],
            end_balances: (0, 0),
        }
    }
}

pub fn reciprocal_input(cfg: &PairCfg) -> wash_predicate::ReciprocalInput {
    use wash_predicate::reciprocal::PairDepositEvidence;
    let mut blocks: Vec<EvidenceBlock> = Vec::new();
    let mut settlements = Vec::new();
    let mut number = PERIOD_START_BLOCK;
    for amount in &cfg.a_sells {
        blocks.push(settlement_block(
            number, 2_000, PAIR_B, PAIR_A, *amount, true,
        ));
        settlements.push(LogRef {
            block: blocks.len() - 1,
            receipt: 0,
            log: 0,
        });
        number += 1;
    }
    for amount in &cfg.b_sells {
        blocks.push(settlement_block(
            number, 2_000, PAIR_A, PAIR_B, *amount, true,
        ));
        settlements.push(LogRef {
            block: blocks.len() - 1,
            receipt: 0,
            log: 0,
        });
        number += 1;
    }
    let mut internal_deposits = Vec::new();
    let mut deposit_number = PERIOD_START_BLOCK + 50;
    for (member, amount) in &cfg.deposits {
        blocks.push(deposit_block(
            deposit_number,
            1_500,
            PAIR_A,
            *member,
            *amount,
            true,
        ));
        internal_deposits.push(PairDepositEvidence {
            member: *member,
            transfer: LogRef {
                block: blocks.len() - 1,
                receipt: 0,
                log: 0,
            },
            deposited: LogRef {
                block: blocks.len() - 1,
                receipt: 0,
                log: 1,
            },
        });
        deposit_number += 1;
    }

    let retain_end = vec![
        (DEPOSITS_ADDRESS, balance_slot(PAIR_A)),
        (DEPOSITS_ADDRESS, balance_slot(PAIR_B)),
    ];

    let end_spec = StateSpec {
        balances: vec![
            (PAIR_A, U256::from(cfg.end_balances.0)),
            (PAIR_B, U256::from(cfg.end_balances.1)),
        ],
        ..Default::default()
    };
    let end_state = state_block(
        PERIOD_END_BLOCK,
        9_000,
        &with_boundary_state(end_spec),
        &retain_end,
    );
    let end_index = blocks.len();
    blocks.push(end_state.block.clone());

    let ledger = |member: Address| BuyerLedger {
        end: end_state.read(end_index, DEPOSITS_ADDRESS, balance_slot(member)),
    };
    wash_predicate::ReciprocalInput {
        chain_id: wash_predicate::BASE_CHAIN_ID,
        period_start_block: PERIOD_START_BLOCK,
        period_end_block: PERIOD_END_BLOCK,
        source_claim_id: B256::from([0x22; 32]),
        address_a: PAIR_A,
        address_b: PAIR_B,
        blocks,
        settlements,
        internal_deposits,
        ledger_a: ledger(PAIR_A),
        ledger_b: ledger(PAIR_B),
    }
}
