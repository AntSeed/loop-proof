use crate::{WashJournal, BASE_CHAIN_ID, CLOSED_LOOP_PREDICATE_ID, RECIPROCAL_PREDICATE_ID};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SELLER_AGGREGATE_SCHEMA_VERSION: u32 = 1;
pub const BLOCK_AUTHENTICATION_CHUNK_SIZE: usize = 100;
pub use crate::{CLOSED_LOOP_PROGRAM_ID, RECIPROCAL_PROGRAM_ID};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildProofInput {
    pub program_id: B256,
    pub program_vkey: B256,
    pub vkey_digest: [u32; 8],
    pub public_values: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellerAggregateInput {
    pub seller: Address,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub closed_loop_program_vkey: B256,
    pub reciprocal_program_vkey: B256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalBlockRef {
    pub number: u64,
    pub block_hash: B256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellerJournal {
    pub schema_version: u32,
    pub chain_id: u64,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub closed_loop_program_vkey: B256,
    pub reciprocal_program_vkey: B256,
    pub seller: Address,
    pub proven_wash_volume: u128,
    pub evidence_digest: B256,
    pub block_reference_count: u32,
    pub block_authentication_chunk_size: u32,
    pub block_authentication_chunk_count: u32,
    pub block_authentication_root: B256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockAuthenticationChunk {
    pub index: u32,
    pub references: Vec<HistoricalBlockRef>,
    pub proof: Vec<B256>,
}

alloy_sol_types::sol! {
    struct SolSellerSettlement {
        bytes32 settlementId;
        uint128 amount;
    }

    struct SolSellerJournal {
        uint32 schemaVersion;
        uint64 chainId;
        uint64 periodStartBlock;
        uint64 periodEndBlock;
        bytes32 closedLoopProgramVKey;
        bytes32 reciprocalProgramVKey;
        address seller;
        uint128 provenWashVolume;
        bytes32 evidenceDigest;
        uint32 blockReferenceCount;
        uint32 blockAuthenticationChunkSize;
        uint32 blockAuthenticationChunkCount;
        bytes32 blockAuthenticationRoot;
    }

    struct SolAuthenticationBlockRef {
        uint64 number;
        bytes32 blockHash;
    }
}

impl SellerJournal {
    pub fn from_children(
        children: &[ChildProofInput],
        input: &SellerAggregateInput,
    ) -> Result<Self, String> {
        validate_input(children, input)?;
        let mut settlements = BTreeMap::<B256, u128>::new();
        let mut block_refs = BTreeMap::<u64, B256>::new();

        for child in children {
            let journal = WashJournal::abi_decode(&child.public_values)?;
            validate_child(child, &journal, input)?;
            let mut subjects = journal
                .subjects
                .iter()
                .filter(|subject| subject.subject == input.seller);
            let subject = subjects
                .next()
                .ok_or("seller aggregate: child does not prove target seller")?;
            if subjects.next().is_some() {
                return Err("seller aggregate: duplicate target seller in child".into());
            }

            let mut child_volume = 0u128;
            for settlement in &subject.settlements {
                if settlement.settlement_id == B256::ZERO || settlement.amount == 0 {
                    return Err("seller aggregate: invalid settlement record".into());
                }
                child_volume = child_volume
                    .checked_add(settlement.amount)
                    .ok_or("seller aggregate: volume overflow")?;
                match settlements.insert(settlement.settlement_id, settlement.amount) {
                    Some(amount) if amount != settlement.amount => {
                        return Err("seller aggregate: conflicting settlement amount".into())
                    }
                    _ => {}
                }
            }
            if child_volume == 0 || child_volume != subject.wash_volume {
                return Err("seller aggregate: child settlement total mismatch".into());
            }

            for (number, block_hash) in journal.block_refs {
                if block_hash == B256::ZERO {
                    return Err("seller aggregate: zero child block hash".into());
                }
                match block_refs.insert(number, block_hash) {
                    Some(existing) if existing != block_hash => {
                        return Err("seller aggregate: conflicting child block hash".into())
                    }
                    _ => {}
                }
            }
        }

        let proven_wash_volume = settlements.values().try_fold(0u128, |total, amount| {
            total
                .checked_add(*amount)
                .ok_or("seller aggregate: volume overflow")
        })?;
        let block_refs = block_refs
            .into_iter()
            .map(|(number, block_hash)| HistoricalBlockRef { number, block_hash })
            .collect::<Vec<_>>();
        let authentication_chunks = block_authentication_chunks(&block_refs)?;
        let block_authentication_root = block_authentication_root(&block_refs)
            .ok_or("seller aggregate: no block references")?;
        let settlement_values = settlements
            .iter()
            .map(|(settlement_id, amount)| SolSellerSettlement {
                settlementId: *settlement_id,
                amount: *amount,
            })
            .collect::<Vec<_>>();
        // Preimage is the Solidity-reproducible
        // `abi.encode(seller, periodStartBlock, periodEndBlock, settlements)`
        // (no outer tuple offset word), where `settlements` is a
        // `(bytes32 settlementId, uint128 amount)[]` sorted by id.
        let evidence_digest = evidence_digest(
            input.seller,
            input.period_start_block,
            input.period_end_block,
            &settlement_values,
        );

        Ok(Self {
            schema_version: SELLER_AGGREGATE_SCHEMA_VERSION,
            chain_id: BASE_CHAIN_ID,
            period_start_block: input.period_start_block,
            period_end_block: input.period_end_block,
            closed_loop_program_vkey: input.closed_loop_program_vkey,
            reciprocal_program_vkey: input.reciprocal_program_vkey,
            seller: input.seller,
            proven_wash_volume,
            evidence_digest,
            block_reference_count: block_refs
                .len()
                .try_into()
                .map_err(|_| "seller aggregate: too many block references")?,
            block_authentication_chunk_size: BLOCK_AUTHENTICATION_CHUNK_SIZE as u32,
            block_authentication_chunk_count: authentication_chunks
                .len()
                .try_into()
                .map_err(|_| "seller aggregate: too many block chunks")?,
            block_authentication_root,
        })
    }

    pub fn abi_encode(&self) -> Vec<u8> {
        SolSellerJournal {
            schemaVersion: self.schema_version,
            chainId: self.chain_id,
            periodStartBlock: self.period_start_block,
            periodEndBlock: self.period_end_block,
            closedLoopProgramVKey: self.closed_loop_program_vkey,
            reciprocalProgramVKey: self.reciprocal_program_vkey,
            seller: self.seller,
            provenWashVolume: self.proven_wash_volume,
            evidenceDigest: self.evidence_digest,
            blockReferenceCount: self.block_reference_count,
            blockAuthenticationChunkSize: self.block_authentication_chunk_size,
            blockAuthenticationChunkCount: self.block_authentication_chunk_count,
            blockAuthenticationRoot: self.block_authentication_root,
        }
        .abi_encode()
    }
}

fn validate_input(
    children: &[ChildProofInput],
    input: &SellerAggregateInput,
) -> Result<(), String> {
    if children.is_empty()
        || input.seller == Address::ZERO
        || input.period_start_block == 0
        || input.period_start_block > input.period_end_block
        || input.closed_loop_program_vkey == B256::ZERO
        || input.reciprocal_program_vkey == B256::ZERO
    {
        return Err("seller aggregate: invalid input".into());
    }
    Ok(())
}

fn validate_child(
    child: &ChildProofInput,
    journal: &WashJournal,
    input: &SellerAggregateInput,
) -> Result<(), String> {
    let expected_vkey = match (child.program_id, journal.predicate_id) {
        (CLOSED_LOOP_PROGRAM_ID, CLOSED_LOOP_PREDICATE_ID) => input.closed_loop_program_vkey,
        (RECIPROCAL_PROGRAM_ID, RECIPROCAL_PREDICATE_ID) => input.reciprocal_program_vkey,
        _ => return Err("seller aggregate: wrong child program".into()),
    };
    if child.program_vkey != expected_vkey || vkey_bytes32(child.vkey_digest) != expected_vkey {
        return Err("seller aggregate: wrong child vkey".into());
    }
    if journal.chain_id != BASE_CHAIN_ID
        || journal.period_start_block != input.period_start_block
        || journal.period_end_block != input.period_end_block
        || journal.source_claim_id == B256::ZERO
        || journal.claim_id == B256::ZERO
    {
        return Err("seller aggregate: child identity mismatch".into());
    }
    Ok(())
}

/// `keccak256(abi.encode(seller, periodStartBlock, periodEndBlock, settlements))`
/// exactly as Solidity's `abi.encode` would produce it for the same arguments.
pub fn evidence_digest(
    seller: Address,
    period_start_block: u64,
    period_end_block: u64,
    settlements: &[SolSellerSettlement],
) -> B256 {
    keccak256((seller, period_start_block, period_end_block, settlements).abi_encode_params())
}

pub fn block_authentication_chunks(
    refs: &[HistoricalBlockRef],
) -> Result<Vec<BlockAuthenticationChunk>, String> {
    if refs.is_empty() {
        return Err("seller aggregate: no block references".into());
    }
    if refs
        .iter()
        .any(|reference| reference.block_hash == B256::ZERO)
        || refs.windows(2).any(|pair| pair[0].number >= pair[1].number)
    {
        return Err("seller aggregate: invalid block references".into());
    }
    let leaves = refs
        .chunks(BLOCK_AUTHENTICATION_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| block_authentication_leaf(index as u32, chunk))
        .collect::<Vec<_>>();
    Ok(refs
        .chunks(BLOCK_AUTHENTICATION_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| BlockAuthenticationChunk {
            index: index as u32,
            references: chunk.to_vec(),
            proof: merkle_proof(&leaves, index),
        })
        .collect())
}

pub fn block_authentication_root(refs: &[HistoricalBlockRef]) -> Option<B256> {
    let leaves = refs
        .chunks(BLOCK_AUTHENTICATION_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| block_authentication_leaf(index as u32, chunk))
        .collect::<Vec<_>>();
    merkle_root(&leaves)
}

fn block_authentication_leaf(index: u32, refs: &[HistoricalBlockRef]) -> B256 {
    let references = refs
        .iter()
        .map(|reference| SolAuthenticationBlockRef {
            number: reference.number,
            blockHash: reference.block_hash,
        })
        .collect::<Vec<_>>();
    keccak256((index, references).abi_encode_params())
}

fn merkle_root(leaves: &[B256]) -> Option<B256> {
    let mut level = leaves.to_vec();
    if level.is_empty() {
        return None;
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| keccak256((pair[0], *pair.get(1).unwrap_or(&pair[0])).abi_encode()))
            .collect();
    }
    level.first().copied()
}

fn merkle_proof(leaves: &[B256], leaf_index: usize) -> Vec<B256> {
    let mut level = leaves.to_vec();
    let mut index = leaf_index;
    let mut proof = Vec::new();
    while level.len() > 1 {
        let sibling = if index % 2 == 0 {
            *level.get(index + 1).unwrap_or(&level[index])
        } else {
            level[index - 1]
        };
        proof.push(sibling);
        level = level
            .chunks(2)
            .map(|pair| keccak256((pair[0], *pair.get(1).unwrap_or(&pair[0])).abi_encode()))
            .collect();
        index /= 2;
    }
    proof
}

pub fn vkey_bytes32(words: [u32; 8]) -> B256 {
    let value = words
        .into_iter()
        .fold(U256::ZERO, |packed, word| (packed << 31) + U256::from(word));
    B256::from(value.to_be_bytes::<32>())
}
