use crate::{WashJournal, BASE_CHAIN_ID};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const AGGREGATE_SCHEMA_VERSION: u32 = 1;
pub use crate::{CLOSED_LOOP_PROGRAM_ID, RECIPROCAL_PROGRAM_ID};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildProofInput {
    pub program_id: B256,
    pub program_vkey: B256,
    pub vkey_digest: [u32; 8],
    pub public_values: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateFinding {
    pub claim_id: B256,
    pub child_program_id: B256,
    pub child_program_vkey: B256,
    pub agent_id: U256,
    pub seller: Address,
    pub source_id: B256,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub offense_epoch: u64,
    pub total_volume: u128,
    pub proven_wash_volume: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateJournal {
    pub schema_version: u32,
    pub chain_id: u64,
    pub findings: Vec<AggregateFinding>,
    pub block_refs: Vec<(u64, B256)>,
}

alloy_sol_types::sol! {
    struct SolAggregateFinding {
        bytes32 claimId;
        bytes32 childProgramId;
        bytes32 childProgramVKey;
        uint256 agentId;
        address seller;
        bytes32 sourceId;
        uint64 periodStartBlock;
        uint64 periodEndBlock;
        uint64 offenseEpoch;
        uint128 totalVolume;
        uint128 provenWashVolume;
    }
    struct SolAggregateBlockRef { uint64 number; bytes32 blockHash; }
    struct SolAggregateJournal {
        uint32 schemaVersion;
        uint64 chainId;
        SolAggregateFinding[] findings;
        SolAggregateBlockRef[] blockRefs;
    }
}

impl AggregateJournal {
    pub fn from_children(children: &[ChildProofInput]) -> Result<Self, String> {
        if children.is_empty() {
            return Err("aggregate: no children".into());
        }
        let mut findings = Vec::new();
        let mut block_refs = BTreeMap::new();
        for child in children {
            if child.program_id == B256::ZERO || child.program_vkey == B256::ZERO {
                return Err("aggregate: invalid child identity".into());
            }
            if vkey_bytes32(child.vkey_digest) != child.program_vkey {
                return Err("aggregate: child vkey encodings disagree".into());
            }
            let journal = WashJournal::abi_decode(&child.public_values)?;
            if journal.chain_id != BASE_CHAIN_ID {
                return Err("aggregate: wrong child chain".into());
            }
            for subject in journal.subjects {
                if subject.agent_id == 0
                    || subject.wash_volume == 0
                    || subject.total_volume == 0
                    || subject.wash_volume > subject.total_volume
                {
                    return Err("aggregate: invalid subject volumes".into());
                }
                findings.push(AggregateFinding {
                    claim_id: keccak256(
                        (child.program_id, journal.claim_id, subject.agent_id).abi_encode(),
                    ),
                    child_program_id: child.program_id,
                    child_program_vkey: child.program_vkey,
                    agent_id: subject.agent_id,
                    seller: subject.subject,
                    source_id: journal.source_id,
                    period_start_block: journal.period_start_block,
                    period_end_block: journal.period_end_block,
                    offense_epoch: journal.offense_epoch,
                    total_volume: subject.total_volume,
                    proven_wash_volume: subject.wash_volume,
                });
            }
            for (number, hash) in journal.block_refs {
                if let Some(existing) = block_refs.insert(number, hash) {
                    if existing != hash {
                        return Err("aggregate: conflicting block hash".into());
                    }
                }
            }
        }
        findings.sort_unstable_by_key(|finding| finding.claim_id);
        if findings
            .windows(2)
            .any(|pair| pair[0].claim_id == pair[1].claim_id)
        {
            return Err("aggregate: duplicate finding".into());
        }
        Ok(Self {
            schema_version: AGGREGATE_SCHEMA_VERSION,
            chain_id: BASE_CHAIN_ID,
            findings,
            block_refs: block_refs.into_iter().collect(),
        })
    }

    pub fn abi_encode(&self) -> Vec<u8> {
        SolAggregateJournal {
            schemaVersion: self.schema_version,
            chainId: self.chain_id,
            findings: self
                .findings
                .iter()
                .map(|finding| SolAggregateFinding {
                    claimId: finding.claim_id,
                    childProgramId: finding.child_program_id,
                    childProgramVKey: finding.child_program_vkey,
                    agentId: finding.agent_id,
                    seller: finding.seller,
                    sourceId: finding.source_id,
                    periodStartBlock: finding.period_start_block,
                    periodEndBlock: finding.period_end_block,
                    offenseEpoch: finding.offense_epoch,
                    totalVolume: finding.total_volume,
                    provenWashVolume: finding.proven_wash_volume,
                })
                .collect(),
            blockRefs: self
                .block_refs
                .iter()
                .map(|(number, hash)| SolAggregateBlockRef {
                    number: *number,
                    blockHash: *hash,
                })
                .collect(),
        }
        .abi_encode()
    }
}

/// SP1's on-chain `bytes32` key is the eight KoalaBear digest words packed
/// as one 248-bit integer, shifting by 31 bits per word.
pub fn vkey_bytes32(words: [u32; 8]) -> B256 {
    let value = words
        .into_iter()
        .fold(U256::ZERO, |packed, word| (packed << 31) + U256::from(word));
    B256::from(value.to_be_bytes::<32>())
}
