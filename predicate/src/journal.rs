//! The public journal — the only data that crosses the proof boundary.
//!
//! Minimal by design (AIP-4 §Journals): the subject(s); per subject, the
//! proven fabricated volume and exact-period total volume read from
//! `AgentStats`; a claim identifier making resubmission idempotent; and
//! the sorted block references the registry authenticates against the
//! Chainlink BlockhashStore. Cohort membership, intermediate arithmetic, and
//! the evidence manifest stay off-chain — the chain never duplicates
//! predicate logic.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectRecord {
    pub subject: Address,
    pub agent_id: U256,
    /// Σ SETTLE — the fabricated volume this claim proves (raw USDC).
    pub wash_volume: u128,
    /// Exact-period `AgentStats.totalVolumeUsdc` delta (raw USDC).
    pub total_volume: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WashJournal {
    pub predicate_id: u8,
    pub source_id: B256,
    pub chain_id: u64,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub offense_epoch: u64,
    pub claim_id: B256,
    pub subjects: Vec<SubjectRecord>,
    /// Sorted, unique `(number, hash)` of every block the proof relied on.
    pub block_refs: Vec<(u64, B256)>,
}

// Solidity mirror. The guest commits `abi_encode()` of this, so the bytes
// the SP1 verifier hashes are exactly what
// `abi.decode(journalData, (WashJournal))` recovers on-chain.
alloy_sol_types::sol! {
    struct SolBlockRef {
        uint64 number;
        bytes32 blockHash;
    }

    struct SolSubjectRecord {
        address subject;
        uint256 agentId;
        uint128 washVolume;
        uint128 totalVolume;
    }

    struct SolWashJournal {
        uint8 predicateId;
        bytes32 sourceId;
        uint64 chainId;
        uint64 periodStartBlock;
        uint64 periodEndBlock;
        uint64 offenseEpoch;
        bytes32 claimId;
        SolSubjectRecord[] subjects;
        SolBlockRef[] blockRefs;
    }
}

impl WashJournal {
    /// ABI encoding matching Solidity `abi.encode(WashJournal)`.
    pub fn abi_encode(&self) -> Vec<u8> {
        SolWashJournal {
            predicateId: self.predicate_id,
            sourceId: self.source_id,
            chainId: self.chain_id,
            periodStartBlock: self.period_start_block,
            periodEndBlock: self.period_end_block,
            offenseEpoch: self.offense_epoch,
            claimId: self.claim_id,
            subjects: self
                .subjects
                .iter()
                .map(|s| SolSubjectRecord {
                    subject: s.subject,
                    agentId: s.agent_id,
                    washVolume: s.wash_volume,
                    totalVolume: s.total_volume,
                })
                .collect(),
            blockRefs: self
                .block_refs
                .iter()
                .map(|(number, hash)| SolBlockRef {
                    number: *number,
                    blockHash: *hash,
                })
                .collect(),
        }
        .abi_encode()
    }

    pub fn abi_decode(data: &[u8]) -> Result<Self, String> {
        let j = SolWashJournal::abi_decode(data).map_err(|e| format!("journal abi: {e}"))?;
        Ok(WashJournal {
            predicate_id: j.predicateId,
            source_id: j.sourceId,
            chain_id: j.chainId,
            period_start_block: j.periodStartBlock,
            period_end_block: j.periodEndBlock,
            offense_epoch: j.offenseEpoch,
            claim_id: j.claimId,
            subjects: j
                .subjects
                .iter()
                .map(|s| SubjectRecord {
                    subject: s.subject,
                    agent_id: s.agentId,
                    wash_volume: s.washVolume,
                    total_volume: s.totalVolume,
                })
                .collect(),
            block_refs: j
                .blockRefs
                .iter()
                .map(|r| (r.number, r.blockHash))
                .collect(),
        })
    }
}
