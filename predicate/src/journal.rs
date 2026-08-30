//! The public child-proof journal.

use alloy_primitives::{Address, B256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectRecord {
    pub subject: Address,
    pub wash_volume: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WashJournal {
    pub predicate_id: u8,
    pub chain_id: u64,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub source_claim_id: B256,
    pub claim_id: B256,
    pub subjects: Vec<SubjectRecord>,
    pub block_refs: Vec<(u64, B256)>,
}

alloy_sol_types::sol! {
    struct SolBlockRef {
        uint64 number;
        bytes32 blockHash;
    }

    struct SolSubjectRecord {
        address subject;
        uint128 washVolume;
    }

    struct SolWashJournal {
        uint8 predicateId;
        uint64 chainId;
        uint64 periodStartBlock;
        uint64 periodEndBlock;
        bytes32 sourceClaimId;
        bytes32 claimId;
        SolSubjectRecord[] subjects;
        SolBlockRef[] blockRefs;
    }
}

impl WashJournal {
    pub fn abi_encode(&self) -> Vec<u8> {
        SolWashJournal {
            predicateId: self.predicate_id,
            chainId: self.chain_id,
            periodStartBlock: self.period_start_block,
            periodEndBlock: self.period_end_block,
            sourceClaimId: self.source_claim_id,
            claimId: self.claim_id,
            subjects: self
                .subjects
                .iter()
                .map(|subject| SolSubjectRecord {
                    subject: subject.subject,
                    washVolume: subject.wash_volume,
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
        let journal =
            SolWashJournal::abi_decode(data).map_err(|error| format!("journal abi: {error}"))?;
        Ok(Self {
            predicate_id: journal.predicateId,
            chain_id: journal.chainId,
            period_start_block: journal.periodStartBlock,
            period_end_block: journal.periodEndBlock,
            source_claim_id: journal.sourceClaimId,
            claim_id: journal.claimId,
            subjects: journal
                .subjects
                .into_iter()
                .map(|subject| SubjectRecord {
                    subject: subject.subject,
                    wash_volume: subject.washVolume,
                })
                .collect(),
            block_refs: journal
                .blockRefs
                .into_iter()
                .map(|reference| (reference.number, reference.blockHash))
                .collect(),
        })
    }
}
