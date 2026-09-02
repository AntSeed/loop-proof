//! The public child-proof journal.

use alloy_primitives::{keccak256, Address, B256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub settlement_id: B256,
    pub amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectRecord {
    pub subject: Address,
    pub wash_volume: u128,
    pub settlements: Vec<SettlementRecord>,
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
        SolSettlementRecord[] settlements;
    }

    struct SolSettlementRecord {
        bytes32 settlementId;
        uint128 amount;
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
                    settlements: subject
                        .settlements
                        .iter()
                        .map(|settlement| SolSettlementRecord {
                            settlementId: settlement.settlement_id,
                            amount: settlement.amount,
                        })
                        .collect(),
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
                    settlements: subject
                        .settlements
                        .into_iter()
                        .map(|settlement| SettlementRecord {
                            settlement_id: settlement.settlementId,
                            amount: settlement.amount,
                        })
                        .collect(),
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

pub fn settlement_id(
    chain_id: u64,
    block_number: u64,
    transaction_index: u64,
    log_index: usize,
) -> B256 {
    keccak256((chain_id, block_number, transaction_index, log_index as u64).abi_encode())
}
