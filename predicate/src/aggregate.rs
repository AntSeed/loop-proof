use crate::{WashJournal, BASE_CHAIN_ID, CLOSED_LOOP_PREDICATE_ID, RECIPROCAL_PREDICATE_ID};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
pub struct HistoricalManifest {
    pub report_root: B256,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub closed_loop_program_vkey: B256,
    pub reciprocal_program_vkey: B256,
    pub claims: Vec<HistoricalManifestClaim>,
    pub block_refs: Vec<HistoricalBlockRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalBlockRef {
    pub number: u64,
    pub block_hash: B256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalManifestClaim {
    pub source_claim_id: B256,
    pub predicate_id: u8,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub subjects: Vec<HistoricalManifestSubject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalManifestSubject {
    pub seller: Address,
    #[serde(with = "decimal_u128")]
    pub proven_wash_volume: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellerResult {
    pub seller: Address,
    pub proven_wash_volume: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateJournal {
    pub schema_version: u32,
    pub chain_id: u64,
    pub report_root: B256,
    pub manifest_digest: B256,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub source_claim_count: u32,
    pub sellers: Vec<SellerResult>,
    pub total_proven_wash_volume: u128,
    pub block_reference_count: u32,
}

alloy_sol_types::sol! {
    struct SolSellerResult {
        address seller;
        uint128 provenWashVolume;
    }

    struct SolAggregateJournal {
        uint32 schemaVersion;
        uint64 chainId;
        bytes32 reportRoot;
        bytes32 manifestDigest;
        uint64 periodStartBlock;
        uint64 periodEndBlock;
        uint32 sourceClaimCount;
        SolSellerResult[] sellers;
        uint128 totalProvenWashVolume;
        uint32 blockReferenceCount;
    }
}

impl HistoricalManifest {
    pub fn digest(&self) -> Result<B256, String> {
        serde_json::to_vec(self)
            .map(keccak256)
            .map_err(|error| format!("aggregate: encode manifest: {error}"))
    }
}

impl AggregateJournal {
    pub fn from_children(
        children: &[ChildProofInput],
        manifest: &HistoricalManifest,
    ) -> Result<Self, String> {
        if children.is_empty() || children.len() != manifest.claims.len() {
            return Err("aggregate: incomplete historical claim set".into());
        }
        validate_manifest(manifest)?;
        let expected_claims = manifest
            .claims
            .iter()
            .map(|claim| (claim.source_claim_id, claim))
            .collect::<BTreeMap<_, _>>();
        let mut observed_claims = BTreeSet::new();
        let mut sellers = BTreeMap::new();
        let mut block_refs = BTreeMap::new();
        let mut total_proven_wash_volume = 0u128;

        for child in children {
            let journal = WashJournal::abi_decode(&child.public_values)?;
            let expected_vkey = match journal.predicate_id {
                CLOSED_LOOP_PREDICATE_ID if child.program_id == CLOSED_LOOP_PROGRAM_ID => {
                    manifest.closed_loop_program_vkey
                }
                RECIPROCAL_PREDICATE_ID if child.program_id == RECIPROCAL_PROGRAM_ID => {
                    manifest.reciprocal_program_vkey
                }
                _ => return Err("aggregate: wrong child program".into()),
            };
            if child.program_vkey != expected_vkey
                || vkey_bytes32(child.vkey_digest) != child.program_vkey
            {
                return Err("aggregate: wrong child program vkey".into());
            }
            if journal.chain_id != BASE_CHAIN_ID {
                return Err("aggregate: wrong child chain".into());
            }
            if !observed_claims.insert(journal.source_claim_id) {
                return Err("aggregate: duplicate source claim".into());
            }
            let expected = expected_claims
                .get(&journal.source_claim_id)
                .ok_or("aggregate: unexpected source claim")?;
            if expected.predicate_id != journal.predicate_id
                || expected.period_start_block != journal.period_start_block
                || expected.period_end_block != journal.period_end_block
                || expected.subjects.len() != journal.subjects.len()
            {
                return Err("aggregate: source claim shape mismatch".into());
            }
            let expected_subjects = expected
                .subjects
                .iter()
                .map(|subject| (subject.seller, subject.proven_wash_volume))
                .collect::<BTreeMap<_, _>>();
            let mut observed_subjects = BTreeSet::new();
            for subject in &journal.subjects {
                if subject.subject == Address::ZERO
                    || subject.wash_volume == 0
                    || expected_subjects.get(&subject.subject) != Some(&subject.wash_volume)
                    || !observed_subjects.insert(subject.subject)
                    || sellers
                        .insert(subject.subject, subject.wash_volume)
                        .is_some()
                {
                    return Err("aggregate: source claim results mismatch".into());
                }
                total_proven_wash_volume = total_proven_wash_volume
                    .checked_add(subject.wash_volume)
                    .ok_or("aggregate: volume overflow")?;
            }
            for (number, hash) in &journal.block_refs {
                if let Some(existing) = block_refs.insert(*number, *hash) {
                    if existing != *hash {
                        return Err("aggregate: conflicting block hash".into());
                    }
                }
            }
        }
        if observed_claims.len() != expected_claims.len() {
            return Err("aggregate: incomplete historical claim set".into());
        }
        let observed_refs = block_refs
            .iter()
            .map(|(number, block_hash)| HistoricalBlockRef {
                number: *number,
                block_hash: *block_hash,
            })
            .collect::<Vec<_>>();
        if observed_refs != manifest.block_refs {
            return Err("aggregate: canonical block references mismatch".into());
        }

        Ok(Self {
            schema_version: AGGREGATE_SCHEMA_VERSION,
            chain_id: BASE_CHAIN_ID,
            report_root: manifest.report_root,
            manifest_digest: manifest.digest()?,
            period_start_block: manifest.period_start_block,
            period_end_block: manifest.period_end_block,
            source_claim_count: children
                .len()
                .try_into()
                .map_err(|_| "aggregate: too many source claims")?,
            sellers: sellers
                .into_iter()
                .map(|(seller, proven_wash_volume)| SellerResult {
                    seller,
                    proven_wash_volume,
                })
                .collect(),
            total_proven_wash_volume,
            block_reference_count: block_refs
                .len()
                .try_into()
                .map_err(|_| "aggregate: too many block references")?,
        })
    }

    pub fn abi_encode(&self) -> Vec<u8> {
        SolAggregateJournal {
            schemaVersion: self.schema_version,
            chainId: self.chain_id,
            reportRoot: self.report_root,
            manifestDigest: self.manifest_digest,
            periodStartBlock: self.period_start_block,
            periodEndBlock: self.period_end_block,
            sourceClaimCount: self.source_claim_count,
            sellers: self
                .sellers
                .iter()
                .map(|result| SolSellerResult {
                    seller: result.seller,
                    provenWashVolume: result.proven_wash_volume,
                })
                .collect(),
            totalProvenWashVolume: self.total_proven_wash_volume,
            blockReferenceCount: self.block_reference_count,
        }
        .abi_encode()
    }

    pub fn committed_public_values(
        &self,
        _manifest: &HistoricalManifest,
    ) -> Result<Vec<u8>, String> {
        Ok(self.abi_encode())
    }
}

fn validate_manifest(manifest: &HistoricalManifest) -> Result<(), String> {
    if manifest.report_root == B256::ZERO
        || manifest.period_start_block == 0
        || manifest.period_start_block > manifest.period_end_block
        || manifest.closed_loop_program_vkey == B256::ZERO
        || manifest.reciprocal_program_vkey == B256::ZERO
        || manifest.claims.is_empty()
        || manifest.block_refs.is_empty()
        || manifest
            .block_refs
            .iter()
            .any(|reference| reference.block_hash == B256::ZERO)
        || manifest
            .block_refs
            .windows(2)
            .any(|pair| pair[0].number >= pair[1].number)
    {
        return Err("aggregate: invalid historical manifest".into());
    }
    let mut claims = BTreeSet::new();
    let mut sellers = BTreeSet::new();
    for claim in &manifest.claims {
        if claim.source_claim_id == B256::ZERO
            || !matches!(
                claim.predicate_id,
                CLOSED_LOOP_PREDICATE_ID | RECIPROCAL_PREDICATE_ID
            )
            || claim.period_start_block < manifest.period_start_block
            || claim.period_end_block > manifest.period_end_block
            || claim.period_start_block > claim.period_end_block
            || claim.subjects.is_empty()
            || !claims.insert(claim.source_claim_id)
        {
            return Err("aggregate: invalid manifest claim".into());
        }
        for subject in &claim.subjects {
            if subject.seller == Address::ZERO
                || subject.proven_wash_volume == 0
                || !sellers.insert(subject.seller)
            {
                return Err("aggregate: invalid manifest subject".into());
            }
        }
    }
    Ok(())
}

pub fn vkey_bytes32(words: [u32; 8]) -> B256 {
    let value = words
        .into_iter()
        .fold(U256::ZERO, |packed, word| (packed << 31) + U256::from(word));
    B256::from(value.to_be_bytes::<32>())
}

mod decimal_u128 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
