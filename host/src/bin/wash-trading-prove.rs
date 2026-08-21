use alloy_consensus::Header;
use alloy_primitives::{address, hex, Address, Bytes, B256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
use anyhow::{bail, Context, Result};
use enforcement_core::{
    EnforcementBlock, LogRef, ReciprocalInput, SettlementEvidence, BASE_CHAIN_ID, CHANNELS_ADDRESS,
    PERIOD_START_BLOCK,
};
use loop_core::{ReceiptProof, CHANNEL_SETTLED_TOPIC};
use risc0_zkvm::sha::{Digest as Risc0Digest, Digestible};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WitnessPackage {
    version: u32,
    kind: String,
    enforceable: bool,
    #[serde(flatten)]
    proof: ProofInput,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "proofType", content = "input")]
enum ProofInput {
    #[serde(rename = "P0_CLOSED_LOOP")]
    ClosedCycle(enforcement_core::ClosedCycleInput),
    #[serde(rename = "P0_RECIPROCAL")]
    Reciprocal(enforcement_core::ReciprocalInput),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofManifest {
    version: u32,
    kind: &'static str,
    chain_id: u64,
    security_mode: &'static str,
    entries: Vec<ProofEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofEntry {
    claim_id: B256,
    claim_type: &'static str,
    subjects: Vec<Address>,
    metrics: serde_json::Value,
    image_id: String,
    journal_bytes: String,
    journal_digest: B256,
    seal: Option<String>,
    user_cycles: Option<u64>,
    total_cycles: Option<u64>,
}

struct GuestExecution {
    journal: Vec<u8>,
    image_id: String,
    seal: Option<String>,
    user_cycles: Option<u64>,
    total_cycles: Option<u64>,
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let args = env::args().skip(1).collect::<Vec<_>>();
    if let Some(output_path) = arg(&args, "--write-sample-reciprocal-witness") {
        return write_sample_reciprocal_witness(output_path);
    }
    let input_path = arg(&args, "--input").context("missing --input <proof-witness.json>")?;
    let output_path = arg(&args, "--output").context("missing --output <proof-result.json>")?;
    let prove = args.iter().any(|value| value == "--prove");
    let production = args.iter().any(|value| value == "--production");
    if production && !prove {
        bail!("--production requires --prove");
    }
    if production && env::var("RISC0_DEV_MODE").ok().as_deref() != Some("0") {
        bail!("production proving requires RISC0_DEV_MODE=0");
    }

    let package: WitnessPackage = serde_json::from_slice(
        &fs::read(&input_path).with_context(|| format!("read {input_path}"))?,
    )
    .with_context(|| format!("decode {input_path}"))?;
    if package.version != 1 || package.kind != "antseed-wash-trading-proof-witness" {
        bail!("expected the current self-contained witness package");
    }
    if !package.enforceable {
        bail!("analysis-only/router-attribution cases cannot be proven or submitted");
    }

    let entry = match package.proof {
        ProofInput::ClosedCycle(input) => {
            let journal =
                enforcement_core::verify_closed_cycle(&input).map_err(anyhow::Error::msg)?;
            let expected = journal.abi_encode();
            let execution = execute_or_prove(
                &input,
                expected,
                closed_cycle_methods::CLOSED_CYCLE_GUEST_ELF,
                closed_cycle_methods::CLOSED_CYCLE_GUEST_ID,
                prove,
            )?;
            entry(
                journal.claim_id,
                "P0_CLOSED_LOOP",
                vec![journal.journal.seller],
                serde_json::json!({
                    "cohortCount": journal.cohort_count,
                    "qualifiedVolumeRaw": journal.qualified_volume_raw.to_string(),
                    "closureKind": journal.closure_kind,
                    "closurePathCount": journal.closure_path_count,
                }),
                execution,
            )
        }
        ProofInput::Reciprocal(input) => {
            let journal =
                enforcement_core::verify_reciprocal(&input).map_err(anyhow::Error::msg)?;
            let expected = journal.abi_encode();
            let execution = execute_or_prove(
                &input,
                expected,
                reciprocal_methods::RECIPROCAL_GUEST_ELF,
                reciprocal_methods::RECIPROCAL_GUEST_ID,
                prove,
            )?;
            entry(
                journal.claim_id,
                "P0_RECIPROCAL",
                vec![journal.journal.address_a, journal.journal.address_b],
                serde_json::json!({
                    "settlementCountAToB": journal.settlement_count_a_to_b,
                    "settlementCountBToA": journal.settlement_count_b_to_a,
                    "volumeAToBRaw": journal.volume_a_to_b_raw.to_string(),
                    "volumeBToARaw": journal.volume_b_to_a_raw.to_string(),
                }),
                execution,
            )
        }
    };

    let manifest = ProofManifest {
        version: 1,
        kind: "antseed-wash-trading-proof-results",
        chain_id: enforcement_core::BASE_CHAIN_ID,
        security_mode: if production {
            "production"
        } else {
            "development"
        },
        entries: vec![entry],
    };
    let output_path = PathBuf::from(output_path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        output_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
    Ok(())
}

fn entry(
    claim_id: B256,
    claim_type: &'static str,
    subjects: Vec<Address>,
    metrics: serde_json::Value,
    execution: GuestExecution,
) -> ProofEntry {
    let journal_digest = B256::from_slice(&Sha256::digest(&execution.journal));
    ProofEntry {
        claim_id,
        claim_type,
        subjects,
        metrics,
        image_id: execution.image_id,
        journal_bytes: format!("0x{}", hex::encode(execution.journal)),
        journal_digest,
        seal: execution.seal,
        user_cycles: execution.user_cycles,
        total_cycles: execution.total_cycles,
    }
}

fn execute_or_prove<T: Serialize>(
    input: &T,
    expected_journal: Vec<u8>,
    elf: &[u8],
    image_id: [u32; 8],
    prove: bool,
) -> Result<GuestExecution> {
    let input_bytes = serde_json::to_vec(input)?;
    let mut builder = risc0_zkvm::ExecutorEnv::builder();
    builder.write_slice(&[u32::try_from(input_bytes.len()).context("guest input too large")?]);
    builder.write_slice(&input_bytes);
    let env = builder.build()?;
    let digest = Risc0Digest::from(image_id);
    if prove {
        let info = risc0_zkvm::default_prover().prove(env, elf)?;
        info.receipt.verify(image_id)?;
        if info.receipt.journal.bytes != expected_journal {
            bail!("guest journal differs from native journal");
        }
        let seal = encode_seal(&info.receipt)?;
        Ok(GuestExecution {
            journal: info.receipt.journal.bytes,
            image_id: digest.to_string(),
            seal: Some(format!("0x{}", hex::encode(seal))),
            user_cycles: Some(info.stats.user_cycles),
            total_cycles: Some(info.stats.total_cycles),
        })
    } else {
        let session = risc0_zkvm::default_executor().execute(env, elf)?;
        if session.journal.bytes != expected_journal {
            bail!("guest journal differs from native journal");
        }
        Ok(GuestExecution {
            journal: session.journal.bytes,
            image_id: digest.to_string(),
            seal: None,
            user_cycles: None,
            total_cycles: None,
        })
    }
}

fn encode_seal(receipt: &risc0_zkvm::Receipt) -> Result<Vec<u8>> {
    let (selector, body): ([u8; 4], Vec<u8>) = match &receipt.inner {
        risc0_zkvm::InnerReceipt::Fake(fake) => {
            ([0xff; 4], fake.claim.digest().as_bytes().to_vec())
        }
        risc0_zkvm::InnerReceipt::Groth16(groth16) => (
            groth16.verifier_parameters.as_bytes()[..4]
                .try_into()
                .unwrap(),
            groth16.seal.to_vec(),
        ),
        _ => bail!("unsupported on-chain receipt type; use a Groth16 production prover"),
    };
    Ok([selector.to_vec(), body].concat())
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|value| value == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn write_sample_reciprocal_witness(output_path: String) -> Result<()> {
    let package = serde_json::json!({
        "version": 1,
        "kind": "antseed-wash-trading-proof-witness",
        "enforceable": true,
        "proofType": "P0_RECIPROCAL",
        "input": sample_reciprocal_input(),
    });
    let output_path = PathBuf::from(output_path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, serde_json::to_vec_pretty(&package)?)?;
    println!(
        "sample reciprocal witness written: {}",
        output_path.display()
    );
    Ok(())
}

fn sample_reciprocal_input() -> ReciprocalInput {
    let address_a = address!("0000000000000000000000000000000000000001");
    let address_b = address!("0000000000000000000000000000000000000002");
    let mut logs = Vec::new();
    let mut settlements = Vec::new();
    for index in 0..100usize {
        let (buyer, seller, amount) = if index < 50 {
            (address_a, address_b, 1_000_000u128)
        } else {
            (address_b, address_a, 800_000u128)
        };
        let mut data = [0u8; 64];
        data[48..].copy_from_slice(&amount.to_be_bytes());
        logs.push(sample_rlp_list(&[
            sample_rlp_bytes(CHANNELS_ADDRESS.as_slice()),
            sample_rlp_list(&[
                sample_rlp_bytes(CHANNEL_SETTLED_TOPIC.as_slice()),
                sample_rlp_bytes(B256::ZERO.as_slice()),
                sample_rlp_bytes(sample_address_topic(buyer).as_slice()),
                sample_rlp_bytes(sample_address_topic(seller).as_slice()),
            ]),
            sample_rlp_bytes(&data),
        ]));
        settlements.push(SettlementEvidence {
            settlement: LogRef {
                block: 0,
                receipt: 0,
                log: index,
            },
        });
    }
    let receipt = Bytes::from(sample_rlp_list(&[
        sample_rlp_uint(1),
        sample_rlp_uint(1),
        sample_rlp_bytes(&[0u8; 256]),
        sample_rlp_list(&logs),
    ]));
    let key = Nibbles::unpack(loop_core::trie_index_key(0));
    let mut builder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![key.clone()]));
    builder.add_leaf(key.clone(), receipt.as_ref());
    let receipts_root = builder.root();
    let proof = builder
        .take_proof_nodes()
        .matching_nodes_sorted(&key)
        .into_iter()
        .map(|(_, node)| node)
        .collect();
    ReciprocalInput {
        chain_id: BASE_CHAIN_ID,
        address_a,
        address_b,
        blocks: vec![EnforcementBlock {
            header: Header {
                number: PERIOD_START_BLOCK,
                timestamp: PERIOD_START_BLOCK,
                receipts_root,
                ..Default::default()
            },
            receipts: vec![ReceiptProof {
                tx_index: 0,
                value: receipt,
                proof,
            }],
            transactions: Vec::new(),
        }],
        settlements,
    }
}

fn sample_address_topic(value: alloy_primitives::Address) -> B256 {
    let mut topic = [0u8; 32];
    topic[12..].copy_from_slice(value.as_slice());
    B256::from(topic)
}

fn sample_rlp_uint(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap();
    sample_rlp_bytes(&bytes[first..])
}

fn sample_rlp_bytes(value: &[u8]) -> Vec<u8> {
    if value.len() == 1 && value[0] < 0x80 {
        return value.to_vec();
    }
    let mut result = sample_rlp_length(0x80, 0xb7, value.len());
    result.extend_from_slice(value);
    result
}

fn sample_rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload = items.concat();
    let mut result = sample_rlp_length(0xc0, 0xf7, payload.len());
    result.extend_from_slice(&payload);
    result
}

fn sample_rlp_length(short_base: u8, long_base: u8, length: usize) -> Vec<u8> {
    if length <= 55 {
        return vec![short_base + length as u8];
    }
    let bytes = length.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap();
    let encoded = &bytes[first..];
    let mut result = vec![long_base + encoded.len() as u8];
    result.extend_from_slice(encoded);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reciprocal_witness_executes_in_the_guest() {
        let input = sample_reciprocal_input();
        let journal = enforcement_core::verify_reciprocal(&input).unwrap();
        let expected = journal.abi_encode();
        let execution = execute_or_prove(
            &input,
            expected.clone(),
            reciprocal_methods::RECIPROCAL_GUEST_ELF,
            reciprocal_methods::RECIPROCAL_GUEST_ID,
            false,
        )
        .unwrap();
        assert_eq!(execution.journal, expected);
        assert!(execution.seal.is_none());
    }
}
