use alloy_consensus::Header;
use alloy_primitives::{address, hex, Address, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
use anyhow::{bail, Context, Result};
use enforcement_core::{
    EnforcementBlock, LogRef, ReciprocalInput, SettlementEvidence, BASE_CHAIN_ID, CHANNELS_ADDRESS,
    PERIOD_START_BLOCK,
};
use loop_core::{ReceiptProof, CHANNEL_SETTLED_TOPIC};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{NetworkProver, ProveRequest, Prover, ProverClient},
    network::proto::GetProofRequestParamsResponse,
    Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofMode, SP1Stdin,
};
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
    #[serde(rename = "programVKey")]
    program_vkey: String,
    journal_bytes: String,
    journal_digest: B256,
    proof_bytes: Option<String>,
    instruction_count: Option<u64>,
    prover_gas_units: Option<u64>,
}

struct GuestExecution {
    journal: Vec<u8>,
    program_vkey: String,
    proof_bytes: Option<String>,
    instruction_count: Option<u64>,
    prover_gas_units: Option<u64>,
}

#[derive(Clone, Copy)]
struct NetworkProofCaps {
    max_base_fee: u64,
    max_price_per_pgu: u64,
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let args = env::args().skip(1).collect::<Vec<_>>();
    if let Some(output_path) = arg(&args, "--program-metadata") {
        return write_program_metadata(output_path);
    }
    if let Some(output_path) = arg(&args, "--write-sample-reciprocal-witness") {
        return write_sample_reciprocal_witness(output_path);
    }
    if let Some(output_path) = arg(&args, "--write-market-sized-reciprocal-witness") {
        return write_market_sized_reciprocal_witness(output_path);
    }
    let input_path = arg(&args, "--input").context("missing --input <proof-witness.json>")?;
    let output_path = arg(&args, "--output").context("missing --output <proof-result.json>")?;
    let prove = args.iter().any(|value| value == "--prove");
    let production = args.iter().any(|value| value == "--production");
    if production && !prove {
        bail!("--production requires --prove");
    }
    if production
        && matches!(
            env::var("SP1_PROVER").ok().as_deref(),
            Some("mock" | "light")
        )
    {
        bail!("production proving requires SP1_PROVER=cpu, cuda, or network");
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
                closed_cycle_methods::CLOSED_CYCLE_GUEST_ELF.clone(),
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
                reciprocal_methods::RECIPROCAL_GUEST_ELF.clone(),
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
        version: 2,
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

fn write_program_metadata(output_path: String) -> Result<()> {
    let client = ProverClient::builder().cpu().build();
    let closed_key = client.setup(closed_cycle_methods::CLOSED_CYCLE_GUEST_ELF.clone())?;
    let reciprocal_key = client.setup(reciprocal_methods::RECIPROCAL_GUEST_ELF.clone())?;
    let metadata = serde_json::json!({
        "version": 1,
        "kind": "antseed-sp1-program-metadata",
        "sp1Version": "6.1.0",
        "programs": {
            "closedCycle": program_metadata(
                &closed_cycle_methods::CLOSED_CYCLE_GUEST_ELF,
                closed_key.verifying_key().bytes32(),
            ),
            "reciprocal": program_metadata(
                &reciprocal_methods::RECIPROCAL_GUEST_ELF,
                reciprocal_key.verifying_key().bytes32(),
            ),
        },
    });
    fs::write(
        output_path,
        format!("{}\n", serde_json::to_string_pretty(&metadata)?),
    )?;
    Ok(())
}

fn program_metadata(elf: &Elf, program_vkey: String) -> serde_json::Value {
    let bytes = match elf {
        Elf::Static(bytes) => *bytes,
        Elf::Dynamic(bytes) => bytes.as_ref(),
    };
    serde_json::json!({
        "programVKey": program_vkey,
        "elfSha256": format!("0x{:x}", Sha256::digest(bytes)),
        "elfBytes": bytes.len(),
    })
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
        program_vkey: execution.program_vkey,
        journal_bytes: format!("0x{}", hex::encode(execution.journal)),
        journal_digest,
        proof_bytes: execution.proof_bytes,
        instruction_count: execution.instruction_count,
        prover_gas_units: execution.prover_gas_units,
    }
}

fn execute_or_prove<T: Serialize>(
    input: &T,
    expected_journal: Vec<u8>,
    elf: Elf,
    prove: bool,
) -> Result<GuestExecution> {
    let input_bytes = serde_json::to_vec(input)?;
    u32::try_from(input_bytes.len()).context("guest input too large")?;
    if prove && env::var("SP1_PROVER").ok().as_deref() == Some("network") {
        return prove_on_network(input_bytes, expected_journal, elf);
    }
    let client = ProverClient::from_env();
    let proving_key = client.setup(elf.clone())?;
    let program_vkey = proving_key.verifying_key().bytes32();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_bytes);
    if prove {
        let proof = client.prove(&proving_key, stdin).groth16().run()?;
        client.verify(&proof, proving_key.verifying_key(), None)?;
        if !matches!(proof.proof, SP1Proof::Groth16(_)) {
            bail!("production proof is not SP1 Groth16");
        }
        if proof.public_values.as_slice() != expected_journal {
            bail!("guest journal differs from native journal");
        }
        Ok(GuestExecution {
            journal: proof.public_values.to_vec(),
            program_vkey,
            proof_bytes: Some(format!("0x{}", hex::encode(proof.bytes()))),
            instruction_count: None,
            prover_gas_units: None,
        })
    } else {
        let (public_values, report) = client.execute(elf, stdin).run()?;
        if public_values.as_slice() != expected_journal {
            bail!("guest journal differs from native journal");
        }
        Ok(GuestExecution {
            journal: public_values.to_vec(),
            program_vkey,
            proof_bytes: None,
            instruction_count: Some(report.total_instruction_count()),
            prover_gas_units: report.gas(),
        })
    }
}

fn prove_on_network(
    input_bytes: Vec<u8>,
    expected_journal: Vec<u8>,
    elf: Elf,
) -> Result<GuestExecution> {
    let client = ProverClient::builder().network().build();
    let caps = network_proof_caps(&client, SP1ProofMode::Groth16)?;
    let proving_key = client.setup(elf)?;
    let program_vkey = proving_key.verifying_key().bytes32();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_bytes);
    let proof = client
        .prove(&proving_key, stdin)
        .groth16()
        .max_price_per_pgu(caps.max_price_per_pgu)
        .run()?;
    client.verify(&proof, proving_key.verifying_key(), None)?;
    if !matches!(proof.proof, SP1Proof::Groth16(_)) {
        bail!("production proof is not SP1 Groth16");
    }
    if proof.public_values.as_slice() != expected_journal {
        bail!("guest journal differs from native journal");
    }
    Ok(GuestExecution {
        journal: proof.public_values.to_vec(),
        program_vkey,
        proof_bytes: Some(format!("0x{}", hex::encode(proof.bytes()))),
        instruction_count: None,
        prover_gas_units: None,
    })
}

fn network_proof_caps(client: &NetworkProver, mode: SP1ProofMode) -> Result<NetworkProofCaps> {
    let caps = NetworkProofCaps {
        max_base_fee: required_base_fee_cap(&mode)?,
        max_price_per_pgu: required_u64_env("SP1_NETWORK_MAX_PRICE_PER_PGU_PROVE_WEI")?,
    };
    let GetProofRequestParamsResponse::Auction(params) = client
        .get_proof_request_params(mode)
        .context("read live SP1 auction parameters")?
    else {
        bail!("SP1 network did not return auction parameters");
    };
    let base_fee = parse_network_u64("base fee", &params.base_fee)?;
    let max_price_per_pgu = parse_network_u64("maximum price per PGU", &params.max_price_per_pgu)?;
    if base_fee > caps.max_base_fee {
        bail!(
            "live SP1 base fee {} exceeds approved cap {}",
            base_fee,
            caps.max_base_fee
        );
    }
    if max_price_per_pgu > caps.max_price_per_pgu {
        bail!(
            "live SP1 max price per PGU {} exceeds approved cap {}",
            max_price_per_pgu,
            caps.max_price_per_pgu
        );
    }
    let balance = client.get_balance().context("read SP1 network balance")?;
    if balance < U256::from(base_fee) {
        bail!(
            "SP1 balance {} is below the live base fee {}",
            balance,
            base_fee
        );
    }
    Ok(caps)
}

fn parse_network_u64(label: &str, value: &str) -> Result<u64> {
    value
        .parse()
        .with_context(|| format!("SP1 network returned an invalid {label}"))
}

fn required_base_fee_cap(mode: &SP1ProofMode) -> Result<u64> {
    match mode {
        SP1ProofMode::Compressed => {
            required_u64_env("SP1_NETWORK_MAX_COMPRESSED_BASE_FEE_PROVE_WEI")
        }
        SP1ProofMode::Groth16 => required_u64_env("SP1_NETWORK_MAX_GROTH16_BASE_FEE_PROVE_WEI"),
        _ => bail!("unsupported SP1 network proof mode for this host"),
    }
}

fn required_u64_env(name: &str) -> Result<u64> {
    env::var(name)
        .with_context(|| format!("{name} is required for SP1 network proving"))?
        .parse()
        .with_context(|| format!("{name} must be an unsigned decimal integer"))
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

fn write_market_sized_reciprocal_witness(output_path: String) -> Result<()> {
    let package = serde_json::json!({
        "version": 1,
        "kind": "antseed-wash-trading-proof-witness",
        "enforceable": true,
        "proofType": "P0_RECIPROCAL",
        "input": market_sized_reciprocal_input(),
    });
    let output_path = PathBuf::from(output_path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, serde_json::to_vec_pretty(&package)?)?;
    println!(
        "market-sized reciprocal witness written: {}",
        output_path.display()
    );
    Ok(())
}

fn market_sized_reciprocal_input() -> ReciprocalInput {
    let address_a = address!("0000000000000000000000000000000000000001");
    let address_b = address!("0000000000000000000000000000000000000002");
    let mut blocks = Vec::with_capacity(100);
    let mut settlements = Vec::with_capacity(100);
    for index in 0..100usize {
        let (buyer, seller, amount) = if index < 50 {
            (address_a, address_b, 1_000_000u128)
        } else {
            (address_b, address_a, 800_000u128)
        };
        let mut data = [0u8; 64];
        data[48..].copy_from_slice(&amount.to_be_bytes());
        let log = sample_rlp_list(&[
            sample_rlp_bytes(CHANNELS_ADDRESS.as_slice()),
            sample_rlp_list(&[
                sample_rlp_bytes(CHANNEL_SETTLED_TOPIC.as_slice()),
                sample_rlp_bytes(B256::ZERO.as_slice()),
                sample_rlp_bytes(sample_address_topic(buyer).as_slice()),
                sample_rlp_bytes(sample_address_topic(seller).as_slice()),
            ]),
            sample_rlp_bytes(&data),
        ]);
        let receipt = Bytes::from(sample_rlp_list(&[
            sample_rlp_uint(1),
            sample_rlp_uint(1),
            sample_rlp_bytes(&[0u8; 256]),
            sample_rlp_list(&[log]),
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
        blocks.push(EnforcementBlock {
            header: Header {
                number: PERIOD_START_BLOCK + index as u64,
                timestamp: PERIOD_START_BLOCK + index as u64,
                receipts_root,
                ..Default::default()
            },
            receipts: vec![ReceiptProof {
                tx_index: 0,
                value: receipt,
                proof,
            }],
            transactions: Vec::new(),
        });
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
            reciprocal_methods::RECIPROCAL_GUEST_ELF.clone(),
            false,
        )
        .unwrap();
        assert_eq!(execution.journal, expected);
        assert!(execution.proof_bytes.is_none());
        assert!(execution.prover_gas_units.is_some());
    }

    #[test]
    fn proof_artifact_preserves_vkey_acronym() {
        let artifact = ProofManifest {
            version: 2,
            kind: "antseed-wash-trading-proof-results",
            chain_id: BASE_CHAIN_ID,
            security_mode: "development",
            entries: vec![ProofEntry {
                claim_id: B256::ZERO,
                claim_type: "P0_RECIPROCAL",
                subjects: Vec::new(),
                metrics: serde_json::Value::Null,
                program_vkey: format!("0x{}", "00".repeat(32)),
                journal_bytes: "0x".into(),
                journal_digest: B256::ZERO,
                proof_bytes: None,
                instruction_count: Some(1),
                prover_gas_units: Some(1),
            }],
        };
        let value = serde_json::to_value(artifact).unwrap();
        assert!(value["entries"][0].get("programVKey").is_some());
        assert!(value["entries"][0].get("programVkey").is_none());
    }
}
