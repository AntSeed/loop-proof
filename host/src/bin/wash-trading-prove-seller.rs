use alloy_primitives::{hex, Address, B256};
use anyhow::{bail, Context, Result};
#[path = "../proving.rs"]
mod proving;
use proving::ProofClient;
use serde_json::json;
use sha2::{Digest, Sha256};
use sp1_sdk::blocking::{Prover, ProverClient};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Stdin};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};
use wash_predicate::seller::block_authentication_chunks;
use wash_predicate::{
    verify_seller, ClosedLoopInput, ReciprocalInput, SellerClaimInput, SellerProofInput,
};

const ARTIFACT_VERSION: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    WitnessOnly,
    ExecuteOnly,
    Development,
    Production,
}

struct ClaimSpec {
    kind: String,
    witness: PathBuf,
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mode = parse_mode(&args)?;
    let seller: Address = required(&args, "--seller")?
        .parse()
        .context("invalid --seller address")?;
    let output = PathBuf::from(required(&args, "--output")?);
    let seller_witness = optional(&args, "--seller-witness").map(PathBuf::from);
    let claim_specs = values(&args, "--claim")
        .into_iter()
        .map(parse_claim)
        .collect::<Result<Vec<_>>>()?;
    if claim_specs.is_empty() {
        bail!("at least one --claim kind:witness.json is required");
    }

    let mut claims = Vec::with_capacity(claim_specs.len());
    let mut source_claim_ids = Vec::with_capacity(claim_specs.len());
    let mut period = None;
    for claim in &claim_specs {
        let bytes = fs::read(&claim.witness)
            .with_context(|| format!("read {}", claim.witness.display()))?;
        let (input, claim_period, source_claim_id) = match claim.kind.as_str() {
            "closed-loop" => {
                let input: ClosedLoopInput = serde_json::from_slice(&bytes)
                    .with_context(|| format!("decode {}", claim.witness.display()))?;
                let claim_period = (input.period_start_block, input.period_end_block);
                let source_claim_id = input.source_claim_id;
                (
                    SellerClaimInput::ClosedLoop(input),
                    claim_period,
                    source_claim_id,
                )
            }
            "reciprocal" => {
                let input: ReciprocalInput = serde_json::from_slice(&bytes)
                    .with_context(|| format!("decode {}", claim.witness.display()))?;
                let claim_period = (input.period_start_block, input.period_end_block);
                let source_claim_id = input.source_claim_id;
                (
                    SellerClaimInput::Reciprocal(input),
                    claim_period,
                    source_claim_id,
                )
            }
            kind => bail!("unsupported claim kind {kind}"),
        };
        if period
            .replace(claim_period)
            .is_some_and(|existing| existing != claim_period)
        {
            bail!("all claim witnesses must use one identical period");
        }
        claims.push(input);
        source_claim_ids.push(source_claim_id);
    }
    source_claim_ids.sort();

    let (period_start_block, period_end_block) = period.expect("claims are not empty");
    let seller_input = SellerProofInput {
        seller,
        period_start_block,
        period_end_block,
        claims,
    };
    let native_start = Instant::now();
    let verified = verify_seller(&seller_input).map_err(anyhow::Error::msg)?;
    let native_duration = native_start.elapsed();
    let expected_public_values = verified.journal.abi_encode();
    let seller_input_bytes = serde_json::to_vec(&seller_input)?;
    if let Some(path) = seller_witness.as_deref() {
        write_atomic(path, &seller_input_bytes)?;
    }
    let chunks = block_authentication_chunks(&verified.block_refs).map_err(anyhow::Error::msg)?;

    if mode == Mode::WitnessOnly {
        let result = json!({
            "version": 1,
            "kind": "antseed-wash-trading-seller-witness",
            "proofArchitecture": "direct-seller-v1",
            "securityMode": "development",
            "proverNetworkSubmitted": false,
            "seller": seller,
            "periodStartBlock": period_start_block,
            "periodEndBlock": period_end_block,
            "claimCount": source_claim_ids.len(),
            "sourceClaimIds": source_claim_ids,
            "provenWashVolumeRaw": verified.journal.proven_wash_volume.to_string(),
            "evidenceDigest": verified.journal.evidence_digest,
            "blockReferenceCount": verified.journal.block_reference_count,
            "blockAuthenticationChunkSize": verified.journal.block_authentication_chunk_size,
            "blockAuthenticationChunkCount": verified.journal.block_authentication_chunk_count,
            "blockAuthenticationRoot": verified.journal.block_authentication_root,
            "publicValues": format!("0x{}", hex::encode(&expected_public_values)),
            "serializedInputBytes": seller_input_bytes.len(),
            "nativeVerificationMillis": native_duration.as_millis(),
            "sellerWitness": seller_witness,
            "verified": true,
        });
        write_json(&output, &result)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    let seller_elf_path = PathBuf::from(required(&args, "--seller-elf")?);
    let elf_bytes = fs::read(&seller_elf_path)
        .with_context(|| format!("read {}", seller_elf_path.display()))?;
    let elf = Elf::Dynamic(elf_bytes.into());
    let light = ProverClient::builder().light().build();
    let key = light.setup(elf.clone())?;
    let seller_program_vkey: B256 = key.verifying_key().bytes32().parse()?;
    let mut execution_stdin = SP1Stdin::new();
    execution_stdin.write(&seller_input_bytes);
    let execution_start = Instant::now();
    let (executed_public_values, report) = light
        .execute(elf.clone(), execution_stdin)
        .deferred_proof_verification(false)
        .run()?;
    let execution_duration = execution_start.elapsed();
    if executed_public_values.as_slice() != expected_public_values {
        bail!("seller guest public values differ from native verification");
    }
    let instruction_count = report.total_instruction_count();

    if mode == Mode::ExecuteOnly {
        let result = proof_artifact(
            &verified,
            &source_claim_ids,
            seller_program_vkey,
            None,
            &expected_public_values,
            &[],
            &chunks,
            seller_input_bytes.len(),
            native_duration.as_millis(),
            execution_duration.as_millis(),
            instruction_count,
            "development",
            false,
        );
        write_json(&output, &result)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    let mut proving_stdin = SP1Stdin::new();
    proving_stdin.write(&seller_input_bytes);
    let (proof, request_id, security_mode) = match mode {
        Mode::Development => {
            let client = ProofClient::from_args(true, &args)?;
            let proving_key = client.setup(elf)?;
            if proving_key.verifying_key().bytes32() != key.verifying_key().bytes32() {
                bail!("SP1 setup returned inconsistent seller vkeys");
            }
            let proof = client.prove_groth16(&proving_key, proving_stdin)?;
            client.verify(&proof, &proving_key)?;
            (proof, None, "development")
        }
        Mode::Production => {
            if !args.iter().any(|value| value == "--confirm-production") {
                bail!("production proving requires --confirm-production");
            }
            let checkpoint_path = PathBuf::from(required(&args, "--request-checkpoint")?);
            let client = ProofClient::from_args(false, &args)?;
            let proving_key = client.setup(elf)?;
            if proving_key.verifying_key().bytes32() != key.verifying_key().bytes32() {
                bail!("SP1 setup returned inconsistent seller vkeys");
            }
            let request_id = if checkpoint_path.exists() {
                load_request_checkpoint(
                    &checkpoint_path,
                    seller,
                    seller_program_vkey,
                    &expected_public_values,
                )?
            } else {
                let request_id = client.request_groth16(&proving_key, proving_stdin)?;
                write_request_checkpoint(
                    &checkpoint_path,
                    seller,
                    seller_program_vkey,
                    request_id,
                    &expected_public_values,
                )?;
                request_id
            };
            let proof = client.wait_proof(request_id)?;
            client.verify(&proof, &proving_key)?;
            (proof, Some(request_id), "production")
        }
        Mode::WitnessOnly | Mode::ExecuteOnly => unreachable!(),
    };
    if proof.public_values.as_slice() != expected_public_values {
        bail!("seller proof public values differ from native verification");
    }
    let serialized_proof = proof.bytes();
    let proof_bytes = if serialized_proof.is_empty() && mode == Mode::Development {
        let mut hasher = Sha256::new();
        hasher.update(b"antseed-wash-trading-development-direct-seller-proof-v1");
        hasher.update(seller_program_vkey.as_slice());
        hasher.update(&expected_public_values);
        hasher.finalize().to_vec()
    } else {
        serialized_proof
    };
    if proof_bytes.is_empty() {
        bail!("seller prover returned an empty Groth16 proof");
    }
    let result = proof_artifact(
        &verified,
        &source_claim_ids,
        seller_program_vkey,
        request_id,
        &expected_public_values,
        &proof_bytes,
        &chunks,
        seller_input_bytes.len(),
        native_duration.as_millis(),
        execution_duration.as_millis(),
        instruction_count,
        security_mode,
        true,
    );
    write_json(&output, &result)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn proof_artifact(
    verified: &wash_predicate::VerifiedSeller,
    source_claim_ids: &[B256],
    seller_program_vkey: B256,
    request_id: Option<B256>,
    public_values: &[u8],
    proof_bytes: &[u8],
    chunks: &[wash_predicate::seller::BlockAuthenticationChunk],
    serialized_input_bytes: usize,
    native_verification_millis: u128,
    execution_millis: u128,
    instruction_count: u64,
    security_mode: &str,
    proved: bool,
) -> serde_json::Value {
    json!({
        "version": ARTIFACT_VERSION,
        "kind": "antseed-wash-trading-seller-proof",
        "proofArchitecture": "direct-seller-v1",
        "securityMode": security_mode,
        "proverNetworkSubmitted": security_mode == "production",
        "schemaVersion": verified.journal.schema_version,
        "seller": verified.journal.seller,
        "sellerProgramVKey": seller_program_vkey,
        "chainId": verified.journal.chain_id,
        "periodStartBlock": verified.journal.period_start_block,
        "periodEndBlock": verified.journal.period_end_block,
        "claimCount": source_claim_ids.len(),
        "sourceClaimIds": source_claim_ids,
        "provenWashVolumeRaw": verified.journal.proven_wash_volume.to_string(),
        "evidenceDigest": verified.journal.evidence_digest,
        "blockReferenceCount": verified.journal.block_reference_count,
        "blockAuthenticationChunkSize": verified.journal.block_authentication_chunk_size,
        "blockAuthenticationChunkCount": verified.journal.block_authentication_chunk_count,
        "blockAuthenticationRoot": verified.journal.block_authentication_root,
        "blockAuthenticationChunks": chunks.iter().map(|chunk| json!({
            "index": chunk.index,
            "references": chunk.references.iter().map(|reference| json!({
                "number": reference.number,
                "blockHash": reference.block_hash,
            })).collect::<Vec<_>>(),
            "proof": chunk.proof,
        })).collect::<Vec<_>>(),
        "publicValues": format!("0x{}", hex::encode(public_values)),
        "proofBytes": format!("0x{}", hex::encode(proof_bytes)),
        "requestId": request_id.map(|value| format!("{value}")),
        "serializedInputBytes": serialized_input_bytes,
        "nativeVerificationMillis": native_verification_millis,
        "executionMillis": execution_millis,
        "instructionCount": instruction_count,
        "proved": proved,
        "verified": true,
    })
}

fn parse_mode(args: &[String]) -> Result<Mode> {
    let modes = [
        ("--witness-only", Mode::WitnessOnly),
        ("--execute-only", Mode::ExecuteOnly),
        ("--development", Mode::Development),
        ("--production", Mode::Production),
    ]
    .into_iter()
    .filter(|(flag, _)| args.iter().any(|value| value == flag))
    .map(|(_, mode)| mode)
    .collect::<Vec<_>>();
    match modes.as_slice() {
        [mode] => Ok(*mode),
        [] => bail!(
            "select exactly one of --witness-only, --execute-only, --development, --production"
        ),
        _ => bail!("proof modes are mutually exclusive"),
    }
}

fn parse_claim(value: String) -> Result<ClaimSpec> {
    let (kind, witness) = value.split_once(':').context("--claim must be kind:path")?;
    Ok(ClaimSpec {
        kind: kind.to_owned(),
        witness: PathBuf::from(witness),
    })
}

fn load_request_checkpoint(
    path: &Path,
    seller: Address,
    seller_program_vkey: B256,
    expected_public_values: &[u8],
) -> Result<B256> {
    let checkpoint: serde_json::Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )?;
    let expected_digest = format!("0x{}", hex::encode(Sha256::digest(expected_public_values)));
    if checkpoint
        .get("version")
        .and_then(serde_json::Value::as_u64)
        != Some(2)
        || checkpoint
            .get("artifactVersion")
            .and_then(serde_json::Value::as_u64)
            != Some(ARTIFACT_VERSION)
        || checkpoint.get("kind").and_then(serde_json::Value::as_str)
            != Some("antseed-wash-trading-seller-proof-request")
        || checkpoint
            .get("securityMode")
            .and_then(serde_json::Value::as_str)
            != Some("production")
        || !checkpoint
            .get("seller")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .eq_ignore_ascii_case(&format!("{seller}"))
        || !checkpoint
            .get("sellerProgramVKey")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .eq_ignore_ascii_case(&format!("{seller_program_vkey}"))
        || !checkpoint
            .get("expectedPublicValuesSha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .eq_ignore_ascii_case(&expected_digest)
    {
        bail!(
            "stale or invalid direct seller request checkpoint {}",
            path.display()
        );
    }
    checkpoint
        .get("requestId")
        .and_then(serde_json::Value::as_str)
        .context("seller request checkpoint is missing requestId")?
        .parse()
        .context("invalid seller requestId")
}

fn write_request_checkpoint(
    path: &Path,
    seller: Address,
    seller_program_vkey: B256,
    request_id: B256,
    expected_public_values: &[u8],
) -> Result<()> {
    let checkpoint = json!({
        "version": 2,
        "artifactVersion": ARTIFACT_VERSION,
        "kind": "antseed-wash-trading-seller-proof-request",
        "securityMode": "production",
        "seller": seller,
        "sellerProgramVKey": seller_program_vkey,
        "requestId": request_id,
        "expectedPublicValuesSha256": format!("0x{}", hex::encode(Sha256::digest(expected_public_values))),
    });
    write_json(path, &checkpoint)
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    write_atomic(path, &serde_json::to_vec_pretty(value)?)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("file")
    ));
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn required(args: &[String], flag: &str) -> Result<String> {
    optional(args, flag).with_context(|| format!("missing {flag}"))
}

fn optional(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|value| value == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn values(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter_map(|(index, value)| {
            (value == flag)
                .then(|| args.get(index + 1).cloned())
                .flatten()
        })
        .collect()
}
