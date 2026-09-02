use alloy_primitives::{hex, Address, B256};
use anyhow::{bail, Context, Result};
#[path = "../proving.rs"]
mod proving;
use proving::ProofClient;
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};
use wash_predicate::aggregate::{
    block_authentication_chunks, vkey_bytes32, HistoricalBlockRef, CLOSED_LOOP_PROGRAM_ID,
    RECIPROCAL_PROGRAM_ID,
};
use wash_predicate::{
    verify_closed_loop, verify_reciprocal, ChildProofInput, ClosedLoopInput, ReciprocalInput,
    SellerAggregateInput, SellerJournal, WashJournal, SELLER_AGGREGATOR_PROGRAM_ID,
};

struct ChildSpec {
    kind: String,
    witness: String,
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let seller: Address = required(&args, "--seller")?
        .parse()
        .context("invalid --seller address")?;
    let aggregator_elf = required(&args, "--aggregator-elf")?;
    let closed_loop_elf = required(&args, "--closed-loop-elf")?;
    let reciprocal_elf = required(&args, "--reciprocal-elf")?;
    let output = required(&args, "--output")?;
    let request_checkpoint = optional(&args, "--request-checkpoint").map(PathBuf::from);
    let child_artifact_dir = optional(&args, "--child-artifact-dir");
    let reuse_child_proofs = args.iter().any(|value| value == "--reuse-child-proofs");
    if reuse_child_proofs && child_artifact_dir.is_none() {
        bail!("--reuse-child-proofs requires --child-artifact-dir");
    }
    let children = values(&args, "--child")
        .into_iter()
        .map(parse_child)
        .collect::<Result<Vec<_>>>()?;
    if children.is_empty() {
        bail!("at least one --child kind:witness.json is required");
    }
    let development = args.iter().any(|value| value == "--development");
    let client = ProofClient::from_args(development, &args)?;

    let closed_key = client.setup(Elf::Dynamic(fs::read(closed_loop_elf)?.into()))?;
    let reciprocal_key = client.setup(Elf::Dynamic(fs::read(reciprocal_elf)?.into()))?;
    let aggregator_key = client.setup(Elf::Dynamic(fs::read(aggregator_elf)?.into()))?;
    let closed_loop_program_vkey: B256 = closed_key.verifying_key().bytes32().parse()?;
    let reciprocal_program_vkey: B256 = reciprocal_key.verifying_key().bytes32().parse()?;
    let mut period = None;
    let mut child_inputs = Vec::with_capacity(children.len());
    let mut deferred_proofs = Vec::with_capacity(children.len());

    for (index, child) in children.iter().enumerate() {
        let witness =
            fs::read(&child.witness).with_context(|| format!("read {}", child.witness))?;
        let (program_id, key, journal) = match child.kind.as_str() {
            "closed-loop" => {
                let input: ClosedLoopInput = serde_json::from_slice(&witness)?;
                let journal = verify_closed_loop(&input).map_err(anyhow::Error::msg)?;
                (CLOSED_LOOP_PROGRAM_ID, &closed_key, journal)
            }
            "reciprocal" => {
                let input: ReciprocalInput = serde_json::from_slice(&witness)?;
                let journal = verify_reciprocal(&input).map_err(anyhow::Error::msg)?;
                (RECIPROCAL_PROGRAM_ID, &reciprocal_key, journal)
            }
            kind => bail!("unsupported child kind {kind}"),
        };
        if !journal
            .subjects
            .iter()
            .any(|subject| subject.subject == seller)
        {
            continue;
        }
        let child_period = (journal.period_start_block, journal.period_end_block);
        if period
            .replace(child_period)
            .is_some_and(|value| value != child_period)
        {
            bail!("all child proofs must use one identical period");
        }
        let source_claim_id = journal.source_claim_id;
        let public_values = journal.abi_encode();
        let proof_path = child_artifact_dir.as_deref().map(|directory| {
            Path::new(directory).join(format!("{index:03}-{source_claim_id}.proof.bin"))
        });
        let cached_proof = if reuse_child_proofs
            && proof_path.as_ref().is_some_and(|path| path.exists())
        {
            let proof =
                SP1ProofWithPublicValues::load(proof_path.as_ref().expect("proof path exists"))?;
            (proof.public_values.as_slice() == public_values).then_some(proof)
        } else {
            None
        };
        let proof = if let Some(proof) = cached_proof {
            eprintln!(
                "[{}/{}] reusing verified {} child proof",
                index + 1,
                children.len(),
                child.kind
            );
            proof
        } else {
            let mut stdin = SP1Stdin::new();
            stdin.write(&witness);
            eprintln!(
                "[{}/{}] proving {} child",
                index + 1,
                children.len(),
                child.kind
            );
            client.prove_compressed(key, stdin)?
        };
        client.verify(&proof, key)?;
        if proof.public_values.as_slice() != public_values {
            bail!(
                "{} child public values differ from native execution",
                child.kind
            );
        }
        if let Some(directory) = child_artifact_dir.as_deref() {
            fs::create_dir_all(directory)?;
            let path = proof_path.expect("child artifact path exists");
            proof.save(&path)?;
            let artifact = serde_json::json!({
                "version": 2,
                "kind": "antseed-wash-trading-child-proof",
                "securityMode": if development { "development" } else { "production" },
                "childKind": child.kind,
                "sourceClaimId": format!("{source_claim_id}"),
                "programId": format!("{program_id}"),
                "programVKey": key.verifying_key().bytes32(),
                "publicValues": format!("0x{}", hex::encode(&public_values)),
                "proofPath": path,
                "verified": true,
            });
            fs::write(
                path.with_extension("json"),
                serde_json::to_vec_pretty(&artifact)?,
            )?;
        }
        let compressed = match proof.proof {
            SP1Proof::Compressed(proof) => *proof,
            _ => bail!("child prover did not return a compressed proof"),
        };
        let vkey_digest = key.verifying_key().hash_u32();
        let program_vkey: B256 = key.verifying_key().bytes32().parse()?;
        if vkey_bytes32(vkey_digest) != program_vkey {
            bail!("SP1 vkey encodings disagree");
        }
        child_inputs.push(ChildProofInput {
            program_id,
            program_vkey,
            vkey_digest,
            public_values,
        });
        deferred_proofs.push((compressed, key.verifying_key().vk.clone()));
    }

    let (period_start_block, period_end_block) = period.expect("children are not empty");
    let aggregate_input = SellerAggregateInput {
        seller,
        period_start_block,
        period_end_block,
        closed_loop_program_vkey,
        reciprocal_program_vkey,
    };
    let expected = SellerJournal::from_children(&child_inputs, &aggregate_input)
        .map_err(anyhow::Error::msg)?;
    let mut aggregate_stdin = SP1Stdin::new();
    aggregate_stdin.write(&child_inputs);
    aggregate_stdin.write(&aggregate_input);
    for (proof, vkey) in deferred_proofs {
        aggregate_stdin.write_proof(proof, vkey);
    }
    eprintln!(
        "proving one Groth16 seller aggregate for {} children",
        child_inputs.len()
    );
    let expected_public_values = expected.abi_encode();
    let (aggregate_proof, request_id) = if development {
        (
            client.prove_groth16(&aggregator_key, aggregate_stdin)?,
            None,
        )
    } else {
        let checkpoint_path = request_checkpoint
            .as_deref()
            .context("production aggregate proving requires --request-checkpoint")?;
        let aggregator_program_vkey: B256 = aggregator_key.verifying_key().bytes32().parse()?;
        let request_id = if checkpoint_path.exists() {
            load_request_checkpoint(checkpoint_path, seller, aggregator_program_vkey)?
        } else {
            let request_id = client.request_groth16(&aggregator_key, aggregate_stdin)?;
            write_request_checkpoint(
                checkpoint_path,
                seller,
                aggregator_program_vkey,
                request_id,
                &expected_public_values,
            )?;
            request_id
        };
        eprintln!("waiting for seller aggregate request {request_id}");
        (client.wait_proof(request_id)?, Some(request_id))
    };
    client.verify(&aggregate_proof, &aggregator_key)?;
    if aggregate_proof.public_values.as_slice() != expected_public_values {
        bail!("seller aggregate public values differ from native aggregation");
    }
    let serialized_proof = aggregate_proof.bytes();
    let proof_bytes = if development && serialized_proof.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(b"antseed-wash-trading-development-seller-proof-v1");
        hasher.update(aggregator_key.verifying_key().bytes32().as_bytes());
        hasher.update(aggregate_proof.public_values.as_slice());
        hasher.finalize().to_vec()
    } else {
        serialized_proof
    };

    let block_refs = merged_block_refs(&child_inputs)?;
    let authentication_chunks =
        block_authentication_chunks(&block_refs).map_err(anyhow::Error::msg)?;
    let result = serde_json::json!({
        "version": 2,
        "kind": "antseed-wash-trading-seller-proof",
        "securityMode": client.security_mode(),
        "chainId": expected.chain_id,
        "periodStartBlock": expected.period_start_block,
        "periodEndBlock": expected.period_end_block,
        "seller": expected.seller,
        "provenWashVolumeRaw": expected.proven_wash_volume.to_string(),
        "evidenceDigest": expected.evidence_digest,
        "closedLoopProgramVKey": expected.closed_loop_program_vkey,
        "reciprocalProgramVKey": expected.reciprocal_program_vkey,
        "aggregatorProgramId": SELLER_AGGREGATOR_PROGRAM_ID,
        "aggregatorProgramVKey": aggregator_key.verifying_key().bytes32(),
        "requestId": request_id.map(|value| format!("{value}")),
        "publicValues": format!("0x{}", hex::encode(aggregate_proof.public_values.as_slice())),
        "proofBytes": format!("0x{}", hex::encode(proof_bytes)),
        "childCount": child_inputs.len(),
        "blockReferenceCount": expected.block_reference_count,
        "blockAuthenticationChunkSize": expected.block_authentication_chunk_size,
        "blockAuthenticationChunkCount": expected.block_authentication_chunk_count,
        "blockAuthenticationRoot": expected.block_authentication_root,
        "blockAuthenticationChunks": authentication_chunks.iter().map(|chunk| serde_json::json!({
            "index": chunk.index,
            "references": chunk.references.iter().map(|reference| serde_json::json!({
                "number": reference.number,
                "blockHash": reference.block_hash,
            })).collect::<Vec<_>>(),
            "proof": chunk.proof,
        })).collect::<Vec<_>>(),
    });
    fs::write(output, serde_json::to_vec_pretty(&result)?)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn load_request_checkpoint(path: &Path, seller: Address, aggregator_vkey: B256) -> Result<B256> {
    let checkpoint: serde_json::Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )?;
    let expected_seller = format!("{seller}");
    let expected_vkey = format!("{aggregator_vkey}");
    let checkpoint_seller = checkpoint
        .get("seller")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let checkpoint_vkey = checkpoint
        .get("aggregatorProgramVKey")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if checkpoint
        .get("version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || checkpoint.get("kind").and_then(serde_json::Value::as_str)
            != Some("antseed-wash-trading-seller-proof-request")
        || checkpoint
            .get("securityMode")
            .and_then(serde_json::Value::as_str)
            != Some("production")
        || !checkpoint_seller.eq_ignore_ascii_case(&expected_seller)
        || !checkpoint_vkey.eq_ignore_ascii_case(&expected_vkey)
    {
        bail!(
            "stale or invalid seller aggregate request checkpoint {}",
            path.display()
        );
    }
    checkpoint
        .get("requestId")
        .and_then(serde_json::Value::as_str)
        .context("seller aggregate request checkpoint is missing requestId")?
        .parse()
        .context("invalid seller aggregate requestId")
}

fn write_request_checkpoint(
    path: &Path,
    seller: Address,
    aggregator_vkey: B256,
    request_id: B256,
    expected_public_values: &[u8],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let checkpoint = serde_json::json!({
        "version": 1,
        "kind": "antseed-wash-trading-seller-proof-request",
        "securityMode": "production",
        "seller": seller,
        "aggregatorProgramVKey": aggregator_vkey,
        "requestId": request_id,
        "expectedPublicValuesSha256": format!("0x{}", hex::encode(Sha256::digest(expected_public_values))),
    });
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(&checkpoint)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn merged_block_refs(children: &[ChildProofInput]) -> Result<Vec<HistoricalBlockRef>> {
    let mut refs = BTreeMap::new();
    for child in children {
        let journal = WashJournal::abi_decode(&child.public_values).map_err(anyhow::Error::msg)?;
        for (number, block_hash) in journal.block_refs {
            if let Some(existing) = refs.insert(number, block_hash) {
                if existing != block_hash {
                    bail!("conflicting child block hash at {number}");
                }
            }
        }
    }
    Ok(refs
        .into_iter()
        .map(|(number, block_hash)| HistoricalBlockRef { number, block_hash })
        .collect())
}

fn parse_child(value: String) -> Result<ChildSpec> {
    let (kind, witness) = value.split_once(':').context("--child must be kind:path")?;
    Ok(ChildSpec {
        kind: kind.to_owned(),
        witness: witness.to_owned(),
    })
}

fn required(args: &[String], flag: &str) -> Result<String> {
    args.iter()
        .position(|value| value == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
        .with_context(|| format!("missing {flag}"))
}

fn optional(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|value| value == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_checkpoint_accepts_checksum_casing_and_rejects_other_sellers() {
        let seller: Address = "0x5b281ff194f7fd3f68e9379a7d433c752013024f"
            .parse()
            .unwrap();
        let aggregator_vkey: B256 =
            "0x00f9652e909f5d559c70da3467865cf37615d463661f5c2b32b8a995f29a277f"
                .parse()
                .unwrap();
        let request_id: B256 = "0xb72a1f2f93ff3a9ea6a4feab9eb1ef00de399aa614953698b8633247cd2b736d"
            .parse()
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "wash-trading-request-checkpoint-{}.json",
            std::process::id()
        ));
        let checkpoint = serde_json::json!({
            "version": 1,
            "kind": "antseed-wash-trading-seller-proof-request",
            "securityMode": "production",
            "seller": format!("{seller:?}"),
            "aggregatorProgramVKey": format!("{aggregator_vkey}"),
            "requestId": format!("{request_id}"),
        });
        fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();

        assert_eq!(
            load_request_checkpoint(&path, seller, aggregator_vkey).unwrap(),
            request_id
        );
        let other_seller: Address = "0x69f915d18ab913f0c86913a94c353b46a5e7baa4"
            .parse()
            .unwrap();
        assert!(load_request_checkpoint(&path, other_seller, aggregator_vkey).is_err());
        fs::remove_file(path).unwrap();
    }
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
