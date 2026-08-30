use alloy_primitives::{hex, B256};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use sp1_sdk::blocking::{MockProver, ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};
use std::{collections::BTreeMap, env, fs, path::Path};
use wash_predicate::aggregate::{
    vkey_bytes32, HistoricalBlockRef, HistoricalManifest, CLOSED_LOOP_PROGRAM_ID,
    RECIPROCAL_PROGRAM_ID,
};
use wash_predicate::{
    verify_closed_loop, verify_reciprocal, AggregateJournal, ChildProofInput, ClosedLoopInput,
    ReciprocalInput, AGGREGATOR_PROGRAM_ID,
};

struct ChildSpec {
    kind: String,
    witness: String,
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let aggregator_elf = required(&args, "--aggregator-elf")?;
    let closed_loop_elf = required(&args, "--closed-loop-elf")?;
    let reciprocal_elf = required(&args, "--reciprocal-elf")?;
    let manifest_path = required(&args, "--manifest")?;
    let output = required(&args, "--output")?;
    let child_artifact_dir = optional(&args, "--child-artifact-dir");
    let reuse_child_proofs = args.iter().any(|value| value == "--reuse-child-proofs");
    if reuse_child_proofs && child_artifact_dir.is_none() {
        bail!("--reuse-child-proofs requires --child-artifact-dir");
    }
    let resolved_manifest_output = optional(&args, "--resolved-manifest-output");
    let children = values(&args, "--child")
        .into_iter()
        .map(parse_child)
        .collect::<Result<Vec<_>>>()?;
    if children.is_empty() {
        bail!("at least one --child kind:witness.json is required");
    }
    let development = args.iter().any(|value| value == "--development");
    if development {
        std::env::set_var("SP1_PROVER", "mock");
    } else if matches!(std::env::var("SP1_PROVER").as_deref(), Ok("mock" | "light")) {
        bail!("mock and light provers require --development");
    }

    let client = ProverClient::from_env();
    let mock_verifier = development.then(MockProver::new);
    let closed_key = client.setup(Elf::Dynamic(fs::read(closed_loop_elf)?.into()))?;
    let reciprocal_key = client.setup(Elf::Dynamic(fs::read(reciprocal_elf)?.into()))?;
    let aggregator_key = client.setup(Elf::Dynamic(fs::read(aggregator_elf)?.into()))?;
    let mut manifest: HistoricalManifest = serde_json::from_slice(
        &fs::read(&manifest_path).with_context(|| format!("read {manifest_path}"))?,
    )?;
    manifest.closed_loop_program_vkey = closed_key.verifying_key().bytes32().parse()?;
    manifest.reciprocal_program_vkey = reciprocal_key.verifying_key().bytes32().parse()?;
    let mut child_inputs = Vec::with_capacity(children.len());
    let mut deferred_proofs = Vec::with_capacity(children.len());

    for (index, child) in children.iter().enumerate() {
        let witness =
            fs::read(&child.witness).with_context(|| format!("read {}", child.witness))?;
        let (program_id, key, public_values) = match child.kind.as_str() {
            "closed-loop" => {
                let input: ClosedLoopInput = serde_json::from_slice(&witness)?;
                let journal = verify_closed_loop(&input).map_err(anyhow::Error::msg)?;
                (CLOSED_LOOP_PROGRAM_ID, &closed_key, journal.abi_encode())
            }
            "reciprocal" => {
                let input: ReciprocalInput = serde_json::from_slice(&witness)?;
                let journal = verify_reciprocal(&input).map_err(anyhow::Error::msg)?;
                (RECIPROCAL_PROGRAM_ID, &reciprocal_key, journal.abi_encode())
            }
            kind => bail!("unsupported child kind {kind}"),
        };
        let source_claim_id = wash_predicate::WashJournal::abi_decode(&public_values)
            .map_err(anyhow::Error::msg)?
            .source_claim_id;
        let proof_path = child_artifact_dir.as_deref().map(|directory| {
            Path::new(directory).join(format!("{index:03}-{source_claim_id}.proof.bin"))
        });
        let proof = if reuse_child_proofs && proof_path.as_ref().is_some_and(|path| path.exists()) {
            eprintln!(
                "[{}/{}] reusing verified {} child proof",
                index + 1,
                children.len(),
                child.kind
            );
            SP1ProofWithPublicValues::load(proof_path.as_ref().expect("proof path exists"))?
        } else {
            let mut stdin = SP1Stdin::new();
            stdin.write(&witness);
            eprintln!(
                "[{}/{}] proving {} child",
                index + 1,
                children.len(),
                child.kind
            );
            client.prove(key, stdin).compressed().run()?
        };
        if let Some(verifier) = &mock_verifier {
            verifier.verify(&proof, key.verifying_key(), None)?;
        } else {
            client.verify(&proof, key.verifying_key(), None)?;
        }
        if proof.public_values.as_slice() != public_values {
            bail!(
                "{} child public values differ from native execution",
                child.kind
            );
        }
        let serialized_child = if let Some(directory) = child_artifact_dir.as_deref() {
            fs::create_dir_all(directory)?;
            let path = proof_path.expect("child artifact path exists");
            proof.save(&path)?;
            Some((
                path,
                fs::read(
                    Path::new(directory).join(format!("{index:03}-{source_claim_id}.proof.bin")),
                )?,
            ))
        } else {
            None
        };
        let compressed = match proof.proof {
            SP1Proof::Compressed(proof) => *proof,
            _ => bail!("child prover did not return a compressed proof"),
        };
        let vkey_digest = key.verifying_key().hash_u32();
        let program_vkey: B256 = key.verifying_key().bytes32().parse()?;
        if vkey_bytes32(vkey_digest) != program_vkey {
            bail!("SP1 vkey encodings disagree");
        }
        if let Some((proof_path, proof_bytes)) = serialized_child {
            let artifact = serde_json::json!({
                "version": 1,
                "kind": "antseed-wash-trading-development-child-proof",
                "securityMode": if development { "development" } else { "production" },
                "childKind": child.kind,
                "sourceClaimId": format!("{source_claim_id}"),
                "programId": format!("{program_id}"),
                "programVKey": format!("{program_vkey}"),
                "publicValues": format!("0x{}", hex::encode(&public_values)),
                "proofBytes": format!("0x{}", hex::encode(&proof_bytes)),
                "proofPath": proof_path,
                "verified": true,
            });
            let path = proof_path.with_extension("json");
            fs::write(path, serde_json::to_vec_pretty(&artifact)?)?;
        }
        child_inputs.push(ChildProofInput {
            program_id,
            program_vkey,
            vkey_digest,
            public_values,
        });
        deferred_proofs.push((compressed, key.verifying_key().vk.clone()));
    }

    let mut block_refs = BTreeMap::new();
    for child in &child_inputs {
        let journal = wash_predicate::WashJournal::abi_decode(&child.public_values)
            .map_err(anyhow::Error::msg)?;
        for (number, block_hash) in journal.block_refs {
            if let Some(existing) = block_refs.insert(number, block_hash) {
                if existing != block_hash {
                    bail!("conflicting child block hash at {number}");
                }
            }
        }
    }
    manifest.block_refs = block_refs
        .into_iter()
        .map(|(number, block_hash)| HistoricalBlockRef { number, block_hash })
        .collect();
    let expected =
        AggregateJournal::from_children(&child_inputs, &manifest).map_err(anyhow::Error::msg)?;
    let mut aggregate_stdin = SP1Stdin::new();
    aggregate_stdin.write(&child_inputs);
    aggregate_stdin.write(&manifest);
    for (proof, vkey) in deferred_proofs {
        aggregate_stdin.write_proof(proof, vkey);
    }
    eprintln!(
        "proving one Groth16 aggregate for {} children",
        child_inputs.len()
    );
    let aggregate_proof = client
        .prove(&aggregator_key, aggregate_stdin)
        .groth16()
        .deferred_proof_verification(!development)
        .run()?;
    if let Some(verifier) = &mock_verifier {
        verifier.verify(&aggregate_proof, aggregator_key.verifying_key(), None)?;
    } else {
        client.verify(&aggregate_proof, aggregator_key.verifying_key(), None)?;
    }
    if aggregate_proof.public_values.as_slice()
        != expected
            .committed_public_values(&manifest)
            .map_err(anyhow::Error::msg)?
    {
        bail!("aggregate public values differ from native aggregation");
    }
    let serialized_proof = aggregate_proof.bytes();
    let proof_bytes = if development && serialized_proof.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(b"antseed-wash-trading-development-proof-v1");
        hasher.update(aggregator_key.verifying_key().bytes32().as_bytes());
        hasher.update(aggregate_proof.public_values.as_slice());
        hasher.finalize().to_vec()
    } else {
        serialized_proof
    };
    if let Some(path) = resolved_manifest_output {
        fs::write(path, serde_json::to_vec_pretty(&manifest)?)?;
    }

    let result = serde_json::json!({
        "version": 1,
        "kind": "antseed-wash-trading-aggregate-proof",
        "securityMode": if development { "development" } else { "production" },
        "chainId": expected.chain_id,
        "reportRoot": manifest.report_root,
        "manifestDigest": manifest.digest().map_err(anyhow::Error::msg)?,
        "periodStartBlock": manifest.period_start_block,
        "periodEndBlock": manifest.period_end_block,
        "aggregatorProgramId": AGGREGATOR_PROGRAM_ID,
        "aggregatorProgramVKey": aggregator_key.verifying_key().bytes32(),
        "publicValues": format!("0x{}", hex::encode(aggregate_proof.public_values.as_slice())),
        "proofBytes": format!("0x{}", hex::encode(proof_bytes)),
        "childCount": child_inputs.len(),
        "sourceClaimCount": manifest.claims.len(),
        "sellerCount": expected.sellers.len(),
        "blockReferenceCount": expected.block_reference_count,
        "provenWashVolumeRaw": expected.total_proven_wash_volume.to_string(),
    });
    fs::write(output, serde_json::to_vec_pretty(&result)?)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
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
