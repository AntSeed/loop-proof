use alloy_primitives::{hex, B256};
use anyhow::{bail, Context, Result};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Proof, SP1Stdin};
use std::{env, fs};
use wash_predicate::aggregate::{vkey_bytes32, CLOSED_LOOP_PROGRAM_ID, RECIPROCAL_PROGRAM_ID};
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
    let output = required(&args, "--output")?;
    let children = values(&args, "--child")
        .into_iter()
        .map(parse_child)
        .collect::<Result<Vec<_>>>()?;
    if children.is_empty() {
        bail!("at least one --child kind:witness.json is required");
    }

    let client = ProverClient::from_env();
    let closed_key = client.setup(Elf::Dynamic(fs::read(closed_loop_elf)?.into()))?;
    let reciprocal_key = client.setup(Elf::Dynamic(fs::read(reciprocal_elf)?.into()))?;
    let aggregator_key = client.setup(Elf::Dynamic(fs::read(aggregator_elf)?.into()))?;
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
        let mut stdin = SP1Stdin::new();
        stdin.write(&witness);
        eprintln!(
            "[{}/{}] proving {} child",
            index + 1,
            children.len(),
            child.kind
        );
        let proof = client.prove(key, stdin).compressed().run()?;
        client.verify(&proof, key.verifying_key(), None)?;
        if proof.public_values.as_slice() != public_values {
            bail!(
                "{} child public values differ from native execution",
                child.kind
            );
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

    let expected = AggregateJournal::from_children(&child_inputs).map_err(anyhow::Error::msg)?;
    let mut aggregate_stdin = SP1Stdin::new();
    aggregate_stdin.write(&child_inputs);
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
        .run()?;
    client.verify(&aggregate_proof, aggregator_key.verifying_key(), None)?;
    if aggregate_proof.public_values.as_slice() != expected.abi_encode() {
        bail!("aggregate public values differ from native aggregation");
    }

    let result = serde_json::json!({
        "version": 1,
        "kind": "antseed-wash-trading-aggregate-proof",
        "chainId": expected.chain_id,
        "aggregatorProgramId": AGGREGATOR_PROGRAM_ID,
        "aggregatorProgramVKey": aggregator_key.verifying_key().bytes32(),
        "publicValues": format!("0x{}", hex::encode(aggregate_proof.public_values.as_slice())),
        "proofBytes": format!("0x{}", hex::encode(aggregate_proof.bytes())),
        "childCount": child_inputs.len(),
        "findingCount": expected.findings.len(),
        "blockReferenceCount": expected.block_refs.len(),
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
