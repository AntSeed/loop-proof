use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::{env, fs, path::PathBuf};
use wash_predicate::{
    resolver::ChainResolver, verify_closed_loop, verify_reciprocal, ClosedLoopInput,
    ReciprocalInput, ALPHA_RETURN_BPS,
};

fn main() -> Result<()> {
    let directory = PathBuf::from(
        env::args()
            .nth(1)
            .context("usage: report_return_coverage WITNESS_DIR")?,
    );
    let mut paths = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| path.to_string_lossy().ends_with(".witness.json"));
    paths.sort();
    let mut claims = Vec::new();
    for path in paths {
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(format!("{}.cache.json", path.display()))?)?;
        let bytes = fs::read(&path)?;
        let report = if metadata["claimType"] == "P0_CLOSED_LOOP" {
            let input: ClosedLoopInput = serde_json::from_slice(&bytes)?;
            let journal = verify_closed_loop(&input).map_err(|error| anyhow!(error))?;
            let resolver = ChainResolver {
                blocks: &input.blocks,
            };
            let returned = input
                .returns
                .iter()
                .try_fold(0u128, |total, path| -> Result<u128> {
                    let credit = path.transfers.iter().try_fold(
                        u128::MAX,
                        |credit, reference| -> Result<u128> {
                            let (_, _, amount, _) = resolver
                                .usdc_transfer(*reference)
                                .map_err(|error| anyhow!(error))?;
                            Ok(credit.min(amount))
                        },
                    )?;
                    total.checked_add(credit).context("return credit overflow")
                })?;
            json!({
                "claimId": input.source_claim_id,
                "kind": "closed-loop",
                "seller": input.seller,
                "funder": input.funder,
                "provenWashVolumeRaw": journal.subjects[0].wash_volume.to_string(),
                "alphaReturnFloorBps": ALPHA_RETURN_BPS,
                "returnMode": if input.seller == input.funder { "identity" } else { "transfer-paths" },
                "returnedCreditRaw": if input.seller == input.funder { None } else { Some(returned.to_string()) },
                "verified": true,
            })
        } else {
            let input: ReciprocalInput = serde_json::from_slice(&bytes)?;
            let journal = verify_reciprocal(&input).map_err(|error| anyhow!(error))?;
            json!({
                "claimId": input.source_claim_id,
                "kind": "reciprocal",
                "returnMode": "not-applicable",
                "subjects": journal.subjects.iter().map(|subject| json!({
                    "seller": subject.subject,
                    "provenWashVolumeRaw": subject.wash_volume.to_string(),
                })).collect::<Vec<_>>(),
                "verified": true,
            })
        };
        eprintln!("verified {}", path.display());
        claims.push(report);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"claims": claims}))?
    );
    Ok(())
}
