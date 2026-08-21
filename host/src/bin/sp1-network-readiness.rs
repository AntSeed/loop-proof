use alloy_primitives::U256;
use anyhow::{bail, Context, Result};
use serde_json::json;
use sp1_sdk::{
    blocking::ProverClient, network::proto::GetProofRequestParamsResponse, SP1ProofMode,
};

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    if std::env::var("NETWORK_PRIVATE_KEY").is_err() {
        bail!("NETWORK_PRIVATE_KEY is required for the read-only SP1 network readiness check");
    }

    let max_compressed_base_fee =
        required_u64_env("SP1_NETWORK_MAX_COMPRESSED_BASE_FEE_PROVE_WEI")?;
    let max_groth16_base_fee = required_u64_env("SP1_NETWORK_MAX_GROTH16_BASE_FEE_PROVE_WEI")?;
    let max_price_per_pgu = required_u64_env("SP1_NETWORK_MAX_PRICE_PER_PGU_PROVE_WEI")?;
    let required_balance = required_u256_env("SP1_NETWORK_REQUIRED_BALANCE_PROVE_WEI")?;
    let client = ProverClient::builder().network().build();
    let balance = client.get_balance().context("read SP1 network balance")?;
    let compressed = auction_params(
        "compressed",
        client
            .get_proof_request_params(SP1ProofMode::Compressed)
            .context("read compressed-proof auction parameters")?,
    )?;
    let groth16 = auction_params(
        "groth16",
        client
            .get_proof_request_params(SP1ProofMode::Groth16)
            .context("read Groth16 auction parameters")?,
    )?;
    for (snapshot, max_base_fee) in [
        (&compressed, max_compressed_base_fee),
        (&groth16, max_groth16_base_fee),
    ] {
        if snapshot.base_fee > max_base_fee {
            bail!(
                "live {} base fee {} exceeds approved cap {}",
                snapshot.name,
                snapshot.base_fee,
                max_base_fee
            );
        }
        if snapshot.max_price_per_pgu > max_price_per_pgu {
            bail!(
                "live {} max price per PGU {} exceeds approved cap {}",
                snapshot.name,
                snapshot.max_price_per_pgu,
                max_price_per_pgu
            );
        }
    }
    if balance < required_balance {
        bail!(
            "SP1 balance {} is below required batch funding {}",
            balance,
            required_balance
        );
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "version": 1,
            "kind": "antseed-sp1-network-readiness",
            "networkMode": format!("{:?}", client.network_mode()).to_lowercase(),
            "balanceProveWei": balance.to_string(),
            "requiredBalanceProveWei": required_balance.to_string(),
            "approvedCaps": {
                "maxCompressedBaseFeeProveWei": max_compressed_base_fee.to_string(),
                "maxGroth16BaseFeeProveWei": max_groth16_base_fee.to_string(),
                "maxPricePerPguProveWei": max_price_per_pgu.to_string(),
            },
            "proofModes": {
                "compressed": compressed.value,
                "groth16": groth16.value,
            },
            "ready": true,
        }))?
    );
    Ok(())
}

struct AuctionSnapshot {
    name: &'static str,
    base_fee: u64,
    max_price_per_pgu: u64,
    value: serde_json::Value,
}

fn auction_params(
    name: &'static str,
    response: GetProofRequestParamsResponse,
) -> Result<AuctionSnapshot> {
    let GetProofRequestParamsResponse::Auction(params) = response else {
        bail!("SP1 network did not return auction parameters");
    };
    let base_fee = params
        .base_fee
        .parse()
        .context("SP1 network returned an invalid base fee")?;
    let max_price_per_pgu = params
        .max_price_per_pgu
        .parse()
        .context("SP1 network returned an invalid maximum price per PGU")?;
    Ok(AuctionSnapshot {
        name,
        base_fee,
        max_price_per_pgu,
        value: json!({
            "baseFeeProveWei": params.base_fee,
            "maxPricePerPguProveWei": params.max_price_per_pgu,
            "auctioneer": format!("0x{}", alloy_primitives::hex::encode(params.auctioneer)),
            "executor": format!("0x{}", alloy_primitives::hex::encode(params.executor)),
            "verifier": format!("0x{}", alloy_primitives::hex::encode(params.verifier)),
            "treasury": format!("0x{}", alloy_primitives::hex::encode(params.treasury)),
        }),
    })
}

fn required_u64_env(name: &str) -> Result<u64> {
    std::env::var(name)
        .with_context(|| format!("{name} is required for the SP1 network readiness check"))?
        .parse()
        .with_context(|| format!("{name} must be an unsigned decimal integer"))
}

fn required_u256_env(name: &str) -> Result<U256> {
    std::env::var(name)
        .with_context(|| format!("{name} is required for the SP1 network readiness check"))?
        .parse()
        .with_context(|| format!("{name} must be an unsigned decimal integer"))
}
