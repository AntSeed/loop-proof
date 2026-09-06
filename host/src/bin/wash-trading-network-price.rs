use anyhow::{bail, Context, Result};
use serde_json::json;
use sp1_sdk::blocking::{NetworkProver, ProverClient};
use sp1_sdk::network::proto::GetProofRequestParamsResponse;
use sp1_sdk::SP1ProofMode;

const READ_ONLY_SIGNER: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

fn main() -> Result<()> {
    let client = ProverClient::builder()
        .network()
        .private_key(READ_ONLY_SIGNER)
        .build();
    let compressed = request_params(&client, SP1ProofMode::Compressed)?;
    let groth16 = request_params(&client, SP1ProofMode::Groth16)?;
    let recommended_max_price = compressed.max_price_per_pgu.max(groth16.max_price_per_pgu);

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "compressed": {
                "maxPricePerPguWei": compressed.max_price_per_pgu.to_string(),
                "baseFeeWei": compressed.base_fee,
            },
            "groth16": {
                "maxPricePerPguWei": groth16.max_price_per_pgu.to_string(),
                "baseFeeWei": groth16.base_fee,
            },
            "recommendedMaxPricePerPguWei": recommended_max_price.to_string(),
        }))?
    );
    Ok(())
}

struct RequestParams {
    max_price_per_pgu: u64,
    base_fee: String,
}

fn request_params(client: &NetworkProver, mode: SP1ProofMode) -> Result<RequestParams> {
    match client.get_proof_request_params(mode)? {
        GetProofRequestParamsResponse::Auction(params) => Ok(RequestParams {
            max_price_per_pgu: params
                .max_price_per_pgu
                .parse()
                .context("network returned invalid max_price_per_pgu")?,
            base_fee: params.base_fee,
        }),
        GetProofRequestParamsResponse::Unsupported => {
            bail!("Succinct RPC does not support auction pricing")
        }
    }
}
