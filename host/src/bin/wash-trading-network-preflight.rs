use alloy_primitives::U256;
use anyhow::{bail, Context, Result};
use serde_json::json;
use sp1_sdk::blocking::ProverClient;
use sp1_sdk::network::signer::NetworkSigner;
use sp1_sdk::SP1_CIRCUIT_VERSION;
use std::env;

fn main() -> Result<()> {
    if env::var("SP1_PROVER").as_deref() != Ok("network") {
        bail!("preflight requires SP1_PROVER=network");
    }
    let private_key = env::var("NETWORK_PRIVATE_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .context("preflight requires NETWORK_PRIVATE_KEY")?;
    let requester = NetworkSigner::local(&private_key)
        .context("invalid NETWORK_PRIVATE_KEY")?
        .address();
    let args = env::args().skip(1).collect::<Vec<_>>();
    let client = ProverClient::builder().network().build();
    let balance = client.get_balance()?;
    if balance == U256::ZERO {
        bail!(
            "Succinct prover-network balance is zero for requester {requester}; fund this requester through https://explorer.succinct.xyz/account"
        );
    }
    let seller = required_vkey(&args, "--expected-seller-vkey")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "networkMode": format!("{:?}", client.network_mode()),
            "requester": requester,
            "circuitVersion": SP1_CIRCUIT_VERSION.trim(),
            "balanceWei": balance.to_string(),
            "sellerProgramVKey": seller,
        }))?
    );
    Ok(())
}

fn required_vkey(args: &[String], flag: &str) -> Result<String> {
    let value = required(args, flag)?;
    if value.len() != 66
        || !value.starts_with("0x")
        || !value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("invalid {flag}");
    }
    Ok(value.to_lowercase())
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
