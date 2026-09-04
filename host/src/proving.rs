use alloy_primitives::B256;
use anyhow::{bail, Context, Result};
use sp1_sdk::blocking::{MockProver, NetworkProver, ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, ProvingKey, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin};
use std::{env, time::Duration};

#[derive(Clone, Copy)]
pub struct NetworkProofOptions {
    pub max_price_per_pgu: u64,
    pub proof_timeout: Duration,
    pub auction_timeout: Duration,
}

pub enum ProofClient {
    Development(MockProver),
    Network {
        client: NetworkProver,
        options: NetworkProofOptions,
    },
}

impl ProofClient {
    pub fn from_args(development: bool, args: &[String]) -> Result<Self> {
        if development {
            return Ok(Self::Development(MockProver::new()));
        }
        if env::var("SP1_PROVER").as_deref() != Ok("network") {
            bail!("production proving requires SP1_PROVER=network");
        }
        if env::var("NETWORK_PRIVATE_KEY")
            .ok()
            .filter(|value| !value.is_empty())
            .is_none()
        {
            bail!("production proving requires NETWORK_PRIVATE_KEY");
        }
        let options = NetworkProofOptions {
            max_price_per_pgu: required_u64(args, "--max-price-per-pgu-wei")?,
            proof_timeout: Duration::from_secs(required_u64(args, "--proof-timeout-secs")?),
            auction_timeout: Duration::from_secs(required_u64(args, "--auction-timeout-secs")?),
        };
        if options.max_price_per_pgu == 0
            || options.proof_timeout.is_zero()
            || options.auction_timeout.is_zero()
        {
            bail!("network proving limits must be nonzero");
        }
        Ok(Self::Network {
            client: ProverClient::builder().network().build(),
            options,
        })
    }

    pub fn setup(&self, elf: Elf) -> Result<SP1ProvingKey> {
        match self {
            Self::Development(client) => client.setup(elf).map_err(Into::into),
            Self::Network { client, .. } => client.setup(elf),
        }
    }

    pub fn prove_groth16(
        &self,
        key: &SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithPublicValues> {
        match self {
            Self::Development(client) => client
                .prove(key, stdin)
                .groth16()
                .deferred_proof_verification(false)
                .run()
                .map_err(Into::into),
            Self::Network { client, options } => client
                .prove(key, stdin)
                .groth16()
                .deferred_proof_verification(false)
                .max_price_per_pgu(options.max_price_per_pgu)
                .timeout(options.proof_timeout)
                .auction_timeout(options.auction_timeout)
                .run(),
        }
    }

    pub fn request_groth16(&self, key: &SP1ProvingKey, stdin: SP1Stdin) -> Result<B256> {
        match self {
            Self::Development(_) => bail!("development proving does not create network requests"),
            Self::Network { client, options } => client
                .prove(key, stdin)
                .groth16()
                .deferred_proof_verification(false)
                .max_price_per_pgu(options.max_price_per_pgu)
                .timeout(options.proof_timeout)
                .request(),
        }
    }

    pub fn wait_proof(&self, request_id: B256) -> Result<SP1ProofWithPublicValues> {
        match self {
            Self::Development(_) => bail!("development proving has no network request to resume"),
            Self::Network { client, options } => match client.wait_proof(
                request_id,
                Some(options.proof_timeout),
                Some(options.auction_timeout),
            ) {
                Ok(proof) => Ok(proof),
                Err(wait_error) => {
                    let (_, proof) = client.get_proof_status(request_id)?;
                    proof.ok_or(wait_error)
                }
            },
        }
    }

    pub fn verify(&self, proof: &SP1ProofWithPublicValues, key: &SP1ProvingKey) -> Result<()> {
        match self {
            Self::Development(client) => client
                .verify(proof, key.verifying_key(), None)
                .map_err(Into::into),
            Self::Network { client, .. } => client
                .verify(proof, key.verifying_key(), None)
                .map_err(Into::into),
        }
    }
}

fn required_u64(args: &[String], flag: &str) -> Result<u64> {
    args.iter()
        .position(|value| value == flag)
        .and_then(|index| args.get(index + 1))
        .with_context(|| format!("missing {flag}"))?
        .parse()
        .with_context(|| format!("invalid {flag}"))
}
