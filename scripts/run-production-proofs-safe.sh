#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mode="${1:-}"
if [[ "$mode" != "canary" && "$mode" != "full" ]]; then
  echo "usage: $0 canary|full" >&2
  exit 1
fi

bundle="${WASH_TRADING_BUNDLE:-out/unified-historical/proof-bundle.json}"
plan="${WASH_TRADING_PLAN:-out/unified-historical/proof-plan.json}"
witness_dir="${WASH_TRADING_WITNESS_DIR:-out/unified-historical/development}"
artifact_dir="${WASH_TRADING_PRODUCTION_DIR:-out/volume-only-historical-production}"
attestation="${WASH_TRADING_GUEST_ATTESTATION:-$artifact_dir/guest-build-attestation.json}"
account="${CAST_KEYSTORE_ACCOUNT:-antseed-verification-deployer}"
canary_seller="${WASH_TRADING_CANARY_SELLER:-0x22564606c08e09bef5d8addedefd4c2491a34ee9}"
seller_concurrency="${WASH_TRADING_SELLER_CONCURRENCY:-1}"
proof_timeout="${SP1_PROOF_TIMEOUT_SECONDS:-14400}"
auction_timeout="${SP1_AUCTION_TIMEOUT_SECONDS:-120}"
seller_elf="$artifact_dir/guests/seller-guest"

mkdir -p "$artifact_dir"
for path in "$bundle" "$plan"; do
  if [[ ! -f "$path" ]]; then
    echo "missing required file: $path" >&2
    exit 1
  fi
done

if [[ ! -f "$attestation" ]]; then
  echo "Building the seller guest twice for reproducibility. This does not request paid proofs."
  node scripts/build-guests-reproducibly.mjs \
    --work-dir ../guest-repro-builds \
    --out "$attestation"
fi
node scripts/verify-guest-build-attestation.mjs "$attestation"
if [[ ! -f "$seller_elf" ]]; then
  echo "missing attested production seller guest: $seller_elf" >&2
  echo "remove $attestation and rerun to rebuild the reproducible guest artifact" >&2
  exit 1
fi

export SP1_PROVER=network
export NETWORK_RPC_URL="${NETWORK_RPC_URL:-https://rpc.mainnet.succinct.xyz}"

scope_args=()
scope_name="full"
if [[ "$mode" == "canary" ]]; then
  scope_args=(--seller "$canary_seller")
  scope_name="$canary_seller"
fi
run_config="$artifact_dir/runs/$scope_name.json"

echo "Querying live Succinct auction pricing. This does not submit a proof request."
cargo build --release -p loop-host --features sp1 --bin wash-trading-network-price
pricing_json="$(target/release/wash-trading-network-price)"
echo "$pricing_json" | jq .
recommended_max_price_per_pgu="$(echo "$pricing_json" | jq -er '.recommendedMaxPricePerPguWei')"
if [[ -f "$run_config" ]]; then
  pinned_max_price_per_pgu="$(jq -er '.networkLimits.maxPricePerPguWei | select(type == "string" and test("^[1-9][0-9]*$"))' "$run_config")"
  if [[ -n "${SP1_MAX_PRICE_PER_PGU_WEI:-}" && "$SP1_MAX_PRICE_PER_PGU_WEI" != "$pinned_max_price_per_pgu" ]]; then
    echo "existing paid run is pinned to $pinned_max_price_per_pgu wei per PGU; refusing override $SP1_MAX_PRICE_PER_PGU_WEI" >&2
    exit 1
  fi
  max_price_per_pgu="$pinned_max_price_per_pgu"
else
  max_price_per_pgu="${SP1_MAX_PRICE_PER_PGU_WEI:-$recommended_max_price_per_pgu}"
fi
if [[ ! "$max_price_per_pgu" =~ ^[1-9][0-9]*$ ]]; then
  echo "maximum price per PGU must be a positive integer in wei" >&2
  exit 1
fi

expires_at="$(node -e 'console.log(new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString())')"
quote="$artifact_dir/proof-cost-$scope_name.json"
node scripts/proving-cost-quote.mjs \
  --bundle "$bundle" \
  --proof-plan "$plan" \
  --network-price-cap-only \
  --max-price-per-pgu-wei "$max_price_per_pgu" \
  --proof-timeout-seconds "$proof_timeout" \
  --auction-timeout-seconds "$auction_timeout" \
  --provider "Succinct Prover Network" \
  --expires-at "$expires_at" \
  --out "$quote" \
  ${scope_args[@]+"${scope_args[@]}"}

jq . "$quote"
quote_digest="$(jq -r .digest "$quote")"
read -r -p "Type the exact quote digest $quote_digest to approve these limits: " approved_digest
if [[ "$approved_digest" != "$quote_digest" ]]; then
  echo "quote digest approval did not match" >&2
  exit 1
fi

expected_seller="$(jq -r '.guests.seller.programVKey' "$attestation")"
cargo build --release -p loop-host --features sp1 \
  --bin wash-trading-network-preflight \
  --bin wash-trading-prove-seller

batch_args=(
  --bundle "$bundle"
  --plan "$plan"
  --artifact-dir "$artifact_dir"
  --witness-dir "$witness_dir"
  --seller-elf "$seller_elf"
  --guest-attestation "$attestation"
  --cost-quote "$quote"
  --approve-cost-digest "$approved_digest"
  --seller-concurrency "$seller_concurrency"
  ${scope_args[@]+"${scope_args[@]}"}
)

node scripts/prove-approved-batch.mjs "${batch_args[@]}" --preflight-only

if [[ -z "${NETWORK_PRIVATE_KEY:-}" ]]; then
  export NETWORK_PRIVATE_KEY="$(cast wallet private-key --account "$account")"
fi
trap 'unset NETWORK_PRIVATE_KEY' EXIT INT TERM

target/release/wash-trading-network-preflight --expected-seller-vkey "$expected_seller"

confirmation="PROVE $mode"
read -r -p "No paid request has been sent. Type '$confirmation' to start paid proving: " final_confirmation
if [[ "$final_confirmation" != "$confirmation" ]]; then
  echo "paid proving cancelled"
  exit 0
fi

node scripts/prove-approved-batch.mjs "${batch_args[@]}" --confirm-production-proving
