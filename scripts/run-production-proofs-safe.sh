#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mode="${1:-}"
if [[ "$mode" != "canary" && "$mode" != "full" ]]; then
  echo "usage: BASE_RPC_URL=... $0 canary|full" >&2
  exit 1
fi
if [[ -z "${BASE_RPC_URLS:-${BASE_RPC_URL:-}}" ]]; then
  echo "BASE_RPC_URLS or BASE_RPC_URL is required" >&2
  exit 1
fi

bundle="${WASH_TRADING_BUNDLE:-out/unified-historical/proof-bundle.json}"
plan="${WASH_TRADING_PLAN:-out/unified-historical/proof-plan.json}"
witness_dir="${WASH_TRADING_WITNESS_DIR:-out/unified-historical/development}"
artifact_dir="${WASH_TRADING_PRODUCTION_DIR:-out/volume-only-historical-production}"
attestation="${WASH_TRADING_GUEST_ATTESTATION:-$artifact_dir/guest-build-attestation.json}"
account="${CAST_KEYSTORE_ACCOUNT:-antseed-verification-deployer}"
canary_seller="${WASH_TRADING_CANARY_SELLER:-0x22564606c08e09bef5d8addedefd4c2491a34ee9}"
child_concurrency="${WASH_TRADING_CHILD_CONCURRENCY:-1}"
seller_concurrency="${WASH_TRADING_SELLER_CONCURRENCY:-1}"
proof_timeout="${SP1_PROOF_TIMEOUT_SECONDS:-14400}"
auction_timeout="${SP1_AUCTION_TIMEOUT_SECONDS:-120}"

closed_loop_elf="$artifact_dir/guests/closed-loop-guest"
reciprocal_elf="$artifact_dir/guests/reciprocal-guest"
aggregator_elf="$artifact_dir/guests/aggregator-guest"

mkdir -p "$artifact_dir"
for path in "$bundle" "$plan"; do
  if [[ ! -f "$path" ]]; then
    echo "missing required file: $path" >&2
    exit 1
  fi
done

if [[ ! -f "$attestation" ]]; then
  echo "Building every guest twice for reproducibility. This does not request paid proofs."
  node scripts/build-guests-reproducibly.mjs \
    --work-dir ../guest-repro-builds \
    --out "$attestation"
fi

for path in "$closed_loop_elf" "$reciprocal_elf" "$aggregator_elf"; do
  if [[ ! -f "$path" ]]; then
    echo "missing attested production guest: $path" >&2
    echo "remove $attestation and rerun to rebuild the reproducible guest artifacts" >&2
    exit 1
  fi
done

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
  echo "Reusing paid-run maximum price per PGU: $max_price_per_pgu wei of PROVE"
else
  max_price_per_pgu="${SP1_MAX_PRICE_PER_PGU_WEI:-$recommended_max_price_per_pgu}"
fi
if [[ ! "$max_price_per_pgu" =~ ^[1-9][0-9]*$ ]]; then
  echo "maximum price per PGU must be a positive integer in wei" >&2
  exit 1
fi
echo "Using maximum price per PGU: $max_price_per_pgu wei of PROVE"
echo "USD limits disabled by request; authorization uses the network price cap only."

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

echo
jq . "$quote"
quote_digest="$(jq -r .digest "$quote")"
echo
read -r -p "Type the exact quote digest $quote_digest to approve these limits: " approved_digest
if [[ "$approved_digest" != "$quote_digest" ]]; then
  echo "quote digest approval did not match" >&2
  exit 1
fi

expected_closed="$(jq -r '.guests["closed-loop"].programVKey' "$attestation")"
expected_reciprocal="$(jq -r '.guests.reciprocal.programVKey' "$attestation")"
expected_aggregator="$(jq -r '.guests.aggregator.programVKey' "$attestation")"

cargo build --release -p loop-host --features sp1 \
  --bin wash-trading-network-preflight \
  --bin wash-trading-prove-child \
  --bin wash-trading-aggregate

batch_args=(
  --bundle "$bundle"
  --plan "$plan"
  --artifact-dir "$artifact_dir"
  --witness-dir "$witness_dir"
  --closed-loop-elf "$closed_loop_elf"
  --reciprocal-elf "$reciprocal_elf"
  --aggregator-elf "$aggregator_elf"
  --guest-attestation "$attestation"
  --cost-quote "$quote"
  --approve-cost-digest "$approved_digest"
  --child-concurrency "$child_concurrency"
  --seller-concurrency "$seller_concurrency"
  ${scope_args[@]+"${scope_args[@]}"}
)

node scripts/prove-approved-batch.mjs "${batch_args[@]}" --preflight-only

if [[ -z "${NETWORK_PRIVATE_KEY:-}" ]]; then
  export NETWORK_PRIVATE_KEY="$(cast wallet private-key --account "$account")"
fi
trap 'unset NETWORK_PRIVATE_KEY' EXIT INT TERM

target/release/wash-trading-network-preflight \
  --expected-closed-loop-vkey "$expected_closed" \
  --expected-reciprocal-vkey "$expected_reciprocal" \
  --expected-aggregator-vkey "$expected_aggregator"

echo
confirmation="PROVE $mode"
read -r -p "No paid request has been sent. Type '$confirmation' to start paid proving: " final_confirmation
if [[ "$final_confirmation" != "$confirmation" ]]; then
  echo "paid proving cancelled"
  exit 0
fi

node scripts/prove-approved-batch.mjs \
  "${batch_args[@]}" \
  --confirm-production-proving
