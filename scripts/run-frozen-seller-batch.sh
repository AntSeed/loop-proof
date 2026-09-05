#!/usr/bin/env bash
set -euo pipefail
set +x

cd "$(dirname "$0")/.."
QUOTE="${1:?usage: run-frozen-seller-batch.sh /absolute/path/to/batch-quote.json}"
SCRIPT=scripts/submit-frozen-seller-batch.mjs

echo "Refreshing unsubmitted proof quotes before approval; saved paid requests remain unchanged."
node "$SCRIPT" refresh "$QUOTE"

node - "$QUOTE" <<'JS'
const fs = require('node:fs');
const quote = JSON.parse(fs.readFileSync(process.argv[2]));
const body = quote.body;
const cost = BigInt(body.estimatedTotalCostWei);
const scale = 10n ** 18n;
console.log(`Queue all ${body.proofCount} seller proofs, ONE AT A TIME.`);
console.log(`Funded requester: ${body.requester}`);
console.log(`Full-batch snapshot estimate: ${cost / scale}.${(cost % scale).toString().padStart(18, '0')} PROVE`);
if (body.estimatedTotalCostWithFeeAllowanceWei != null) {
  const bufferedCost = BigInt(body.estimatedTotalCostWithFeeAllowanceWei);
  console.log(`Base-fee allowance for new requests: ${body.newRequestBaseFeeBufferBps / 100}% above the refreshed snapshot; PGU price caps unchanged.`);
  console.log(`Full-batch estimate including that allowance: ${bufferedCost / scale}.${(bufferedCost % scale).toString().padStart(18, '0')} PROVE`);
}
console.log(body.feeCaveat);
console.log(body.fundingPolicy);
console.log(body.policyWarning);
console.log('This submits to Succinct, not to the on-chain wash-trading registry.');
console.log('No top-up or replacement paid request is made automatically.');
JS

DIGEST="$(node - "$QUOTE" <<'JS'
const fs = require('node:fs');
process.stdout.write(JSON.parse(fs.readFileSync(process.argv[2])).digest);
JS
)"

node "$SCRIPT" preflight "$QUOTE" "$DIGEST"

read -r -p "Type PROVE ALL to approve the quoted queue, or anything else to stop: " CONFIRM </dev/tty
if [[ "$CONFIRM" != "PROVE ALL" ]]; then
  echo "Stopped without submitting."
  exit 0
fi

trap 'unset NETWORK_PRIVATE_KEY UNLOCKED' EXIT
echo "Unlock antseed-verification-deployer locally. Do not share the password or key."
UNLOCKED="$(cast wallet decrypt-keystore antseed-verification-deployer </dev/tty)"
if [[ "$UNLOCKED" =~ (0x[0-9a-fA-F]{64}) ]]; then
  export NETWORK_PRIVATE_KEY="${BASH_REMATCH[1]}"
else
  echo "Could not read the decrypted key; stopped without submitting."
  exit 1
fi
unset UNLOCKED

if command -v caffeinate >/dev/null 2>&1; then
  caffeinate -i node "$SCRIPT" run "$QUOTE" "$DIGEST"
else
  node "$SCRIPT" run "$QUOTE" "$DIGEST"
fi
