# Production seller proofs — 54 sellers, 30% return threshold

This package contains all 54 completed Succinct production proofs that passed
full submission on a Base mainnet fork on September 6, 2026. The compressed
artifacts unpack to the exact original bytes: public values, proof bytes,
block references, and Merkle paths are unchanged.

**No proof generation, Succinct access, private witness files, or PROVE credits
are needed to submit these proofs.** The submitting wallet needs Base ETH for
transaction fees. It need not be the contract deployer or the proving requester.

## Contents and validation

- `manifest.json`: seller names, original/compressed SHA-256 checksums, proof IDs,
  deployment settings, and totals.
- `artifacts/*.json.gz`: 54 original production artifacts, about 16.2 MB compressed.
- `anvil-validation.json`: all 54 successful local results and their receipt hashes.
- `anvil-seller-results.csv`: named per-seller wash/total volumes and local results.

The run authenticated 384,375 block-reference occurrences in 3,867 chunks.
All 232,400 unique required block hashes were present in the real Chainlink store.
All 54 proofs staged and finalized using the real SP1 verifier, with no verifier
or store mocks and no storage/code overrides.

Totals: **146,692.697298 USDC wash volume**, **190,205.878768 USDC total seller volume**.

The Anvil run used 611 submission transactions by batching eight authentication
chunks per transaction through a forwarding helper. The direct-call instructions
below require **3,975 transactions** for a fresh registry: 54 stages, 3,867 chunk
authentications, and 54 finalizations. They do not require a helper deployment.
This is slower and adds transaction overhead. Have sufficient ETH, review current
fees, and consider reviewed batching tooling for a faster production submission.
No total ETH spending cap is provided by the example loop below.

**All addresses and transaction hashes in the Anvil result files are local-fork
results, not mainnet deployment addresses or receipts.**

## 1. Deploy and check the correct registry

Use the updated `AntseedWashTradingRegistry` from merged AntSeed/antseed PR #895,
commit `1d647bd4aa88afc86f9a30a925841bfd200d7277` (registry source also at `843f1fd66`).
Deploy on Base mainnet, chain ID **8453**, with these exact values:

```ini
SP1_VERIFIER=0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2
SP1_VERIFIER_HASH=0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696
WASH_TRADING_BLOCKHASH_STORE=0x78b69899C8cD252126cBB1A50171ec37286C3877
WASH_TRADING_SELLER_PROGRAM_VKEY=0x0028d499469d8bdb345427dccf15bbbf3f1c582625a0a5690e7ac3576ef6ed99
HISTORICAL_PERIOD_START_BLOCK=44471575
HISTORICAL_PERIOD_END_BLOCK=50672526
```

These settings are public, not signing keys. The package does not select a
mainnet registry address: get the actual new deployment address from the deployer.
Do not copy a test registry address from the Anvil reports.

## 2. Verify and prepare locally

Prerequisites: Node.js 20+ and Foundry `cast` on PATH. No npm installation or Rust
build is required. Run from the root of the `AntSeed/loop-proof` checkout containing
this package:

```bash
PACKAGE=proofs/2026-09-06-vt30
node scripts/published-seller-proofs.mjs verify "$PACKAGE"
node scripts/published-seller-proofs.mjs prepare "$PACKAGE" out/vt30-submission
```

Both commands are offline. Preparation requires a new output directory and
refuses to overwrite one. It decompresses and checks every artifact, verifies its
proof ID, and writes per-seller `artifact.json`, `proof-id.txt`, `stage.hex`,
`chunks/00000.hex` onward, and `finalize.hex`. `prepared.json` is written only after
all sellers are prepared. The generated calls were independently compared against
ethers ABI encoding for all 3,975 calls.

Set your own RPC and the real registry address locally; never commit RPC secrets:

```bash
export ETH_RPC_URL='YOUR_BASE_MAINNET_RPC_URL'
export REGISTRY='ACTUAL_DEPLOYED_REGISTRY_ADDRESS'
node scripts/published-seller-proofs.mjs check-deployment "$PACKAGE" "$REGISTRY"
```

This check is **read-only**. It verifies chain ID, registry/verifier/store runtime
bytecode hashes, and all six deployed settings. A different compiler or metadata
can change the registry code hash even when the source is similar. If it fails,
stop and review the actual build/deployment; do not bypass the check to submit.

## 3. Submit through your own signer

For each seller, in order:

1. If `proofFinalized(proofId)` is already true, skip that proof.
2. If `proofStaged(proofId)` is false, send `stage.hex`.
3. For each chunk whose `proofBlockChunkAuthenticated(proofId,index)` is false,
   send that chunk's `.hex` file.
4. Send `finalize.hex`. Check `proofFinalized(proofId)` and the seller's V/T getters.

The contract signatures are:

```text
stageSellerProof(bytes publicValues, bytes proofBytes)
authenticateBlockReferences(bytes32 proofId, uint32 chunkIndex, (uint64 number, bytes32 blockHash)[] references, bytes32[] proof)
finalizeSellerProof(bytes32 proofId)
```

Do not alter the proof bytes or re-encode the journal with a different schema.
The root is committed into the proof; every chunk is required before finalization.

### Reviewed direct-call example (Bash)

This example **spends real Base ETH** when pointed at mainnet. Review it first.
Use your own encrypted Foundry keystore account. For unattended keystore access,
Foundry's `ETH_PASSWORD` variable is a **path to a password file**, not the password
itself. Store that file outside the repository with mode `600`, and remove it when
finished. Otherwise Foundry prompts for the password on each signing operation.
Never use the public Anvil test key on mainnet.
Read-only calls below clear `ETH_PASSWORD` for that command only: Foundry otherwise
requires a keystore even for `cast call`. Signing commands keep the password file.

Run the preparation and read-only deployment check above first. Then, in Bash:

```bash
set -euo pipefail
set +x
export ACCOUNT='YOUR_FOUNDRY_KEYSTORE_ACCOUNT'
PACKAGE=proofs/2026-09-06-vt30
PREPARED=out/vt30-submission
test -f "$PREPARED/prepared.json"
node scripts/published-seller-proofs.mjs check-deployment "$PACKAGE" "$REGISTRY"
SENDER="$(cast wallet address --account "$ACCOUNT")"
echo "Submit up to 3,975 direct transactions from $SENDER to $REGISTRY on Base."
read -r -p "Type SUBMIT $REGISTRY to continue: " APPROVAL </dev/tty
test "$APPROVAL" = "SUBMIT $REGISTRY"

send_file() {
  local calldata_file="$1" receipt_file="$2" latest_nonce pending_nonce
  latest_nonce="$(env -u ETH_PASSWORD cast nonce "$SENDER" --block latest)"
  pending_nonce="$(env -u ETH_PASSWORD cast nonce "$SENDER" --block pending)"
  if [[ "$latest_nonce" != "$pending_nonce" ]]; then
    echo "STOP: this wallet has a pending transaction. Resolve it before continuing."
    exit 1
  fi
  cast send "$REGISTRY" "$(cat "$calldata_file")" \
    --account "$ACCOUNT" --confirmations 2 --json > "$receipt_file"
  node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1])); if(BigInt(r.status)!==1n) process.exit(1)' "$receipt_file"
}

for DIR in "$PREPARED"/0x*; do
  PROOF_ID="$(cat "$DIR/proof-id.txt")"
  DONE="$(env -u ETH_PASSWORD cast call "$REGISTRY" 'proofFinalized(bytes32)(bool)' "$PROOF_ID")"
  if [[ "$DONE" == true ]]; then continue; fi
  mkdir -p "$DIR/receipts"
  STAGED="$(env -u ETH_PASSWORD cast call "$REGISTRY" 'proofStaged(bytes32)(bool)' "$PROOF_ID")"
  if [[ "$STAGED" == false ]]; then
    send_file "$DIR/stage.hex" "$DIR/receipts/stage.json"
  elif [[ "$STAGED" != true ]]; then
    echo 'Unexpected stage state'; exit 1
  fi
  for CHUNK in "$DIR"/chunks/*.hex; do
    CHUNK_NAME="$(basename "$CHUNK" .hex)"
    INDEX=$((10#$CHUNK_NAME))
    AUTHENTICATED="$(env -u ETH_PASSWORD cast call "$REGISTRY" 'proofBlockChunkAuthenticated(bytes32,uint32)(bool)' "$PROOF_ID" "$INDEX")"
    if [[ "$AUTHENTICATED" == false ]]; then
      send_file "$CHUNK" "$DIR/receipts/chunk-$CHUNK_NAME.json"
    elif [[ "$AUTHENTICATED" != true ]]; then
      echo 'Unexpected chunk state'; exit 1
    fi
  done
  send_file "$DIR/finalize.hex" "$DIR/receipts/finalize.json"
  DONE="$(env -u ETH_PASSWORD cast call "$REGISTRY" 'proofFinalized(bytes32)(bool)' "$PROOF_ID")"
  test "$DONE" = true
  echo "Finalized $(basename "$DIR")"
done
```

The loop uses on-chain state to skip mined stages/chunks/proofs; it does not
regenerate proofs. Do not run concurrent submitters with the same wallet. If a
send times out or its result is ambiguous, inspect the wallet's transactions and
receipts first. Do not blindly replace a pending transaction or reset its nonce.
After confirming its outcome, rerun against the **same registry** and untouched
prepared files. Re-check deployment settings if changing RPC or registry.

For a seller, check recorded values with:

```bash
env -u ETH_PASSWORD cast call "$REGISTRY" 'provenWashVolume(address)(uint128)' "$SELLER"
env -u ETH_PASSWORD cast call "$REGISTRY" 'totalSellerVolume(address)(uint128)' "$SELLER"
env -u ETH_PASSWORD cast call "$REGISTRY" 'provenWashShareBps(address)(uint256)' "$SELLER"
```

V and T are raw USDC units (six decimals). Expected values are in `manifest.json`.
If another proof has already recorded an equal or stronger V, finalization can
reject this proof; investigate the existing seller record rather than altering
the proof.

## Scope and caveats

This package establishes acceptance by the tested registry for the existing 30%
predicate. It does **not** resolve the previously identified AIP-4 cumulative
funding-completeness or direct-USDC attribution gaps. `aip4Compliant` remains false.
Reward/slashing policy deployment and activation are separate from recording these
proofs. No mainnet transactions were submitted while preparing this package.
