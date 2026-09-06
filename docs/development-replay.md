# Frozen 30% seller development replay

This workflow executes the existing seller guest with `ALPHA_RETURN_BPS = 3000`.
It does not add a settlement-coverage requirement, change attribution, or claim
compliance with the pasted AIP-4 specification. No network requests or live-chain
transactions are made by the replay runner. Existing witnesses contain the
period-end storage proofs, so replay does not need Base RPC access.

## Inputs and provenance

`docs/proof-history/2026-09-05-alpha-return-30-development-replay.json` selects
54 supported sellers and preserves the five previously excluded sellers. It
uses the expanded authenticated returns for ClaudeNode, StrataCode, Argus AI,
and surplus-provider without changing their expected V or T. Other sellers
reuse their saved historical inputs. Old lists and artifacts are not changed.

The runner verifies every source hash in the reproducible guest attestation and
the ELF hash before starting. Every output must match the selected seller,
period, evidence digest, V, T, and 30% guest vkey. Witness hashes are streamed
before and after execution, including inputs larger than Node's string limit.
The summary records input, executable, manifest, ELF, and artifact hashes.
Resuming requires matching provenance; it never silently accepts an old 50%
artifact as a 30% proof.

## Run

```sh
cargo test --features sp1 -p loop-host --bin wash-trading-prove-seller
cargo build --release --features sp1 -p loop-host --bin wash-trading-prove-seller
node scripts/replay-seller-development.mjs \
  docs/proof-history/2026-09-05-alpha-return-30-development-replay.json \
  /absolute/path/to/new-output-directory
```

The runner uses at most two simultaneous guest executions and writes progress
atomically to `summary.json`. Outputs are in `sellers/`, and complete execution
logs are in `logs/`. Re-run the same command to resume an interrupted run.

The host also accepts an already materialized input directly:

```sh
target/release/wash-trading-prove-seller --development \
  --seller 0x0123456789012345678901234567890123456789 \
  --seller-input /absolute/path/to/seller-input.json \
  --seller-elf /absolute/path/to/attested/seller-guest \
  --output /absolute/path/to/development.json
```

`--seller-input` cannot be mixed with `--evidence`, legacy `--claim`, or
`--total-volume-witness`. The input's seller must match `--seller`. Native
predicate verification and actual guest execution still run, and their public
values must agree before a development artifact is produced.

## Local contract submission

```sh
node scripts/check-development-replay-anvil.mjs \
  /absolute/path/to/new-output-directory/summary.json \
  /absolute/path/to/contracts-checkout/packages/contracts \
  /absolute/path/to/new-anvil-report-directory
```

This can run while guest execution is in progress. Each successful artifact is
passed to the contracts worktree's existing Anvil E2E test, which creates its own
local chain and verifies staging, all block-authentication chunks, finalization,
stored V/T, and the ratio getter. Tests also reject use of an absent real
Chainlink store. The report pins the registry, interface, mock, and test source
hashes. Use a fresh Anvil report directory for another test run.

These are **development/mock proofs**, not cryptographically sound production
Groth16 proofs. The local verifier and BlockhashStore are development mocks.
Successful Anvil tests establish transaction-flow and ABI compatibility, not
production proof verification or live canonical BlockhashStore coverage.

## Production blockers

### Measured proving preparation

`wash-trading-prove-seller --execute-only` now records `proverGasUnits` from SP1's
gas-enabled execution report. Instruction counts are not used as a proxy for PGU.
The guest, public values, evidence, and 30% predicate remain unchanged.

```sh
node scripts/prepare-seller-proving.mjs \
  docs/proof-history/2026-09-05-alpha-return-30-development-replay.json \
  /absolute/path/to/completed-development/summary.json \
  /absolute/path/to/pinned-pgu-prover \
  /absolute/path/to/new-estimate-directory
```

This executes without requester credentials or paid requests. It checks the
attested guest, saved input hashes, and every estimate's public values against
the completed development replay. Estimates resume only with matching provenance.
Existing development artifacts are not overwritten.

For a separately approved, single-seller production canary:

```sh
node scripts/submit-frozen-seller-canary.mjs prepare \
  docs/proof-history/2026-09-05-alpha-return-30-development-replay.json \
  /absolute/path/to/completed-development/summary.json \
  /absolute/path/to/estimate-directory \
  /absolute/path/to/new-canary-directory \
  0xYourFundedRequesterAddress
node scripts/submit-frozen-seller-canary.mjs preflight \
  /absolute/path/to/new-canary-directory/canary-quote.json APPROVED_DIGEST
```

Preparation selects the lowest measured-PGU successful seller, pins the source,
input, estimate, executable, and guest hashes, and obtains live auction pricing.
It does not require the entire batch's estimates to finish. `preflight` makes no
paid requests. Only `submit` (in place of `preflight`) sends a paid request, with
an explicitly approved digest and a locally configured `NETWORK_PRIVATE_KEY`.
The requester must match the quote and have sufficient available network balance.
The current quote explicitly retains the unresolved AIP-4 policy differences.

The host enforces `--max-prover-gas` against measured execution and pins the
request's gas and cycle limits to that execution, avoiding a redundant network
SDK simulation. The PGU price cap is enforced, but the base fee is fetched again
inside the SDK: the displayed total is a snapshot estimate, not a guaranteed
total-fee cap. An increased base fee detected before launch blocks a new request.

Keep each request checkpoint. If a launch stops before its request ID is saved,
the canary runner refuses to blindly resubmit: reconcile network history first.
A stale execution lock similarly needs operator review, not automatic deletion.
Proving does not require BlockhashStore writes to finish; registry submission
still requires live canonical hash availability and separate authorization.

### Full production queue

Once all selected sellers have successful PGU estimates, prepare the full queue:

```sh
node scripts/submit-frozen-seller-batch.mjs prepare \
  docs/proof-history/2026-09-05-alpha-return-30-development-replay.json \
  /absolute/path/to/completed-development/summary.json \
  /absolute/path/to/estimate-directory \
  /absolute/path/to/new-batch-directory \
  0xYourFundedRequesterAddress \
  /absolute/path/to/existing-canary-directory
bash scripts/run-frozen-seller-batch.sh \
  /absolute/path/to/new-batch-directory/batch-quote.json
```

Preparation requires a complete, unique-seller estimate set matching the frozen
replay. The batch approval binds every per-seller quote and reuses the original
canary directory, so a previously paid canary is not requested in a new location.
The shell launcher shows the full snapshot estimate, validates inputs without
signing, requires `PROVE ALL`, then unlocks the named Foundry keystore locally.

This is a local sequential queue, not an immediate submission of 54 concurrent
requests. It generates and verifies one proof before starting the next. Each new
request checks the funded requester and current available PROVE; insufficient
funds pause the queue without automatically topping up. Fund that same network
requester and rerun the same launcher to resume. A saved paid request can still
be retrieved when available balance is zero; only new requests require funds.

The batch saves verified artifact hashes and skips those completed entries on
restart. It preserves per-seller request checkpoints for interrupted work and
stops on ambiguous submissions, request failures, changed inputs or fee/approval
problems instead of silently paying for replacements. Expired quotes can resume
already-created requests; new requests need unexpired approval. Do not delete
checkpoints, submission markers, or locks to force a retry. No on-chain registry
submission is part of this queue.

- Buyer funding completeness and direct-USDC signer attribution remain unresolved.
- Return/hop calibration differs from the pasted AIP-4 near-unity constraints.
- Zero/partial denominator handling and enforcement-policy alignment need resolution.
- Live BlockhashStore coverage must be checked for the final evidence set.
- Production proofs must be generated and checked against the appropriate real
  verifier after the rule and registry configuration are finalized.

`productionReady` and `aip4Compliant` stay false even when every development
execution and local submission test succeeds. Do not use completion of this
replay as authorization for a paid prover-network request or Base submission.
