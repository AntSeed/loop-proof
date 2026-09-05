import assert from "node:assert/strict";
import test from "node:test";
import { ALPHA_RETURN_BPS, PREDICATE_POLICY, PREDICATE_POLICY_HASH, isCurrentPolicyCheckpoint } from "./predicate-policy.mjs";
import { requiredReturnRaw } from "./return-path-selection.mjs";
import { evaluateClosedLoopCandidate, supportedSettlementCapacity } from "./build-discovery-proof-bundle.mjs";

test("all planning stages use the current 30-percent predicate floor", () => {
  assert.equal(ALPHA_RETURN_BPS, 3000n);
  assert.equal(PREDICATE_POLICY.alphaReturnBps, 3000);
  assert.match(PREDICATE_POLICY_HASH, /^[0-9a-f]{64}$/);
  assert.equal(requiredReturnRaw(101n), 31n);
  assert.equal(supportedSettlementCapacity([{ amountRaw: "90" }], [{ amountRaw: "30" }]), 100n);
  const candidate = { sellerVolumeRaw: "1000", settlements: [{ amountRaw: "100" }], fundings: [{ amountRaw: "90" }] };
  assert.equal(evaluateClosedLoopCandidate({ ...candidate, paths: [{ amountRaw: "30" }] }).accepted, true);
  assert.equal(evaluateClosedLoopCandidate({ ...candidate, paths: [{ amountRaw: "29" }] }).accepted, false);
});

test("legacy and other-policy checkpoints are not reusable", () => {
  assert.equal(isCurrentPolicyCheckpoint({ version: 2 }), false);
  assert.equal(isCurrentPolicyCheckpoint({ version: 3, predicatePolicyHash: "old-50-percent" }), false);
  assert.equal(isCurrentPolicyCheckpoint({ version: 3, predicatePolicyHash: PREDICATE_POLICY_HASH }), true);
});
