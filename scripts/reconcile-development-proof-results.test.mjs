import assert from "node:assert/strict";
import test from "node:test";
import { reconcileDevelopmentProofResults } from "./reconcile-development-proof-results.mjs";

test("verified child proofs promote only matching proof candidates", () => {
  const result = reconcileDevelopmentProofResults({
    discovery: {
      version: 1,
      kind: "antseed-p0-loop-discovery",
      counts: {},
      candidates: [candidate("candidate", "proof_candidate"), candidate("clean", "complete_no_loop")],
    },
    bundle: {
      version: 1,
      kind: "antseed-wash-trading-proof-bundle",
      claims: [{ claimId: hash("a"), subjects: [address("candidate")], metrics: { qualifiedVolumeRaw: "60" } }],
    },
    childProofs: [{
      version: 1,
      kind: "antseed-wash-trading-development-child-proof",
      securityMode: "development",
      verified: true,
      sourceClaimId: hash("a"),
      programId: hash("b"),
      programVKey: hash("c"),
      publicValues: "0x12",
      proofBytes: "0x34",
      proofPath: "/tmp/candidate.proof.bin",
    }],
    aggregate: {
      version: 1,
      kind: "antseed-wash-trading-aggregate-proof",
      securityMode: "development",
      childCount: 1,
      sourceClaimCount: 1,
      reportRoot: hash("d"),
      aggregatorProgramId: hash("e"),
      aggregatorProgramVKey: hash("f"),
      provenWashVolumeRaw: "60",
    },
    diagnostics: [{ seller: address("candidate"), selectedSettlementRaw: "60", sellerVolumeRaw: "100", selectedShareBps: 6000, retainedFundingRaw: "90", bottleneckReturnRaw: "18" }],
  });
  assert.equal(result.discovery.candidates[0].state, "proof_validated");
  assert.equal(result.discovery.candidates[0].proof.proofPath, "/tmp/candidate.proof.bin");
  assert.equal(result.discovery.candidates[1].state, "complete_no_loop");
  assert.equal(result.discovery.counts.proof_validated, 1);
  assert.equal(result.report.sellers.length, 2);
  assert.equal(result.report.sellers[0].maximumProvableSellerVolumeShareBps, 6000);
});

test("unverified child proof artifacts are rejected", () => {
  assert.throws(() => reconcileDevelopmentProofResults({
    discovery: { version: 1, kind: "antseed-p0-loop-discovery", candidates: [] },
    bundle: { version: 1, kind: "antseed-wash-trading-proof-bundle", claims: [] },
    childProofs: [{ version: 1, kind: "antseed-wash-trading-development-child-proof", securityMode: "development", verified: false }],
    aggregate: { version: 1, kind: "antseed-wash-trading-aggregate-proof", securityMode: "development" },
  }), /invalid development child proof/);
});

function candidate(seed, state) {
  return {
    seller: address(seed),
    displayName: seed,
    state,
    eligibility: { sellerVolumeRaw: "100" },
    traceCoverage: { requested: 3, completed: 3, unresolved: [] },
    pathCount: state === "proof_candidate" ? 3 : 0,
    bottleneckReturnRaw: state === "proof_candidate" ? "18" : "0",
    convergences: state === "proof_candidate" ? [{ destination: address("hub") }] : [],
  };
}

function address(seed) {
  return `0x${Buffer.from(seed).toString("hex").padEnd(40, "0").slice(0, 40)}`;
}

function hash(seed) {
  return `0x${Buffer.from(seed).toString("hex").padEnd(64, "0").slice(0, 64)}`;
}
