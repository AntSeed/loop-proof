import assert from "node:assert/strict";
import test from "node:test";
import { reconcileDevelopmentProofResults } from "./reconcile-development-proof-results.mjs";

test("verified direct seller proofs promote only matching proof candidates", () => {
  const seller = address("candidate");
  const claimId = hash("a");
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
      reportRoot: hash("d"),
      claims: [{ claimId, subjects: [seller], metrics: { qualifiedVolumeRaw: "60" } }],
    },
    sellerProofs: [proof(seller, claimId)],
    diagnostics: [{ seller, selectedSettlementRaw: "60", sellerVolumeRaw: "100", selectedShareBps: 6000 }],
  });
  assert.equal(result.discovery.candidates[0].state, "proof_validated");
  assert.equal(result.discovery.candidates[0].proof.provenWashVolumeRaw, "60");
  assert.equal(result.discovery.candidates[0].proof.totalSellerVolumeRaw, "100");
  assert.equal(result.discovery.candidates[1].state, "complete_no_loop");
  assert.equal(result.report.totalProvenWashVolumeRaw, "60");
  assert.equal(result.report.totalSellerVolumeRaw, "100");
  assert.equal(result.report.proofArchitecture, "direct-seller-v1");
});

test("recursive or unverified artifacts are rejected", () => {
  const seller = address("candidate");
  const claimId = hash("a");
  const base = {
    discovery: { version: 1, kind: "antseed-p0-loop-discovery", candidates: [] },
    bundle: { version: 1, kind: "antseed-wash-trading-proof-bundle", claims: [{ claimId, subjects: [seller] }] },
  };
  assert.throws(() => reconcileDevelopmentProofResults({
    ...base,
    sellerProofs: [{ ...proof(seller, claimId), proofArchitecture: "recursive" }],
  }), /invalid development direct seller proof/);
  assert.throws(() => reconcileDevelopmentProofResults({
    ...base,
    sellerProofs: [{ ...proof(seller, claimId), verified: false }],
  }), /invalid development direct seller proof/);
  assert.throws(() => reconcileDevelopmentProofResults({
    ...base,
    sellerProofs: [{ ...proof(seller, claimId), totalSellerVolumeRaw: undefined }],
  }), /invalid development direct seller proof/);
  for (const mutation of [
    { evidenceFormat: undefined }, { claimCount: 2 },
    { sourceClaimIds: [] }, { sourceClaimIds: [claimId, hash("b")] },
    { sourceClaimIds: "a" },
  ]) {
    assert.throws(() => reconcileDevelopmentProofResults({
      ...base,
      sellerProofs: [{ ...proof(seller, claimId), ...mutation }],
    }), /invalid development direct seller proof/);
  }
});

function proof(seller, claimId) {
  return {
    version: 3,
    kind: "antseed-wash-trading-seller-proof",
    proofArchitecture: "direct-seller-v1",
    evidenceFormat: "single-bundle-v1",
    claimCount: 1,
    securityMode: "development",
    proved: true,
    verified: true,
    seller,
    sourceClaimIds: [claimId],
    sellerProgramVKey: hash("v"),
    publicValues: "0x12",
    proofBytes: "0x34",
    provenWashVolumeRaw: "60",
    totalSellerVolumeRaw: "100",
    evidenceDigest: hash("e"),
    blockAuthenticationRoot: hash("b"),
  };
}

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
