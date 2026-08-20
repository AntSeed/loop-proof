import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildCoverageReport } from "./report-wash-trading-proof-coverage.mjs";

test("coverage report deduplicates settlement logs across policies", () => {
  const dependencyLeaf = JSON.stringify({
    evidenceType: "SETTLEMENT",
    transactionHash: `0x${"1".repeat(64)}`,
    logIndex: 7,
    amountRaw: "1000000000",
  });
  const bundle = {
    version: 1,
    chainId: 8_453,
    reportRoot: `0x${"2".repeat(64)}`,
    period: { startBlock: 1, endBlockExclusive: 2 },
    claims: [
      { claimId: "cohort", type: "P1_COORDINATED_CONTROL", subjects: ["seller"], metrics: { qualifiedVolumeRaw: "2000000000" } },
      { claimId: "pair", type: "P0_RECIPROCAL", subjects: ["a", "b"], metrics: { volumeAToBRaw: "600000000", volumeBToARaw: "400000000" } },
    ],
  };
  const selected = { dependencyId: "dependency", evidenceType: "SETTLEMENT", receiptLogIndex: 7, dependencyLeaf };
  const plan = {
    version: 1,
    reportRoot: bundle.reportRoot,
    claimCount: 2,
    claims: [
      { claimId: "cohort", type: "P1_COORDINATED_CONTROL", subjects: ["seller"], selectedEvidence: [selected], selectedBlocks: [1], checkpointWindows: [] },
      { claimId: "pair", type: "P0_RECIPROCAL", subjects: ["a", "b"], selectedEvidence: [{ ...selected, evidenceType: "RECIPROCAL_SETTLEMENT" }], selectedBlocks: [1], checkpointWindows: [] },
    ],
  };
  const report = buildCoverageReport(bundle, plan);
  assert.equal(report.authenticatedSelectedVolume.uniqueAcrossAllClaimsRaw, "1000000000");
  assert.equal(report.authenticatedSelectedVolume.cohortRawBeforeCrossPolicyDeduplication, "1000000000");
  assert.equal(report.authenticatedSelectedVolume.reciprocalRawBeforeCrossPolicyDeduplication, "1000000000");
  assert.equal(report.reportRootClassifiedVolume.combinedRawNotDeduplicated, "3000000000");
});

test("coverage report rejects forged result journal digests", () => {
  const { bundle, plan, results } = coverageFixture();
  results.entries[0].journalDigest = `0x${"0".repeat(64)}`;
  assert.throws(() => buildCoverageReport(bundle, plan, results), /journal digest mismatch/);
});

test("coverage report rejects result identity changes", () => {
  const { bundle, plan, results } = coverageFixture();
  results.entries[0].subjects = ["attacker"];
  assert.throws(() => buildCoverageReport(bundle, plan, results), /result identity differs/);
});

function coverageFixture() {
  const reportRoot = `0x${"2".repeat(64)}`;
  const dependencyLeaf = JSON.stringify({
    evidenceType: "SETTLEMENT",
    transactionHash: `0x${"1".repeat(64)}`,
    logIndex: null,
    amountRaw: "1000000000",
  });
  const selectedEvidence = [{ dependencyId: "dependency", evidenceType: "SETTLEMENT", receiptLogIndex: 7, dependencyLeaf }];
  const bundle = {
    version: 1,
    chainId: 8_453,
    reportRoot,
    period: { startBlock: 1, endBlockExclusive: 2 },
    claims: [{ claimId: "cohort", type: "P1_COORDINATED_CONTROL", subjects: ["seller"], metrics: { qualifiedVolumeRaw: "1000000000" } }],
  };
  const plan = {
    version: 1,
    reportRoot,
    claimCount: 1,
    claims: [{ claimId: "cohort", type: "P1_COORDINATED_CONTROL", subjects: ["seller"], selectedEvidence, selectedBlocks: [1], checkpointWindows: [] }],
  };
  const journalBytes = "0x01";
  const journalDigest = `0x${createHash("sha256").update(Buffer.from("01", "hex")).digest("hex")}`;
  const results = {
    version: 1,
    kind: "antseed-wash-trading-proof-results",
    chainId: 8_453,
    reportRoot,
    securityMode: "execute-only",
    entries: [{
      claimId: "cohort",
      claimType: "P1_COORDINATED_CONTROL",
      subjects: ["seller"],
      imageId: "1".repeat(64),
      journalBytes,
      journalDigest,
      selectedEvidence,
      selectedBlocks: [1],
      checkpointWindows: [],
    }],
  };
  return { bundle, plan, results };
}
