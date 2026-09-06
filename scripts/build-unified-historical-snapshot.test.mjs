import assert from "node:assert/strict";
import test from "node:test";
import { readProofPlanSummary, validateSnapshotInputs } from "./build-unified-historical-snapshot.mjs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

function fixture() {
  const period = { startBlock: 10, endBlockExclusive: 20 };
  return {
    manifest: { status: "complete", request: { seller: null } },
    scan: { status: "complete", scanId: "scan", proofPeriod: period, counts: { sellers: 2 } },
    sellerCoverage: { complete: true, evaluated: ["a", "b"], incomplete: [] },
    proofCoverage: { source: { scanId: "scan" }, summary: { totalProofs: 1 } },
    bundle: { scanId: "scan", reportRoot: "root", period, claims: [{ claimId: "claim" }] },
    plan: { reportRoot: "root", period, claimCount: 1, claims: [{ claimId: "claim" }] },
  };
}

test("unified snapshot accepts one fully covered scan", () => {
  assert.doesNotThrow(() => validateSnapshotInputs(fixture()));
});

test("unified snapshot rejects missing sellers and partial plans", () => {
  const missingSeller = fixture();
  missingSeller.sellerCoverage.evaluated.pop();
  assert.throws(() => validateSnapshotInputs(missingSeller), /seller universe/);
  const partialPlan = fixture();
  partialPlan.plan.claims = [];
  partialPlan.plan.claimCount = 0;
  assert.throws(() => validateSnapshotInputs(partialPlan), /complete unified bundle/);
});

test("proof plan summary streams claim identities without loading the full plan", async () => {
  const directory = await mkdtemp(join(tmpdir(), "proof-plan-summary-"));
  const path = join(directory, "plan.json");
  await writeFile(path, JSON.stringify({ version: 2, reportRoot: "root", period: { startBlock: 1, endBlockExclusive: 2 }, claimCount: 2, claims: [{ claimId: "a", selectedEvidence: [{ payload: "x".repeat(10_000) }] }, { claimId: "b" }], evidenceBlockSelection: { materializationBlockNumbers: [1] } }));
  const summary = await readProofPlanSummary(path);
  assert.equal(summary.claimCount, 2);
  assert.deepEqual(summary.claims, [{ claimId: "a" }, { claimId: "b" }]);
});
