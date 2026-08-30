import assert from "node:assert/strict";
import test from "node:test";
import { mergeProofPlans } from "./merge-proof-plans.mjs";

test("plan merging refreshes report and claim memberships", () => {
  const hashes = [`0x${"01".repeat(32)}`, `0x${"02".repeat(32)}`];
  const bundle = {
    version: 1,
    chainId: 8453,
    reportRoot: `0x${"03".repeat(32)}`,
    period: { startBlock: 1, endBlockExclusive: 10 },
    claims: [
      { claimId: "a", leafHash: hashes[0] },
      { claimId: "b", leafHash: hashes[1] },
    ],
  };
  const claim = (claimId, block) => ({
    claimId,
    reportRoot: "old",
    selectedBlocks: [block],
    selectedEvidence: [{ evidenceType: "SETTLEMENT", dependencyLeaf: "leaf", dependencyMembership: { steps: [] } }],
  });
  const merged = mergeProofPlans(bundle, [{ claims: [claim("a", 3)] }, { claims: [claim("b", 2)] }]);
  assert.equal(merged.claimCount, 2);
  assert.deepEqual(merged.evidenceBlockSelection.materializationBlockNumbers, [2, 3]);
  assert.ok(merged.claims.every((entry) => entry.reportRoot === bundle.reportRoot && entry.claimMembership.steps.length === 1));
  assert.equal("dependencyLeaf" in merged.claims[0].selectedEvidence[0], false);
  assert.equal("dependencyMembership" in merged.claims[0].selectedEvidence[0], false);
});
