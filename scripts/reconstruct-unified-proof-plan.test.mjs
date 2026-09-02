import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { finalizeBundle, finalizeClaim } from "./proof-bundle.mjs";
import { planClaim, attachMemberships } from "./proof-planner.mjs";
import { reconstructUnifiedProofPlan } from "./reconstruct-unified-proof-plan.mjs";

test("reconstruction reuses reciprocal evidence and rebuilds closed-loop memberships", async () => {
  const startBlock = 44_471_575;
  const directory = await mkdtemp(join(tmpdir(), "wash-plan-reuse-"));
  const reciprocal = finalizeClaim({
    type: "P0_RECIPROCAL",
    subjects: ["a", "b"],
    walletA: "a",
    walletB: "b",
    metrics: { volumeAToBRaw: "1", volumeBToARaw: "1" },
    dependencies: [settlement("ab", "a", "b", "RECIPROCAL_SETTLEMENT", startBlock + 1), settlement("ba", "b", "a", "RECIPROCAL_SETTLEMENT", startBlock + 2)],
  });
  const closed = finalizeClaim({
    type: "P0_CLOSED_LOOP",
    subjects: ["seller"],
    approvedBuyers: ["buyer"],
    approvedFunders: ["seller"],
    metrics: { qualifiedVolumeRaw: "1", qualifiedBuyerCount: 1 },
    dependencies: [funding("fund", startBlock), settlement("settle", "buyer", "seller", "SETTLEMENT", startBlock + 1)],
  });
  const bundle = finalizeBundle({ version: 1, chainId: 8453, period: { startBlock, endBlockExclusive: startBlock + 10 }, claims: [reciprocal, closed] });
  const reciprocalPlan = attachMemberships(planClaim(reciprocal, reciprocal.dependencies, bundle), reciprocal, bundle.claims);
  await writeFile(join(directory, `000-${reciprocal.claimId.slice(2, 18)}.plan.json`), JSON.stringify({ version: 2, kind: "antseed-wash-trading-proof-plan-shard", chainId: 8453, period: bundle.period, claims: [reciprocalPlan] }));
  const outPath = join(directory, "plan.json");
  await reconstructUnifiedProofPlan({ bundle, shardDirectory: directory, outPath });
  const plan = JSON.parse(await readFile(outPath, "utf8"));
  assert.equal(plan.reportRoot, bundle.reportRoot);
  assert.equal(plan.claimCount, 2);
  assert.deepEqual(plan.evidenceBlockSelection.materializationBlockNumbers, [startBlock, startBlock + 1, startBlock + 2]);
  assert.ok(plan.claims.every((claim) => claim.claimMembership != null && claim.claimLeaf != null));
  assert.ok(plan.claims.flatMap((claim) => claim.selectedEvidence).every((entry) => entry.dependencyMembership != null && entry.dependencyLeaf != null));
});

function settlement(id, buyer, seller, evidenceType, blockNumber) {
  return { dependencyId: id, evidenceType, buyer, seller, amountRaw: "1", blockNumber, transactionIndex: 0, logIndex: 0 };
}
function funding(id, blockNumber) {
  return { dependencyId: id, evidenceType: "USDC_FUNDING", buyer: "buyer", funder: "seller", amountRaw: "1", blockNumber, transactionIndex: 0, logIndex: 0 };
}
