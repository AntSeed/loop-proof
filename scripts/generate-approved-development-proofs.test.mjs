import assert from "node:assert/strict";
import test from "node:test";
import {
  buildApprovedBatchSummary,
  validateApprovedSet,
} from "./generate-approved-development-proofs.mjs";

test("approved development summary requires and totals every claim", () => {
  const bundle = fixtureBundle();
  const plan = fixturePlan();
  assert.deepEqual(buildApprovedBatchSummary(bundle, plan), {
    reportRoot: bundle.reportRoot,
    period: bundle.period,
    approvedClaimCount: 2,
    approvedSellerCount: 3,
    closedLoopVolumeRaw: "100",
    reciprocalVolumeRaw: "70",
    uniqueSuspectedVolumeRaw: "170",
    uniqueSettlementCount: 3,
  });
});

test("approved development summary rejects partial plans", () => {
  const plan = fixturePlan();
  plan.claims.pop();
  plan.claimCount = 1;
  assert.throws(() => validateApprovedSet(fixtureBundle(), plan), /partial proof plan/);
});

function fixtureBundle() {
  return {
    version: 1,
    kind: "antseed-wash-trading-proof-bundle",
    chainId: 8_453,
    reportRoot: `0x${"1".repeat(64)}`,
    period: { startBlock: 10, endBlockExclusive: 20 },
    claims: [
      { claimId: "closed", type: "P0_CLOSED_LOOP", subjects: ["seller"], metrics: { qualifiedVolumeRaw: "100" } },
      { claimId: "pair", type: "P0_RECIPROCAL", subjects: ["a", "b"], metrics: { volumeAToBRaw: "30", volumeBToARaw: "40" } },
    ],
  };
}

function fixturePlan() {
  const period = { startBlock: 10, endBlockExclusive: 20 };
  return {
    version: 2,
    kind: "antseed-wash-trading-proof-plan",
    chainId: 8_453,
    reportRoot: `0x${"1".repeat(64)}`,
    period,
    claimCount: 2,
    claims: [
      {
        claimId: "closed",
        type: "P0_CLOSED_LOOP",
        selectedEvidence: [settlement("SETTLEMENT", "a", 0, "100")],
      },
      {
        claimId: "pair",
        type: "P0_RECIPROCAL",
        selectedEvidence: [
          settlement("RECIPROCAL_SETTLEMENT", "b", 0, "30"),
          settlement("RECIPROCAL_SETTLEMENT", "c", 1, "40"),
        ],
      },
    ],
  };
}

function settlement(evidenceType, transaction, logIndex, amountRaw) {
  return {
    evidenceType,
    transactionHash: `0x${transaction.repeat(64)}`,
    receiptLogIndex: logIndex,
    amountRaw,
  };
}
