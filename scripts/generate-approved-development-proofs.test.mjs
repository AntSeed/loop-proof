import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  buildApprovedBatchSummary,
  countClaimMaterializationBlocks,
  isCurrentWitness,
  mapWithConcurrency,
  writeWitnessCacheMetadata,
  validateClaimMaterializationBlocks,
  validateApprovedSet,
  validateSnapshotLock,
} from "./generate-approved-development-proofs.mjs";

test("bounded worker queue preserves result order and concurrency", async () => {
  let active = 0;
  let maximumActive = 0;
  const results = await mapWithConcurrency([30, 5, 20, 10], 2, async (delay, index) => {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    await new Promise((resolveDelay) => setTimeout(resolveDelay, delay));
    active -= 1;
    return index;
  });
  assert.deepEqual(results, [0, 1, 2, 3]);
  assert.equal(maximumActive, 2);
});

test("bounded worker queue rejects invalid concurrency", async () => {
  await assert.rejects(() => mapWithConcurrency([1], 0, async () => {}), /positive integer/);
});

test("materialization block preflight mirrors relay expansion and deduplication", () => {
  const claim = {
    claimId: "claim",
    selectedEvidence: [
      { evidenceType: "SETTLEMENT", blockNumber: 10 },
      {
        evidenceType: "RELAY_PATH",
        sellerPayment: { blockNumber: 11 },
        relayForward: { blockNumber: 12 },
        funderReceipt: { blockNumber: 11 },
      },
    ],
  };
  assert.equal(countClaimMaterializationBlocks(claim, 19), 4);
  assert.equal(validateClaimMaterializationBlocks(claim, 19, 4), 4);
  assert.throws(() => validateClaimMaterializationBlocks(claim, 19, 3), /exceed predicate maximum/);
});

test("witness cache metadata binds identity, generator, size, and mtime", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wash-witness-cache-"));
  const witnessPath = join(directory, "witness.json");
  const claim = { claimId: `0x${"1".repeat(64)}`, type: "P0_RECIPROCAL" };
  const period = { startBlock: 10, endBlockExclusive: 20 };
  const materializerSha256 = `0x${"2".repeat(64)}`;
  try {
    await writeFile(witnessPath, "{}\n");
    await writeWitnessCacheMetadata(witnessPath, period, claim, materializerSha256);
    assert.equal(await isCurrentWitness(witnessPath, period, claim, materializerSha256), true);
    assert.equal(await isCurrentWitness(witnessPath, period, claim, `0x${"3".repeat(64)}`), false);
    await writeFile(witnessPath, "{\"changed\":true}\n");
    assert.equal(await isCurrentWitness(witnessPath, period, claim, materializerSha256), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

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
    uniqueSettlementVolumeRaw: "170",
    uniqueSettlementCount: 3,
  });
});

test("approved development summary rejects partial plans", () => {
  const plan = fixturePlan();
  plan.claims.pop();
  plan.claimCount = 1;
  assert.throws(() => validateApprovedSet(fixtureBundle(), plan), /partial proof plan/);
});

test("development generation binds the unified snapshot lock", () => {
  const bundle = fixtureBundle();
  const plan = fixturePlan();
  const lock = {
    version: 1,
    kind: "antseed-unified-historical-wash-snapshot-lock",
    reportRoot: bundle.reportRoot,
    counts: { approvedClaims: 2, approvedSellers: 3 },
    bundle: { path: "/bundle.json" },
    plan: { path: "/plan.json" },
  };
  assert.doesNotThrow(() => validateSnapshotLock(lock, "/bundle.json", "/plan.json", bundle, plan));
  lock.counts.approvedSellers = 2;
  assert.throws(() => validateSnapshotLock(lock, "/bundle.json", "/plan.json", bundle, plan), /totals/);
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
