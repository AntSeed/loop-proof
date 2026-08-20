import assert from "node:assert/strict";
import test from "node:test";
import { checkpointBlockNumber, planClaim, selectMinimumSettlementWindows } from "./proof-planner.mjs";

test("checkpoint windows preserve protocol boundary alignment", () => {
  assert.equal(checkpointBlockNumber(46_302_961), 46_302_990);
  assert.equal(checkpointBlockNumber(46_302_990), 46_302_990);
  assert.equal(checkpointBlockNumber(46_302_991), 46_303_020);
});

test("cohort selector accounts for funding windows and reaches exact threshold", () => {
  const buyers = ["a", "b", "c"];
  const fundingByBuyer = new Map(buyers.map((buyer, index) => [buyer, evidence(`f${buyer}`, buyer, 46_303_001 + index, 0n)]));
  const settlements = buyers.map((buyer, index) => evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n));
  const result = selectMinimumSettlementWindows(settlements, fundingByBuyer);
  assert.deepEqual(result.buyers, buyers);
  assert.equal(result.volumeRaw, 1_000_000_000n);
});

test("cohort selector reuses supported historical funding evidence", () => {
  const buyers = ["a", "b", "c"];
  const fundingByBuyer = new Map(buyers.map((buyer, index) => [buyer, evidence(`f${buyer}`, buyer, 45_000_001 + index, 0n)]));
  const settlements = buyers.map((buyer, index) => evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n));
  const result = selectMinimumSettlementWindows(settlements, fundingByBuyer);
  assert.deepEqual(result.buyers, buyers);
  assert.equal(result.volumeRaw, 1_000_000_000n);
});

test("closed-loop planner prioritizes direct seller-funder over relays", () => {
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: ["a", "b", "c"], approvedFunders: ["funder"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("direct", null, 46_303_100, 1n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "funder" },
    ...["a", "b", "c"].flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1n), evidenceType: "USDC_FUNDING", funder: "funder" },
      { ...evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n), evidenceType: "SETTLEMENT" },
    ]),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.closureType, "DIRECT_SELLER_FUNDER");
  assert.equal(plan.selectedEvidence.filter((entry) => entry.evidenceType.startsWith("RELAY")).length, 0);
});

test("native cohort funding is never aggregated across funders", () => {
  const claim = { claimId: "claim", type: "P1_COORDINATED_CONTROL", subjects: ["seller"], approvedBuyers: ["a", "b", "c"], approvedFunders: ["f1", "f2"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("fa", "a", 46_303_001, 1n), evidenceType: "NATIVE_FUNDING", funder: "f1" },
    { ...evidence("fb", "b", 46_303_002, 1n), evidenceType: "NATIVE_FUNDING", funder: "f1" },
    { ...evidence("fc", "c", 46_303_003, 1n), evidenceType: "NATIVE_FUNDING", funder: "f2" },
    ...["a", "b", "c"].map((buyer, index) => evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n)),
  ];
  assert.throws(() => planClaim(claim, dependencies, { reportRoot: "0x2" }), /no valid cohort funding strategy/);
});

test("closed-loop closure must match the selected cohort funder", () => {
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: ["a", "b", "c"], approvedFunders: ["good", "other"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("closure", null, 46_303_100, 1n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "other" },
    ...["a", "b", "c"].flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1n), evidenceType: "USDC_FUNDING", funder: "good" },
      evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n),
    ]),
  ];
  assert.throws(() => planClaim(claim, dependencies, { reportRoot: "0x2" }), /no valid cohort funding strategy/);
});

test("direct buyer closure buyer is included in the settled cohort", () => {
  const buyers = ["a", "b", "c", "d"];
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: buyers, approvedFunders: ["funder"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("closure", "a", 46_303_100, 1n), evidenceType: "DIRECT_SELLER_BUYER" },
    ...buyers.flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1n), evidenceType: "USDC_FUNDING", funder: "funder" },
      evidence(`s${buyer}`, buyer, 46_303_031 + index, buyer === "a" ? 1n : 400_000_000n),
    ]),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.closureType, "DIRECT_SELLER_BUYER");
  assert(plan.selectedEvidence.some((entry) => entry.evidenceType === "SETTLEMENT" && entry.buyer === "a"));
});

test("reciprocal planner enforces the exact 80 percent volume boundary", () => {
  const claim = { claimId: "pair", type: "P0_RECIPROCAL", walletA: "a", walletB: "b", subjects: ["a", "b"], dependencyRoot: "0x1" };
  const qualifying = [
    ...Array.from({ length: 50 }, (_, index) => ({ ...evidence(`ab${index}`, "a", 46_303_001 + index, 1_000_000n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "b" })),
    ...Array.from({ length: 50 }, (_, index) => ({ ...evidence(`ba${index}`, "b", 46_303_101 + index, 800_000n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "a" })),
  ];
  const plan = planClaim(claim, qualifying, { reportRoot: "0x2" });
  assert.equal(plan.selectedEvidence.length, 100);

  const below = qualifying.map((entry) => entry.dependencyId.startsWith("ba") ? { ...entry, amountRaw: "799999" } : entry);
  assert.throws(() => planClaim(claim, below, { reportRoot: "0x2" }), /80% reciprocity/);
});

test("planner rejects unknown claim types", () => {
  assert.throws(
    () => planClaim({ claimId: "claim", type: "P0_UNKNOWN" }, [], { reportRoot: "0x2" }),
    /unsupported claim type/,
  );
});

function evidence(dependencyId, buyer, blockNumber, amountRaw) {
  return { dependencyId, evidenceType: "SETTLEMENT", buyer, blockNumber, transactionIndex: 0, logIndex: 0, amountRaw: amountRaw.toString() };
}
