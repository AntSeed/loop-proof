import assert from "node:assert/strict";
import test from "node:test";
import { assessJointCandidate, selectLedgerCandidate } from "./search-joint-wash-volume.mjs";
import { discoverExpandedReturnGraph } from "./expanded-return-graph.mjs";
import { planClaim } from "./proof-planner.mjs";

test("higher return percentage cannot replace a larger baseline with a smaller V", () => {
  const result = assessJointCandidate({ baselineVolumeRaw: "4000", candidateVolumeRaw: "2400", returnedRaw: "1200" });
  assert.equal(result.eligibleForNativeVerification, false);
  assert.equal(result.disposition, "retain-baseline-smaller-candidate");
});

test("joint expansion requires both greater V and enough returns", () => {
  assert.equal(assessJointCandidate({ baselineVolumeRaw: "4000", candidateVolumeRaw: "7000", returnedRaw: "3600" }).eligibleForNativeVerification, true);
  assert.equal(assessJointCandidate({ baselineVolumeRaw: "4000", candidateVolumeRaw: "7000", returnedRaw: "2000" }).returnShortfallRaw, "1500");
  assert.equal(assessJointCandidate({ baselineVolumeRaw: "4000", candidateVolumeRaw: "4001", returnedRaw: "2000" }).returnShortfallRaw, "1");
});

test("more authenticated payments do not bypass buyer ledger capacity", () => {
  const dependencies = [
    { dependencyId: "fund", evidenceType: "USDC_FUNDING", buyer: "buyer", amountRaw: "100", blockNumber: 46_303_001, transactionIndex: 0, logIndex: 0 },
    { dependencyId: "first", evidenceType: "SETTLEMENT", buyer: "buyer", amountRaw: "90", blockNumber: 46_303_010, transactionIndex: 0, logIndex: 0 },
    { dependencyId: "extra", evidenceType: "SETTLEMENT", buyer: "buyer", amountRaw: "20", blockNumber: 46_303_011, transactionIndex: 0, logIndex: 0 },
  ];
  assert.equal(selectLedgerCandidate(dependencies, new Map([["buyer", 10n]])).volumeRaw, 90n);
});

test("expanded graph discovers a four-transfer path through a newly traced intermediary", async () => {
  const transfer = (identifier, from, to, timestamp) => ({ txHash: `0x${identifier.toString(16).padStart(64, "0")}`, logIndex: 0, from, to, timestamp, amountRaw: "100" });
  const first = transfer(1, "seller", "relay", 20);
  const second = transfer(2, "relay", "intermediary", 21);
  const third = transfer(3, "intermediary", "terminal", 22);
  const fourth = transfer(4, "terminal", "funder", 23);
  const traces = { seller: { complete: true, outboundUsdc: [first] }, relay: { complete: true, outboundUsdc: [second] }, intermediary: { complete: true, outboundUsdc: [third] }, funder: { complete: true, inboundUsdc: [fourth] } };
  const options = { seller: "seller", funder: "funder", earliest: 10, end: 100, loadTrace: async (address) => traces[address] };
  const graph = await discoverExpandedReturnGraph(options);
  assert.equal(graph.paths.length, 1);
  assert.equal(graph.paths[0].hops.length, 4);
  assert.equal(graph.paths[0].creditRaw, "100");
  assert.equal(graph.truncated, false);
  const capped = await discoverExpandedReturnGraph({ ...options, maxSteps: 1 });
  assert.equal(capped.truncated, true);
  assert.equal(capped.exhaustive, false);
});

test("joint planner maximizes V before cost and enforces an explicit 50% target", () => {
  const make = (id, type, buyer, funder, amountRaw, block) => ({ dependencyId: id, evidenceType: type, buyer, funder, amountRaw: String(amountRaw), blockNumber: block, transactionIndex: 0, logIndex: 0, timestamp: block });
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: ["a", "b"], approvedFunders: ["cheap", "large"], dependencyRoot: "0x1" };
  const dependencies = [
    make("fa", "USDC_FUNDING", "a", "cheap", 100, 46_303_001),
    make("sa", "SETTLEMENT", "a", undefined, 100, 46_303_010),
    make("ra", "DIRECT_SELLER_FUNDER", undefined, "cheap", 50, 46_303_100),
    make("fb", "USDC_FUNDING", "b", "large", 200, 46_303_002),
    make("sb1", "SETTLEMENT", "b", undefined, 100, 46_303_011),
    make("sb2", "SETTLEMENT", "b", undefined, 100, 46_303_012),
    make("rb", "DIRECT_SELLER_FUNDER", undefined, "large", 100, 46_303_101),
  ];
  const options = { allowLedgerSelection: true, ledgerBalances: new Map([["a", 0n], ["b", 0n]]), returnTargetBps: 5000 };
  assert.equal(planClaim(claim, dependencies, {}, options).provenVolumeRaw, "100");
  const expanded = planClaim(claim, dependencies, {}, { ...options, maximizeVolume: true });
  assert.equal(expanded.provenVolumeRaw, "200");
  assert.equal(expanded.returnTargetBps, 5000);
  assert.equal(expanded.selectionObjective, "maximize-volume-then-minimize-cost");
  const fewerReturns = dependencies.map((entry) => entry.dependencyId === "rb" ? { ...entry, amountRaw: "60" } : entry);
  assert.equal(planClaim(claim, fewerReturns, {}, { ...options, maximizeVolume: true }).provenVolumeRaw, "100");
});
