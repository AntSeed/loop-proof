import assert from "node:assert/strict";
import test from "node:test";
import { planClaim, resolveDependency, selectMinimumSettlementBlocks, validRelayPath } from "./proof-planner.mjs";

test("cohort selector accounts for funding blocks and reaches exact threshold", () => {
  const buyers = ["a", "b", "c"];
  const fundingByBuyer = new Map(buyers.map((buyer, index) => [buyer, evidence(`f${buyer}`, buyer, 46_303_001 + index, 0n)]));
  const settlements = buyers.map((buyer, index) => evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n));
  const result = selectMinimumSettlementBlocks(settlements, fundingByBuyer);
  assert.deepEqual(result.buyers, buyers);
  assert.equal(result.volumeRaw, 1_000_000_000n);
});

test("cohort selector reuses supported historical funding evidence", () => {
  const buyers = ["a", "b", "c"];
  const fundingByBuyer = new Map(buyers.map((buyer, index) => [buyer, evidence(`f${buyer}`, buyer, 45_000_001 + index, 0n)]));
  const settlements = buyers.map((buyer, index) => evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n));
  const result = selectMinimumSettlementBlocks(settlements, fundingByBuyer);
  assert.deepEqual(result.buyers, buyers);
  assert.equal(result.volumeRaw, 1_000_000_000n);
});

test("closed-loop planner prioritizes direct seller-funder over relays", () => {
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: ["a", "b", "c"], approvedFunders: ["funder"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("direct", null, 46_303_100, 1_000_000n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "funder" },
    ...["a", "b", "c"].flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1_000_000n), evidenceType: "USDC_FUNDING", funder: "funder" },
      { ...evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n), evidenceType: "SETTLEMENT" },
    ]),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.closureType, "DIRECT_SELLER_FUNDER");
  assert.equal(plan.selectedEvidence.filter((entry) => entry.evidenceType.startsWith("RELAY")).length, 0);
});

test("closed-loop planner uses authenticated self-funded closure without self-transfer evidence", () => {
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["SeLlEr"], approvedBuyers: ["a", "b", "c"], approvedFunders: ["seller"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("direct", null, 46_303_100, 1_000_000n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "seller", from: "seller", to: "seller" },
    ...["a", "b", "c"].flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1_000_000n), evidenceType: "USDC_FUNDING", funder: "seller" },
      { ...evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n), evidenceType: "SETTLEMENT" },
    ]),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.closureType, "SELF_FUNDED");
  assert.equal(plan.selectedEvidence.some((entry) => entry.dependencyId === "direct"), false);
});

test("closed-loop closure must match the selected cohort funder", () => {
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: ["a", "b", "c"], approvedFunders: ["good", "other"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("closure", null, 46_303_100, 1_000_000n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "other" },
    ...["a", "b", "c"].flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1_000_000n), evidenceType: "USDC_FUNDING", funder: "good" },
      evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n),
    ]),
  ];
  assert.throws(() => planClaim(claim, dependencies, { reportRoot: "0x2" }), /no valid cohort funding strategy/);
});

test("direct buyer closure buyer is included in the settled cohort", () => {
  const buyers = ["a", "b", "c", "d"];
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: buyers, approvedFunders: ["funder"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("closure", "a", 46_303_100, 1_000_000n), evidenceType: "DIRECT_SELLER_BUYER" },
    ...buyers.flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1_000_000n), evidenceType: "USDC_FUNDING", funder: "funder" },
      evidence(`s${buyer}`, buyer, 46_303_031 + index, buyer === "a" ? 1n : 400_000_000n),
    ]),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.closureType, "DIRECT_SELLER_BUYER");
  assert(plan.selectedEvidence.some((entry) => entry.evidenceType === "SETTLEMENT" && entry.buyer === "a"));
});

test("direct closure below one USDC is rejected", () => {
  const buyers = ["a", "b", "c"];
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: buyers, approvedFunders: ["funder"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("closure", null, 46_303_100, 999_999n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "funder" },
    ...buyers.flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1_000_000n), evidenceType: "USDC_FUNDING", funder: "funder" },
      evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n),
    ]),
  ];
  assert.throws(() => planClaim(claim, dependencies, { reportRoot: "0x2" }), /no valid cohort funding strategy/);
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

test("reciprocal planner may select more than 100 receipts to reach directional volume", () => {
  const claim = { claimId: "pair", type: "P0_RECIPROCAL", walletA: "a", walletB: "b", subjects: ["a", "b"], dependencyRoot: "0x1" };
  const dependencies = [
    ...Array.from({ length: 100 }, (_, index) => ({ ...evidence(`ab${index}`, "a", 46_303_001 + index, 100_000n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "b" })),
    ...Array.from({ length: 100 }, (_, index) => ({ ...evidence(`ba${index}`, "b", 46_303_201 + index, 100_000n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "a" })),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.selectedEvidence.length, 200);
});

test("relay validation mirrors guest duration, ordering, minimum, and retained-value boundaries", () => {
  const valid = relayPath({ firstAmount: 100_000_000n, secondAmount: 100_000_000n, thirdAmount: 98_000_000n });
  assert.equal(validRelayPath(valid), true);
  assert.equal(validRelayPath(relayPath({ secondTimestamp: 86_400, thirdTimestamp: 172_800 })), false);
  assert.equal(validRelayPath(relayPath({ secondLogIndex: 0 })), false);
  assert.equal(validRelayPath(relayPath({ firstAmount: 999_999n, secondAmount: 999_999n, thirdAmount: 999_999n })), false);
  assert.equal(validRelayPath(relayPath({ firstAmount: 100_000_000n, secondAmount: 100_001_000n, thirdAmount: 100_000_500n })), false);
  assert.equal(validRelayPath(relayPath({ firstAmount: 100_000_000n, secondAmount: 99_999_000n, thirdAmount: 97_999_100n })), false);
});

test("dependency resolution rejects reverted and sub-minimum native funding", async () => {
  const dependency = {
    dependencyId: "native",
    evidenceType: "NATIVE_FUNDING",
    transactionHash: `0x${"1".repeat(64)}`,
    funder: "0x0000000000000000000000000000000000000010",
    buyer: "0x0000000000000000000000000000000000000020",
    amountWei: "1",
  };
  const bundle = rpcBundle();
  await assert.rejects(
    () => resolveDependency(dependency, bundle, async () => ({ status: "0x0", blockNumber: "0x2c2f6dd", transactionIndex: "0x0" })),
    /receipt reverted/,
  );
  const callRpc = async (method) => method === "eth_getTransactionReceipt"
    ? { status: "0x1", blockNumber: "0x2c2f6dd", transactionIndex: "0x0", logs: [] }
    : { type: "0x2", from: dependency.funder, to: dependency.buyer, value: "0x1" };
  await assert.rejects(() => resolveDependency(dependency, bundle, callRpc), /native funding parties\/value mismatch/);
});

test("dependency timing is refetched from the authenticated receipt block", async () => {
  const blockHash = `0x${"a".repeat(64)}`;
  const dependency = {
    dependencyId: "timed-native",
    evidenceType: "NATIVE_FUNDING",
    transactionHash: `0x${"1".repeat(64)}`,
    funder: "0x0000000000000000000000000000000000000010",
    buyer: "0x0000000000000000000000000000000000000020",
    amountWei: "50000000000000",
    timestamp: 999_999,
  };
  const callRpc = async (method) => {
    if (method === "eth_getTransactionReceipt") return { status: "0x1", blockNumber: "0x2c2f6dd", blockHash, transactionIndex: "0x0", logs: [] };
    if (method === "eth_getBlockByNumber") return { number: "0x2c2f6dd", hash: blockHash, timestamp: "0x64" };
    return { type: "0x2", from: dependency.funder, to: dependency.buyer, value: "0x2d79883d2000" };
  };
  const resolved = await resolveDependency(dependency, rpcBundle(), callRpc);
  assert.equal(resolved.timestamp, 100);
});

test("protocol-deposit funding cannot be attributed to a different funder", async () => {
  const funder = "0x0000000000000000000000000000000000000010";
  const attacker = "0x0000000000000000000000000000000000000099";
  const buyer = "0x0000000000000000000000000000000000000020";
  const bundle = rpcBundle();
  const transfer = {
    address: bundle.contracts.usdc,
    logIndex: "0x1",
    topics: [
      "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
      addressTopic(attacker),
      addressTopic(bundle.contracts.deposits),
    ],
    data: word(1_000_000n),
  };
  const deposited = {
    address: bundle.contracts.deposits,
    logIndex: "0x2",
    topics: [
      "0x2da466a7b24304f47e87fa2e1e5a81b9831ce54fec19055ce277ca2f39ba42c4",
      addressTopic(buyer),
    ],
    data: word(1_000_000n),
  };
  const dependency = {
    dependencyId: "deposit",
    evidenceType: "USDC_FUNDING",
    transactionHash: `0x${"2".repeat(64)}`,
    funder,
    buyer,
    amountRaw: "1000000",
    logIndex: 1,
  };
  const callRpc = async (method) => method === "eth_getTransactionReceipt"
    ? { status: "0x1", blockNumber: "0x2c2f6dd", transactionIndex: "0x0", logs: [transfer, deposited] }
    : { from: attacker };
  await assert.rejects(() => resolveDependency(dependency, bundle, callRpc), /authenticated log mismatch/);
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

function relayPath({
  firstAmount = 10_000_000n,
  secondAmount = firstAmount,
  thirdAmount = firstAmount,
  secondTimestamp = 1,
  thirdTimestamp = 2,
  secondLogIndex = 1,
} = {}) {
  const transfer = (dependencyId, blockNumber, logIndex, timestamp, amountRaw) => ({
    dependencyId,
    evidenceType: dependencyId,
    blockNumber,
    transactionIndex: 0,
    logIndex,
    timestamp,
    amountRaw: amountRaw.toString(),
  });
  return {
    evidenceType: "RELAY_PATH",
    sellerPayment: transfer("RELAY_SELLER_PAYMENT", 46_303_100, 0, 0, firstAmount),
    relayForward: transfer("RELAY_FORWARD", 46_303_100, secondLogIndex, secondTimestamp, secondAmount),
    funderReceipt: transfer("RELAY_FUNDER_RECEIPT", 46_303_101, 0, thirdTimestamp, thirdAmount),
  };
}

function rpcBundle() {
  return {
    period: { startBlock: 44_471_575, endBlockExclusive: 49_936_173 },
    contracts: {
      channels: "0x0000000000000000000000000000000000000030",
      usdc: "0x0000000000000000000000000000000000000040",
      deposits: "0x0000000000000000000000000000000000000050",
    },
  };
}

function addressTopic(address) {
  return `0x${address.slice(2).padStart(64, "0")}`;
}

function word(value) {
  return `0x${value.toString(16).padStart(64, "0")}`;
}
