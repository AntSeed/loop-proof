import assert from "node:assert/strict";
import test from "node:test";
import { planClaim, resolveDependency, selectApprovedSettlements, selectLedgerAwareSettlements, validRelayPath } from "./proof-planner.mjs";

test("cohort selector accepts one buyer and a tiny approved volume", () => {
  const buyers = ["a"];
  const fundingByBuyer = new Map(buyers.map((buyer, index) => [buyer, evidence(`f${buyer}`, buyer, 46_303_001 + index, 0n)]));
  const settlements = buyers.map((buyer, index) => evidence(`s${buyer}`, buyer, 46_303_031 + index, 1n));
  const result = selectApprovedSettlements(settlements, fundingByBuyer, [], [], 1n);
  assert.deepEqual(result.buyers, buyers);
  assert.equal(result.volumeRaw, 1n);
});

test("cohort selector reuses supported historical funding evidence", () => {
  const buyers = ["a"];
  const fundingByBuyer = new Map(buyers.map((buyer, index) => [buyer, evidence(`f${buyer}`, buyer, 45_000_001 + index, 0n)]));
  const settlements = buyers.map((buyer, index) => evidence(`s${buyer}`, buyer, 46_303_031 + index, 1n));
  const result = selectApprovedSettlements(settlements, fundingByBuyer, [], [], 1n);
  assert.deepEqual(result.buyers, buyers);
  assert.equal(result.volumeRaw, 1n);
});

test("ledger-aware selector excludes a settlement just above buyer capacity", () => {
  const fundingByBuyer = new Map([["a", [evidence("fund", "a", 46_303_001, 100n)]]]);
  const settlements = [
    evidence("small", "a", 46_303_010, 5n),
    evidence("boundary", "a", 46_303_011, 90n),
    evidence("over", "a", 46_303_012, 1n),
  ];
  const selected = selectLedgerAwareSettlements(settlements, fundingByBuyer, new Map([["a", 10n]]));
  assert.deepEqual(selected.settlements.map((entry) => entry.dependencyId), ["small", "boundary"]);
  assert.equal(selected.volumeRaw, 95n);
});

test("ledger-aware selector is deterministic and uses later replenishment", () => {
  const fundingByBuyer = new Map([["a", [
    evidence("fund-one", "a", 46_303_001, 50n),
    evidence("fund-two", "a", 46_303_020, 50n),
  ]] ]);
  const settlements = [
    evidence("late-large", "a", 46_303_030, 70n),
    evidence("early-small", "a", 46_303_010, 25n),
    evidence("excluded", "a", 46_303_031, 1n),
  ];
  const balances = new Map([["a", 10n]]);
  const forward = selectLedgerAwareSettlements(settlements, fundingByBuyer, balances);
  const reverse = selectLedgerAwareSettlements([...settlements].reverse(), fundingByBuyer, balances);
  assert.deepEqual(forward.settlements.map((entry) => entry.dependencyId), ["early-small", "late-large"]);
  assert.deepEqual(reverse.settlements, forward.settlements);
});

test("ledger-aware selector obeys the aggregate return-volume capacity", () => {
  const fundingByBuyer = new Map([["a", [evidence("fund", "a", 46_303_001, 200n)]]]);
  const settlements = [
    evidence("first", "a", 46_303_010, 60n),
    evidence("second", "a", 46_303_011, 40n),
    evidence("third", "a", 46_303_012, 1n),
  ];
  const selected = selectLedgerAwareSettlements(settlements, fundingByBuyer, new Map([["a", 0n]]), [], [], null, 100n);
  assert.deepEqual(selected.settlements.map((entry) => entry.dependencyId), ["first", "second"]);
  assert.equal(selected.volumeRaw, 100n);
});

test("closed-loop planner prioritizes direct seller-funder over relays", () => {
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: ["a", "b", "c"], approvedFunders: ["funder"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("direct", null, 46_303_100, 200_000_000n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "funder" },
    ...["a", "b", "c"].flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1_000_000n), evidenceType: "USDC_FUNDING", funder: "funder" },
      { ...evidence(`s${buyer}`, buyer, 46_303_031 + index, index === 0 ? 400_000_000n : 300_000_000n), evidenceType: "SETTLEMENT" },
    ]),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.closureType, "DIRECT_SELLER_FUNDER");
  assert.equal(plan.selectedEvidence.filter((entry) => entry.evidenceType.startsWith("RELAY")).length, 0);
});

test("closed-loop planner combines direct and relay returns when direct credit is insufficient", () => {
  const claim = {
    claimId: "claim",
    type: "P0_CLOSED_LOOP",
    subjects: ["seller"],
    approvedBuyers: ["a"],
    approvedFunders: ["funder"],
    dependencyRoot: "0x1",
    metrics: { qualifiedVolumeRaw: "100" },
  };
  const relay = {
    evidenceType: "RELAY_PATH",
    funder: "funder",
    hops: [
      { ...evidence("relay-one", null, 46_303_100, 10n), from: "seller", to: "relay", timestamp: 100 },
      { ...evidence("relay-two", null, 46_303_101, 10n), from: "relay", to: "intermediary", timestamp: 101 },
      { ...evidence("relay-three", null, 46_303_102, 10n), from: "intermediary", to: "funder", timestamp: 102 },
    ],
  };
  const dependencies = [
    { ...evidence("direct", null, 46_303_099, 10n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "funder", from: "seller", to: "funder", timestamp: 99 },
    relay,
    { dependencyId: "native", evidenceType: "NATIVE_FUNDING", buyer: "a", funder: "funder", blockNumber: 46_303_001, transactionIndex: 0, logIndex: 0, valueWei: "7" },
    evidence("settlement", "a", 46_303_031, 100n),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.closureType, "DIRECT_AND_RELAY");
  assert.deepEqual(
    plan.selectedEvidence.filter((entry) => ["DIRECT_SELLER_FUNDER", "RELAY_PATH"].includes(entry.evidenceType)).map((entry) => entry.evidenceType).sort(),
    ["DIRECT_SELLER_FUNDER", "RELAY_PATH"],
  );
  assert.equal(plan.provenVolumeRaw, "100");
});

test("closed-loop planner retains replenishments before the final settlement", () => {
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: ["a"], approvedFunders: ["funder"], dependencyRoot: "0x1", metrics: { qualifiedVolumeRaw: "10" } };
  const dependencies = [
    { ...evidence("direct", null, 46_303_100, 2n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "funder" },
    { ...evidence("funding-early", "a", 46_303_001, 4n), evidenceType: "USDC_FUNDING", funder: "funder" },
    { ...evidence("funding-replenish", "a", 46_303_020, 6n), evidenceType: "USDC_FUNDING", funder: "funder" },
    { ...evidence("settlement-one", "a", 46_303_031, 5n), evidenceType: "SETTLEMENT" },
    { ...evidence("funding-late", "a", 46_303_040, 100n), evidenceType: "USDC_FUNDING", funder: "funder" },
    { ...evidence("settlement-two", "a", 46_303_050, 5n), evidenceType: "SETTLEMENT" },
    { ...evidence("funding-after-final", "a", 46_303_060, 200n), evidenceType: "USDC_FUNDING", funder: "funder" },
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.deepEqual(plan.selectedEvidence.filter((entry) => entry.evidenceType === "USDC_FUNDING").map((entry) => entry.dependencyId), ["funding-early", "funding-replenish", "funding-late"]);
  assert.deepEqual(plan.fundingDiagnostics, [{
    buyer: "a",
    retainedRecords: 3,
    excludedLateRecords: 1,
    totalRecords: 4,
    fundingUnit: "usdc_raw",
    retainedAmountRaw: "110",
    excludedLateAmountRaw: "200",
    totalAmountRaw: "310",
  }]);
});

test("closed-loop planner reports native funding diagnostics in wei", () => {
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: ["a"], approvedFunders: ["funder"], dependencyRoot: "0x1", metrics: { qualifiedVolumeRaw: "10" } };
  const dependencies = [
    { ...evidence("closure", null, 46_303_100, 3n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "funder" },
    { dependencyId: "native", evidenceType: "NATIVE_FUNDING", buyer: "a", funder: "funder", blockNumber: 46_303_001, transactionIndex: 0, logIndex: 0, valueWei: "7" },
    evidence("settlement", "a", 46_303_031, 10n),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.fundingStrategy, "NATIVE");
  assert.deepEqual(plan.fundingDiagnostics, [{
    buyer: "a",
    retainedRecords: 1,
    excludedLateRecords: 0,
    totalRecords: 1,
    fundingUnit: "wei",
    retainedAmountRaw: "7",
    excludedLateAmountRaw: "0",
    totalAmountRaw: "7",
  }]);
});

test("native funding selection is capped by authenticated return capacity", () => {
  const claim = {
    claimId: "claim",
    type: "P0_CLOSED_LOOP",
    subjects: ["seller"],
    approvedBuyers: ["a"],
    approvedFunders: ["funder"],
    dependencyRoot: "0x1",
    metrics: { qualifiedVolumeRaw: "101" },
  };
  const dependencies = [
    { ...evidence("closure", null, 46_303_100, 20n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "funder" },
    { dependencyId: "native", evidenceType: "NATIVE_FUNDING", buyer: "a", funder: "funder", blockNumber: 46_303_001, transactionIndex: 0, logIndex: 0, valueWei: "7" },
    evidence("first", "a", 46_303_031, 60n),
    evidence("second", "a", 46_303_032, 40n),
    evidence("excluded", "a", 46_303_033, 1n),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" }, { allowLedgerSelection: true });
  assert.equal(plan.provenVolumeRaw, "100");
  assert.deepEqual(
    plan.selectedEvidence.filter((entry) => entry.evidenceType === "SETTLEMENT").map((entry) => entry.dependencyId),
    ["first", "second"],
  );
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
      evidence(`s${buyer}`, buyer, 46_303_031 + index, 1_000_000n),
    ]),
  ];
  assert.throws(() => planClaim(claim, dependencies, { reportRoot: "0x2" }), /no valid cohort funding strategy/);
});

test("direct seller-buyer transfers are not accepted as seller-to-funder returns", () => {
  const buyers = ["a", "b", "c", "d"];
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: buyers, approvedFunders: ["funder"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("closure", "a", 46_303_100, 1_000_000n), evidenceType: "DIRECT_SELLER_BUYER" },
    ...buyers.flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1_000_000n), evidenceType: "USDC_FUNDING", funder: "funder" },
      evidence(`s${buyer}`, buyer, 46_303_031 + index, buyer === "a" ? 1n : 400_000_000n),
    ]),
  ];
  assert.throws(() => planClaim(claim, dependencies, { reportRoot: "0x2" }), /no valid cohort funding strategy/);
});

test("positive direct closure has no absolute amount floor", () => {
  const buyers = ["a", "b", "c"];
  const claim = { claimId: "claim", type: "P0_CLOSED_LOOP", subjects: ["seller"], approvedBuyers: buyers, approvedFunders: ["funder"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("closure", null, 46_303_100, 999_999n), evidenceType: "DIRECT_SELLER_FUNDER", funder: "funder" },
    ...buyers.flatMap((buyer, index) => [
      { ...evidence(`f${buyer}`, buyer, 46_303_001 + index, 1_000_000n), evidenceType: "USDC_FUNDING", funder: "funder" },
      evidence(`s${buyer}`, buyer, 46_303_031 + index, 1_000_000n),
    ]),
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.closureType, "DIRECT_SELLER_FUNDER");
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

test("reciprocal planner has no receipt-count or directional-volume floor", () => {
  const claim = { claimId: "pair", type: "P0_RECIPROCAL", walletA: "a", walletB: "b", subjects: ["a", "b"], dependencyRoot: "0x1" };
  const dependencies = [
    { ...evidence("ab", "a", 46_303_001, 1n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "b" },
    { ...evidence("ba", "b", 46_303_002, 1n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "a" },
  ];
  const plan = planClaim(claim, dependencies, { reportRoot: "0x2" });
  assert.equal(plan.selectedEvidence.length, 2);
});

test("relay validation mirrors guest duration, ordering, and per-hop retention boundaries", () => {
  const valid = relayPath({ firstAmount: 100_000_000n, secondAmount: 100_000_000n, thirdAmount: 98_000_000n });
  assert.equal(validRelayPath(valid), true);
  assert.equal(validRelayPath(relayPath({ secondTimestamp: 200_000, thirdTimestamp: 259_201 })), false);
  assert.equal(validRelayPath(relayPath({ secondLogIndex: 0 })), false);
  assert.equal(validRelayPath(relayPath({ firstAmount: 999_999n, secondAmount: 999_999n, thirdAmount: 999_999n })), true);
  assert.equal(validRelayPath(relayPath({ firstAmount: 100_000_000n, secondAmount: 27_999_999n, thirdAmount: 27_999_999n })), false);
  assert.equal(validRelayPath(relayPath({ firstAmount: 100_000_000n, secondAmount: 28_000_000n, thirdAmount: 7_839_999n })), false);
});

test("reciprocal plans include pair-internal protocol deposits", () => {
  const claim = { claimId: "pair", type: "P0_RECIPROCAL", walletA: "a", walletB: "b", subjects: ["a", "b"], dependencyRoot: "0x1" };
  const settlements = [
    ...Array.from({ length: 50 }, (_, index) => ({ ...evidence(`ab${index}`, "a", 46_303_001 + index, 1_000_000n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "b" })),
    ...Array.from({ length: 50 }, (_, index) => ({ ...evidence(`ba${index}`, "b", 46_303_101 + index, 1_000_000n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "a" })),
  ];
  const deposit = { ...evidence("deposit", "a", 46_303_300, 10_000_000n), evidenceType: "USDC_FUNDING", funder: "b", depositLogIndex: 2 };
  const plan = planClaim(claim, [...settlements, deposit], { reportRoot: "0x2" });
  assert.equal(plan.selectedEvidence.filter((entry) => entry.evidenceType === "RECIPROCAL_SETTLEMENT").length, 100);
  assert.equal(plan.selectedEvidence.filter((entry) => entry.evidenceType === "USDC_FUNDING").length, 1);
});

test("planner rejects settlement volume that differs from approved analysis metrics", () => {
  const claim = {
    claimId: "pair",
    type: "P0_RECIPROCAL",
    walletA: "a",
    walletB: "b",
    subjects: ["a", "b"],
    dependencyRoot: "0x1",
    metrics: { volumeAToBRaw: "50000001", volumeBToARaw: "50000000" },
  };
  const settlements = [
    ...Array.from({ length: 50 }, (_, index) => ({ ...evidence(`ab${index}`, "a", 46_303_001 + index, 1_000_000n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "b" })),
    ...Array.from({ length: 50 }, (_, index) => ({ ...evidence(`ba${index}`, "b", 46_303_101 + index, 1_000_000n), evidenceType: "RECIPROCAL_SETTLEMENT", seller: "a" })),
  ];
  assert.throws(() => planClaim(claim, settlements, { reportRoot: "0x2" }), /do not equal approved analysis volumes/);
});

test("dependency resolution rejects reverted and zero native funding", async () => {
  const dependency = {
    dependencyId: "native",
    evidenceType: "NATIVE_FUNDING",
    transactionHash: `0x${"1".repeat(64)}`,
    funder: "0x0000000000000000000000000000000000000010",
    buyer: "0x0000000000000000000000000000000000000020",
    amountWei: "0",
  };
  const bundle = rpcBundle();
  await assert.rejects(
    () => resolveDependency(dependency, bundle, async () => ({ status: "0x0", blockNumber: "0x2c2f6dd", transactionIndex: "0x0" })),
    /receipt reverted/,
  );
  const callRpc = async (method) => method === "eth_getTransactionReceipt"
    ? { status: "0x1", blockNumber: "0x2c2f6dd", transactionIndex: "0x0", logs: [] }
    : { type: "0x2", from: dependency.funder, to: dependency.buyer, value: "0x0" };
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

test("two-transfer relay resolution never requests a missing third receipt", async () => {
  const bundle = rpcBundle();
  const seller = "0x0000000000000000000000000000000000000010";
  const relay = "0x0000000000000000000000000000000000000020";
  const funder = "0x0000000000000000000000000000000000000030";
  const firstHash = `0x${"1".repeat(64)}`;
  const secondHash = `0x${"2".repeat(64)}`;
  const transferDependency = (evidenceType, transactionHash, from, to, blockNumber) => ({
    dependencyId: `${evidenceType}-${blockNumber}`,
    evidenceType,
    transactionHash,
    logIndex: 1,
    from,
    to,
    amountRaw: "100",
    timestamp: 1,
  });
  const dependency = {
    evidenceType: "RELAY_PATH",
    seller,
    funder,
    sellerPayment: transferDependency("RELAY_SELLER_PAYMENT", firstHash, seller, relay, 46_303_100),
    relayForward: transferDependency("RELAY_FORWARD", secondHash, relay, funder, 46_303_101),
  };
  const receipts = new Map([
    [firstHash, transferReceipt(bundle.contracts.usdc, seller, relay, 100n, 46_303_100)],
    [secondHash, transferReceipt(bundle.contracts.usdc, relay, funder, 100n, 46_303_101)],
  ]);
  const requestedReceipts = [];
  const resolved = await resolveDependency(dependency, bundle, async (method, [value]) => {
    if (method === "eth_getTransactionReceipt") {
      requestedReceipts.push(value);
      return receipts.get(value);
    }
    if (method === "eth_getBlockByNumber") return { number: value, hash: `0x${"a".repeat(64)}`, timestamp: "0x64" };
    throw new Error(`unexpected RPC method ${method}`);
  });
  assert.deepEqual(requestedReceipts, [firstHash, secondHash]);
  assert.equal(resolved.relayForward.to, funder);
  assert.equal("funderReceipt" in resolved, false);
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

function transferReceipt(usdc, from, to, amountRaw, blockNumber) {
  return {
    status: "0x1",
    blockNumber: `0x${blockNumber.toString(16)}`,
    blockHash: `0x${"a".repeat(64)}`,
    transactionIndex: "0x0",
    logs: [{
      address: usdc,
      logIndex: "0x1",
      topics: [
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        addressTopic(from),
        addressTopic(to),
      ],
      data: word(amountRaw),
    }],
  };
}
