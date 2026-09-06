import assert from "node:assert/strict";
import test from "node:test";
import {
  discoverCachedRelayReturns,
  requiredReturnRaw,
  selectReturnEvidence,
} from "./return-path-selection.mjs";

test("return selector combines direct and relay credit without reusing logs", () => {
  const direct = transfer("direct", "seller", "funder", 8n, 20);
  direct.evidenceType = "DIRECT_SELLER_FUNDER";
  const first = relayPath("one", 7n, 30);
  const duplicate = { ...relayPath("duplicate", 9n, 40), hops: [first.hops[0], ...relayPath("duplicate", 9n, 40).hops.slice(1)] };
  const second = relayPath("two", 6n, 50);
  const result = selectReturnEvidence([second, duplicate, direct, first], {
    requiredRaw: 15n,
    earliestSettlementTimestamp: 10,
  });
  assert.equal(result.complete, true);
  assert.equal(result.returnedRaw, 15n);
  assert.deepEqual(result.evidence.map((entry) => entry.evidenceType), ["DIRECT_SELLER_FUNDER", "RELAY_PATH"]);
});

test("cached relay discovery is seller and funder agnostic and deterministic", async () => {
  const sellerTrace = {
    outboundUsdc: [
      transfer("seller-two", "seller", "relay-two", 100n, 20),
      transfer("seller-one", "seller", "relay-one", 100n, 10),
    ],
  };
  const relayTraces = new Map([
    ["relay-one", { complete: true, outboundUsdc: [transfer("forward-one", "relay-one", "intermediary", 100n, 11)] }],
    ["relay-two", { complete: true, outboundUsdc: [transfer("forward-two", "relay-two", "intermediary", 100n, 21)] }],
  ]);
  const funderTrace = {
    inboundUsdc: [
      transfer("finish-two", "intermediary", "funder", 100n, 22),
      transfer("finish-one", "intermediary", "funder", 100n, 12),
    ],
  };
  const options = {
    seller: "seller",
    funder: "funder",
    sellerTrace,
    funderTrace,
    loadTrace: async (address) => relayTraces.get(address),
    earliestSettlementTimestamp: 0,
    requiredRaw: 200n,
    traceConcurrency: 2,
  };
  const forward = await discoverCachedRelayReturns(options);
  const reverse = await discoverCachedRelayReturns({
    ...options,
    sellerTrace: { outboundUsdc: [...sellerTrace.outboundUsdc].reverse() },
    funderTrace: { inboundUsdc: [...funderTrace.inboundUsdc].reverse() },
  });
  assert.equal(forward.complete, true);
  assert.equal(forward.returnedRaw, 200n);
  assert.equal(forward.paths.length, 2);
  assert.deepEqual(reverse.paths, forward.paths);
  const used = forward.paths.flatMap((path) => path.hops.map((hop) => `${hop.txHash}:${hop.logIndex}`));
  assert.equal(new Set(used).size, used.length);
});

test("required return rounds up to the smallest raw unit", () => {
  assert.equal(requiredReturnRaw(10_612_500_621n), 3_183_750_187n);
});

test("two-transfer relay evidence receives the smaller-hop credit", () => {
  const evidence = {
    evidenceType: "RELAY_PATH",
    sellerPayment: transfer("first", "seller", "relay", 100n, 10),
    relayForward: transfer("second", "relay", "funder", 99n, 11),
  };
  const result = selectReturnEvidence([evidence], { requiredRaw: 99n, earliestSettlementTimestamp: 0 });
  assert.equal(result.complete, true);
  assert.equal(result.returnedRaw, 99n);
  assert.equal(result.evidence.length, 1);
});

function relayPath(id, amountRaw, timestamp) {
  return {
    evidenceType: "RELAY_PATH",
    funder: "funder",
    hops: [
      transfer(`${id}-one`, "seller", `${id}-relay`, amountRaw, timestamp),
      transfer(`${id}-two`, `${id}-relay`, `${id}-intermediary`, amountRaw, timestamp + 1),
      transfer(`${id}-three`, `${id}-intermediary`, "funder", amountRaw, timestamp + 2),
    ],
  };
}

function transfer(txHash, from, to, amountRaw, timestamp) {
  return {
    txHash,
    transactionHash: txHash,
    logIndex: 0,
    from,
    to,
    amountRaw: amountRaw.toString(),
    timestamp,
  };
}
