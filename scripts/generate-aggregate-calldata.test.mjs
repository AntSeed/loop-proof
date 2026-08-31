import assert from "node:assert/strict";
import test from "node:test";
import {
  buildAggregateCalldataArtifact,
  encodeSubmitHistoricalAggregate,
  submitHistoricalAggregateSelector,
} from "./generate-aggregate-calldata.mjs";

test("submitHistoricalAggregate calldata matches the Solidity ABI layout", () => {
  const calldata = encodeSubmitHistoricalAggregate("0x1234", "0xabcdef");
  const body = calldata.slice(2 + submitHistoricalAggregateSelector.length);
  assert.equal(BigInt(`0x${body.slice(0, 64)}`), 64n);
  assert.equal(BigInt(`0x${body.slice(64, 128)}`), 128n);
  assert.equal(BigInt(`0x${body.slice(128, 192)}`), 2n);
  assert.equal(body.slice(192, 196), "1234");
  assert.equal(BigInt(`0x${body.slice(256, 320)}`), 3n);
  assert.equal(body.slice(320, 326), "abcdef");
});

test("calldata artifact preserves aggregate identity", () => {
  const artifact = buildAggregateCalldataArtifact({
    version: 1,
    kind: "antseed-wash-trading-aggregate-proof",
    securityMode: "development",
    chainId: 8453,
    aggregatorProgramId: `0x${"12".repeat(32)}`,
    aggregatorProgramVKey: `0x${"34".repeat(32)}`,
    publicValues: "0x1234",
    proofBytes: "0xabcd",
  });
  assert.equal(artifact.aggregatorProgramVKey, `0x${"34".repeat(32)}`);
  assert.equal(artifact.callSignature, "submitHistoricalAggregate(bytes,bytes)");
  assert.ok(artifact.calldata.startsWith(`0x${submitHistoricalAggregateSelector}`));
});

test("calldata generation rejects malformed aggregate fields", () => {
  assert.throws(() => buildAggregateCalldataArtifact({
    version: 1,
    kind: "antseed-wash-trading-aggregate-proof",
    aggregatorProgramId: "0x12",
    aggregatorProgramVKey: `0x${"34".repeat(32)}`,
    publicValues: "0x",
    proofBytes: "0x",
  }), /invalid aggregator program ID/);
});
