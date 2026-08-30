import assert from "node:assert/strict";
import test from "node:test";
import {
  buildAggregateCalldataArtifact,
  encodeSubmitAggregate,
  submitAggregateSelector,
} from "./generate-aggregate-calldata.mjs";

test("submitAggregate calldata matches the Solidity ABI layout", () => {
  const programId = `0x${"11".repeat(32)}`;
  const calldata = encodeSubmitAggregate(programId, "0x1234", "0xabcdef");
  const body = calldata.slice(2 + submitAggregateSelector.length);
  assert.equal(body.slice(0, 64), programId.slice(2));
  assert.equal(BigInt(`0x${body.slice(64, 128)}`), 96n);
  assert.equal(BigInt(`0x${body.slice(128, 192)}`), 160n);
  assert.equal(BigInt(`0x${body.slice(192, 256)}`), 2n);
  assert.equal(body.slice(256, 260), "1234");
  assert.equal(BigInt(`0x${body.slice(320, 384)}`), 3n);
  assert.equal(body.slice(384, 390), "abcdef");
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
  assert.equal(artifact.callSignature, "submitAggregate(bytes32,bytes,bytes)");
  assert.ok(artifact.calldata.startsWith(`0x${submitAggregateSelector}`));
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
