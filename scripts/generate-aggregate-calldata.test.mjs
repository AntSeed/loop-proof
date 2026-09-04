import assert from "node:assert/strict";
import test from "node:test";
import {
  buildSellerCalldataArtifact,
  encodeStageSellerProof,
  stageSellerProofSelector,
} from "./generate-aggregate-calldata.mjs";

test("stageSellerProof calldata matches the Solidity ABI layout", () => {
  const calldata = encodeStageSellerProof("0x1234", "0xabcdef");
  const body = calldata.slice(2 + stageSellerProofSelector.length);
  assert.equal(BigInt(`0x${body.slice(0, 64)}`), 64n);
  assert.equal(BigInt(`0x${body.slice(64, 128)}`), 128n);
  assert.equal(BigInt(`0x${body.slice(128, 192)}`), 2n);
  assert.equal(body.slice(192, 196), "1234");
  assert.equal(BigInt(`0x${body.slice(256, 320)}`), 3n);
  assert.equal(body.slice(320, 326), "abcdef");
});

test("calldata artifact preserves direct seller identity", () => {
  const artifact = buildSellerCalldataArtifact(proof());
  assert.equal(artifact.sellerProgramVKey, `0x${"34".repeat(32)}`);
  assert.equal(artifact.callSignature, "stageSellerProof(bytes,bytes)");
  assert.ok(artifact.calldata.startsWith(`0x${stageSellerProofSelector}`));
});

test("calldata generation rejects recursive and empty proof artifacts", () => {
  assert.throws(() => buildSellerCalldataArtifact({ ...proof(), version: 2 }), /invalid direct seller proof/);
  assert.throws(() => buildSellerCalldataArtifact({ ...proof(), proofBytes: "0x" }), /proof bytes are empty/);
});

function proof() {
  return {
    version: 3,
    kind: "antseed-wash-trading-seller-proof",
    proofArchitecture: "direct-seller-v1",
    securityMode: "development",
    chainId: 8453,
    seller: `0x${"12".repeat(20)}`,
    sellerProgramVKey: `0x${"34".repeat(32)}`,
    publicValues: "0x1234",
    proofBytes: "0xabcd",
    proved: true,
    verified: true,
  };
}
