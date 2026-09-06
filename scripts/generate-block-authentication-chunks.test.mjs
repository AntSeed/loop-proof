import assert from "node:assert/strict";
import test from "node:test";
import { buildBlockAuthenticationChunks } from "./generate-block-authentication-chunks.mjs";

test("builds ordered gas-bounded direct seller authentication chunks", () => {
  const result = buildBlockAuthenticationChunks(proof(), 2);
  assert.equal(result.chunkCount, 2);
  assert.equal(result.chunks[0].references.length, 2);
  assert.equal(result.chunks[1].references.length, 1);
  assert.equal(result.seller, `0x${"99".repeat(20)}`);
});

test("rejects reordered references", () => {
  const artifact = proof();
  artifact.blockAuthenticationChunks[1].references[0].number = 10;
  assert.throws(() => buildBlockAuthenticationChunks(artifact, 2), /strictly ordered/);
});

function proof() {
  const references = [
    { number: 10, blockHash: `0x${"11".repeat(32)}` },
    { number: 20, blockHash: `0x${"22".repeat(32)}` },
    { number: 30, blockHash: `0x${"33".repeat(32)}` },
  ];
  return {
    version: 3,
    kind: "antseed-wash-trading-seller-proof",
    proofArchitecture: "direct-seller-v1",
    chainId: 8_453,
    seller: `0x${"99".repeat(20)}`,
    evidenceDigest: `0x${"44".repeat(32)}`,
    blockReferenceCount: references.length,
    blockAuthenticationChunkSize: 2,
    blockAuthenticationChunkCount: 2,
    blockAuthenticationRoot: `0x${"55".repeat(32)}`,
    blockAuthenticationChunks: [
      { index: 0, references: references.slice(0, 2), proof: [`0x${"66".repeat(32)}`] },
      { index: 1, references: references.slice(2), proof: [`0x${"77".repeat(32)}`] },
    ],
  };
}
