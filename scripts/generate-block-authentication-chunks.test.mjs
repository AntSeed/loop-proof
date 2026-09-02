import assert from "node:assert/strict";
import test from "node:test";
import { buildBlockAuthenticationChunks } from "./generate-block-authentication-chunks.mjs";

test("builds ordered gas-bounded authentication chunks", () => {
  const references = [
    { number: 10, blockHash: `0x${"11".repeat(32)}` },
    { number: 20, blockHash: `0x${"22".repeat(32)}` },
    { number: 30, blockHash: `0x${"33".repeat(32)}` },
  ];
  const chunks = [
    { index: 0, references: references.slice(0, 2), proof: [`0x${"66".repeat(32)}`] },
    { index: 1, references: references.slice(2), proof: [`0x${"77".repeat(32)}`] },
  ];
  const result = buildBlockAuthenticationChunks({
    version: 1,
    kind: "antseed-wash-trading-aggregate-proof",
    chainId: 8_453,
    reportRoot: `0x${"44".repeat(32)}`,
    blockReferenceCount: references.length,
    blockAuthenticationChunkSize: 2,
    blockAuthenticationChunkCount: 2,
    blockAuthenticationRoot: `0x${"55".repeat(32)}`,
    blockReferences: references,
    blockAuthenticationChunks: chunks,
  }, 2);
  assert.equal(result.chunkCount, 2);
  assert.equal(result.chunks[0].references.length, 2);
  assert.equal(result.chunks[1].references.length, 1);
});

test("rejects reordered references", () => {
  const aggregate = {
    version: 1,
    kind: "antseed-wash-trading-aggregate-proof",
    blockReferenceCount: 2,
    blockAuthenticationChunkSize: 100,
    blockAuthenticationChunkCount: 1,
    blockAuthenticationRoot: `0x${"55".repeat(32)}`,
    blockAuthenticationChunks: [{ index: 0, references: [], proof: [] }],
    blockReferences: [
      { number: 20, blockHash: `0x${"11".repeat(32)}` },
      { number: 10, blockHash: `0x${"22".repeat(32)}` },
    ],
  };
  assert.throws(() => buildBlockAuthenticationChunks(aggregate), /strictly ordered/);
});
