#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

export function buildBlockAuthenticationChunks(aggregate, chunkSize = 100) {
  if (aggregate?.version !== 1 || aggregate.kind !== "antseed-wash-trading-aggregate-proof") {
    throw new Error("invalid aggregate proof artifact");
  }
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) throw new Error("chunk size must be positive");
  if (chunkSize !== aggregate.blockAuthenticationChunkSize) throw new Error("chunk size differs from SP1 commitment");
  if (!Array.isArray(aggregate.blockReferences)
      || aggregate.blockReferences.length !== aggregate.blockReferenceCount) {
    throw new Error("aggregate block-reference count mismatch");
  }
  const references = aggregate.blockReferences.map((reference, index) => {
    const number = Number(reference.number);
    const blockHash = normalizeHash(reference.blockHash);
    if (!Number.isSafeInteger(number) || number <= 0) throw new Error(`invalid block number at ${index}`);
    if (index > 0 && number <= Number(aggregate.blockReferences[index - 1].number)) {
      throw new Error("block references must be strictly ordered");
    }
    return { number, blockHash };
  });
  const root = normalizeHash(aggregate.blockAuthenticationRoot);
  const chunks = aggregate.blockAuthenticationChunks;
  if (!Array.isArray(chunks) || chunks.length !== aggregate.blockAuthenticationChunkCount) {
    throw new Error("aggregate block-authentication chunk count mismatch");
  }
  let observedReferences = 0;
  for (const [index, chunk] of chunks.entries()) {
    if (chunk.index !== index || !Array.isArray(chunk.references) || !Array.isArray(chunk.proof)) {
      throw new Error("invalid block-authentication chunk");
    }
    observedReferences += chunk.references.length;
  }
  if (observedReferences !== references.length) throw new Error("block-authentication chunks are incomplete");
  return {
    version: 1,
    kind: "antseed-wash-trading-block-authentication-chunks",
    chainId: aggregate.chainId,
    reportRoot: aggregate.reportRoot,
    blockReferenceCount: references.length,
    blockAuthenticationRoot: root,
    chunkSize,
    chunkCount: chunks.length,
    chunks: chunks.map((chunk) => ({ ...chunk, offset: chunk.index * chunkSize })),
  };
}

function normalizeHash(value) {
  if (!/^0x[0-9a-f]{64}$/i.test(value ?? "")) throw new Error(`invalid bytes32 ${value}`);
  return value.toLowerCase();
}

if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  const args = process.argv.slice(2);
  const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
  const aggregatePath = value("--aggregate");
  const outputPath = value("--output");
  if (!aggregatePath || !outputPath) throw new Error("usage: generate-block-authentication-chunks.mjs --aggregate aggregate.json --output chunks.json [--chunk-size 100]");
  const aggregate = JSON.parse(await readFile(resolve(aggregatePath), "utf8"));
  const result = buildBlockAuthenticationChunks(aggregate, Number(value("--chunk-size") ?? 100));
  await writeFile(resolve(outputPath), `${JSON.stringify(result, null, 2)}\n`);
}
