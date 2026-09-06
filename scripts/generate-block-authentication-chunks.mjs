#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

export function buildBlockAuthenticationChunks(sellerProof, chunkSize = 100) {
  if (sellerProof?.version !== 3 || sellerProof.kind !== "antseed-wash-trading-seller-proof"
      || sellerProof.proofArchitecture !== "direct-seller-v1") {
    throw new Error("invalid direct seller proof artifact");
  }
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) throw new Error("chunk size must be positive");
  if (chunkSize !== sellerProof.blockAuthenticationChunkSize) throw new Error("chunk size differs from SP1 commitment");
  const chunks = sellerProof.blockAuthenticationChunks;
  if (!Array.isArray(chunks) || chunks.length !== sellerProof.blockAuthenticationChunkCount) {
    throw new Error("seller block-authentication chunk count mismatch");
  }
  const references = [];
  for (const [index, chunk] of chunks.entries()) {
    if (chunk.index !== index || !Array.isArray(chunk.references) || chunk.references.length === 0
        || chunk.references.length > chunkSize || !Array.isArray(chunk.proof)) {
      throw new Error("invalid block-authentication chunk");
    }
    for (const reference of chunk.references) {
      const number = Number(reference.number);
      const blockHash = normalizeHash(reference.blockHash);
      if (!Number.isSafeInteger(number) || number <= 0) throw new Error(`invalid block number in chunk ${index}`);
      if (references.length > 0 && number <= references.at(-1).number) {
        throw new Error("block references must be strictly ordered");
      }
      references.push({ number, blockHash });
    }
  }
  if (references.length !== sellerProof.blockReferenceCount) {
    throw new Error("seller block-reference count mismatch");
  }
  return {
    version: 2,
    kind: "antseed-wash-trading-seller-block-authentication-chunks",
    proofArchitecture: "direct-seller-v1",
    chainId: sellerProof.chainId,
    seller: sellerProof.seller.toLowerCase(),
    evidenceDigest: normalizeHash(sellerProof.evidenceDigest),
    blockReferenceCount: references.length,
    blockAuthenticationRoot: normalizeHash(sellerProof.blockAuthenticationRoot),
    chunkSize,
    chunkCount: chunks.length,
    chunks: chunks.map((chunk) => ({
      index: chunk.index,
      offset: chunk.index * chunkSize,
      references: chunk.references.map((reference) => ({
        number: Number(reference.number),
        blockHash: normalizeHash(reference.blockHash),
      })),
      proof: chunk.proof.map(normalizeHash),
    })),
  };
}

function normalizeHash(value) {
  if (!/^0x[0-9a-f]{64}$/i.test(value ?? "")) throw new Error(`invalid bytes32 ${value}`);
  return value.toLowerCase();
}

if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const index = args.indexOf(flag);
    return index < 0 ? null : args[index + 1];
  };
  const sellerProofPath = value("--seller-proof") ?? value("--aggregate");
  const outputPath = value("--output");
  if (!sellerProofPath || !outputPath) {
    throw new Error("usage: generate-block-authentication-chunks.mjs --seller-proof seller.json --output chunks.json [--chunk-size 100]");
  }
  const sellerProof = JSON.parse(await readFile(resolve(sellerProofPath), "utf8"));
  const result = buildBlockAuthenticationChunks(sellerProof, Number(value("--chunk-size") ?? 100));
  await writeFile(resolve(outputPath), `${JSON.stringify(result, null, 2)}\n`);
}
