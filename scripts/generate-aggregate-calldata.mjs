#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

export const submitHistoricalAggregateSignature = "submitHistoricalAggregate(bytes,bytes)";
export const submitHistoricalAggregateSelector = "2a64a7e6";

export function buildAggregateCalldataArtifact(aggregate) {
  if (aggregate?.version !== 1 || aggregate.kind !== "antseed-wash-trading-aggregate-proof") {
    throw new Error("invalid aggregate proof artifact");
  }
  const aggregatorProgramId = fixedHex(aggregate.aggregatorProgramId, 32, "aggregator program ID");
  const aggregatorProgramVKey = fixedHex(aggregate.aggregatorProgramVKey, 32, "aggregator program vkey");
  const publicValues = dynamicHex(aggregate.publicValues, "public values");
  const proofBytes = dynamicHex(aggregate.proofBytes, "proof bytes");
  const calldata = encodeSubmitHistoricalAggregate(publicValues, proofBytes);
  return {
    version: 1,
    kind: "antseed-wash-trading-submit-historical-aggregate-calldata",
    securityMode: aggregate.securityMode,
    chainId: aggregate.chainId,
    callSignature: submitHistoricalAggregateSignature,
    aggregatorProgramId,
    aggregatorProgramVKey,
    publicValues,
    proofBytes,
    calldata,
  };
}

export function encodeSubmitHistoricalAggregate(publicValues, proofBytes) {
  const publicValuesBody = encodeDynamicBytes(dynamicHex(publicValues, "public values"));
  const proofBody = encodeDynamicBytes(dynamicHex(proofBytes, "proof bytes"));
  const headSize = 32 * 2;
  const proofOffset = headSize + publicValuesBody.length / 2;
  return `0x${submitHistoricalAggregateSelector}${word(headSize)}${word(proofOffset)}${publicValuesBody}${proofBody}`;
}

function encodeDynamicBytes(value) {
  const bytes = value.slice(2);
  const byteLength = bytes.length / 2;
  const paddedLength = Math.ceil(byteLength / 32) * 64;
  return `${word(byteLength)}${bytes.padEnd(paddedLength, "0")}`;
}

function fixedHex(value, byteLength, label) {
  if (!new RegExp(`^0x[0-9a-fA-F]{${byteLength * 2}}$`).test(value ?? "")) {
    throw new Error(`invalid ${label}`);
  }
  return value.toLowerCase();
}

function dynamicHex(value, label) {
  if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(value ?? "")) throw new Error(`invalid ${label}`);
  return value.toLowerCase();
}

function word(value) {
  return BigInt(value).toString(16).padStart(64, "0");
}

if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const index = args.indexOf(flag);
    return index < 0 ? null : args[index + 1];
  };
  const aggregatePath = value("--aggregate");
  const outputPath = value("--output");
  if (!aggregatePath || !outputPath) {
    throw new Error("usage: generate-aggregate-calldata.mjs --aggregate aggregate-proof.json --output calldata.json");
  }
  const aggregate = JSON.parse(await readFile(resolve(aggregatePath), "utf8"));
  const artifact = buildAggregateCalldataArtifact(aggregate);
  await writeFile(resolve(outputPath), `${JSON.stringify(artifact, null, 2)}\n`);
}
