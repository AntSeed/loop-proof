#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

export const stageSellerProofSignature = "stageSellerProof(bytes,bytes)";
export const stageSellerProofSelector = "2be631a3";

export function buildSellerCalldataArtifact(sellerProof) {
  if (sellerProof?.version !== 3 || sellerProof.kind !== "antseed-wash-trading-seller-proof"
      || sellerProof.proofArchitecture !== "direct-seller-v1" || sellerProof.proved !== true
      || sellerProof.verified !== true) {
    throw new Error("invalid direct seller proof artifact");
  }
  const sellerProgramVKey = fixedHex(sellerProof.sellerProgramVKey, 32, "seller program vkey");
  const publicValues = dynamicHex(sellerProof.publicValues, "public values");
  const proofBytes = dynamicHex(sellerProof.proofBytes, "proof bytes");
  if (proofBytes === "0x") throw new Error("proof bytes are empty");
  return {
    version: 2,
    kind: "antseed-wash-trading-stage-seller-proof-calldata",
    proofArchitecture: "direct-seller-v1",
    securityMode: sellerProof.securityMode,
    chainId: sellerProof.chainId,
    seller: sellerProof.seller.toLowerCase(),
    sellerProgramVKey,
    callSignature: stageSellerProofSignature,
    publicValues,
    proofBytes,
    calldata: encodeStageSellerProof(publicValues, proofBytes),
  };
}

export function encodeStageSellerProof(publicValues, proofBytes) {
  const publicValuesBody = encodeDynamicBytes(dynamicHex(publicValues, "public values"));
  const proofBody = encodeDynamicBytes(dynamicHex(proofBytes, "proof bytes"));
  const headSize = 64;
  const proofOffset = headSize + publicValuesBody.length / 2;
  return `0x${stageSellerProofSelector}${word(headSize)}${word(proofOffset)}${publicValuesBody}${proofBody}`;
}

function encodeDynamicBytes(value) {
  const bytes = value.slice(2);
  const byteLength = bytes.length / 2;
  const paddedLength = Math.ceil(byteLength / 32) * 64;
  return `${word(byteLength)}${bytes.padEnd(paddedLength, "0")}`;
}

function fixedHex(value, byteLength, label) {
  if (!new RegExp(`^0x[0-9a-fA-F]{${byteLength * 2}}$`).test(value ?? "")) throw new Error(`invalid ${label}`);
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
  const sellerProofPath = value("--seller-proof") ?? value("--aggregate");
  const outputPath = value("--output");
  if (!sellerProofPath || !outputPath) {
    throw new Error("usage: generate-aggregate-calldata.mjs --seller-proof seller-proof.json --output calldata.json");
  }
  const sellerProof = JSON.parse(await readFile(resolve(sellerProofPath), "utf8"));
  await writeFile(resolve(outputPath), `${JSON.stringify(buildSellerCalldataArtifact(sellerProof), null, 2)}\n`);
}
