#!/usr/bin/env node
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { encodeStageSellerProof } from "./generate-aggregate-calldata.mjs";

export function sha256(bytes) {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

export function unpackArtifact(compressed, entry) {
  if (sha256(compressed) !== entry.gzipSha256) throw new Error("compressed artifact checksum mismatch");
  const bytes = gunzipSync(compressed, { maxOutputLength: 16 * 1024 * 1024 });
  if (bytes.length !== entry.uncompressedBytes || sha256(bytes) !== entry.sha256) {
    throw new Error("original artifact checksum mismatch");
  }
  return { bytes, artifact: JSON.parse(bytes) };
}

export function validateArtifact(artifact, entry, configuration) {
  if (artifact.version !== 3 || artifact.kind !== "antseed-wash-trading-seller-proof"
    || artifact.proofArchitecture !== "direct-seller-v1" || artifact.securityMode !== "production"
    || !artifact.proved || !artifact.verified || artifact.seller.toLowerCase() !== entry.seller
    || artifact.sellerProgramVKey !== configuration.sellerProgramVKey
    || !/^0x[0-9a-f]{768}$/i.test(artifact.publicValues)
    || !/^0x(?:[0-9a-f]{2})+$/i.test(artifact.proofBytes)) throw new Error("invalid production artifact");
  const words = artifact.publicValues.slice(2).match(/.{64}/g);
  const integer = index => BigInt(`0x${words[index]}`);
  if (integer(0) !== 1n || integer(1) !== 8453n
    || integer(2) !== BigInt(configuration.periodStartBlock)
    || integer(3) !== BigInt(configuration.periodEndBlock)
    || integer(4) !== BigInt(entry.seller)
    || integer(5) !== BigInt(entry.provenWashVolumeRaw)
    || integer(6) !== BigInt(entry.totalSellerVolumeRaw)
    || integer(5) !== BigInt(artifact.provenWashVolumeRaw)
    || integer(6) !== BigInt(artifact.totalSellerVolumeRaw)
    || `0x${words[7]}` !== artifact.evidenceDigest
    || integer(8) !== BigInt(entry.blockReferenceCount)
    || integer(8) !== BigInt(artifact.blockReferenceCount)
    || integer(9) !== BigInt(artifact.blockAuthenticationChunkSize)
    || integer(10) !== BigInt(entry.blockAuthenticationChunkCount)
    || integer(10) !== BigInt(artifact.blockAuthenticationChunks.length)
    || `0x${words[11]}` !== artifact.blockAuthenticationRoot
    || artifact.proofBytes.slice(0, 10).toLowerCase() !== configuration.verifierHash.slice(0, 10)) {
    throw new Error("proof journal or verifier does not match the package manifest");
  }
  let references = 0;
  for (const [index, chunk] of artifact.blockAuthenticationChunks.entries()) {
    if (chunk.index !== index) throw new Error("chunk order mismatch");
    references += chunk.references.length;
  }
  if (references !== entry.blockReferenceCount) throw new Error("reference count mismatch");
}

export async function loadPackage(directory) {
  const manifest = JSON.parse(await readFile(join(directory, "manifest.json"), "utf8"));
  if (manifest.version !== 1 || manifest.kind !== "antseed-published-seller-proofs"
    || manifest.chainId !== 8453 || manifest.proofCount !== manifest.artifacts.length) {
    throw new Error("invalid package manifest");
  }
  const artifacts = [];
  const sellers = new Set();
  let volume = 0n;
  let total = 0n;
  for (const entry of manifest.artifacts) {
    if (!/^0x[0-9a-f]{40}$/.test(entry.seller)
      || entry.file !== `artifacts/${entry.seller}.json.gz` || sellers.has(entry.seller)) {
      throw new Error("invalid or duplicate artifact path/seller");
    }
    const unpacked = unpackArtifact(await readFile(join(directory, entry.file)), entry);
    validateArtifact(unpacked.artifact, entry, manifest.configuration);
    artifacts.push({ entry, ...unpacked });
    sellers.add(entry.seller);
    volume += BigInt(entry.provenWashVolumeRaw);
    total += BigInt(entry.totalSellerVolumeRaw);
  }
  if (volume !== BigInt(manifest.totalProvenWashVolumeRaw) || total !== BigInt(manifest.totalSellerVolumeRaw)) {
    throw new Error("package totals mismatch");
  }
  return { manifest, artifacts };
}

export function cast(args, execute = execFileSync) {
  const env = { ...process.env };
  delete env.ETH_PASSWORD;
  try {
    return execute("cast", args, { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 2 * 1024 * 1024 }).trim();
  } catch {
    throw new Error(`cast ${args[0]} failed; check your local Foundry installation and RPC configuration`);
  }
}

export function encodeChunk(proofId, chunk, encode = cast) {
  return encode(["calldata", "authenticateBlockReferences(bytes32,uint32,(uint64,bytes32)[],bytes32[])",
    proofId, String(chunk.index), `[${chunk.references.map(reference => `(${reference.number},${reference.blockHash})`).join(",")}]`,
    `[${chunk.proof.join(",")}]`]);
}

async function prepare(directory, output) {
  const { manifest, artifacts } = await loadPackage(directory);
  await mkdir(dirname(output), { recursive: true });
  await mkdir(output);
  let calls = 0;
  for (const { entry, artifact, bytes } of artifacts) {
    if (cast(["keccak", artifact.publicValues]).toLowerCase() !== entry.proofId) throw new Error("proof ID mismatch");
    const sellerDirectory = join(output, entry.seller);
    await mkdir(join(sellerDirectory, "chunks"), { recursive: true });
    await writeFile(join(sellerDirectory, "artifact.json"), bytes);
    await writeFile(join(sellerDirectory, "proof-id.txt"), `${entry.proofId}\n`);
    await writeFile(join(sellerDirectory, "stage.hex"), `${encodeStageSellerProof(artifact.publicValues, artifact.proofBytes)}\n`);
    for (const chunk of artifact.blockAuthenticationChunks) {
      await writeFile(join(sellerDirectory, "chunks", `${String(chunk.index).padStart(5, "0")}.hex`), `${encodeChunk(entry.proofId, chunk)}\n`);
    }
    await writeFile(join(sellerDirectory, "finalize.hex"), `${cast(["calldata", "finalizeSellerProof(bytes32)", entry.proofId])}\n`);
    calls += 2 + artifact.blockAuthenticationChunks.length;
    console.log(`Prepared ${entry.label}: ${entry.seller}`);
  }
  await writeFile(join(output, "prepared.json"), `${JSON.stringify({ proofCount: artifacts.length, directCalls: calls,
    configuration: manifest.configuration, packageManifestSha256: sha256(await readFile(join(directory, "manifest.json"))) }, null, 2)}\n`);
  console.log(`Prepared ${artifacts.length} sellers, ${calls} direct calls. No RPC or signing operation was performed.`);
}

export function checkDeployment(manifest, registry, query = cast) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(registry) || /^0x0{40}$/i.test(registry)) throw new Error("provide the real deployed registry address");
  if (query(["chain-id"]) !== "8453") throw new Error("RPC must be Base chain ID 8453");
  for (const [address, expectedHash] of [[registry, manifest.registryRuntimeCodeHash],
    [manifest.configuration.verifier, manifest.verifierRuntimeCodeHash],
    [manifest.configuration.blockhashStore, manifest.blockhashStoreRuntimeCodeHash]]) {
    const code = query(["code", address]);
    if (code === "0x" || query(["keccak", code]).toLowerCase() !== expectedHash) {
      throw new Error(`runtime bytecode mismatch at ${address}; stop for deployment/build review`);
    }
  }
  for (const [field, type] of [["verifier", "address"], ["verifierHash", "bytes32"], ["blockhashStore", "address"],
    ["sellerProgramVKey", "bytes32"], ["periodStartBlock", "uint64"], ["periodEndBlock", "uint64"]]) {
    const actual = query(["call", registry, `${field}()(${type})`]).split(/\s/)[0].toLowerCase();
    if (actual !== String(manifest.configuration[field]).toLowerCase()) throw new Error(`deployed ${field} mismatch`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [mode, directory, extra, ...rest] = process.argv.slice(2);
  if (!directory || rest.length || !["verify", "prepare", "check-deployment"].includes(mode)
    || (mode === "verify" ? extra != null : extra == null)) {
    throw new Error("usage: published-seller-proofs.mjs verify PACKAGE | prepare PACKAGE NEW_OUTPUT | check-deployment PACKAGE REGISTRY");
  }
  if (mode === "prepare") await prepare(resolve(directory), resolve(extra));
  else {
    const { manifest } = await loadPackage(resolve(directory));
    if (mode === "check-deployment") {
      if (!process.env.ETH_RPC_URL) throw new Error("set ETH_RPC_URL for read-only deployment checks");
      checkDeployment(manifest, extra);
    }
    console.log(`${manifest.proofCount} artifacts verified${mode === "check-deployment" ? "; deployed code and all six settings match" : " (integrity/journal checks, not a new SNARK verification)"}. No transactions sent.`);
  }
}
