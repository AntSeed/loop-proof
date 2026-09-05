import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return `0x${hash.digest("hex")}`;
}

export function validateArtifact(artifact, seller, manifest) {
  const expected = {
    version: 3,
    kind: "antseed-wash-trading-seller-proof",
    proofArchitecture: "direct-seller-v1",
    securityMode: "development",
    alphaReturnBps: 3000,
    seller: seller.seller,
    periodStartBlock: manifest.periodStartBlock,
    periodEndBlock: manifest.periodEndBlock,
    sellerProgramVKey: manifest.sellerProgramVKey,
    provenWashVolumeRaw: seller.provenWashVolumeRaw,
    totalSellerVolumeRaw: seller.totalSellerVolumeRaw,
    evidenceDigest: seller.evidenceDigest,
    proved: true,
    verified: true,
    proverNetworkSubmitted: false,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (artifact[key] !== value) throw new Error(`${seller.seller}: unexpected ${key}`);
  }
  if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(artifact.proofBytes ?? "")) throw new Error("missing development proof bytes");
  if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(artifact.publicValues ?? "")) throw new Error("missing public values");
  if (!Array.isArray(artifact.blockAuthenticationChunks)
    || artifact.blockAuthenticationChunks.length !== artifact.blockAuthenticationChunkCount
    || artifact.blockAuthenticationChunkCount < 1) throw new Error("missing block authentication chunks");
}

export function validateManifest(manifest) {
  if (manifest.alphaReturnBps !== 3000 || manifest.securityMode !== "development"
    || manifest.productionReady !== false || !Array.isArray(manifest.sellers) || !manifest.sellers.length
    || !Number.isSafeInteger(manifest.periodStartBlock) || manifest.periodStartBlock < 1
    || !Number.isSafeInteger(manifest.periodEndBlock) || manifest.periodEndBlock < manifest.periodStartBlock) {
    throw new Error("invalid development manifest");
  }
  const sellers = new Set();
  for (const seller of manifest.sellers) {
    if (!/^0x[0-9a-f]{40}$/.test(seller.seller) || sellers.has(seller.seller)) throw new Error("invalid or duplicate seller");
    sellers.add(seller.seller);
    if (Boolean(seller.sellerInput) === Boolean(seller.evidencePath)
      || (!seller.sellerInput && (!seller.totalVolumePath || !["closed-loop", "reciprocal"].includes(seller.evidenceKind)))) {
      throw new Error("select exactly one saved seller input or evidence with total-volume witness");
    }
  }
}

async function run(command, args, logPath) {
  const log = createWriteStream(logPath);
  await new Promise((accept, reject) => {
    const child = spawn(command, args, { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.pipe(log, { end: false });
    child.stderr.pipe(log, { end: false });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? accept() : reject(new Error(`command exited ${code}; see ${logPath}`)));
  }).finally(() => new Promise((accept) => log.end(accept)));
}

async function main() {
  const [manifestPath, outputPath] = process.argv.slice(2);
  if (!manifestPath || !outputPath || process.argv.length !== 4) throw new Error("usage: node scripts/replay-seller-development.mjs manifest.json output-directory");
  const manifest = JSON.parse(await readFile(resolve(manifestPath), "utf8"));
  validateManifest(manifest);
  const attestation = JSON.parse(await readFile(manifest.guestAttestation, "utf8"));
  if (!attestation.reproducible || attestation.guests?.seller?.programVKey !== manifest.sellerProgramVKey
    || await sha256(manifest.sellerElf) !== attestation.guests.seller.elfSha256) throw new Error("guest attestation mismatch");
  const sourceFiles = Object.entries(attestation.verifiedGuestSourceFiles ?? {});
  if (!sourceFiles.length) throw new Error("missing source attestation");
  for (const [path, expected] of sourceFiles) {
    if (await sha256(join(root, path)) !== expected) throw new Error(`guest source drift: ${path}`);
  }
  const output = resolve(outputPath);
  await mkdir(join(output, "sellers"), { recursive: true });
  await mkdir(join(output, "logs"), { recursive: true });
  const manifestHash = await sha256(resolve(manifestPath));
  const proverHash = await sha256(manifest.prover);
  const checkpointPath = join(output, "summary.json");
  let summary;
  try {
    summary = JSON.parse(await readFile(checkpointPath, "utf8"));
    if (summary.manifestSha256 !== manifestHash || summary.proverSha256 !== proverHash) throw new Error("checkpoint provenance mismatch; use a fresh output directory");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    summary = {
      version: 1, securityMode: "development", alphaReturnBps: 3000,
      productionReady: false, aip4Compliant: false, proverNetworkSubmitted: false,
      blockers: manifest.blockers, manifestSha256: manifestHash, proverSha256: proverHash,
      sellerProgramVKey: manifest.sellerProgramVKey, guestElfSha256: attestation.guests.seller.elfSha256,
      expectedSellerCount: manifest.sellers.length, excluded: manifest.excluded,
      startedAt: new Date().toISOString(), results: [], complete: false,
    };
  }
  let writes = Promise.resolve();
  const persist = () => {
    const content = `${JSON.stringify(summary, null, 2)}\n`;
    writes = writes.then(async () => {
      await writeFile(`${checkpointPath}.tmp`, content);
      await rename(`${checkpointPath}.tmp`, checkpointPath);
    });
    return writes;
  };
  await persist();
  let next = 0;
  const worker = async () => {
    while (next < manifest.sellers.length) {
      const seller = manifest.sellers[next++];
      const artifactPath = join(output, "sellers", `${seller.seller}.json`);
      const logPath = join(output, "logs", `${seller.seller}.log`);
      try {
        const inputs = seller.sellerInput ? [seller.sellerInput] : [seller.evidencePath, seller.totalVolumePath];
        const hashes = Object.fromEntries(await Promise.all(inputs.map(async (path) => [path, await sha256(path)])));
        const previous = summary.results.find((result) => result.seller === seller.seller && result.success);
        if (previous) {
          if (JSON.stringify(previous.inputSha256) !== JSON.stringify(hashes)
            || await sha256(artifactPath) !== previous.artifactSha256) throw new Error("resume input/artifact changed");
          validateArtifact(JSON.parse(await readFile(artifactPath, "utf8")), seller, manifest);
          continue;
        }
        console.log(`START ${seller.label ?? seller.seller}`);
        const args = ["--development", "--seller", seller.seller, "--seller-elf", manifest.sellerElf, "--output", artifactPath];
        if (seller.sellerInput) args.push("--seller-input", seller.sellerInput);
        else args.push("--evidence", `${seller.evidenceKind}:${seller.evidencePath}`, "--total-volume-witness", seller.totalVolumePath);
        await run(manifest.prover, args, logPath);
        for (const [path, hash] of Object.entries(hashes)) if (await sha256(path) !== hash) throw new Error("input changed during execution");
        const artifact = JSON.parse(await readFile(artifactPath, "utf8"));
        validateArtifact(artifact, seller, manifest);
        const artifactSha256 = await sha256(artifactPath);
        summary.results = summary.results.filter((result) => result.seller !== seller.seller);
        summary.results.push({ seller: seller.seller, label: seller.label, success: true,
          artifact: artifactPath, artifactSha256, inputSha256: hashes,
          provenWashVolumeRaw: artifact.provenWashVolumeRaw, totalSellerVolumeRaw: artifact.totalSellerVolumeRaw,
          executionMillis: artifact.executionMillis, instructionCount: artifact.instructionCount,
          blockReferenceCount: artifact.blockReferenceCount, evidenceDigest: artifact.evidenceDigest });
        console.log(`PASS ${seller.label ?? seller.seller} (${artifact.executionMillis}ms)`);
      } catch (error) {
        summary.results = summary.results.filter((result) => result.seller !== seller.seller);
        summary.results.push({ seller: seller.seller, success: false, error: error.message });
        console.error(`FAIL ${seller.label ?? seller.seller}: ${error.message}`);
      }
      await persist();
    }
  };
  await Promise.all([worker(), worker()]);
  summary.complete = summary.results.length === manifest.sellers.length && summary.results.every((result) => result.success);
  const successful = summary.results.filter((result) => result.success);
  summary.totalProvenWashVolumeRaw = successful.reduce((sum, result) => sum + BigInt(result.provenWashVolumeRaw), 0n).toString();
  summary.totalSellerVolumeRaw = successful.reduce((sum, result) => sum + BigInt(result.totalSellerVolumeRaw), 0n).toString();
  summary.finishedAt = new Date().toISOString();
  await persist();
  if (!summary.complete) process.exitCode = 1;
  console.log(`SUMMARY ${checkpointPath}: ${successful.length}/${manifest.sellers.length}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error); process.exitCode = 1; });
}
