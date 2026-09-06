import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { atomicReturnEvidence, discoverCachedRelayReturns, requiredReturnRaw, returnPathCreditRaw, selectReturnEvidence } from "./return-path-selection.mjs";
import { ALPHA_RETURN_BPS, MAX_RETURN_PATHS, T_PATH_SECONDS } from "./predicate-policy.mjs";

const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const key = (hop) => `${String(hop.txHash ?? hop.transactionHash).toLowerCase()}:${Number(hop.logIndex)}`;
const sum = (paths) => paths.reduce((total, path) => total + returnPathCreditRaw(path), 0n);

export function classifySeller(entry, targetBps = 5000) {
  requiredReturnRaw(0, targetBps);
  if (!entry.supports30PercentReturnFloor) return "excluded-baseline";
  if (entry.guestAlphaReturnBps >= Number(targetBps)) return "already-meets-target";
  if (entry.returnedCreditRaw == null) return "missing-return-measurement";
  return BigInt(entry.returnedCreditRaw) >= requiredReturnRaw(entry.provenWashVolumeRaw, targetBps)
    ? "already-meets-target" : "search-required";
}

export function selectFixedVolumeReturns({ candidates, baseline, volumeRaw, targetBps = 5000, seller, funder, earliest, end, startBlock, endBlock }) {
  const requiredRaw = requiredReturnRaw(volumeRaw, targetBps);
  const valid = (path) => {
    const hops = atomicReturnEvidence(path);
    return hops.length > 0 && hops[0].from?.toLowerCase() === seller.toLowerCase()
      && hops.at(-1).to?.toLowerCase() === funder.toLowerCase()
      && hops.every((hop) => Number.isSafeInteger(Number(hop.timestamp)) && Number(hop.timestamp) > earliest
        && Number(hop.timestamp) <= end && /^0x[0-9a-f]{64}$/i.test(hop.txHash ?? hop.transactionHash ?? "")
        && Number.isSafeInteger(Number(hop.logIndex)) && Number(hop.logIndex) >= 0
        && (hop.blockNumber == null || (Number(hop.blockNumber) >= startBlock && Number(hop.blockNumber) <= endBlock)));
  };
  if (!baseline.every(valid)) throw new Error("baseline paths do not match seller, funder or period");
  const baselineCredit = sum(baseline);
  const checkedBaseline = selectReturnEvidence(baseline, { requiredRaw: baselineCredit, earliestSettlementTimestamp: earliest });
  if (!checkedBaseline.complete || checkedBaseline.evidence.length !== baseline.length) throw new Error("baseline contains invalid or overlapping return paths");
  const remaining = selectReturnEvidence(candidates.filter(valid), {
    requiredRaw: requiredRaw > baselineCredit ? requiredRaw - baselineCredit : 0n,
    earliestSettlementTimestamp: earliest,
    reservedKeys: baseline.flatMap(atomicReturnEvidence).map(key),
    maxPaths: MAX_RETURN_PATHS - baseline.length,
  });
  const augmented = { evidence: [...baseline, ...remaining.evidence], returnedRaw: baselineCredit + remaining.returnedRaw };
  const reselected = selectReturnEvidence([...baseline, ...candidates].filter(valid), { requiredRaw, earliestSettlementTimestamp: earliest });
  const selected = augmented.returnedRaw >= reselected.returnedRaw ? augmented : reselected;
  return {
    fixedVolumeRaw: String(volumeRaw), targetReturnBps: Number(targetBps), requiredReturnRaw: requiredRaw.toString(),
    baselineReturnRaw: baselineCredit.toString(), candidateReturnRaw: selected.returnedRaw.toString(),
    shortfallRaw: (requiredRaw > selected.returnedRaw ? requiredRaw - selected.returnedRaw : 0n).toString(),
    targetMetByCandidates: selected.returnedRaw >= requiredRaw,
    paths: selected.evidence.map((path) => ({ creditRaw: returnPathCreditRaw(path).toString(), hops: atomicReturnEvidence(path).map((hop) => ({
      ...hop, txHash: (hop.txHash ?? hop.transactionHash).toLowerCase(),
    })) })),
  };
}

async function optionalJson(path) {
  try { return await readJson(path); } catch (error) { if (error.code === "ENOENT") return null; throw error; }
}

function pathsFromDocument(document) {
  if (Array.isArray(document.paths) && document.paths.every((path) => path.hops?.every((hop) => typeof hop === "object"))) {
    return document.paths.map((path) => ({ evidenceType: "RELAY_PATH", hops: path.hops }));
  }
  if (document.edges && document.paths) {
    const edges = new Map(document.edges.map((edge) => [edge.id, edge]));
    return document.paths.map((path) => ({ evidenceType: "RELAY_PATH", hops: path.hops.map((id) => {
      if (!edges.has(id)) throw new Error(`missing candidate edge ${id}`);
      return edges.get(id);
    }) }));
  }
  if (document.claims) return document.claims.flatMap((claim) => claim.selectedEvidence ?? [])
    .filter((entry) => ["RELAY_PATH", "DIRECT_SELLER_FUNDER", "DIRECT_SELLER_BUYER"].includes(entry.evidenceType));
  throw new Error("unsupported return candidate document");
}

export async function searchFixedVolumeReturns({ statusPath, manifestPath, traceDirectory, outputDirectory, targetBps = 5000 }) {
  requiredReturnRaw(0, targetBps);
  const statusBytes = await readFile(statusPath);
  const manifestBytes = await readFile(manifestPath);
  const status = JSON.parse(statusBytes);
  const manifest = JSON.parse(manifestBytes);
  await mkdir(outputDirectory, { recursive: false });
  const report = {
    targetReturnBps: Number(targetBps), activeGuestReturnBps: Number(ALPHA_RETURN_BPS),
    statusSha256: hash(statusBytes), manifestSha256: hash(manifestBytes),
    volumeSelectionChanged: false, guestChanged: false, proverNetworkSubmitted: false,
    candidateEvidenceAuthenticated: false, results: [],
  };
  await writeFile(join(outputDirectory, "inputs.json"), JSON.stringify({ statusPath, manifestPath, traceDirectory, ...report }, null, 2), { flag: "wx" });
  for (const entry of status.sellers) {
    const classification = classifySeller(entry, targetBps);
    if (classification !== "search-required") {
      report.results.push({ seller: entry.seller, status: classification });
      continue;
    }
    const result = { seller: entry.seller, name: entry.name, provenWashVolumeRaw: entry.provenWashVolumeRaw, totalSellerVolumeRaw: entry.totalSellerVolumeRaw };
    try {
      const config = manifest.sellers.find((candidate) => candidate.seller === entry.seller);
      if (!config) throw new Error("missing fixed-volume input manifest");
      const artifactBytes = await readFile(entry.artifact);
      if (hash(artifactBytes) !== entry.artifactSha256.replace(/^0x/, "")) throw new Error("baseline artifact hash mismatch");
      const artifact = JSON.parse(artifactBytes);
      if (!artifact.verified || artifact.provenWashVolumeRaw !== entry.provenWashVolumeRaw || artifact.totalSellerVolumeRaw !== entry.totalSellerVolumeRaw) throw new Error("baseline artifact V/T mismatch");
      const inputBytes = await readFile(config.sellerInput);
      const input = JSON.parse(inputBytes);
      const evidence = input.evidence?.input;
      if (!evidence || input.seller !== entry.seller || evidence.seller !== entry.seller || input.period_start_block !== status.periodStartBlock || input.period_end_block !== status.periodEndBlock) throw new Error("seller input subject or period mismatch");
      const earliest = Math.min(...evidence.settlements.map((ref) => Number(evidence.blocks[ref.block].header.timestamp)));
      const end = Number(input.total_volume.header.timestamp);
      const baseline = pathsFromDocument(await readJson(config.baselineReturns));
      if (sum(baseline).toString() !== entry.returnedCreditRaw || baseline.length !== evidence.returns.length) throw new Error("baseline return measurement mismatch");
      const candidates = [...baseline];
      const sourceHashes = {};
      for (const path of config.candidateSources ?? []) {
        const bytes = await readFile(path);
        sourceHashes[path] = hash(bytes);
        candidates.push(...pathsFromDocument(JSON.parse(bytes)));
      }
      const missingTraces = new Set();
      const loadTrace = async (address) => {
        const cached = config.traceOverrides?.[address] ? await readJson(config.traceOverrides[address]) : await optionalJson(join(traceDirectory, `${address}.json`));
        if (!cached?.complete) missingTraces.add(address);
        const bound = (values) => (values ?? []).filter((hop) => Number(hop.timestamp) > earliest && Number(hop.timestamp) <= end);
        return cached ? { ...cached, inboundUsdc: bound(cached.inboundUsdc), outboundUsdc: bound(cached.outboundUsdc) } : null;
      };
      const sellerTrace = await loadTrace(entry.seller);
      const funderTrace = await loadTrace(evidence.funder);
      const discovered = await discoverCachedRelayReturns({ seller: entry.seller, funder: evidence.funder, sellerTrace, funderTrace, loadTrace,
        earliestSettlementTimestamp: earliest, requiredRaw: (1n << 128n) - 1n });
      candidates.push(...discovered.paths);
      candidates.push(...(sellerTrace?.outboundUsdc ?? []).filter((hop) => hop.to === evidence.funder).map((hop) => ({ ...hop, evidenceType: "DIRECT_SELLER_FUNDER" })));
      const selected = selectFixedVolumeReturns({ candidates, baseline, volumeRaw: entry.provenWashVolumeRaw, targetBps,
        seller: entry.seller, funder: evidence.funder, earliest, end, startBlock: input.period_start_block, endBlock: input.period_end_block });
      if (hash(await readFile(config.sellerInput)) !== hash(inputBytes)) throw new Error("baseline input changed during search");
      Object.assign(result, selected, { paths: undefined, status: selected.targetMetByCandidates ? "candidate-target-met-needs-authentication" : "candidate-shortfall",
        sellerInput: config.sellerInput, sellerInputSha256: hash(inputBytes), funder: evidence.funder,
        sourceHashes, candidateCount: candidates.length, selectedPathCount: selected.paths.length,
        missingTraces: [...missingTraces].sort(), searchExhaustive: false, pathWindowSeconds: T_PATH_SECONDS });
      await writeFile(join(outputDirectory, `${entry.seller}.json`), JSON.stringify({ ...result, paths: selected.paths }, null, 2), { flag: "wx" });
    } catch (error) {
      Object.assign(result, { status: "search-failed", error: error.message });
    }
    report.results.push(result);
    console.log(JSON.stringify(result));
  }
  if (hash(await readFile(statusPath)) !== report.statusSha256) throw new Error("baseline status changed during search");
  await writeFile(join(outputDirectory, "summary.json"), JSON.stringify(report, null, 2), { flag: "wx" });
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const value = (flag) => args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined;
  if (!value("--status") || !value("--manifest") || !value("--trace-dir") || !value("--out-dir")) throw new Error("require --status, --manifest, --trace-dir and a NEW --out-dir; optional --target-bps (default 5000)");
  await searchFixedVolumeReturns({ statusPath: resolve(value("--status")), manifestPath: resolve(value("--manifest")), traceDirectory: resolve(value("--trace-dir")), outputDirectory: resolve(value("--out-dir")), targetBps: value("--target-bps") ?? 5000 });
}
