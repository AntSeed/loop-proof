#!/usr/bin/env node
import { createReadStream } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dedupeDependencies, finalizeBundle, finalizeClaim, locator, relayDependency, returnPathDependency } from "./proof-bundle.mjs";
import { returnPathCreditRaw } from "./return-path-selection.mjs";
import { ALPHA_FUND_BPS, ALPHA_RETURN_BPS } from "./predicate-policy.mjs";

const DEFAULT_SCAN = "/Users/alex/.antseed/forensics/wash-trading/scans/2026-08-13T22-54-53-096Z";

export async function buildDiscoveryProofBundle({ scanDirectory, baselineBundle, candidates, supplementalReturnPaths = [] }) {
  const protocolDeposits = await readJson(join(scanDirectory, "raw", "protocol-deposits.json"));
  const reports = new Map();
  const cases = new Map();
  const totalSettlementsBySeller = new Map(
    baselineBundle.claims
      .flatMap((claim) => claim.subjects)
      .map((seller) => [normalizeAddress(seller), []]),
  );
  const diagnostics = [];
  for (const candidate of candidates.candidates ?? []) {
    if (!candidate.eligibility?.eligible) continue;
    const report = await readJson(join(scanDirectory, "sellers", `${candidate.seller}.json`));
    reports.set(candidate.seller, report);
    if (candidate.state !== "proof_candidate") {
      diagnostics.push({ seller: candidate.seller, state: candidate.state, reason: candidate.state === "incomplete" ? "recipient_tracing_incomplete" : "no_fragmented_relay_convergence" });
      continue;
    }
    const seller = normalizeAddress(candidate.seller);
    const funder = normalizeAddress(candidate.eligibility.funder);
    const approvedBuyers = new Set((report.strongestCohort?.buyers ?? []).map((entry) => normalizeAddress(typeof entry === "string" ? entry : entry.buyer)).filter(Boolean));
    const fundingDependencies = [];
    const fundingTimes = new Map();
    const depositsByBuyer = groupBy((protocolDeposits.records ?? []).filter((entry) => normalizeAddress(entry.funder) === funder && approvedBuyers.has(normalizeAddress(entry.buyer)) && BigInt(entry.amountRaw) > 0n), (entry) => normalizeAddress(entry.buyer));
    for (const buyer of approvedBuyers) {
      const trace = await readJson(join(scanDirectory, "raw", "traces", `${buyer}.json`));
      if (!trace?.complete) continue;
      const direct = (trace.inboundUsdc ?? []).filter((entry) => normalizeAddress(entry.from) === funder && normalizeAddress(entry.to) === buyer && BigInt(entry.amountRaw) > 0n);
      const deposits = depositsByBuyer.get(buyer) ?? [];
      for (const entry of direct) fundingDependencies.push(locator("USDC_FUNDING", entry, { buyer, funder, amountRaw: String(entry.amountRaw), fundingKind: "direct_usdc_transfer" }));
      for (const entry of deposits) fundingDependencies.push(locator("USDC_FUNDING", entry, { buyer, funder, amountRaw: String(entry.amountRaw), fundingKind: "protocol_deposit" }));
      const earliest = [...direct, ...deposits].sort(compareTime)[0];
      if (earliest) fundingTimes.set(buyer, Number(earliest.timestamp));
    }
    const fundedBuyers = new Set([...approvedBuyers].filter((buyer) => fundingTimes.has(buyer)));
    cases.set(seller, {
      candidate,
      report,
      seller,
      funder,
      approvedBuyers: fundedBuyers,
      fundingTimes,
      fundingDependencies: dedupeDependencies(fundingDependencies),
      closureDependencies: candidate.paths.map((path) => relayDependency(path, seller, funder)),
      settlementDependencies: [],
    });
    if (!totalSettlementsBySeller.has(seller)) totalSettlementsBySeller.set(seller, []);
  }

  await streamSettlements(join(scanDirectory, "raw", "antscan", "settlementVolumes.ndjson"), (row) => {
    const seller = normalizeAddress(row.seller);
    const totalSettlements = totalSettlementsBySeller.get(seller);
    if (totalSettlements) {
      totalSettlements.push(locator("TOTAL_SETTLEMENT", row, {
        buyer: normalizeAddress(row.buyer),
        seller,
        amountRaw: String(row.deltaUsdc),
        channelId: row.channelId,
      }));
    }
    const entry = cases.get(seller);
    if (!entry) return;
    const buyer = normalizeAddress(row.buyer);
    const fundingTime = entry.fundingTimes.get(buyer);
    if (fundingTime == null || Number(row.timestamp) <= fundingTime) return;
    entry.settlementDependencies.push(locator("SETTLEMENT", row, {
      buyer,
      seller,
      amountRaw: String(row.deltaUsdc),
      channelId: row.channelId,
    }));
  });

  const newClaims = [];
  for (const entry of cases.values()) {
    const allSettlements = entry.settlementDependencies.sort(compareEvidenceTime);
    const sellerVolumeRaw = BigInt(entry.report.stats.volumeRaw);
    const allRetainedFunding = entry.fundingDependencies.filter((funding) => {
      const latest = allSettlements.filter((settlement) => settlement.buyer === funding.buyer).at(-1);
      return latest && Number(funding.timestamp) < Number(latest.timestamp);
    });
    const settlementCapacityRaw = supportedSettlementCapacity(allRetainedFunding, entry.closureDependencies);
    const settlements = selectLargestDeterministicSettlementSet(allSettlements, settlementCapacityRaw);
    const selectedBuyers = new Set(settlements.map((settlement) => settlement.buyer));
    const retainedFunding = allRetainedFunding.filter((funding) => selectedBuyers.has(funding.buyer));
    const evaluation = evaluateClosedLoopCandidate({ sellerVolumeRaw, settlements, fundings: retainedFunding, paths: entry.closureDependencies });
    const { accepted, selectedSettlementRaw: qualifiedVolumeRaw, retainedFundingRaw: fundingRaw, bottleneckReturnRaw, deficits } = evaluation;
    diagnostics.push({
      seller: entry.seller,
      state: accepted ? "proof_candidate" : "predicate_rejected",
      buyerCount: selectedBuyers.size,
      sellerVolumeRaw: sellerVolumeRaw.toString(),
      selectedSettlementRaw: qualifiedVolumeRaw.toString(),
      selectedShareBps: sellerVolumeRaw === 0n ? 0 : Number(qualifiedVolumeRaw * 10_000n / sellerVolumeRaw),
      retainedFundingRaw: fundingRaw.toString(),
      bottleneckReturnRaw: bottleneckReturnRaw.toString(),
      pathCount: entry.closureDependencies.length,
      destinationCount: new Set(entry.closureDependencies.map((path) => path.intermediary)).size,
      deficits,
    });
    if (!accepted) continue;
    newClaims.push(finalizeClaim({
      type: "P0_CLOSED_LOOP",
      subjects: [entry.seller],
      seller: entry.seller,
      approvedBuyers: [...selectedBuyers].sort(),
      approvedFunders: [entry.funder],
      evidenceCodes: ["fragmented_relay_convergence"],
      metrics: {
        sellerVolumeRaw: sellerVolumeRaw.toString(),
        qualifiedVolumeRaw: qualifiedVolumeRaw.toString(),
        qualifiedBuyerCount: selectedBuyers.size,
      },
      period: baselineBundle.period,
      dependencies: dedupeDependencies([
        ...retainedFunding,
        ...entry.closureDependencies,
        ...settlements,
        ...(totalSettlementsBySeller.get(entry.seller) ?? []),
      ]),
    }));
  }

  const replacedSellers = new Set(newClaims.map((claim) => claim.seller));
  const retainedClaims = baselineBundle.claims
    .filter((claim) => claim.type !== "P0_CLOSED_LOOP" || !replacedSellers.has(claim.seller))
    .map((claim) => {
      const { claimId: _claimId, leafHash: _leafHash, dependencyRoot: _dependencyRoot, ...body } = claim;
      const supplemental = supplementalReturnPaths.filter((path) => path.valid && normalizeAddress(path.hops?.[0]?.from) === normalizeAddress(claim.subjects[0]));
      return finalizeClaim({
        ...body,
        dependencies: dedupeDependencies([
          ...claim.dependencies.filter((entry) => entry.evidenceType !== "TOTAL_SETTLEMENT" && (supplemental.length === 0 || entry.evidenceType !== "RELAY_PATH")),
          ...supplemental.map((path) => returnPathDependency(path, normalizeAddress(claim.subjects[0]), normalizeAddress(path.hops.at(-1).to))),
          ...claim.subjects.flatMap((seller) => totalSettlementsBySeller.get(normalizeAddress(seller)) ?? []),
        ]),
      });
    });
  const claims = [...retainedClaims, ...newClaims];
  const bundle = finalizeBundle({
    ...baselineBundle,
    policyVersion: "aip-4-conserved-loop-bottleneck-v2",
    claims,
  });
  return { bundle, diagnostics };
}

export function evaluateClosedLoopCandidate({ sellerVolumeRaw, settlements, fundings, paths }) {
  const selectedSettlementRaw = sumRaw(settlements);
  const retainedFundingRaw = sumRaw(fundings);
  const bottleneckReturnRaw = paths.reduce((total, path) => total + returnPathCreditRaw(path), 0n);
  const deficits = {
    positiveVolumeRaw: selectedSettlementRaw > 0n ? "0" : "1",
    fundingRaw: retainedFundingRaw * 10_000n >= selectedSettlementRaw * ALPHA_FUND_BPS ? "0" : (ceilDiv(selectedSettlementRaw * ALPHA_FUND_BPS, 10_000n) - retainedFundingRaw).toString(),
    returnRaw: bottleneckReturnRaw * 10_000n >= selectedSettlementRaw * ALPHA_RETURN_BPS ? "0" : (ceilDiv(selectedSettlementRaw * ALPHA_RETURN_BPS, 10_000n) - bottleneckReturnRaw).toString(),
  };
  return {
    accepted: Object.values(deficits).every((value) => value === "0"),
    selectedSettlementRaw,
    retainedFundingRaw,
    bottleneckReturnRaw,
    deficits,
  };
}

export function supportedSettlementCapacity(fundings, paths) {
  const fundingRaw = sumRaw(fundings);
  const returnRaw = paths.reduce((total, path) => total + returnPathCreditRaw(path), 0n);
  const fundingCapacity = fundingRaw * 10_000n / ALPHA_FUND_BPS;
  const returnCapacity = returnRaw * 10_000n / ALPHA_RETURN_BPS;
  return fundingCapacity < returnCapacity ? fundingCapacity : returnCapacity;
}

export function selectLargestDeterministicSettlementSet(settlements, capacityRaw) {
  const chronological = [...settlements].sort(compareEvidenceTime);
  if (chronological.length === 0) return [];
  const selected = [chronological[0]];
  let total = BigInt(chronological[0].amountRaw);
  if (total > capacityRaw) return [];
  for (const settlement of chronological.slice(1).sort((left, right) => {
    const amountDifference = BigInt(right.amountRaw) - BigInt(left.amountRaw);
    return amountDifference === 0n ? compareEvidenceTime(left, right) : amountDifference > 0n ? 1 : -1;
  })) {
    const amount = BigInt(settlement.amountRaw);
    if (total + amount > capacityRaw) continue;
    selected.push(settlement);
    total += amount;
  }
  return selected.sort(compareEvidenceTime);
}

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
  const scanDirectory = resolve(value("--scan-dir") ?? DEFAULT_SCAN);
  const baselinePath = resolve(value("--baseline") ?? join(scanDirectory, "proof", "final-inputs", "proof-bundle.json"));
  const candidatesPath = resolve(value("--candidates") ?? join(scanDirectory, "discovery", "p0-loop-candidates.json"));
  const outputPath = resolve(value("--out") ?? join(scanDirectory, "proof", "candidate-bundle.json"));
  const diagnosticsPath = resolve(value("--diagnostics") ?? join(scanDirectory, "proof", "candidate-diagnostics.json"));
  const supplementalPath = resolve(value("--supplemental-return-paths") ?? join(dirname(fileURLToPath(import.meta.url)), "..", "cases", "flash-full-return-paths.json"));
  let supplementalReturnPaths = [];
  try {
    supplementalReturnPaths = await readJson(supplementalPath);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const { bundle, diagnostics } = await buildDiscoveryProofBundle({
    scanDirectory,
    baselineBundle: await readJson(baselinePath),
    candidates: await readJson(candidatesPath),
    supplementalReturnPaths,
  });
  await mkdir(dirname(outputPath), { recursive: true });
  await Promise.all([
    writeFile(outputPath, `${JSON.stringify(bundle, null, 2)}\n`),
    writeFile(diagnosticsPath, `${JSON.stringify({ version: 1, diagnostics }, null, 2)}\n`),
  ]);
  console.log(JSON.stringify({ outputPath, diagnosticsPath, claimCounts: bundle.claimCounts, reportRoot: bundle.reportRoot }));
}

async function streamSettlements(path, visit) {
  const lines = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    for (const row of JSON.parse(line).items ?? []) visit(row);
  }
}

function groupBy(values, key) { const result = new Map(); for (const value of values) { const group = key(value); const rows = result.get(group) ?? []; rows.push(value); result.set(group, rows); } return result; }
function compareTime(left, right) { return Number(left.timestamp) - Number(right.timestamp) || String(left.txHash).localeCompare(String(right.txHash)); }
function compareEvidenceTime(left, right) { return Number(left.timestamp) - Number(right.timestamp) || String(left.transactionHash).localeCompare(String(right.transactionHash)) || Number(left.logIndex ?? -1) - Number(right.logIndex ?? -1); }
function sumRaw(values) { return values.reduce((total, value) => total + BigInt(value.amountRaw), 0n); }
function minRaw(values) { return values.map(BigInt).reduce((minimum, value) => value < minimum ? value : minimum); }
function ceilDiv(numerator, denominator) { return (numerator + denominator - 1n) / denominator; }
function normalizeAddress(input) { return typeof input === "string" && /^0x[0-9a-f]{40}$/i.test(input) ? input.toLowerCase() : null; }
async function readJson(path) { return JSON.parse(await readFile(path, "utf8")); }

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { console.error(error.stack ?? error.message); process.exitCode = 1; });
