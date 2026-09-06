import { createReadStream } from "node:fs";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { finalizeBundle, finalizeClaim, locator, relayDependency, returnPathDependency } from "./proof-bundle.mjs";
import { atomicReturnEvidence, discoverCachedRelayReturns, selectReturnEvidence, returnPathCreditRaw } from "./return-path-selection.mjs";
import { PREDICATE_POLICY, PREDICATE_POLICY_HASH, MAX_RETURN_PATHS } from "./predicate-policy.mjs";

export function primaryUsdcCohort(report, selectedFunder = report.strongestCohort?.funder) {
  const funder = selectedFunder;
  const source = (report.fundingProvenance?.sources ?? []).find((entry) => entry.funder === funder);
  if (!source || BigInt(source.fundedAmountRaw ?? 0) <= 0n || !source.buyers?.length) throw new Error("no positive primary USDC funding cohort");
  return { funder, buyers: [...new Set(source.buyers)].sort() };
}

export async function buildUsdcCandidates({ scanDirectory, baseline, sellers, outputDirectory, supplementalTraceDirectory, funderBySeller = {}, traceOverrides = {}, baselineReturnEvidence = {} }) {
  await mkdir(outputDirectory, { recursive: true });
  const scan = await readJson(join(scanDirectory, "scan.json"));
  if (JSON.stringify(scan.proofPeriod) !== JSON.stringify(baseline.period)) throw new Error("scan/bundle period mismatch");
  const deposits = await readJson(join(scanDirectory, "raw", "protocol-deposits.json"));
  const traceCache = new Map();
  const loadTrace = async (address) => {
    if (!traceCache.has(address)) {
      const supplemental = traceOverrides[address] ? await readJson(traceOverrides[address])
        : supplementalTraceDirectory ? await optionalJson(join(supplementalTraceDirectory, `${address}.json`)) : null;
      traceCache.set(address, supplemental ?? await optionalJson(join(scanDirectory, "raw", "traces", `${address}.json`)));
    }
    return traceCache.get(address);
  };
  const cases = new Map();
  const diagnostics = [];
  for (const seller of [...new Set(sellers)]) {
    try {
      const report = await readJson(join(scanDirectory, "sellers", `${seller}.json`));
      const { funder, buyers } = primaryUsdcCohort(report, funderBySeller[seller] ?? report.strongestCohort?.funder);
      const funding = [];
      const earliest = new Map();
      for (const buyer of buyers) {
        const trace = await loadTrace(buyer);
        if (!trace?.complete) throw new Error(`incomplete funding trace: ${buyer}`);
        const direct = (trace.inboundUsdc ?? []).filter((entry) => entry.from === funder && entry.to === buyer);
        const deposited = (deposits.records ?? []).filter((entry) => entry.funder === funder && entry.buyer === buyer);
        for (const [kind, entries] of [["direct_usdc_transfer", direct], ["protocol_deposit", deposited]]) {
          for (const entry of entries) {
            if (BigInt(entry.amountRaw) <= 0n || entry.timestamp < scan.period.from || entry.timestamp > scan.period.to) continue;
            funding.push(locator("USDC_FUNDING", entry, { buyer, funder, amountRaw: String(entry.amountRaw), fundingKind: kind }));
            earliest.set(buyer, Math.min(earliest.get(buyer) ?? Infinity, Number(entry.timestamp)));
          }
        }
      }
      cases.set(seller, { seller, report, funder, funding, earliest, settlements: [] });
    } catch (error) {
      diagnostics.push({ seller, status: "rejected", error: error.message });
    }
  }
  const lines = createInterface({ input: createReadStream(join(scanDirectory, "raw", "antscan", "settlementVolumes.ndjson")), crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    for (const row of JSON.parse(line).items ?? []) {
      const entry = cases.get(row.seller?.toLowerCase());
      const fundingTime = entry?.earliest.get(row.buyer?.toLowerCase());
      if (!entry || fundingTime == null || Number(row.timestamp) <= fundingTime || Number(row.timestamp) > scan.period.to || BigInt(row.deltaUsdc) <= 0n) continue;
      entry.settlements.push(locator("SETTLEMENT", row, { seller: entry.seller, buyer: row.buyer.toLowerCase(), amountRaw: String(row.deltaUsdc), channelId: row.channelId }));
    }
  }
  for (const entry of cases.values()) {
    try {
      if (!entry.settlements.length) throw new Error("no in-period post-funding settlements");
      const earliestSettlementTimestamp = Math.min(...entry.settlements.map((item) => Number(item.timestamp)));
      const sellerTrace = await loadTrace(entry.seller);
      if (!sellerTrace?.complete) throw new Error("incomplete seller trace");
      const discovered = await discoverCachedRelayReturns({ seller: entry.seller, funder: entry.funder, sellerTrace, funderTrace: await loadTrace(entry.funder), loadTrace, earliestSettlementTimestamp, requiredRaw: (1n << 128n) - 1n });
      const prior = await optionalJson(join(scanDirectory, "discovery", "sellers", `${entry.seller}.json`));
      const returns = [
        ...(baselineReturnEvidence[entry.seller] ?? []),
        ...discovered.paths.map((path) => returnPathDependency({ hops: path.hops.map((hop) => ({ ...hop, tx: hop.txHash })) }, entry.seller, entry.funder)),
        ...(prior?.paths ?? []).filter((path) => path.funder === entry.funder).map((path) => relayDependency(path, entry.seller, entry.funder)),
        ...(sellerTrace.outboundUsdc ?? []).filter((item) => item.to === entry.funder && item.timestamp > earliestSettlementTimestamp && item.timestamp <= scan.period.to && BigInt(item.amountRaw) > 0n).map((item) => locator("DIRECT_SELLER_FUNDER", item, { seller: entry.seller, funder: entry.funder, from: entry.seller, to: entry.funder, amountRaw: String(item.amountRaw) })),
      ];
      const inPeriodReturns = returns.filter((path) => atomicReturnEvidence(path)
        .every((transfer) => transfer.timestamp != null && Number(transfer.timestamp) >= scan.period.from && Number(transfer.timestamp) <= scan.period.to));
      let selected = selectReturnEvidence(inPeriodReturns, { earliestSettlementTimestamp, requiredRaw: (1n << 128n) - 1n });
      const priorSelected = selectReturnEvidence((baselineReturnEvidence[entry.seller] ?? []).filter((path) => inPeriodReturns.includes(path)), { earliestSettlementTimestamp, requiredRaw: (1n << 128n) - 1n });
      if (priorSelected.evidence.length > 0) {
        const extra = selectReturnEvidence(inPeriodReturns, { earliestSettlementTimestamp, requiredRaw: (1n << 128n) - 1n,
          reservedKeys: priorSelected.usedKeys, maxPaths: MAX_RETURN_PATHS - priorSelected.evidence.length });
        if (priorSelected.returnedRaw + extra.returnedRaw > selected.returnedRaw) selected = { evidence: [...priorSelected.evidence, ...extra.evidence] };
      }
      if (entry.seller !== entry.funder && !selected.evidence.length) throw new Error("no non-overlapping return path to the actual USDC funder in available traces");
      const settlementRaw = entry.settlements.reduce((total, item) => total + BigInt(item.amountRaw), 0n);
      const buyers = [...new Set(entry.settlements.map((item) => item.buyer))].sort();
      const claim = finalizeClaim({ type: "P0_CLOSED_LOOP", subjects: [entry.seller], seller: entry.seller, approvedBuyers: buyers, approvedFunders: [entry.funder], evidenceCodes: ["usdc-capital-candidate"], metrics: { sellerVolumeRaw: entry.report.stats.volumeRaw, qualifiedVolumeRaw: settlementRaw.toString(), qualifiedBuyerCount: buyers.length }, period: baseline.period, dependencies: [...entry.funding, ...entry.settlements, ...(entry.seller === entry.funder ? [] : selected.evidence)] });
      const bundle = finalizeBundle({ ...baseline, predicatePolicy: PREDICATE_POLICY, predicatePolicyHash: PREDICATE_POLICY_HASH, claims: [claim] });
      const filename = join(outputDirectory, `${entry.seller}.draft-bundle.json`);
      await writeFile(filename, JSON.stringify(bundle), { flag: "wx" });
      diagnostics.push({ seller: entry.seller, status: "draft-not-proof", funder: entry.funder, candidateSettlementRaw: settlementRaw.toString(), fundingRaw: entry.funding.reduce((total, item) => total + BigInt(item.amountRaw), 0n).toString(), returnedRaw: selected.evidence.reduce((total, item) => total + returnPathCreditRaw(item), 0n).toString(), returnPaths: selected.evidence.length, bundle: filename });
    } catch (error) {
      diagnostics.push({ seller: entry.seller, status: "rejected", error: error.message });
    }
  }
  await writeFile(join(outputDirectory, "candidate-summary.json"), JSON.stringify({ predicatePolicy: PREDICATE_POLICY, diagnostics }, null, 2), { flag: "wx" });
  return diagnostics;
}

async function readJson(filename) { return JSON.parse(await readFile(filename, "utf8")); }
async function optionalJson(filename) { try { return await readJson(filename); } catch (error) { if (error.code === "ENOENT") return null; throw error; } }

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
  const sellers = args.flatMap((argument, index) => argument === "--seller" ? [args[index + 1]?.toLowerCase()] : []);
  if (!value("--scan-dir") || !value("--baseline-bundle") || !value("--out-dir") || !sellers.length || sellers.some((seller) => !/^0x[0-9a-f]{40}$/.test(seller ?? ""))) throw new Error("require --scan-dir, --baseline-bundle, --out-dir and one or more --seller addresses");
  console.log(JSON.stringify(await buildUsdcCandidates({ scanDirectory: resolve(value("--scan-dir")), baseline: await readJson(value("--baseline-bundle")), sellers, outputDirectory: resolve(value("--out-dir")), supplementalTraceDirectory: value("--trace-dir") }), null, 2));
}
