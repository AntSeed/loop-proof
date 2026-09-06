import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildUsdcCandidates } from "./build-usdc-candidate-bundle.mjs";
import { authenticateClaim, planClaim, selectLedgerAwareSettlements } from "./proof-planner.mjs";
import { returnPathDependency } from "./proof-bundle.mjs";
import { discoverExpandedReturnGraph } from "./expanded-return-graph.mjs";
import { selectFixedVolumeReturns } from "./search-fixed-volume-returns.mjs";
import { requiredReturnRaw, returnPathCreditRaw } from "./return-path-selection.mjs";

const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function assessJointCandidate({ baselineVolumeRaw, candidateVolumeRaw, returnedRaw, targetBps = 5000 }) {
  const required = requiredReturnRaw(candidateVolumeRaw, targetBps);
  const gap = required > BigInt(returnedRaw) ? required - BigInt(returnedRaw) : 0n;
  const regresses = BigInt(candidateVolumeRaw) < BigInt(baselineVolumeRaw);
  return { preservesBaselineVolume: !regresses, returnShortfallRaw: gap.toString(),
    eligibleForNativeVerification: !regresses && gap === 0n,
    disposition: regresses ? "retain-baseline-smaller-candidate" : gap > 0n ? "retain-baseline-insufficient-returns" : "candidate-needs-native-verification" };
}

export function selectLedgerCandidate(dependencies, balances) {
  const fundingByBuyer = new Map();
  for (const entry of dependencies.filter((item) => item.evidenceType === "USDC_FUNDING")) {
    if (!fundingByBuyer.has(entry.buyer)) fundingByBuyer.set(entry.buyer, []);
    fundingByBuyer.get(entry.buyer).push(entry);
  }
  const settlements = dependencies.filter((item) => item.evidenceType === "SETTLEMENT" && fundingByBuyer.has(item.buyer)
    && item.blockNumber > Math.min(...fundingByBuyer.get(item.buyer).map((funding) => funding.blockNumber)));
  return selectLedgerAwareSettlements(settlements, fundingByBuyer, balances);
}

export async function searchJointWashVolume({ historyPath, manifestPath, baselineBundlePath, scanDirectory, outputDirectory, endpoint, targetBps = 5000, graphLimits = {} }) {
  if (!endpoint) throw new Error("BASE_RPC_URL required");
  requiredReturnRaw(0, targetBps);
  const historyBytes = await readFile(historyPath);
  const history = JSON.parse(historyBytes);
  const manifest = await readJson(manifestPath);
  const baselineBundle = await readJson(baselineBundlePath);
  await mkdir(outputDirectory, { recursive: false });
  const results = [];
  for (const entry of history.results.filter((seller) => seller.status === "shortfall")) {
    const result = { seller: entry.seller, name: entry.name, baselineVolumeRaw: entry.provenWashVolumeRaw, totalSellerVolumeRaw: entry.totalSellerVolumeRaw, targetReturnBps: Number(targetBps), funders: [] };
    const directory = join(outputDirectory, entry.seller);
    await mkdir(directory);
    try {
      const inputBytes = await readFile(entry.baselineInput);
      if (hash(inputBytes) !== entry.baselineInputSha256) throw new Error("baseline input hash mismatch");
      const input = JSON.parse(inputBytes);
      if (input.seller !== entry.seller || input.evidence?.input?.seller !== entry.seller) throw new Error("baseline seller mismatch");
      const evidence = input.evidence.input;
      const config = manifest.sellers.find((seller) => seller.seller === entry.seller);
      if (!config) throw new Error("manifest missing targeted seller");
      const earliest = Math.min(...evidence.settlements.map((ref) => Number(evidence.blocks[ref.block].header.timestamp)));
      const end = Number(input.total_volume.header.timestamp);
      const baselinePaths = (await readJson(config.baselineReturns)).paths.map((path) => ({ evidenceType: "RELAY_PATH", hops: path.hops }));
      const loadTrace = async (address) => {
        try { return await readJson(config.traceOverrides?.[address] ?? join(scanDirectory, "raw", "traces", `${address}.json`)); }
        catch (error) { if (error.code === "ENOENT") return null; throw error; }
      };
      console.log(`${entry.name}: expanding the return graph`);
      const graph = await discoverExpandedReturnGraph({ seller: entry.seller, funder: evidence.funder, earliest, end, loadTrace, ...graphLimits });
      const selected = selectFixedVolumeReturns({ candidates: graph.paths, baseline: baselinePaths, volumeRaw: entry.totalSellerVolumeRaw,
        seller: entry.seller, funder: evidence.funder, targetBps, earliest, end, startBlock: input.period_start_block, endBlock: input.period_end_block });
      const expandedReturns = selected.paths.map((path) => returnPathDependency({ hops: path.hops.map((hop) => ({ ...hop, tx: hop.txHash ?? hop.transactionHash })) }, entry.seller, evidence.funder));
      result.expandedReturnCandidateRaw = selected.candidateReturnRaw;
      result.graph = { ...graph, paths: undefined, pathCount: graph.paths.length };
      await writeFile(join(directory, "return-candidates.json"), JSON.stringify({ ...selected, graph: result.graph }), { flag: "wx" });
      const scanReport = await readJson(join(scanDirectory, "sellers", `${entry.seller}.json`));
      const funders = (scanReport.fundingProvenance?.sources ?? []).filter((source) => BigInt(source.fundedAmountRaw ?? 0) > 0n && source.buyers?.length);
      for (const source of funders) {
        const fundingDirectory = join(directory, source.funder);
        const assessment = { funder: source.funder, discoveredBuyerCount: source.buyers.length };
        try {
          console.log(`${entry.name}: scanning settlements and funding for ${source.funder}`);
          const [draft] = await buildUsdcCandidates({ scanDirectory, baseline: baselineBundle, sellers: [entry.seller], outputDirectory: fundingDirectory,
            funderBySeller: { [entry.seller]: source.funder }, traceOverrides: config.traceOverrides,
            baselineReturnEvidence: source.funder === evidence.funder ? { [entry.seller]: expandedReturns } : {} });
          if (draft.status !== "draft-not-proof") throw new Error(draft.error ?? "no draft");
          Object.assign(assessment, { candidateSettlementRaw: draft.candidateSettlementRaw, candidateFundingRaw: draft.fundingRaw, candidateReturnRaw: draft.returnedRaw });
          const draftBundle = await readJson(draft.bundle);
          const claim = draftBundle.claims[0];
          const authenticated = await authenticateClaim(claim, draftBundle, { rpcUrl: endpoint, concurrency: 12, onProgress: (message) => console.log(`${entry.name}: ${message}`) });
          await writeFile(join(fundingDirectory, "authenticated-dependencies.json"), JSON.stringify({ resolved: authenticated.resolved, rejected: authenticated.rejected,
            ledgerBalances: Object.fromEntries([...authenticated.ledgerBalances].map(([buyer, balance]) => [buyer, balance.toString()])) }), { flag: "wx" });
          assessment.rejectedDependencyCount = authenticated.rejected.length;
          assessment.ledgerSelectedVolumeBeforeReturnCheckRaw = (selectLedgerCandidate(authenticated.resolved, authenticated.ledgerBalances)?.volumeRaw ?? 0n).toString();
          const planned = planClaim(claim, authenticated.resolved, draftBundle, { ledgerBalances: authenticated.ledgerBalances, allowLedgerSelection: true, returnTargetBps: targetBps, maximizeVolume: true });
          const returns = planned.selectedEvidence.filter((item) => ["RELAY_PATH", "DIRECT_SELLER_FUNDER", "DIRECT_SELLER_BUYER"].includes(item.evidenceType));
          const returnedRaw = returns.reduce((total, path) => total + returnPathCreditRaw(path), 0n);
          Object.assign(assessment, { candidateVolumeAt50Raw: planned.provenVolumeRaw, authenticatedReturnMetadataRaw: returnedRaw.toString(),
            ...assessJointCandidate({ baselineVolumeRaw: entry.provenWashVolumeRaw, candidateVolumeRaw: planned.provenVolumeRaw, returnedRaw, targetBps }) });
          await writeFile(join(fundingDirectory, "candidate-plan.json"), JSON.stringify({ version: 2, kind: "antseed-wash-trading-proof-plan", chainId: 8453,
            period: draftBundle.period, claims: [planned], analysisOnly: true, returnTargetBps: Number(targetBps), nativeVerified: false }), { flag: "wx" });
          assessment.plan = join(fundingDirectory, "candidate-plan.json");
        } catch (error) { Object.assign(assessment, { disposition: "retain-baseline-search-failed", error: error.message }); }
        result.funders.push(assessment);
        console.log(JSON.stringify({ seller: entry.seller, ...assessment }));
      }
      if (hash(await readFile(entry.baselineInput)) !== hash(inputBytes)) throw new Error("baseline input changed during search");
      result.baselineInputUnchanged = true;
      result.eligibleCandidateCount = result.funders.filter((funder) => funder.eligibleForNativeVerification).length;
    } catch (error) { result.error = error.message; }
    results.push(result);
    await writeFile(join(outputDirectory, "progress.json"), JSON.stringify({ results }, null, 2));
  }
  if (hash(await readFile(historyPath)) !== hash(historyBytes)) throw new Error("baseline history changed");
  const report = { scope: "remaining below-50 sellers", objective: "maximize V subject to return target and accounting checks", targetReturnBps: Number(targetBps),
    originalHistorySha256: hash(historyBytes), baselineReplaced: false, nativeVerified: false, guestChanged: false, proverNetworkSubmitted: false, exhaustive: false, results };
  await writeFile(join(outputDirectory, "summary.json"), JSON.stringify(report, null, 2), { flag: "wx" });
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const value = (flag) => args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined;
  for (const flag of ["--history", "--manifest", "--baseline-bundle", "--scan-dir", "--out-dir"]) if (!value(flag)) throw new Error(`missing ${flag}`);
  await searchJointWashVolume({ historyPath: resolve(value("--history")), manifestPath: resolve(value("--manifest")), baselineBundlePath: resolve(value("--baseline-bundle")),
    scanDirectory: resolve(value("--scan-dir")), outputDirectory: resolve(value("--out-dir")), targetBps: value("--target-bps") ?? 5000, endpoint: process.env.BASE_RPC_URL,
    graphLimits: { maxSteps: Number(value("--max-graph-steps") ?? 2_000_000), maxPaths: Number(value("--max-return-candidates") ?? 100_000) } });
}
