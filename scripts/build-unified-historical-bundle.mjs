import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import {
  discoverCachedRelayReturns,
  requiredReturnRaw,
  selectReturnEvidence,
} from "./return-path-selection.mjs";

const args = process.argv.slice(2);
const value = (flag) => {
  const index = args.indexOf(flag);
  return index < 0 ? null : args[index + 1];
};
const scanDirectory = resolve(value("--scan-dir") ?? ".");
const coveragePath = resolve(value("--coverage") ?? join(scanDirectory, "proof", "proof-coverage.json"));
const outputPath = resolve(value("--out") ?? join(scanDirectory, "proof", "unified-proof-bundle.json"));
const sellerCoveragePath = resolve(value("--seller-coverage") ?? join(scanDirectory, "discovery", "seller-coverage.json"));
const manifestPath = join(scanDirectory, "manifest.json");

const [scan, manifest, sellerCoverage, coverage, firstNativeFunding, protocolDeposits, reciprocalPairs] = await Promise.all([
  readJson(join(scanDirectory, "scan.json")),
  readJson(manifestPath),
  readJson(sellerCoveragePath),
  readJson(coveragePath),
  readJson(join(scanDirectory, "raw", "first-native-funding.json")),
  readJson(join(scanDirectory, "raw", "protocol-deposits.json")),
  readJson(join(scanDirectory, "network", "reciprocal-pairs.json")),
]);
if (manifest.status !== "complete" || scan.status !== "complete") throw new Error("unified proof bundle requires one completed scan");
if (manifest.request?.seller) throw new Error("unified proof bundle rejects seller-targeted scans");
if (!sellerCoverage.complete || sellerCoverage.incomplete.length !== 0) throw new Error("seller discovery coverage is incomplete");
const expectedSellers = scan.counts?.sellers ?? scan.sellers?.length;
if (sellerCoverage.evaluated.length !== expectedSellers || new Set(sellerCoverage.evaluated).size !== expectedSellers) {
  throw new Error(`seller coverage ${sellerCoverage.evaluated.length} does not match scan seller count ${expectedSellers}`);
}
if (coverage.source.scanId !== scan.scanId || coverage.summary.totalProofs !== coverage.productionCases.length) {
  throw new Error("coverage does not match the completed scan");
}
const PERIOD = Object.freeze({
  startBlock: scan.proofPeriod?.startBlock,
  endBlockExclusive: scan.proofPeriod?.endBlockExclusive,
});
if (!Number.isSafeInteger(PERIOD.startBlock) || !Number.isSafeInteger(PERIOD.endBlockExclusive) || PERIOD.endBlockExclusive <= PERIOD.startBlock) {
  throw new Error("completed scan has an invalid proof period");
}
const FROM_TIMESTAMP = Number(scan.period?.from);
const TO_TIMESTAMP = Number(scan.period?.to);
if (!Number.isSafeInteger(FROM_TIMESTAMP) || !Number.isSafeInteger(TO_TIMESTAMP) || TO_TIMESTAMP <= FROM_TIMESTAMP) {
  throw new Error("completed scan has an invalid timestamp period");
}

const closedCases = new Map();
for (const approved of coverage.closedLoopSellers.filter((entry) => entry.enforceable)) {
  const seller = normalizeAddress(approved.seller);
  const report = await readJson(join(scanDirectory, "sellers", `${seller}.json`));
  const discovery = await readJson(join(scanDirectory, "discovery", "sellers", `${seller}.json`));
  const sellerTrace = await readJson(join(scanDirectory, "raw", "traces", `${seller}.json`));
  const selected = approved.bestSingleFunder;
  const funder = normalizeAddress(selected.funder);
  const fundingDependencies = [];
  const fundingTimes = new Map();
  let approvedBuyers;

  if (selected.type === "first_native_funder") {
    const cohort = (report.networkSignals?.nativeFunderCohorts ?? []).find((entry) => normalizeAddress(entry.funder) === funder);
    if (!cohort) throw new Error(`${seller}: selected native cohort is missing`);
    approvedBuyers = new Set((cohort.buyerAddresses ?? []).map(normalizeAddress));
    const byBuyer = new Map((firstNativeFunding.records ?? []).map((entry) => [normalizeAddress(entry.buyer), entry]));
    for (const buyer of approvedBuyers) {
      const funding = byBuyer.get(buyer);
      if (!funding || normalizeAddress(funding.from) !== funder) continue;
      fundingDependencies.push(locator("NATIVE_FUNDING", funding, {
        buyer,
        funder,
        amountWei: String(funding.amountWei),
      }));
      fundingTimes.set(buyer, Number(funding.timestamp));
    }
  } else if (selected.type === "primary_usdc_funder") {
    approvedBuyers = new Set((report.strongestCohort?.buyers ?? []).map((entry) => normalizeAddress(typeof entry === "string" ? entry : entry.buyer)));
    const depositsByBuyer = groupBy(
      (protocolDeposits.records ?? []).filter((entry) => normalizeAddress(entry.funder) === funder && BigInt(entry.amountRaw) >= 1_000_000n),
      (entry) => normalizeAddress(entry.buyer),
    );
    for (const buyer of approvedBuyers) {
      const trace = await readJson(join(scanDirectory, "raw", "traces", `${buyer}.json`));
      if (!trace.complete) throw new Error(`${seller}: incomplete trace for ${buyer}`);
      const direct = (trace.inboundUsdc ?? [])
        .filter((entry) => normalizeAddress(entry.from) === funder && normalizeAddress(entry.to) === buyer && BigInt(entry.amountRaw) >= 1_000_000n);
      const deposits = depositsByBuyer.get(buyer) ?? [];
      for (const entry of direct) {
        fundingDependencies.push(locator("USDC_FUNDING", entry, {
          buyer,
          funder,
          amountRaw: String(entry.amountRaw),
          fundingKind: "direct_usdc_transfer",
        }));
      }
      for (const entry of deposits) {
        fundingDependencies.push(locator("USDC_FUNDING", entry, {
          buyer,
          funder,
          amountRaw: String(entry.amountRaw),
          fundingKind: "protocol_deposit",
        }));
      }
      const earliest = [...direct, ...deposits].sort(compareTime)[0];
      if (earliest) fundingTimes.set(buyer, Number(earliest.timestamp));
    }
  } else {
    throw new Error(`${seller}: unsupported selected funding type ${selected.type}`);
  }

  approvedBuyers = new Set([...approvedBuyers].filter((buyer) => fundingTimes.has(buyer)));
  if (approvedBuyers.size !== selected.result.buyerCount) {
    throw new Error(`${seller}: expected ${selected.result.buyerCount} funded buyers, found ${approvedBuyers.size}`);
  }
  const closureDependencies = seller === funder ? [] : dedupeDependencies([
    ...directReturnDependencies(sellerTrace, seller, funder),
    ...relayDependencies(discovery.paths ?? [], seller, funder),
  ]);
  closedCases.set(seller, {
    approved,
    report,
    seller,
    funder,
    approvedBuyers,
    fundingTimes,
    fundingDependencies: dedupeDependencies(fundingDependencies),
    closureDependencies,
    sellerTrace,
    settlementDependencies: [],
    selectedVolumeRaw: 0n,
  });
}

const reciprocalByDirection = new Map();
const reciprocalCases = reciprocalPairs
  .filter((pair) => coverage.reciprocalPairs.some((approved) => samePair(pair, approved) && approved.enforceable))
  .map((pair) => {
    const walletA = normalizeAddress(pair.walletA);
    const walletB = normalizeAddress(pair.walletB);
    const entry = { pair, walletA, walletB, settlements: [], volumeAToB: 0n, volumeBToA: 0n };
    reciprocalByDirection.set(`${walletA}:${walletB}`, entry);
    reciprocalByDirection.set(`${walletB}:${walletA}`, entry);
    return entry;
  });

const settlementPath = join(scanDirectory, "raw", "antscan", "settlementVolumes.ndjson");
const lines = createInterface({ input: createReadStream(settlementPath), crlfDelay: Infinity });
for await (const line of lines) {
  if (!line.trim()) continue;
  for (const row of JSON.parse(line).items ?? []) {
    const timestamp = Number(row.timestamp);
    if (!Number.isSafeInteger(timestamp) || timestamp < FROM_TIMESTAMP || timestamp >= TO_TIMESTAMP) continue;
    const buyer = normalizeAddress(row.buyer);
    const seller = normalizeAddress(row.seller);
    const amountRaw = BigInt(row.deltaUsdc);
    const closed = closedCases.get(seller);
    if (closed?.approvedBuyers.has(buyer)) {
      closed.settlementDependencies.push(locator("SETTLEMENT", row, {
        buyer,
        seller,
        amountRaw: amountRaw.toString(),
        channelId: row.channelId,
      }));
      if (Number(row.timestamp) > closed.fundingTimes.get(buyer)) closed.selectedVolumeRaw += amountRaw;
    }
    const reciprocal = reciprocalByDirection.get(`${buyer}:${seller}`);
    if (reciprocal) {
      reciprocal.settlements.push(locator("RECIPROCAL_SETTLEMENT", row, {
        buyer,
        seller,
        amountRaw: amountRaw.toString(),
        channelId: row.channelId,
      }));
      if (buyer === reciprocal.walletA) reciprocal.volumeAToB += amountRaw;
      else reciprocal.volumeBToA += amountRaw;
    }
  }
}

const claims = [];
for (const entry of closedCases.values()) {
  const expectedVolume = BigInt(entry.approved.bestSingleFunder.result.volumeRaw);
  if (entry.selectedVolumeRaw !== expectedVolume) {
    throw new Error(`${entry.seller}: selected volume ${entry.selectedVolumeRaw} != approved ${expectedVolume}`);
  }
  const earliestSettlement = entry.settlementDependencies
    .filter((item) => Number(item.timestamp) > entry.fundingTimes.get(item.buyer))
    .sort(compareTime)[0];
  const initialClosureDependencies = entry.closureDependencies.filter(
    (path) => closureStartTimestamp(path) > Number(earliestSettlement.timestamp),
  );
  let closureDependencies = initialClosureDependencies;
  if (entry.seller !== entry.funder) {
    const requiredRaw = requiredReturnRaw(expectedVolume);
    let selection = selectReturnEvidence(initialClosureDependencies, {
      requiredRaw,
      earliestSettlementTimestamp: Number(earliestSettlement.timestamp),
    });
    if (!selection.complete) {
      const funderTrace = await readJsonOptional(join(scanDirectory, "raw", "traces", `${entry.funder}.json`));
      if (funderTrace?.complete) {
        const discovered = await discoverCachedRelayReturns({
          seller: entry.seller,
          funder: entry.funder,
          sellerTrace: entry.sellerTrace,
          funderTrace,
          loadTrace: (address) => readJsonOptional(join(scanDirectory, "raw", "traces", `${address}.json`)),
          earliestSettlementTimestamp: Number(earliestSettlement.timestamp),
          requiredRaw: requiredRaw - selection.returnedRaw,
          maxPaths: 512 - selection.evidence.length,
          reservedKeys: [...selection.usedKeys],
        });
        const discoveredDependencies = discovered.paths.map(cachedRelayDependency);
        selection = selectReturnEvidence([...selection.evidence, ...discoveredDependencies], {
          requiredRaw,
          earliestSettlementTimestamp: Number(earliestSettlement.timestamp),
        });
      }
    }
    if (!selection.complete) {
      throw new Error(`${entry.seller}: return credit ${selection.returnedRaw} below required ${requiredRaw} for ${expectedVolume} settled volume`);
    }
    closureDependencies = selection.evidence;
  }
  claims.push(finalizeClaim({
    type: "P0_CLOSED_LOOP",
    subjects: [entry.seller],
    seller: entry.seller,
    approvedBuyers: [...entry.approvedBuyers].sort(),
    approvedFunders: [entry.funder],
    evidenceCodes: entry.report.evidence?.map((item) => item.code) ?? [],
    metrics: {
      sellerVolumeRaw: String(entry.approved.totalVolumeRaw),
      qualifiedVolumeRaw: expectedVolume.toString(),
      qualifiedBuyerCount: entry.approvedBuyers.size,
    },
    period: PERIOD,
    dependencies: dedupeDependencies([
      ...entry.fundingDependencies,
      ...closureDependencies,
      ...entry.settlementDependencies,
    ]),
  }));
}

for (const entry of reciprocalCases) {
  const expectedAToB = BigInt(entry.pair.volumeAToBRaw);
  const expectedBToA = BigInt(entry.pair.volumeBToARaw);
  if (entry.volumeAToB !== expectedAToB || entry.volumeBToA !== expectedBToA) {
    throw new Error(`${entry.walletA}/${entry.walletB}: reciprocal volumes do not match approved analysis`);
  }
  const subjects = new Set([entry.walletA, entry.walletB]);
  const internalDeposits = (protocolDeposits.records ?? [])
    .filter((deposit) => subjects.has(normalizeAddress(deposit.buyer)) && subjects.has(normalizeAddress(deposit.funder)))
    .map((deposit) => locator("USDC_FUNDING", deposit, {
      buyer: normalizeAddress(deposit.buyer),
      funder: normalizeAddress(deposit.funder),
      amountRaw: String(deposit.amountRaw),
      fundingKind: "protocol_deposit",
    }));
  claims.push(finalizeClaim({
    type: "P0_RECIPROCAL",
    subjects: [...subjects].sort(),
    walletA: entry.walletA,
    walletB: entry.walletB,
    metrics: {
      volumeAToBRaw: expectedAToB.toString(),
      volumeBToARaw: expectedBToA.toString(),
      settlementCount: entry.pair.settlements,
      reciprocityNumeratorRaw: minRaw(expectedAToB, expectedBToA),
      reciprocityDenominatorRaw: maxRaw(expectedAToB, expectedBToA),
    },
    period: PERIOD,
    dependencies: dedupeDependencies([...entry.settlements, ...internalDeposits]),
  }));
}

claims.sort((left, right) => left.claimId.localeCompare(right.claimId));
const bundle = {
  version: 1,
  kind: "antseed-wash-trading-proof-bundle",
  scanId: scan.scanId,
  scanSchemaVersion: scan.version,
  scoringVersion: scan.scoringVersion,
  networkAnalysisVersion: scan.networkAnalysisVersion,
  policyVersion: "aip-4-conserved-loop-v1",
  chainId: 8_453,
  contracts: {
    usdc: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    channels: "0xba66d3b4fbcf472f6f11d6f9f96aace96516f09d",
    deposits: "0x0f7a3a8f4da01637d1202bb5443fcf7f88f99fd2",
  },
  period: PERIOD,
  thresholds: coverage.rule,
  claimCounts: {
    P0_CLOSED_LOOP: claims.filter((claim) => claim.type === "P0_CLOSED_LOOP").length,
    P0_RECIPROCAL: claims.filter((claim) => claim.type === "P0_RECIPROCAL").length,
    total: claims.length,
  },
  reportRoot: merkleRoot(claims.map((claim) => claim.leafHash)),
  claims,
};
if (bundle.claimCounts.total !== coverage.summary.totalProofs) {
  throw new Error(`bundle count ${bundle.claimCounts.total} != approved ${coverage.summary.totalProofs}`);
}
await writeFile(outputPath, `${JSON.stringify(bundle)}\n`);
console.error(JSON.stringify({ outputPath, claimCounts: bundle.claimCounts, reportRoot: bundle.reportRoot }));

function relayDependencies(paths, seller, funder) {
  return paths
    .filter((entry) => normalizeAddress(entry.seller) === seller && normalizeAddress(entry.funder) === funder)
    .map((entry) => ({
      evidenceType: "RELAY_PATH",
      seller,
      funder,
      relay: normalizeAddress(entry.relay),
      intermediary: normalizeAddress(entry.intermediary),
      sellerPayment: locator("RELAY_SELLER_PAYMENT", {
        txHash: entry.sellerPaymentTx,
        timestamp: entry.sellerPaymentAt,
        amountRaw: entry.sellerPaymentRaw,
      }, { from: seller, to: normalizeAddress(entry.relay), amountRaw: String(entry.sellerPaymentRaw) }),
      relayForward: locator("RELAY_FORWARD", {
        txHash: entry.relayForwardTx,
        timestamp: entry.relayForwardAt,
        amountRaw: entry.relayForwardRaw,
      }, { from: normalizeAddress(entry.relay), to: normalizeAddress(entry.intermediary), amountRaw: String(entry.relayForwardRaw) }),
      funderReceipt: locator("RELAY_FUNDER_RECEIPT", {
        txHash: entry.funderReceiptTx,
        timestamp: entry.funderReceiptAt,
        amountRaw: entry.funderReceiptRaw,
      }, { from: normalizeAddress(entry.intermediary), to: funder, amountRaw: String(entry.funderReceiptRaw) }),
    }));
}

function cachedRelayDependency(path) {
  return {
    evidenceType: "RELAY_PATH",
    seller: path.seller,
    funder: path.funder,
    relay: path.relay,
    intermediary: path.intermediary,
    hops: path.hops.map((hop, index) => locator(
      index === 0 ? "RELAY_SELLER_PAYMENT" : index === path.hops.length - 1 ? "RELAY_FUNDER_RECEIPT" : "RELAY_FORWARD",
      hop,
      {
      from: normalizeAddress(hop.from),
      to: normalizeAddress(hop.to),
      amountRaw: String(hop.amountRaw),
      },
    )),
  };
}

function directReturnDependencies(trace, seller, funder) {
  return (trace.outboundUsdc ?? [])
    .filter((entry) => normalizeAddress(entry.from) === seller
      && normalizeAddress(entry.to) === funder
      && BigInt(entry.amountRaw) > 0n)
    .map((entry) => locator("DIRECT_SELLER_FUNDER", entry, {
      from: seller,
      to: funder,
      funder,
      amountRaw: String(entry.amountRaw),
    }));
}

function closureStartTimestamp(dependency) {
  return Number(dependency.evidenceType === "RELAY_PATH"
    ? dependency.sellerPayment.timestamp
    : dependency.timestamp);
}

function locator(evidenceType, source, extra) {
  return {
    evidenceType,
    blockNumber: numericOrNull(source.blockNumber),
    transactionHash: source.txHash ?? source.transactionHash ?? null,
    transactionIndex: numericOrNull(source.transactionIndex),
    logIndex: numericOrNull(source.logIndex),
    timestamp: numericOrNull(source.timestamp),
    ...extra,
  };
}

function finalizeClaim(claim) {
  const dependencies = claim.dependencies.map((dependency) => ({
    ...dependency,
    dependencyId: hashCanonical("dependency", dependency),
  })).sort((left, right) => left.dependencyId.localeCompare(right.dependencyId));
  const dependencyRoot = merkleRoot(dependencies.map((entry) => entry.dependencyId));
  const { dependencies: _dependencies, ...claimBody } = { ...claim, dependencyRoot };
  const claimId = hashCanonical("claim-id", claimBody);
  const leaf = { ...claimBody, claimId };
  return { ...leaf, leafHash: hashCanonical("claim-leaf", leaf), dependencies };
}

function dedupeDependencies(values) {
  return [...new Map(values.map((entry) => [canonicalJson(entry), entry])).values()]
    .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
}

function canonicalJson(input) {
  if (input === null || typeof input !== "object") return JSON.stringify(input);
  if (Array.isArray(input)) return `[${input.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(input).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(input[key])}`).join(",")}}`;
}

function merkleRoot(hashes) {
  if (hashes.length === 0) return sha256(Buffer.from([0]));
  let level = [...hashes].sort();
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      next.push(sha256(Buffer.concat([
        Buffer.from([1]),
        Buffer.from(level[index].slice(2), "hex"),
        Buffer.from((level[index + 1] ?? level[index]).slice(2), "hex"),
      ])));
    }
    level = next;
  }
  return level[0];
}

function hashCanonical(domain, input) {
  return sha256(Buffer.concat([Buffer.from(`${domain}\0`), Buffer.from(canonicalJson(input))]));
}

function sha256(input) {
  return `0x${createHash("sha256").update(input).digest("hex")}`;
}

function groupBy(values, key) {
  const result = new Map();
  for (const value of values) {
    const group = key(value);
    const entries = result.get(group) ?? [];
    entries.push(value);
    result.set(group, entries);
  }
  return result;
}

function samePair(left, right) {
  return new Set([normalizeAddress(left.walletA), normalizeAddress(left.walletB)]).size === 2
    && [normalizeAddress(left.walletA), normalizeAddress(left.walletB)].every((wallet) => [normalizeAddress(right.walletA), normalizeAddress(right.walletB)].includes(wallet));
}

function compareTime(left, right) {
  return Number(left.timestamp) - Number(right.timestamp) || String(left.txHash).localeCompare(String(right.txHash));
}

function minRaw(left, right) {
  return (left < right ? left : right).toString();
}

function maxRaw(left, right) {
  return (left > right ? left : right).toString();
}

function normalizeAddress(input) {
  return typeof input === "string" && /^0x[0-9a-f]{40}$/i.test(input) ? input.toLowerCase() : null;
}

function numericOrNull(input) {
  if (input == null) return null;
  const number = Number(input);
  return Number.isSafeInteger(number) ? number : null;
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function readJsonOptional(path) {
  try {
    return await readJson(path);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}
