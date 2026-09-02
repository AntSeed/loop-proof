import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { finalizeBundle, finalizeClaim } from "./proof-bundle.mjs";
import {
  requiredReturnRaw,
  returnPathCreditRaw,
  selectReturnEvidence,
} from "./return-path-selection.mjs";

export const HISTORICAL_START_BLOCK = 44_469_557;
export const MINIMUM_RECIPROCAL_VOLUME_BPS = 8_000n;

const MAX_RELAY_SECONDS = 259_200;
const MIN_RELAY_RETAINED_BPS = 2_800n;
const EPSILON_LEDGER_BPS = 500n;
const ALPHA_RETURN_BPS = 2_000n;
const MAX_RETURN_PATHS = 512;
const BUYERS_SELECTOR = "0x97a993aa";

class RpcTransportError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "RpcTransportError";
  }
}

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CHANNEL_SETTLED_TOPIC = "0x0b287f37d8bd14ef37f2966734ab387c243cc1a1663616a25a4cc259877736b1";
const DEPOSITED_TOPIC = "0x2da466a7b24304f47e87fa2e1e5a81b9831ce54fec19055ce277ca2f39ba42c4";

export async function planProofBundle(bundle, {
  rpcUrl,
  concurrency = 20,
  fetchJson = defaultFetchJson,
  claimIds = null,
  onProgress = () => {},
  finalizeLedger = true,
  authenticatedClaims: suppliedAuthenticatedClaims = new Map(),
  claimConcurrency = 1,
  planCheckpointDirectory = null,
} = {}) {
  validateBundle(bundle);
  if (!rpcUrl) throw new Error("ANTSEED_BASE_RPC_URL or --rpc-url is required");
  let authenticatedClaims = suppliedAuthenticatedClaims;
  if (finalizeLedger) {
    const finalized = await finalizeLedgerAwareBundle(bundle, { rpcUrl, concurrency, fetchJson, onProgress });
    bundle = finalized.bundle;
    authenticatedClaims = finalized.authenticatedClaims;
  }
  const selectedClaims = claimIds == null ? bundle.claims : bundle.claims.filter((claim) => claimIds.includes(claim.claimId));
  if (selectedClaims.length === 0) throw new Error("no requested claims found in proof bundle");
  if (planCheckpointDirectory) await mkdir(planCheckpointDirectory, { recursive: true });
  const claims = await mapConcurrent(selectedClaims, claimConcurrency, async (claim, claimIndex) => {
    const checkpoint = planCheckpointDirectory
      ? await readPlanCheckpoint(planCheckpointDirectory, claim, bundle)
      : null;
    if (checkpoint) {
      onProgress(`[${claimIndex + 1}/${selectedClaims.length}] resumed ${checkpoint.selectedEvidence.length} evidence objects`);
      return checkpoint;
    }
    const cacheKey = claimAuthenticationKey(claim);
    const authenticated = authenticatedClaims.get(cacheKey)
      ?? await authenticateClaim(claim, bundle, { rpcUrl, concurrency, fetchJson, onProgress: (message) => onProgress(`[${claimIndex + 1}/${selectedClaims.length}] ${message}`) });
    const { resolved, rejected, ledgerBalances } = authenticated;
    const requiredRejections = rejected.filter((entry) => entry.evidenceType === "TOTAL_SETTLEMENT");
    if (requiredRejections.length > 0) {
      const rejectionCounts = Object.fromEntries([...groupBy(requiredRejections, (entry) => entry.reason).entries()].map(([reason, values]) => [reason, values.length]));
      throw new Error(`${claim.claimId}: incomplete total-settlement authentication; rejected=${requiredRejections.length}; rejectionCounts=${JSON.stringify(rejectionCounts)}`);
    }
    onProgress(`[${claimIndex + 1}/${selectedClaims.length}] optimizing ${resolved.length} authenticated dependencies`);
    let planned;
    try {
      planned = planClaim(claim, resolved, bundle, { ledgerBalances });
    } catch (error) {
      const rejectionCounts = Object.fromEntries([...groupBy(rejected, (entry) => entry.reason).entries()].map(([reason, values]) => [reason, values.length]));
      throw new Error(`${error.message}; authenticated=${resolved.length}; rejected=${rejected.length}; rejectionCounts=${JSON.stringify(rejectionCounts)}`);
    }
    const finalizedPlan = attachMemberships({
      ...planned,
      rejectedAlternatives: [...(planned.rejectedAlternatives ?? []), ...rejected],
    }, claim, bundle.claims);
    if (planCheckpointDirectory) await writePlanCheckpoint(planCheckpointDirectory, claim, finalizedPlan, bundle);
    onProgress(`[${claimIndex + 1}/${selectedClaims.length}] selected ${planned.selectedEvidence.length} evidence objects`);
    return finalizedPlan;
  });
  const materializationBlockNumbers = [...new Set(claims.flatMap((claim) => claim.selectedBlocks))].sort(numberAscending);
  onProgress(`selected ${claims.length} claims across ${materializationBlockNumbers.length} canonical Base blocks`);
  return {
    version: 2,
    kind: "antseed-wash-trading-proof-plan",
    bundleVersion: bundle.version,
    chainId: bundle.chainId,
    reportRoot: bundle.reportRoot,
    period: bundle.period,
    claimCount: claims.length,
    claims,
    evidenceBlockSelection: {
      version: 1,
      chain_id: bundle.chainId,
      start_block: bundle.period.startBlock,
      end_block_exclusive: bundle.period.endBlockExclusive,
      materializationBlockNumbers,
    },
  };
}

async function readPlanCheckpoint(directory, claim, bundle) {
  try {
    const checkpoint = JSON.parse(await readFile(`${directory}/${claim.claimId}.json`, "utf8"));
    if (checkpoint.version !== 1
      || checkpoint.claimId !== claim.claimId
      || checkpoint.reportRoot !== bundle.reportRoot) return null;
    return checkpoint.plan;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function writePlanCheckpoint(directory, claim, plan, bundle) {
  await writeFile(`${directory}/${claim.claimId}.json`, `${JSON.stringify({
    version: 1,
    claimId: claim.claimId,
    reportRoot: bundle.reportRoot,
    plan,
  })}\n`);
}

async function prefetchDependencies(dependencies, url, cache, fetchJson, concurrency, onProgress) {
  const atomic = dependencies.flatMap(atomicEvidence);
  const receipts = uniqueRpcRequests(atomic, "eth_getTransactionReceipt");
  const transactions = uniqueRpcRequests(atomic.filter((entry) => entry.evidenceType === "NATIVE_FUNDING"), "eth_getTransactionByHash");
  const requests = [...receipts, ...transactions].map((request, index) => ({ ...request, id: index + 1 }));
  const chunks = [];
  for (let index = 0; index < requests.length; index += 100) chunks.push(requests.slice(index, index + 100));
  let completed = 0;
  const batchConcurrency = Math.min(10, Math.max(1, Math.ceil(concurrency / 20)));
  await mapConcurrent(chunks, batchConcurrency, async (chunk) => {
    const responses = await rpcBatch(url, chunk, fetchJson);
    for (const request of chunk) {
      const response = responses.get(request.id);
      if (response && !response.error) cache.set(request.key, Promise.resolve(response.result));
    }
    completed += chunk.length;
    if (completed === requests.length || completed % 5_000 < chunk.length) onProgress(`prefetched ${completed}/${requests.length} RPC objects`);
  });
}

function uniqueRpcRequests(dependencies, method) {
  const requests = new Map();
  for (const dependency of dependencies) {
    if (!dependency.transactionHash) continue;
    const params = [dependency.transactionHash];
    const key = `${method}:${JSON.stringify(params)}`;
    if (!requests.has(key)) requests.set(key, { key, method, params });
  }
  return [...requests.values()];
}

export function planClaim(claim, dependencies, bundle, { ledgerBalances = null, allowLedgerSelection = false } = {}) {
  if (claim.type === "P0_RECIPROCAL") return planReciprocal(claim, dependencies, bundle);
  if (claim.type !== "P0_CLOSED_LOOP") throw new Error(`${claim.claimId}: unsupported claim type ${claim.type}`);
  return planCohort(claim, dependencies, bundle, ledgerBalances, allowLedgerSelection);
}

function authenticationGroup(blockNumber) {
  if (!Number.isSafeInteger(blockNumber) || blockNumber < HISTORICAL_START_BLOCK) {
    throw new Error(`block ${blockNumber} predates supported historical state coverage`);
  }
  return `block:${blockNumber}`;
}

export function merkleMembership(hashes, targetHash) {
  return merkleMembershipIndex(hashes).get(targetHash);
}

function merkleMembershipIndex(hashes) {
  const levels = [[...hashes].sort()];
  while (levels.at(-1).length > 1) {
    const level = levels.at(-1);
    const next = [];
    for (let cursor = 0; cursor < level.length; cursor += 2) {
      next.push(sha256Hex(Buffer.concat([Buffer.from([1]), hexBytes(level[cursor]), hexBytes(level[cursor + 1] ?? level[cursor])])));
    }
    levels.push(next);
  }
  const positions = new Map(levels[0].map((hash, index) => [hash, index]));
  return {
    get(targetHash) {
      let index = positions.get(targetHash);
      if (index == null) throw new Error(`Merkle target ${targetHash} not found`);
      const steps = [];
      for (const level of levels.slice(0, -1)) {
        const siblingIndex = index % 2 === 0 ? Math.min(index + 1, level.length - 1) : index - 1;
        steps.push({ sibling: level[siblingIndex], sibling_on_left: siblingIndex < index });
        index = Math.floor(index / 2);
      }
      return { steps };
    },
  };
}

function legacyMerkleMembership(hashes, targetHash) {
  let level = [...hashes].sort();
  let index = level.indexOf(targetHash);
  if (index < 0) throw new Error(`Merkle target ${targetHash} not found`);
  const steps = [];
  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? Math.min(index + 1, level.length - 1) : index - 1;
    steps.push({ sibling: level[siblingIndex], sibling_on_left: siblingIndex < index });
    const next = [];
    for (let cursor = 0; cursor < level.length; cursor += 2) {
      next.push(sha256Hex(Buffer.concat([Buffer.from([1]), hexBytes(level[cursor]), hexBytes(level[cursor + 1] ?? level[cursor])])));
    }
    index = Math.floor(index / 2);
    level = next;
  }
  return { steps };
}

export async function resolveDependency(dependency, bundle, callRpc) {
  if (dependency.evidenceType === "RELAY_PATH") {
    if (Array.isArray(dependency.hops)) {
      return { ...dependency, hops: await Promise.all(dependency.hops.map((hop) => resolveDependency(hop, bundle, callRpc))) };
    }
    return {
      ...dependency,
      sellerPayment: await resolveDependency(dependency.sellerPayment, bundle, callRpc),
      relayForward: await resolveDependency(dependency.relayForward, bundle, callRpc),
      funderReceipt: await resolveDependency(dependency.funderReceipt, bundle, callRpc),
    };
  }
  if (!dependency.transactionHash) throw new Error(`${dependency.dependencyId}: missing transaction hash`);
  const receipt = await callRpc("eth_getTransactionReceipt", [dependency.transactionHash]);
  if (!receipt) throw new Error(`${dependency.dependencyId}: receipt not found`);
  if (receipt.status == null || BigInt(receipt.status) !== 1n) throw new Error(`${dependency.dependencyId}: receipt reverted`);
  const blockNumber = hexNumber(receipt.blockNumber);
  if (["SETTLEMENT", "RECIPROCAL_SETTLEMENT", "TOTAL_SETTLEMENT"].includes(dependency.evidenceType)
      && (blockNumber < bundle.period.startBlock || blockNumber >= bundle.period.endBlockExclusive)) {
    throw new Error(`${dependency.dependencyId}: block ${blockNumber} outside approved period`);
  }
  authenticationGroup(blockNumber);
  const transactionIndex = hexNumber(receipt.transactionIndex);
  let authenticatedTimestamp = dependency.timestamp;
  if (dependency.timestamp != null) {
    const block = await callRpc("eth_getBlockByNumber", [receipt.blockNumber, false]);
    if (!block || hexNumber(block.number) !== blockNumber || normalizeHash(block.hash) !== normalizeHash(receipt.blockHash)) {
      throw new Error(`${dependency.dependencyId}: receipt block identity mismatch`);
    }
    authenticatedTimestamp = hexNumber(block.timestamp);
  }
  const resolved = { ...dependency, blockNumber, transactionIndex, ...(authenticatedTimestamp == null ? {} : { timestamp: authenticatedTimestamp }) };
  if (dependency.evidenceType === "NATIVE_FUNDING") {
    const transaction = await callRpc("eth_getTransactionByHash", [dependency.transactionHash]);
    if (!transaction) throw new Error(`${dependency.dependencyId}: transaction not found`);
    const type = transaction.type == null ? 0 : hexNumber(transaction.type);
    if (![0, 1, 2].includes(type)) throw new Error(`${dependency.dependencyId}: unsupported transaction type ${type}`);
    if (normalize(transaction.from) !== dependency.funder
        || normalize(transaction.to) !== dependency.buyer
        || BigInt(transaction.value) <= 0n
        || BigInt(transaction.value) !== BigInt(dependency.amountWei)) {
      throw new Error(`${dependency.dependencyId}: native funding parties/value mismatch`);
    }
    return { ...resolved, transactionType: type, valueWei: BigInt(transaction.value).toString() };
  }
  const log = locateLog(receipt.logs ?? [], dependency, bundle.contracts);
  validateLog(log, dependency, bundle.contracts);
  const resolvedLog = { ...resolved, logIndex: hexNumber(log.logIndex), receiptLogIndex: (receipt.logs ?? []).indexOf(log) };
  if (dependency.evidenceType === "USDC_FUNDING") {
    if (BigInt(dependency.amountRaw) <= 0n) throw new Error(`${dependency.dependencyId}: USDC funding must be positive`);
    const transaction = await callRpc("eth_getTransactionByHash", [dependency.transactionHash]);
    if (!transaction || normalize(transaction.from) !== dependency.funder) throw new Error(`${dependency.dependencyId}: funding transaction signer mismatch`);
  }
  if (dependency.evidenceType === "USDC_FUNDING" && topicAddress(log.topics?.[2]?.toLowerCase()) === normalize(bundle.contracts.deposits)) {
    const deposited = (receipt.logs ?? []).filter((candidate) => normalize(candidate.address) === normalize(bundle.contracts.deposits)
      && candidate.topics?.[0]?.toLowerCase() === DEPOSITED_TOPIC
      && topicAddress(candidate.topics?.[1]?.toLowerCase()) === dependency.buyer
      && dataWord(candidate.data, 0) === BigInt(dependency.amountRaw));
    if (deposited.length !== 1) throw new Error(`${dependency.dependencyId}: expected one matching Deposited log, found ${deposited.length}`);
    if (hexNumber(deposited[0].logIndex) <= resolvedLog.logIndex) throw new Error(`${dependency.dependencyId}: Deposited log must follow the funding transfer`);
    return { ...resolvedLog, depositLogIndex: hexNumber(deposited[0].logIndex), depositReceiptLogIndex: (receipt.logs ?? []).indexOf(deposited[0]) };
  }
  return resolvedLog;
}

function planCohort(claim, dependencies, bundle, ledgerBalances, allowLedgerSelection) {
  const strategyCandidates = [
    ...buildCohortStrategies("USDC", claim, dependencies, bundle.period, ledgerBalances, allowLedgerSelection),
    ...buildCohortStrategies("NATIVE", claim, dependencies, bundle.period, null, allowLedgerSelection),
  ];
  if (strategyCandidates.length === 0) throw new Error(`${claim.claimId}: no valid cohort funding strategy; ${cohortDiagnostics(claim, dependencies)}`);
  strategyCandidates.sort(compareCost);
  const selected = strategyCandidates[0];
  const totals = dependencies.filter((entry) => entry.evidenceType === "TOTAL_SETTLEMENT");
  const evidence = [...selected.closure.evidence, ...selected.funding, ...selected.settlements, ...totals];
  const plannedClaim = allowLedgerSelection
    ? { ...claim, metrics: { ...claim.metrics, qualifiedVolumeRaw: selected.volumeRaw.toString(), qualifiedBuyerCount: selected.buyers.length } }
    : claim;
  return finalizePlanClaim(plannedClaim, evidence, {
    selectionReason: `${selected.strategy} cohort; ${selected.closure.evidenceClass ?? "no closure"}; cost=${selected.cost.join("/")}`,
    rejectedAlternatives: [...selected.closure.rejected, ...strategyCandidates.slice(1).map(summarizeAlternative)],
    provenBuyerCount: selected.buyers.length,
    provenVolumeRaw: selected.volumeRaw.toString(),
    fundingStrategy: selected.strategy,
    closureType: selected.closure.evidenceClass,
    optimizationMode: selected.optimizationMode,
    fundingDiagnostics: selected.fundingDiagnostics,
  }, bundle);
}

function cohortDiagnostics(claim, dependencies) {
  const settlements = dependencies.filter((entry) => entry.evidenceType === "SETTLEMENT" && claim.approvedBuyers.includes(entry.buyer));
  return ["USDC", "NATIVE"].map((strategy) => {
    const fundingType = strategy === "USDC" ? "USDC_FUNDING" : "NATIVE_FUNDING";
    const fundings = dependencies.filter((entry) => entry.evidenceType === fundingType && claim.approvedBuyers.includes(entry.buyer) && claim.approvedFunders.includes(entry.funder));
    const fundedBuyers = new Set(fundings.map((entry) => entry.buyer));
    const postFundingVolume = settlements.filter((entry) => fundings.some((funding) => funding.buyer === entry.buyer && entry.blockNumber > funding.blockNumber)).reduce((total, entry) => total + BigInt(entry.amountRaw), 0n);
    return `${strategy.toLowerCase()}Fundings=${fundings.length},buyers=${fundedBuyers.size},postFundingVolumeRaw=${postFundingVolume}`;
  }).join("; ");
}

function buildCohortStrategies(strategy, claim, dependencies, period, ledgerBalances = null, allowLedgerSelection = false) {
  const fundingType = strategy === "USDC" ? "USDC_FUNDING" : "NATIVE_FUNDING";
  const fundings = dependencies.filter((entry) => entry.evidenceType === fundingType && claim.approvedBuyers.includes(entry.buyer) && claim.approvedFunders.includes(entry.funder));
  const settlements = dependencies.filter((entry) => entry.evidenceType === "SETTLEMENT" && claim.approvedBuyers.includes(entry.buyer));
  const funderGroups = [...new Set(fundings.map((entry) => entry.funder))].sort();
  return funderGroups.flatMap((selectedFunder) => {
    const closure = selectClosureForFunder(dependencies, selectedFunder, claim.approvedBuyers, claim.subjects[0], period);
    if (!closure) return [];
    const candidate = buildCohortStrategy(
      strategy,
      fundings.filter((entry) => entry.funder === selectedFunder),
      settlements,
      closure,
      allowLedgerSelection ? null : claim.metrics?.qualifiedVolumeRaw,
      ledgerBalances,
    );
    return candidate ? [candidate] : [];
  });
}

function buildCohortStrategy(strategy, fundings, settlements, closure, approvedVolumeRaw, ledgerBalances) {
  const fundingByBuyer = new Map();
  for (const funding of fundings) {
    if (!fundingByBuyer.has(funding.buyer)) fundingByBuyer.set(funding.buyer, []);
    fundingByBuyer.get(funding.buyer).push(funding);
  }
  for (const records of fundingByBuyer.values()) records.sort(compareEvidence);
  const earliestFundingByBuyer = new Map([...fundingByBuyer].map(([buyer, records]) => [buyer, records[0]]));
  const eligibleSettlements = settlements.filter((entry) => {
    const funding = earliestFundingByBuyer.get(entry.buyer);
    return funding && entry.blockNumber > funding.blockNumber;
  });
  if (fundingByBuyer.size === 0 || eligibleSettlements.length === 0) return null;
  if (closure.evidence.length > 0) {
    const targetReturnRaw = approvedVolumeRaw == null
      ? closure.evidence.reduce((total, entry) => total + returnPathCreditRaw(entry), 0n)
      : requiredReturnRaw(approvedVolumeRaw);
    const selectedClosure = selectReturnEvidence(closure.evidence, { requiredRaw: targetReturnRaw });
    if (approvedVolumeRaw != null && !selectedClosure.complete) return null;
    closure = { ...closure, evidence: selectedClosure.evidence };
  }
  const fixedBlocks = closure.evidence.flatMap(atomicEvidence).map((entry) => entry.blockNumber).filter(Number.isSafeInteger);
  const requiredBuyers = closure.evidence.filter((entry) => entry.evidenceType === "DIRECT_SELLER_BUYER").map((entry) => entry.buyer);
  const maximumVolumeRaw = returnSettlementCapacity(closure.evidence);
  const selection = strategy === "USDC" && ledgerBalances
    ? selectLedgerAwareSettlements(
      eligibleSettlements,
      fundingByBuyer,
      ledgerBalances,
      fixedBlocks,
      requiredBuyers,
      approvedVolumeRaw,
      maximumVolumeRaw,
    )
    : selectApprovedSettlements(
      eligibleSettlements,
      earliestFundingByBuyer,
      fixedBlocks,
      requiredBuyers,
      approvedVolumeRaw,
      maximumVolumeRaw,
    );
  if (!selection) return null;
  if (closure.evidence.length > 0 && !closureOccursAfterSettlements(selection.settlements, closure.evidence)) return null;
  if (!returnCoverageQualifies(closure.evidence, selection.volumeRaw)) return null;
  const latestSettlementByBuyer = new Map();
  for (const settlement of selection.settlements) {
    const current = latestSettlementByBuyer.get(settlement.buyer);
    if (!current || compareEvidence(current, settlement) < 0) latestSettlementByBuyer.set(settlement.buyer, settlement);
  }
  const funding = selection.buyers.flatMap((buyer) => (fundingByBuyer.get(buyer) ?? [])
    .filter((entry) => entry.blockNumber < latestSettlementByBuyer.get(buyer).blockNumber));
  if (strategy === "USDC" && ledgerBalances && sumRaw(funding) * 10_000n < selection.volumeRaw * 9_000n) return null;
  const fundingDiagnostics = selection.buyers.map((buyer) => {
    const records = fundingByBuyer.get(buyer) ?? [];
    const retained = funding.filter((entry) => entry.buyer === buyer);
    const excludedLate = records.filter((entry) => !retained.includes(entry));
    const total = (values) => values.reduce(
      (sum, entry) => sum + BigInt(strategy === "NATIVE" ? entry.valueWei : entry.amountRaw),
      0n,
    ).toString();
    return {
      buyer,
      retainedRecords: retained.length,
      excludedLateRecords: excludedLate.length,
      totalRecords: records.length,
      fundingUnit: strategy === "NATIVE" ? "wei" : "usdc_raw",
      retainedAmountRaw: total(retained),
      excludedLateAmountRaw: total(excludedLate),
      totalAmountRaw: total(records),
    };
  });
  const allEvidence = [...closure.evidence, ...funding, ...selection.settlements];
  return {
    strategy,
    closure,
    funding,
    settlements: selection.settlements,
    buyers: selection.buyers,
    volumeRaw: selection.volumeRaw,
    fundingDiagnostics,
    optimizationMode: selection.optimizationMode,
    cost: costTuple(allEvidence),
  };
}

export function selectApprovedSettlements(
  settlements,
  fundingByBuyer,
  fixedBlocks = [],
  requiredBuyers = [],
  approvedVolumeRaw = null,
  maximumVolumeRaw = null,
) {
  fixedBlocks.forEach(authenticationGroup);
  const eligible = settlements
    .filter((entry) => fundingByBuyer.has(entry.buyer))
    .sort(compareEvidence);
  const selected = maximumVolumeRaw == null ? eligible : selectWithinCapacity(eligible, maximumVolumeRaw);
  if (selected.length === 0) return null;
  const buyers = [...new Set(selected.map((entry) => entry.buyer))].sort();
  if (requiredBuyers.some((buyer) => !buyers.includes(buyer))) return null;
  const volumeRaw = sumRaw(selected);
  if (approvedVolumeRaw != null && volumeRaw !== BigInt(approvedVolumeRaw)) return null;
  return { settlements: selected, buyers, volumeRaw, optimizationMode: "exact-approved-evidence" };
}

export function selectLedgerAwareSettlements(
  settlements,
  fundingByBuyer,
  ledgerBalances,
  fixedBlocks = [],
  requiredBuyers = [],
  approvedVolumeRaw = null,
  maximumVolumeRaw = null,
) {
  fixedBlocks.forEach(authenticationGroup);
  const selected = [];
  for (const [buyer, values] of groupBy(
    settlements.filter((entry) => fundingByBuyer.has(entry.buyer)),
    (entry) => entry.buyer,
  )) {
    const balanceEnd = ledgerBalances.get(buyer);
    if (balanceEnd == null) throw new Error(`missing period-end ledger balance for ${buyer}`);
    const fundings = [...(fundingByBuyer.get(buyer) ?? [])].sort(compareEvidence);
    let eligible = [...values].sort(compareEvidence);
    let previous = null;
    while (eligible.length > 0) {
      const latest = eligible.reduce((maximum, entry) => compareEvidence(maximum, entry) < 0 ? entry : maximum);
      const fundedRaw = sumRaw(fundings.filter((entry) => compareEvidence(entry, latest) < 0));
      const capacityRaw = fundedRaw * (10_000n + EPSILON_LEDGER_BPS) / 10_000n;
      const availableRaw = capacityRaw > balanceEnd ? capacityRaw - balanceEnd : 0n;
      const retained = selectWithinCapacity(eligible, availableRaw);
      const fingerprint = retained.map((entry) => entry.dependencyId).join(":");
      eligible = retained;
      if (fingerprint === previous) break;
      previous = fingerprint;
    }
    selected.push(...eligible);
  }
  selected.sort(compareEvidence);
  const bounded = maximumVolumeRaw == null ? selected : selectWithinCapacity(selected, maximumVolumeRaw);
  if (bounded.length === 0) return null;
  const buyers = [...new Set(bounded.map((entry) => entry.buyer))].sort();
  if (requiredBuyers.some((buyer) => !buyers.includes(buyer))) return null;
  const volumeRaw = sumRaw(bounded);
  if (approvedVolumeRaw != null && volumeRaw !== BigInt(approvedVolumeRaw)) return null;
  return { settlements: bounded, buyers, volumeRaw, optimizationMode: "authenticated-ledger-capacity" };
}

function selectWithinCapacity(settlements, capacityRaw) {
  let selectedRaw = 0n;
  const selected = [];
  const candidates = [...settlements].sort(compareEvidence);
  for (const settlement of candidates) {
    const amountRaw = BigInt(settlement.amountRaw);
    if (selectedRaw + amountRaw > capacityRaw) continue;
    selected.push(settlement);
    selectedRaw += amountRaw;
  }
  return selected.sort(compareEvidence);
}

function returnCoverageQualifies(closureEvidence, settlementVolumeRaw) {
  if (closureEvidence.length === 0) return true;
  if (closureEvidence.length > MAX_RETURN_PATHS) return false;
  const returnedRaw = closureEvidence.reduce((total, path) => {
    const credit = atomicEvidence(path).map((entry) => BigInt(entry.amountRaw))
      .reduce((minimum, amount) => amount < minimum ? amount : minimum);
    return total + credit;
  }, 0n);
  return returnedRaw * 10_000n >= settlementVolumeRaw * ALPHA_RETURN_BPS;
}

function returnSettlementCapacity(closureEvidence) {
  if (closureEvidence.length === 0) return null;
  if (closureEvidence.length > MAX_RETURN_PATHS) return 0n;
  const returnedRaw = closureEvidence.reduce((total, path) => {
    const credit = atomicEvidence(path).map((entry) => BigInt(entry.amountRaw))
      .reduce((minimum, amount) => amount < minimum ? amount : minimum);
    return total + credit;
  }, 0n);
  return returnedRaw * 10_000n / ALPHA_RETURN_BPS;
}
function planReciprocal(claim, dependencies, bundle) {
  const selected = dependencies.filter((entry) => entry.evidenceType === "RECIPROCAL_SETTLEMENT").sort(compareEvidence);
  const totals = dependencies.filter((entry) => entry.evidenceType === "TOTAL_SETTLEMENT").sort(compareEvidence);
  const volumeAToB = sumRaw(selected.filter((entry) => entry.buyer === claim.walletA && entry.seller === claim.walletB));
  const volumeBToA = sumRaw(selected.filter((entry) => entry.buyer === claim.walletB && entry.seller === claim.walletA));
  if (!reciprocalVolumesQualify(volumeAToB, volumeBToA)) {
    throw new Error("reciprocal selection cannot satisfy 80% reciprocity");
  }
  const subjects = new Set(claim.subjects.map(normalize));
  const internalDeposits = dependencies.filter((entry) => entry.evidenceType === "USDC_FUNDING"
    && entry.depositLogIndex != null
    && subjects.has(normalize(entry.buyer))
    && subjects.has(normalize(entry.funder)));
  return finalizePlanClaim(claim, [...internalDeposits, ...selected, ...totals], {
    selectionReason: `exact approved settlements; at least 80% volume reciprocity; cost=${costTuple(selected).join("/")}`,
    rejectedAlternatives: [],
    provenSettlementCount: selected.length,
    provenDirections: 2,
    optimizationMode: "exact",
  }, bundle);
}

function selectClosureForFunder(dependencies, funder, approvedBuyers, seller, period) {
  if (normalize(funder) === normalize(seller)) return { evidence: [], evidenceClass: "SELF_FUNDED", rejected: [] };
  const direct = dependencies.filter((entry) => entry.evidenceType === "DIRECT_SELLER_FUNDER"
    && entry.funder === funder
    && BigInt(entry.amountRaw) > 0n
    && atomicEvidence(entry).every(nonSelfTransfer)
    && (!period || atomicEvidence(entry).every((evidence) => evidence.blockNumber >= period.startBlock && evidence.blockNumber < period.endBlockExclusive)));
  const relayCandidates = dependencies.filter((entry) => entry.evidenceType === "RELAY_PATH" && entry.funder === funder);
  const relay = relayCandidates
    .filter((candidate) => atomicEvidence(candidate).every(nonSelfTransfer) && validRelayPath(candidate, period))
    .sort(compareRelayPath);
  const evidence = [...direct, ...relay];
  if (evidence.length === 0) return null;
  const evidenceClass = direct.length > 0 && relay.length > 0
    ? "DIRECT_AND_RELAY"
    : direct.length > 0 ? "DIRECT_SELLER_FUNDER" : "RELAY_PATH";
  return {
    evidence,
    evidenceClass,
    rejected: relayCandidates.filter((candidate) => !relay.includes(candidate)).map(summarizeEvidence),
  };
}

function closureOccursAfterSettlements(settlements, closureEvidence) {
  const earliestSettlement = [...settlements].sort(compareEvidence)[0];
  return earliestSettlement != null
    && closureEvidence.flatMap(atomicEvidence).every((entry) => compareEvidence(entry, earliestSettlement) > 0);
}

export function validRelayPath(path, period = null) {
  const hops = atomicEvidence(path);
  if (hops.length === 0 || hops.length > 9 || !hops.every((entry) => Number.isSafeInteger(entry.blockNumber))) return false;
  if (period && !hops.every((entry) => entry.blockNumber >= period.startBlock && entry.blockNumber < period.endBlockExclusive)) return false;
  for (let index = 0; index < hops.length; index += 1) {
    if (BigInt(hops[index].amountRaw) <= 0n) return false;
    if (index === 0) continue;
    if (compareEvidence(hops[index - 1], hops[index]) >= 0 || hops[index].timestamp < hops[index - 1].timestamp) return false;
    if (BigInt(hops[index].amountRaw) * 10_000n < BigInt(hops[index - 1].amountRaw) * MIN_RELAY_RETAINED_BPS) return false;
  }
  return hops.at(-1).timestamp - hops[0].timestamp <= MAX_RELAY_SECONDS;
}

function nonSelfTransfer(entry) {
  return entry.from == null || entry.to == null || normalize(entry.from) !== normalize(entry.to);
}

function flattenRelay(path) {
  return atomicEvidence(path);
}

function finalizePlanClaim(claim, evidence, details, bundle) {
  const selected = dedupe(evidence).sort(compareEvidence);
  validateAnalysisVolume(claim, selected);
  const selectedBlocks = [...new Set(selected.flatMap(atomicEvidence).map((entry) => entry.blockNumber))].sort(numberAscending);
  return {
    claimId: claim.claimId,
    type: claim.type,
    subjects: claim.subjects,
    reportRoot: bundle.reportRoot,
    dependencyRoot: claim.dependencyRoot,
    selectedEvidence: selected,
    selectedBlocks,
    materializationBlocks: selectedBlocks,
    cost: costTuple(selected),
    ...details,
  };
}

function validateAnalysisVolume(claim, selected) {
  if (claim.metrics == null) return;
  const settlements = selected.filter((entry) => ["SETTLEMENT", "RECIPROCAL_SETTLEMENT"].includes(entry.evidenceType));
  if (claim.type === "P0_CLOSED_LOOP") {
    const actual = sumRaw(settlements);
    const expected = BigInt(claim.metrics.qualifiedVolumeRaw);
    if (actual !== expected) throw new Error(`${claim.claimId}: selected settlement volume ${actual} does not equal approved analysis volume ${expected}`);
    return;
  }
  const [addressA, addressB] = claim.subjects.map(normalize).sort();
  const volumeAToB = sumRaw(settlements.filter((entry) => normalize(entry.buyer) === addressA && normalize(entry.seller) === addressB));
  const volumeBToA = sumRaw(settlements.filter((entry) => normalize(entry.buyer) === addressB && normalize(entry.seller) === addressA));
  const expectedAToB = BigInt(claim.metrics.volumeAToBRaw);
  const expectedBToA = BigInt(claim.metrics.volumeBToARaw);
  if (volumeAToB !== expectedAToB || volumeBToA !== expectedBToA) {
    throw new Error(`${claim.claimId}: selected reciprocal volumes ${volumeAToB}/${volumeBToA} do not equal approved analysis volumes ${expectedAToB}/${expectedBToA}`);
  }
}

export function attachMemberships(plan, claim, allClaims) {
  const dependencyHashes = claim.dependencies.map((entry) => entry.dependencyId);
  const dependencyMemberships = merkleMembershipIndex(dependencyHashes);
  const originalById = new Map(claim.dependencies.map((entry) => [entry.dependencyId, entry]));
  const claimLeaf = { ...claim };
  delete claimLeaf.leafHash;
  delete claimLeaf.dependencies;
  return {
    ...plan,
    claimLeaf: canonicalJson(claimLeaf),
    claimMembership: merkleMembership(allClaims.map((entry) => entry.leafHash), claim.leafHash),
    selectedEvidence: plan.selectedEvidence.map((entry) => {
      const original = originalById.get(entry.dependencyId);
      if (!original) throw new Error(`${claim.claimId}: selected evidence lacks a report dependency`);
      const dependencyLeaf = { ...original };
      delete dependencyLeaf.dependencyId;
      return {
        ...entry,
        dependencyLeaf: canonicalJson(dependencyLeaf),
        dependencyMembership: dependencyMemberships.get(entry.dependencyId),
      };
    }),
  };
}

function reciprocalVolumesQualify(volumeAToB, volumeBToA) {
  if (volumeAToB <= 0n || volumeBToA <= 0n) return false;
  const minimum = volumeAToB < volumeBToA ? volumeAToB : volumeBToA;
  const maximum = volumeAToB > volumeBToA ? volumeAToB : volumeBToA;
  return minimum * 10_000n >= maximum * MINIMUM_RECIPROCAL_VOLUME_BPS;
}

function locateLog(logs, dependency, contracts) {
  if (dependency.logIndex != null) {
    const found = logs.find((log) => hexNumber(log.logIndex) === dependency.logIndex);
    if (found) return found;
  }
  const matches = logs.filter((log) => logMatches(log, dependency, contracts));
  if (matches.length !== 1) throw new Error(`${dependency.dependencyId}: expected one matching log, found ${matches.length}`);
  return matches[0];
}

function validateLog(log, dependency, contracts) {
  if (!logMatches(log, dependency, contracts)) throw new Error(`${dependency.dependencyId}: authenticated log mismatch`);
}

function logMatches(log, dependency, contracts) {
  const topics = (log.topics ?? []).map((topic) => topic.toLowerCase());
  if (["SETTLEMENT", "RECIPROCAL_SETTLEMENT", "TOTAL_SETTLEMENT"].includes(dependency.evidenceType)) {
    return normalize(log.address) === normalize(contracts.channels)
      && topics[0] === CHANNEL_SETTLED_TOPIC
      && topicAddress(topics[2]) === dependency.buyer
      && topicAddress(topics[3]) === dependency.seller
      && dataWord(log.data, 1) === BigInt(dependency.amountRaw);
  }
  const transferTypes = new Set(["USDC_FUNDING", "DIRECT_SELLER_FUNDER", "DIRECT_SELLER_BUYER", "RELAY_SELLER_PAYMENT", "RELAY_FORWARD", "RELAY_FUNDER_RECEIPT"]);
  if (!transferTypes.has(dependency.evidenceType)) return false;
  if (normalize(log.address) !== normalize(contracts.usdc) || topics[0] !== TRANSFER_TOPIC) return false;
  const from = topicAddress(topics[1]);
  const to = topicAddress(topics[2]);
  if (dependency.from && from !== dependency.from) return false;
  if (dependency.to && to !== dependency.to) return false;
  if (dependency.funder && dependency.buyer) {
    if (from !== dependency.funder) return false;
    if (to !== dependency.buyer && to !== normalize(contracts.deposits)) return false;
  }
  return dependency.amountRaw == null || dataWord(log.data, 0) === BigInt(dependency.amountRaw);
}

function costTuple(evidence) {
  const atomic = evidence.flatMap(atomicEvidence);
  const windows = new Set(atomic.map((entry) => authenticationGroup(entry.blockNumber))).size;
  const witnessBytes = evidence.reduce((total, entry) => total + JSON.stringify(entry).length, 0);
  return [windows, atomic.length, witnessBytes, canonicalEvidence(evidence)];
}

function compareCost(left, right) {
  for (let index = 0; index < 3; index += 1) if (left.cost[index] !== right.cost[index]) return left.cost[index] - right.cost[index];
  return left.cost[3].localeCompare(right.cost[3]);
}

function validateBundle(bundle) {
  if (bundle?.version !== 1 || bundle?.chainId !== 8_453 || !Array.isArray(bundle.claims)) throw new Error("unsupported proof bundle");
}

export async function finalizeLedgerAwareBundle(bundle, {
  rpcUrl,
  concurrency = 20,
  fetchJson = defaultFetchJson,
  onProgress = () => {},
  checkpointDirectory = null,
} = {}) {
  if (checkpointDirectory) await mkdir(checkpointDirectory, { recursive: true });
  const claims = [];
  const authenticatedClaims = new Map();
  const closedClaims = bundle.claims.filter((claim) => claim.type === "P0_CLOSED_LOOP");
  let closedIndex = 0;
  for (const claim of bundle.claims) {
    if (claim.type !== "P0_CLOSED_LOOP") {
      claims.push(claim);
      continue;
    }
    closedIndex += 1;
    const checkpoint = checkpointDirectory ? await readClaimCheckpoint(checkpointDirectory, claim, bundle) : null;
    if (checkpoint) {
      claims.push(checkpoint);
      authenticatedClaims.set(claimAuthenticationKey(checkpoint), {
        resolved: checkpoint.dependencies,
        rejected: [],
        ledgerBalances: null,
      });
      onProgress(`[ledger ${closedIndex}/${closedClaims.length}] resumed ${checkpoint.metrics.qualifiedVolumeRaw} raw across ${checkpoint.approvedBuyers.length} buyers`);
      continue;
    }
    onProgress(`[ledger ${closedIndex}/${closedClaims.length}] authenticating ${claim.claimId}`);
    const authenticated = await authenticateClaim(claim, bundle, { rpcUrl, concurrency, fetchJson, onProgress: () => {} });
    const requiredRejections = authenticated.rejected.filter((entry) => entry.evidenceType === "TOTAL_SETTLEMENT");
    if (requiredRejections.length > 0) throw new Error(`${claim.claimId}: incomplete total-settlement authentication during ledger finalization`);
    const planned = planClaim(claim, authenticated.resolved, bundle, {
      ledgerBalances: authenticated.ledgerBalances,
      allowLedgerSelection: true,
    });
    const selectedSettlements = planned.selectedEvidence.filter((entry) => entry.evidenceType === "SETTLEMENT");
    const selectedBuyers = [...new Set(selectedSettlements.map((entry) => entry.buyer))].sort();
    const claimBody = { ...claim };
    delete claimBody.claimId;
    delete claimBody.leafHash;
    delete claimBody.dependencyRoot;
    delete claimBody.dependencies;
    const finalizedClaim = finalizeClaim({
      ...claimBody,
      approvedBuyers: selectedBuyers,
      metrics: {
        ...claim.metrics,
        qualifiedVolumeRaw: sumRaw(selectedSettlements).toString(),
        qualifiedBuyerCount: selectedBuyers.length,
      },
      dependencies: planned.selectedEvidence.map(stripDependencyId),
    });
    claims.push(finalizedClaim);
    authenticatedClaims.set(claimAuthenticationKey(finalizedClaim), {
      resolved: finalizedClaim.dependencies,
      rejected: authenticated.rejected,
      ledgerBalances: authenticated.ledgerBalances,
    });
    if (checkpointDirectory) await writeClaimCheckpoint(checkpointDirectory, claim, finalizedClaim, bundle);
    onProgress(`[ledger ${closedIndex}/${closedClaims.length}] selected ${finalizedClaim.metrics.qualifiedVolumeRaw} raw across ${selectedBuyers.length} buyers`);
  }
  return { bundle: finalizeBundle({ ...bundle, claims }), authenticatedClaims };
}

async function readClaimCheckpoint(directory, sourceClaim, bundle) {
  try {
    const checkpoint = JSON.parse(await readFile(`${directory}/${sourceClaim.claimId}.json`, "utf8"));
    if (checkpoint.version !== 1
      || checkpoint.sourceClaimId !== sourceClaim.claimId
      || canonicalJson(checkpoint.period) !== canonicalJson(bundle.period)
      || canonicalJson(checkpoint.contracts) !== canonicalJson(bundle.contracts)) return null;
    return checkpoint.finalizedClaim;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function writeClaimCheckpoint(directory, sourceClaim, finalizedClaim, bundle) {
  await writeFile(`${directory}/${sourceClaim.claimId}.json`, `${JSON.stringify({
    version: 1,
    sourceClaimId: sourceClaim.claimId,
    period: bundle.period,
    contracts: bundle.contracts,
    finalizedClaim,
  })}\n`);
}

async function authenticateClaim(claim, bundle, { rpcUrl, concurrency, fetchJson, onProgress }) {
  const rpcCache = new Map();
  const callRpc = (method, params) => {
    const key = `${method}:${JSON.stringify(params)}`;
    if (!rpcCache.has(key)) rpcCache.set(key, rpc(rpcUrl, method, params, fetchJson));
    return rpcCache.get(key);
  };
  onProgress(`prefetching ${claim.dependencies.length} dependencies for ${claim.claimId}`);
  await prefetchDependencies(claim.dependencies, rpcUrl, rpcCache, fetchJson, concurrency, () => {});
  const entries = await mapConcurrent(claim.dependencies, concurrency, async (dependency) => {
    try {
      return { dependency: await resolveDependency(dependency, bundle, callRpc), rejection: null };
    } catch (error) {
      if (error instanceof RpcTransportError) throw error;
      return { dependency: null, rejection: { dependencyId: dependency.dependencyId, evidenceType: dependency.evidenceType, reason: error.message } };
    }
  });
  const resolved = [];
  const rejected = [];
  for (const entry of entries) (entry.dependency ? resolved : rejected).push(entry.dependency ?? entry.rejection);
  const ledgerBalances = claim.type === "P0_CLOSED_LOOP"
    ? await loadClaimLedgerBalances(claim, bundle, callRpc)
    : null;
  return { resolved, rejected, ledgerBalances };
}

async function loadClaimLedgerBalances(claim, bundle, callRpc) {
  const block = `0x${(bundle.period.endBlockExclusive - 1).toString(16)}`;
  const balances = new Map();
  for (const buyer of claim.approvedBuyers) {
    const data = `${BUYERS_SELECTOR}${buyer.slice(2).padStart(64, "0")}`;
    const result = await callRpc("eth_call", [{ to: bundle.contracts.deposits, data }, block]);
    if (typeof result !== "string" || result.length < 66) throw new Error(`${claim.claimId}: invalid period-end ledger response for ${buyer}`);
    balances.set(buyer, BigInt(`0x${result.slice(2, 66)}`));
  }
  return balances;
}

function claimAuthenticationKey(claim) {
  return `${claim.type}:${claim.subjects.join(":")}`;
}

function stripDependencyId(dependency) {
  const result = structuredClone(dependency);
  delete result.dependencyId;
  for (const entry of atomicEvidence(result)) delete entry.dependencyId;
  return result;
}

async function rpc(url, method, params, fetchJson) {
  let lastError;
  for (let attempt = 0; attempt < 9; attempt += 1) {
    const response = await fetchJson(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    if (!response.error) return response.result;
    lastError = new Error(`${method}: ${JSON.stringify(response.error)}`);
    if (![-32_000, -32_005, -32_600, -32_603].includes(response.error.code)) throw lastError;
    await retryDelay(attempt);
  }
  throw new RpcTransportError(lastError.message, { cause: lastError });
}

async function rpcBatch(url, requests, fetchJson) {
  const body = requests.map(({ id, method, params }) => ({ jsonrpc: "2.0", id, method, params }));
  const response = await fetchJson(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!Array.isArray(response)) throw new RpcTransportError("RPC batch returned a non-array response");
  return new Map(response.map((entry) => [entry.id, entry]));
}

async function defaultFetchJson(url, options) {
  let lastError;
  for (let attempt = 0; attempt < 9; attempt += 1) {
    try {
      const response = await fetch(url, { ...options, signal: AbortSignal.timeout(20_000) });
      if (response.ok) return response.json();
      lastError = new RpcTransportError(`RPC HTTP ${response.status}`);
      if (![429, 500, 502, 503, 504].includes(response.status)) throw lastError;
      await retryDelay(attempt, retryAfterMilliseconds(response));
      continue;
    } catch (error) {
      if (error instanceof RpcTransportError && !/^RPC HTTP (429|500|502|503|504)$/.test(error.message)) throw error;
      lastError = error instanceof RpcTransportError
        ? error
        : new RpcTransportError(error.message, { cause: error });
    }
    await retryDelay(attempt);
  }
  throw lastError;
}

async function retryDelay(attempt, minimumMilliseconds = 0) {
  const exponential = 250 * (2 ** Math.min(attempt, 6));
  const jitter = Math.floor(Math.random() * Math.max(1, exponential / 4));
  await new Promise((resolve) => setTimeout(resolve, Math.max(minimumMilliseconds, exponential) + jitter));
}

function retryAfterMilliseconds(response) {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter == null) return 0;
  const seconds = Number(retryAfter);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1_000);
  const timestamp = Date.parse(retryAfter);
  return Number.isFinite(timestamp) ? Math.max(0, timestamp - Date.now()) : 0;
}

async function mapConcurrent(values, concurrency, mapper) {
  const results = new Array(values.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (cursor < values.length) {
      const index = cursor++;
      results[index] = await mapper(values[index], index);
    }
  }));
  return results;
}

function compareEvidence(left, right) {
  if (left.evidenceType === "RELAY_PATH" || right.evidenceType === "RELAY_PATH") return canonicalEvidence([left]).localeCompare(canonicalEvidence([right]));
  return left.blockNumber - right.blockNumber || left.transactionIndex - right.transactionIndex || left.logIndex - right.logIndex || left.dependencyId.localeCompare(right.dependencyId);
}

function compareRelayPath(left, right) {
  return costTuple(flattenRelay(left)).slice(0, 3).find((value, index) => value !== costTuple(flattenRelay(right))[index]) ?? canonicalEvidence(flattenRelay(left)).localeCompare(canonicalEvidence(flattenRelay(right)));
}

function summarizeEvidence(entry) { return { evidenceType: entry.evidenceType, dependencyId: entry.dependencyId ?? null, reason: "higher deterministic cost" }; }
function summarizeAlternative(entry) { return { strategy: entry.strategy, cost: entry.cost, reason: "higher deterministic cost" }; }
function canonicalEvidence(entries) { return [...entries].map((entry) => entry.dependencyId ?? JSON.stringify(entry)).sort().join(":"); }
function sumRaw(entries) { return entries.reduce((total, entry) => total + BigInt(entry.amountRaw), 0n); }
function normalize(value) { return typeof value === "string" ? value.toLowerCase() : null; }
function normalizeHash(value) { return typeof value === "string" && /^0x[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : null; }
function topicAddress(topic) { return topic ? `0x${topic.slice(-40)}`.toLowerCase() : null; }
function dataWord(data, index) { return BigInt(`0x${data.slice(2 + index * 64, 2 + (index + 1) * 64)}`); }
function hexNumber(value) { const number = Number(BigInt(value)); if (!Number.isSafeInteger(number)) throw new Error(`unsafe numeric RPC value ${value}`); return number; }
function numberAscending(left, right) { return left - right; }
function groupBy(values, key) { const result = new Map(); for (const value of values) { const group = key(value); const rows = result.get(group) ?? []; rows.push(value); result.set(group, rows); } return result; }
function dedupe(values) { const result = new Map(); for (const value of values) result.set(value.dependencyId ?? JSON.stringify(value), value); return [...result.values()]; }
function atomicEvidence(value) { return value.evidenceType === "RELAY_PATH" ? (value.hops ?? [value.sellerPayment, value.relayForward, value.funderReceipt]) : [value]; }
function canonicalJson(value) { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`; }
function sha256Hex(value) { return `0x${(awaitableSha256(value))}`; }
function awaitableSha256(value) { return createHash("sha256").update(value).digest("hex"); }
function hexBytes(value) { return Buffer.from(value.slice(2), "hex"); }

export async function planFile({
  bundlePath,
  outPath,
  rpcUrl,
  concurrency,
  claimIds,
  onProgress,
  checkpointDirectory = null,
  claimConcurrency = 1,
  planCheckpointDirectory = null,
}) {
  const draftBundle = JSON.parse(await readFile(bundlePath, "utf8"));
  const finalized = await finalizeLedgerAwareBundle(draftBundle, { rpcUrl, concurrency, onProgress, checkpointDirectory });
  await writeFile(bundlePath, `${JSON.stringify(finalized.bundle)}\n`);
  const plan = await planProofBundle(finalized.bundle, {
    rpcUrl,
    concurrency,
    claimIds,
    onProgress,
    finalizeLedger: false,
    authenticatedClaims: finalized.authenticatedClaims,
    claimConcurrency,
    planCheckpointDirectory,
  });
  await writePlanFile(outPath, plan);
  return plan;
}

async function writePlanFile(path, plan) {
  const { claims, ...metadata } = plan;
  const file = await open(path, "w");
  try {
    const prefix = JSON.stringify(metadata);
    await file.write(`${prefix.slice(0, -1)},\"claims\":[`);
    for (let index = 0; index < claims.length; index += 1) {
      if (index > 0) await file.write(",");
      await file.write(JSON.stringify(claims[index]));
    }
    await file.write("]}\n");
  } finally {
    await file.close();
  }
}
