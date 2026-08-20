import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

export const AGGREGATE_VERIFIER_START_BLOCK = 46_302_960;
export const CHECKPOINT_WINDOW_BLOCKS = 30;
export const HISTORICAL_START_BLOCK = 44_469_557;
export const MINIMUM_VOLUME_RAW = 1_000_000_000n;
export const MINIMUM_RECIPROCAL_DIRECTION_VOLUME_RAW = 10_000_000n;
export const MINIMUM_RECIPROCAL_VOLUME_BPS = 8_000n;

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CHANNEL_SETTLED_TOPIC = "0x0b287f37d8bd14ef37f2966734ab387c243cc1a1663616a25a4cc259877736b1";
const DEPOSITED_TOPIC = "0x2da466a7b24304f47e87fa2e1e5a81b9831ce54fec19055ce277ca2f39ba42c4";

export async function planProofBundle(bundle, { rpcUrl, concurrency = 20, fetchJson = defaultFetchJson, claimIds = null, onProgress = () => {} } = {}) {
  validateBundle(bundle);
  if (!rpcUrl) throw new Error("ANTSEED_BASE_RPC_URL or --rpc-url is required");
  const selectedClaims = claimIds == null ? bundle.claims : bundle.claims.filter((claim) => claimIds.includes(claim.claimId));
  if (selectedClaims.length === 0) throw new Error("no requested claims found in proof bundle");
  const claims = [];
  for (let claimIndex = 0; claimIndex < selectedClaims.length; claimIndex += 1) {
    const claim = selectedClaims[claimIndex];
    const rpcCache = new Map();
    const callRpc = (method, params) => {
      const key = `${method}:${JSON.stringify(params)}`;
      if (!rpcCache.has(key)) rpcCache.set(key, rpc(rpcUrl, method, params, fetchJson));
      return rpcCache.get(key);
    };
    onProgress(`[${claimIndex + 1}/${selectedClaims.length}] prefetching ${claim.dependencies.length} dependencies for ${claim.claimId}`);
    await prefetchDependencies(claim.dependencies, rpcUrl, rpcCache, fetchJson, concurrency, () => {});
    const resolved = [];
    const rejected = [];
    const entries = await mapConcurrent(claim.dependencies, concurrency, async (dependency) => {
      try {
        return { dependency: await resolveDependency(dependency, bundle, callRpc), rejection: null };
      } catch (error) {
        return { dependency: null, rejection: { dependencyId: dependency.dependencyId, evidenceType: dependency.evidenceType, reason: error.message } };
      }
    });
    for (const entry of entries) (entry.dependency ? resolved : rejected).push(entry.dependency ?? entry.rejection);
    onProgress(`[${claimIndex + 1}/${selectedClaims.length}] optimizing ${resolved.length} authenticated dependencies`);
    let planned;
    try {
      planned = planClaim(claim, resolved, bundle);
    } catch (error) {
      const rejectionCounts = Object.fromEntries([...groupBy(rejected, (entry) => entry.reason).entries()].map(([reason, values]) => [reason, values.length]));
      throw new Error(`${error.message}; authenticated=${resolved.length}; rejected=${rejected.length}; rejectionCounts=${JSON.stringify(rejectionCounts)}`);
    }
    claims.push(attachMemberships({
      ...planned,
      rejectedAlternatives: [...(planned.rejectedAlternatives ?? []), ...rejected],
    }, claim, bundle.claims));
    onProgress(`[${claimIndex + 1}/${selectedClaims.length}] selected ${planned.selectedEvidence.length} evidence objects`);
  }
  const checkpointWindows = mergeCheckpointWindows(claims.flatMap((claim) => claim.checkpointWindows));
  onProgress(`selected ${claims.length} claims across ${checkpointWindows.length} checkpoint windows`);
  return {
    version: 1,
    kind: "antseed-wash-trading-proof-plan",
    bundleVersion: bundle.version,
    chainId: bundle.chainId,
    reportRoot: bundle.reportRoot,
    period: bundle.period,
    claimCount: claims.length,
    claims,
    checkpointSelection: {
      version: 1,
      chain_id: bundle.chainId,
      start_block: bundle.period.startBlock,
      end_block_exclusive: bundle.period.endBlockExclusive,
      aggregate_verifier_start_block: AGGREGATE_VERIFIER_START_BLOCK,
      selected_block_numbers: [...new Set(claims.flatMap((claim) => claim.selectedBlocks).filter(isCheckpointBlock))].sort(numberAscending),
      historical_block_numbers: [...new Set(claims.flatMap((claim) => claim.selectedBlocks).filter((block) => !isCheckpointBlock(block)))].sort(numberAscending),
      checkpoint_windows: checkpointWindows.map((window) => ({ checkpoint_block_number: window.checkpointBlockNumber, target_blocks: window.targetBlocks })),
    },
  };
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

export function planClaim(claim, dependencies, bundle) {
  if (claim.type === "P0_RECIPROCAL") return planReciprocal(claim, dependencies, bundle);
  if (claim.type !== "P0_CLOSED_LOOP") throw new Error(`${claim.claimId}: unsupported claim type ${claim.type}`);
  return planCohort(claim, dependencies, bundle);
}

export function checkpointBlockNumber(blockNumber) {
  if (!Number.isSafeInteger(blockNumber) || blockNumber <= AGGREGATE_VERIFIER_START_BLOCK) {
    throw new Error(`block ${blockNumber} predates AggregateVerifier checkpoint coverage`);
  }
  const offset = blockNumber - AGGREGATE_VERIFIER_START_BLOCK - 1;
  return AGGREGATE_VERIFIER_START_BLOCK + (Math.floor(offset / CHECKPOINT_WINDOW_BLOCKS) + 1) * CHECKPOINT_WINDOW_BLOCKS;
}

function authenticationGroup(blockNumber) {
  if (!Number.isSafeInteger(blockNumber) || blockNumber < HISTORICAL_START_BLOCK) {
    throw new Error(`block ${blockNumber} predates supported historical state coverage`);
  }
  return isCheckpointBlock(blockNumber) ? `checkpoint:${checkpointBlockNumber(blockNumber)}` : `historical:${blockNumber}`;
}

function isCheckpointBlock(blockNumber) {
  return blockNumber > AGGREGATE_VERIFIER_START_BLOCK;
}

export function merkleMembership(hashes, targetHash) {
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

async function resolveDependency(dependency, bundle, callRpc) {
  if (dependency.evidenceType === "RELAY_PATH") {
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
  const blockNumber = hexNumber(receipt.blockNumber);
  if (["SETTLEMENT", "RECIPROCAL_SETTLEMENT"].includes(dependency.evidenceType)
      && (blockNumber < bundle.period.startBlock || blockNumber >= bundle.period.endBlockExclusive)) {
    throw new Error(`${dependency.dependencyId}: block ${blockNumber} outside approved period`);
  }
  authenticationGroup(blockNumber);
  const transactionIndex = hexNumber(receipt.transactionIndex);
  const resolved = { ...dependency, blockNumber, transactionIndex };
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
  if (dependency.evidenceType === "USDC_FUNDING" && topicAddress(log.topics?.[2]?.toLowerCase()) === normalize(bundle.contracts.deposits)) {
    const deposited = (receipt.logs ?? []).filter((candidate) => normalize(candidate.address) === normalize(bundle.contracts.deposits)
      && candidate.topics?.[0]?.toLowerCase() === DEPOSITED_TOPIC
      && topicAddress(candidate.topics?.[1]?.toLowerCase()) === dependency.buyer
      && dataWord(candidate.data, 0) === BigInt(dependency.amountRaw));
    if (deposited.length !== 1) throw new Error(`${dependency.dependencyId}: expected one matching Deposited log, found ${deposited.length}`);
    return { ...resolvedLog, depositLogIndex: hexNumber(deposited[0].logIndex), depositReceiptLogIndex: (receipt.logs ?? []).indexOf(deposited[0]) };
  }
  return resolvedLog;
}

function planCohort(claim, dependencies, bundle) {
  const strategyCandidates = [
    ...buildCohortStrategies("USDC", claim, dependencies),
    ...buildCohortStrategies("NATIVE", claim, dependencies),
  ];
  if (strategyCandidates.length === 0) throw new Error(`${claim.claimId}: no valid cohort funding strategy; ${cohortDiagnostics(claim, dependencies)}`);
  strategyCandidates.sort(compareCost);
  const selected = strategyCandidates[0];
  const evidence = [...selected.closure.evidence, ...selected.funding, ...selected.settlements];
  return finalizePlanClaim(claim, evidence, {
    selectionReason: `${selected.strategy} cohort; ${selected.closure.evidenceClass ?? "no closure"}; cost=${selected.cost.join("/")}`,
    rejectedAlternatives: [...selected.closure.rejected, ...strategyCandidates.slice(1).map(summarizeAlternative)],
    provenBuyerCount: selected.buyers.length,
    provenVolumeRaw: selected.volumeRaw.toString(),
    fundingStrategy: selected.strategy,
    closureType: selected.closure.evidenceClass,
    optimizationMode: selected.optimizationMode,
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

function buildCohortStrategies(strategy, claim, dependencies) {
  const fundingType = strategy === "USDC" ? "USDC_FUNDING" : "NATIVE_FUNDING";
  const fundings = dependencies.filter((entry) => entry.evidenceType === fundingType && claim.approvedBuyers.includes(entry.buyer) && claim.approvedFunders.includes(entry.funder));
  const settlements = dependencies.filter((entry) => entry.evidenceType === "SETTLEMENT" && claim.approvedBuyers.includes(entry.buyer));
  const funderGroups = [...new Set(fundings.map((entry) => entry.funder))].sort();
  return funderGroups.flatMap((selectedFunder) => {
    const closure = selectClosureForFunder(dependencies, selectedFunder, claim.approvedBuyers, claim.subjects[0]);
    if (!closure) return [];
    const candidate = buildCohortStrategy(strategy, fundings.filter((entry) => entry.funder === selectedFunder), settlements, closure);
    return candidate ? [candidate] : [];
  });
}

function buildCohortStrategy(strategy, fundings, settlements, closure) {
  const fundingByBuyer = new Map();
  for (const funding of fundings) {
    const current = fundingByBuyer.get(funding.buyer);
    if (!current || compareEvidence(funding, current) < 0) fundingByBuyer.set(funding.buyer, funding);
  }
  const eligibleSettlements = settlements.filter((entry) => {
    const funding = fundingByBuyer.get(entry.buyer);
    return funding && entry.blockNumber > funding.blockNumber;
  });
  if (fundingByBuyer.size < 3 || eligibleSettlements.length === 0) return null;
  const fixedBlocks = closure.evidence.flatMap(atomicEvidence).map((entry) => entry.blockNumber).filter(Number.isSafeInteger);
  const requiredBuyers = closure.evidence.filter((entry) => entry.evidenceType === "DIRECT_SELLER_BUYER").map((entry) => entry.buyer);
  const selection = selectMinimumSettlementWindows(eligibleSettlements, fundingByBuyer, fixedBlocks, requiredBuyers);
  if (!selection) return null;
  if (closure.evidence.length > 0 && !closureOccursAfterThreshold(selection.settlements, closure.evidence)) return null;
  const funding = selection.buyers.map((buyer) => fundingByBuyer.get(buyer));
  const allEvidence = [...closure.evidence, ...funding, ...selection.settlements];
  return {
    strategy,
    closure,
    funding,
    settlements: selection.settlements,
    buyers: selection.buyers,
    volumeRaw: selection.volumeRaw,
    optimizationMode: selection.optimizationMode,
    cost: costTuple(allEvidence),
  };
}

export function selectMinimumSettlementWindows(settlements, fundingByBuyer, fixedBlocks = [], requiredBuyers = []) {
  const baseFixed = new Set(fixedBlocks.map(authenticationGroup));
  const fundingGroups = [...groupBy([...fundingByBuyer], ([, funding]) => authenticationGroup(funding.blockNumber)).entries()]
    .map(([checkpoint, rows]) => ({ checkpoint, buyers: rows.map(([buyer]) => buyer).sort() }))
    .sort((left, right) => left.checkpoint.localeCompare(right.checkpoint));
  const buyerGroup = new Map();
  fundingGroups.forEach((group, index) => group.buyers.forEach((buyer) => buyerGroup.set(buyer, index)));
  const windows = [...groupBy(settlements, (entry) => authenticationGroup(entry.blockNumber)).entries()]
    .map(([checkpoint, entries]) => {
      const groupedEntries = Array.from({ length: fundingGroups.length }, () => []);
      const volumeByGroup = new Array(fundingGroups.length).fill(0);
      for (const entry of entries) {
        const groupIndex = buyerGroup.get(entry.buyer);
        if (groupIndex == null) continue;
        const amount = Number(BigInt(entry.amountRaw));
        if (!Number.isSafeInteger(amount)) throw new Error(`unsafe settlement amount ${entry.amountRaw}`);
        groupedEntries[groupIndex].push(entry);
        volumeByGroup[groupIndex] += amount;
      }
      return { checkpoint, groupedEntries, volumeByGroup };
    })
    .sort((left, right) => left.checkpoint.localeCompare(right.checkpoint));
  const fullMask = (1n << BigInt(fundingGroups.length)) - 1n;
  const masks = candidateFundingMasks(fundingGroups, windows, fullMask);
  let best = null;
  for (const mask of masks) {
    let enabledBuyerCount = 0;
    const fixed = new Set(baseFixed);
    for (let index = 0; index < fundingGroups.length; index += 1) {
      if ((mask & (1n << BigInt(index))) === 0n) continue;
      enabledBuyerCount += fundingGroups[index].buyers.length;
      fixed.add(fundingGroups[index].checkpoint);
    }
    if (enabledBuyerCount < 3) continue;
    const freeEntries = windows.filter((window) => fixed.has(window.checkpoint)).flatMap((window) => entriesForMask(window, mask));
    let selectedEntries = freeEntries;
    let selectedVolume = Number(sumRaw(freeEntries));
    if (!Number.isSafeInteger(selectedVolume)) throw new Error("unsafe selected settlement volume");
    let chosen;
    if (selectedVolume >= Number(MINIMUM_VOLUME_RAW)) {
      try { chosen = minimumReceipts(selectedEntries, 3, MINIMUM_VOLUME_RAW, requiredBuyers); } catch {}
    }
    if (!chosen) {
      const maximumAdditional = best == null ? windows.length : Math.max(0, best.cost[0] - fixed.size);
      if (maximumAdditional === 0) continue;
      const ranked = topWindowsForMask(windows, mask, fixed, maximumAdditional);
      for (const window of ranked) {
        selectedEntries = [...selectedEntries, ...entriesForMask(window, mask)];
        selectedVolume += window.volume;
        if (selectedVolume < Number(MINIMUM_VOLUME_RAW)) continue;
        try {
          chosen = minimumReceipts(selectedEntries, 3, MINIMUM_VOLUME_RAW, requiredBuyers);
          break;
        } catch {}
      }
    }
    if (!chosen) continue;
    const checkpoints = new Set(baseFixed);
    for (const entry of chosen.entries) checkpoints.add(authenticationGroup(entry.blockNumber));
    for (const buyer of chosen.buyers) checkpoints.add(authenticationGroup(fundingByBuyer.get(buyer).blockNumber));
    const funding = chosen.buyers.map((buyer) => fundingByBuyer.get(buyer));
    const cost = [
      checkpoints.size,
      chosen.entries.length + funding.length,
      JSON.stringify([...funding, ...chosen.entries]).length,
      canonicalEvidence([...funding, ...chosen.entries]),
    ];
    const candidate = { ...chosen, cost };
    if (!best || compareCost(candidate, best) < 0) best = candidate;
  }
  return best && {
    settlements: best.entries,
    buyers: best.buyers,
    volumeRaw: best.volumeRaw,
    optimizationMode: fundingGroups.length <= 12 ? "exact" : "bounded-large-cohort",
  };
}

function candidateFundingMasks(fundingGroups, windows, fullMask) {
  if (fundingGroups.length <= 12) {
    const count = Number(fullMask);
    return [fullMask, ...Array.from({ length: count - 1 }, (_, index) => BigInt(index + 1))];
  }
  const masks = new Set([fullMask]);
  const groupVolume = new Array(fundingGroups.length).fill(0);
  for (const window of windows) {
    for (let index = 0; index < groupVolume.length; index += 1) groupVolume[index] += window.volumeByGroup[index];
  }
  const rankedGroups = groupVolume.map((volume, index) => ({ index, volume }))
    .sort((left, right) => right.volume - left.volume || left.index - right.index);
  let prefix = 0n;
  for (const group of rankedGroups.slice(0, Math.min(30, rankedGroups.length))) {
    prefix |= 1n << BigInt(group.index);
    masks.add(prefix);
  }
  const candidates = rankedGroups.slice(0, Math.min(16, rankedGroups.length)).map((entry) => entry.index);
  for (let first = 0; first < candidates.length; first += 1) {
    masks.add(1n << BigInt(candidates[first]));
    for (let second = first + 1; second < candidates.length; second += 1) {
      masks.add((1n << BigInt(candidates[first])) | (1n << BigInt(candidates[second])));
      for (let third = second + 1; third < candidates.length; third += 1) {
        masks.add((1n << BigInt(candidates[first])) | (1n << BigInt(candidates[second])) | (1n << BigInt(candidates[third])));
      }
    }
  }
  return [...masks];
}

function entriesForMask(window, mask) {
  const entries = [];
  for (let index = 0; index < window.groupedEntries.length; index += 1) {
    if ((mask & (1n << BigInt(index))) !== 0n) entries.push(...window.groupedEntries[index]);
  }
  return entries;
}

function volumeForMask(window, mask) {
  let volume = 0;
  for (let index = 0; index < window.volumeByGroup.length; index += 1) {
    if ((mask & (1n << BigInt(index))) !== 0n) volume += window.volumeByGroup[index];
  }
  return volume;
}

function topWindowsForMask(windows, mask, fixed, limit) {
  const heap = [];
  for (const window of windows) {
    if (fixed.has(window.checkpoint)) continue;
    const ranked = { ...window, volume: volumeForMask(window, mask) };
    if (ranked.volume === 0) continue;
    pushTopWindow(heap, ranked, limit);
  }
  return heap.sort(compareWindowRank);
}

function pushTopWindow(heap, window, limit) {
  if (heap.length < limit) {
    heap.push(window);
    siftWindowUp(heap, heap.length - 1);
    return;
  }
  if (compareWindowRank(window, heap[0]) >= 0) return;
  heap[0] = window;
  siftWindowDown(heap, 0);
}

function siftWindowUp(heap, start) {
  let index = start;
  while (index > 0) {
    const parent = Math.floor((index - 1) / 2);
    if (!windowIsWorse(heap[index], heap[parent])) break;
    [heap[index], heap[parent]] = [heap[parent], heap[index]];
    index = parent;
  }
}

function siftWindowDown(heap, start) {
  let index = start;
  while (true) {
    const left = index * 2 + 1;
    const right = left + 1;
    let worst = index;
    if (left < heap.length && windowIsWorse(heap[left], heap[worst])) worst = left;
    if (right < heap.length && windowIsWorse(heap[right], heap[worst])) worst = right;
    if (worst === index) return;
    [heap[index], heap[worst]] = [heap[worst], heap[index]];
    index = worst;
  }
}

function windowIsWorse(left, right) {
  return left.volume < right.volume || (left.volume === right.volume && left.checkpoint > right.checkpoint);
}

function compareWindowRank(left, right) {
  return right.volume - left.volume || left.checkpoint.localeCompare(right.checkpoint);
}

function planReciprocal(claim, dependencies, bundle) {
  const settlements = dependencies.filter((entry) => entry.evidenceType === "RECIPROCAL_SETTLEMENT");
  const selected = minimumReciprocalReceipts(settlements, claim);
  return finalizePlanClaim(claim, selected, {
    selectionReason: `100 receipts; at least 80% volume reciprocity; cost=${costTuple(selected).join("/")}`,
    rejectedAlternatives: [],
    provenSettlementCount: selected.length,
    provenDirections: 2,
    optimizationMode: "exact",
  }, bundle);
}

function selectClosureForFunder(dependencies, funder, approvedBuyers, seller) {
  if (normalize(funder) === normalize(seller)) return { evidence: [], evidenceClass: "SELF_FUNDED", rejected: [] };
  const classes = ["DIRECT_SELLER_FUNDER", "DIRECT_SELLER_BUYER", "RELAY_PATH"];
  const rejected = [];
  for (const evidenceClass of classes) {
    const candidates = dependencies.filter((entry) => entry.evidenceType === evidenceClass
      && (evidenceClass !== "DIRECT_SELLER_BUYER" || approvedBuyers.includes(entry.buyer))
      && (evidenceClass === "DIRECT_SELLER_BUYER" || entry.funder === funder)
      && atomicEvidence(entry).every(nonSelfTransfer)
      && (evidenceClass === "RELAY_PATH" || BigInt(entry.amountRaw) > 0n));
    if (candidates.length === 0) continue;
    if (evidenceClass !== "RELAY_PATH") {
      candidates.sort(compareEvidence);
      const selected = candidates.at(-1);
      return { evidence: [selected], evidenceClass, rejected: [...rejected, ...candidates.slice(0, -1).map(summarizeEvidence)] };
    }
    const valid = candidates.filter(validRelayPath).sort(compareRelayPath);
    if (valid.length >= 3) return { evidence: valid.slice(-3), evidenceClass, rejected: [...rejected, ...valid.slice(0, -3).map(summarizeEvidence)] };
    rejected.push(...candidates.map(summarizeEvidence));
  }
  return null;
}

function closureOccursAfterThreshold(settlements, closureEvidence) {
  const ordered = [...settlements].sort(compareEvidence);
  let volume = 0n;
  let crossing = null;
  for (const settlement of ordered) {
    volume += BigInt(settlement.amountRaw);
    if (crossing == null && volume >= MINIMUM_VOLUME_RAW) crossing = settlement;
  }
  if (crossing == null) return false;
  return closureEvidence.flatMap(atomicEvidence).every((entry) => compareEvidence(entry, crossing) > 0);
}

function validRelayPath(path) {
  const first = path.sellerPayment;
  const second = path.relayForward;
  const third = path.funderReceipt;
  if (![first, second, third].every((entry) => Number.isSafeInteger(entry.blockNumber))) return false;
  if (second.blockNumber < first.blockNumber || third.blockNumber < second.blockNumber) return false;
  if (second.timestamp < first.timestamp || third.timestamp < second.timestamp) return false;
  if (second.timestamp - first.timestamp > 86_400 || third.timestamp - second.timestamp > 86_400) return false;
  const firstAmount = BigInt(first.amountRaw);
  const secondAmount = BigInt(second.amountRaw);
  const thirdAmount = BigInt(third.amountRaw);
  if (firstAmount <= 0n || secondAmount <= 0n || thirdAmount <= 0n || thirdAmount > secondAmount) return false;
  if (absolute(firstAmount - secondAmount) > 1_000n) return false;
  const retained = secondAmount - thirdAmount;
  return retained <= 1_000_000n || thirdAmount * 10_000n >= secondAmount * 9_800n;
}

function nonSelfTransfer(entry) {
  return entry.from == null || entry.to == null || normalize(entry.from) !== normalize(entry.to);
}

function flattenRelay(path) {
  return [path.sellerPayment, path.relayForward, path.funderReceipt];
}

function finalizePlanClaim(claim, evidence, details, bundle) {
  const selected = dedupe(evidence).sort(compareEvidence);
  const selectedBlocks = [...new Set(selected.flatMap(atomicEvidence).map((entry) => entry.blockNumber))].sort(numberAscending);
  return {
    claimId: claim.claimId,
    type: claim.type,
    subjects: claim.subjects,
    reportRoot: bundle.reportRoot,
    dependencyRoot: claim.dependencyRoot,
    selectedEvidence: selected,
    selectedBlocks,
    historicalBlocks: selectedBlocks.filter((block) => !isCheckpointBlock(block)),
    checkpointWindows: windowsForBlocks(selectedBlocks),
    cost: costTuple(selected),
    ...details,
  };
}

function attachMemberships(plan, claim, allClaims) {
  const dependencyHashes = claim.dependencies.map((entry) => entry.dependencyId);
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
        dependencyMembership: merkleMembership(dependencyHashes, entry.dependencyId),
      };
    }),
  };
}

function minimumReceipts(entries, minimumBuyers, minimumVolumeRaw, requiredBuyers = []) {
  const sorted = [...entries].sort((left, right) => BigInt(right.amountRaw) > BigInt(left.amountRaw) ? 1 : BigInt(right.amountRaw) < BigInt(left.amountRaw) ? -1 : compareEvidence(left, right));
  const buyers = [...groupBy(sorted, (entry) => entry.buyer).keys()].sort();
  if (minimumBuyers !== 3 || buyers.length < minimumBuyers || requiredBuyers.some((buyer) => !buyers.includes(buyer))) {
    throw new Error("selected windows cannot satisfy cohort predicate");
  }
  let prefixVolume = 0n;
  for (let count = 1; count <= sorted.length; count += 1) {
    prefixVolume += BigInt(sorted[count - 1].amountRaw);
    if (count < minimumBuyers || prefixVolume < minimumVolumeRaw) continue;
    const prefix = sorted.slice(0, count);
    const prefixBuyers = new Set(prefix.map((entry) => entry.buyer));
    if (prefixBuyers.size >= minimumBuyers && requiredBuyers.every((buyer) => prefixBuyers.has(buyer))) return finalizeReceiptSelection(prefix);
    const candidate = minimumReceiptsForCount(sorted, buyers, count, minimumVolumeRaw, requiredBuyers);
    if (candidate) return finalizeReceiptSelection(candidate);
  }
  throw new Error("selected windows cannot satisfy cohort predicate");
}

function minimumReceiptsForCount(sorted, buyers, count, minimumVolumeRaw, requiredBuyers) {
  const bestByBuyer = new Map();
  for (const entry of sorted) if (!bestByBuyer.has(entry.buyer)) bestByBuyer.set(entry.buyer, entry);
  let best = null;
  for (let first = 0; first < buyers.length - 2; first += 1) {
    for (let second = first + 1; second < buyers.length - 1; second += 1) {
      for (let third = second + 1; third < buyers.length; third += 1) {
        const selected = [bestByBuyer.get(buyers[first]), bestByBuyer.get(buyers[second]), bestByBuyer.get(buyers[third])];
        const used = new Set(selected.map((entry) => entry.dependencyId));
        for (const entry of sorted) {
          if (selected.length === count) break;
          if (!used.has(entry.dependencyId)) { selected.push(entry); used.add(entry.dependencyId); }
        }
        const selectedBuyers = new Set(selected.map((entry) => entry.buyer));
        if (requiredBuyers.some((buyer) => !selectedBuyers.has(buyer))) continue;
        if (sumRaw(selected) < minimumVolumeRaw) continue;
        if (!best || canonicalEvidence(selected).localeCompare(canonicalEvidence(best)) < 0) best = selected;
      }
    }
  }
  return best;
}

function finalizeReceiptSelection(entries) {
  const buyers = [...new Set(entries.map((entry) => entry.buyer))].sort();
  return { entries: [...entries].sort(compareEvidence), buyers, volumeRaw: sumRaw(entries) };
}

function minimumReciprocalReceipts(entries, claim) {
  const byAmount = (left, right) => BigInt(right.amountRaw) > BigInt(left.amountRaw) ? 1 : BigInt(right.amountRaw) < BigInt(left.amountRaw) ? -1 : compareEvidence(left, right);
  const aToB = entries.filter((entry) => entry.buyer === claim.walletA && entry.seller === claim.walletB).sort(byAmount);
  const bToA = entries.filter((entry) => entry.buyer === claim.walletB && entry.seller === claim.walletA).sort(byAmount);
  for (let totalCount = 100; totalCount <= aToB.length + bToA.length; totalCount += 1) {
    let best = null;
    const minimumAToB = Math.max(10, totalCount - bToA.length);
    const maximumAToB = Math.min(aToB.length, totalCount - 10);
    for (let countAToB = minimumAToB; countAToB <= maximumAToB; countAToB += 1) {
      const countBToA = totalCount - countAToB;
      const selectedAToB = aToB.slice(0, countAToB);
      const selectedBToA = bToA.slice(0, countBToA);
      const volumeAToB = sumRaw(selectedAToB);
      const volumeBToA = sumRaw(selectedBToA);
      if (!reciprocalVolumesQualify(volumeAToB, volumeBToA)) continue;
      const selected = [...selectedAToB, ...selectedBToA].sort(compareEvidence);
      const candidate = { selected, cost: costTuple(selected) };
      if (!best || compareCost(candidate, best) < 0) best = candidate;
    }
    if (best) return best.selected;
  }
  throw new Error("reciprocal selection cannot satisfy count, directional volume, and 80% reciprocity");
}

function reciprocalVolumesQualify(volumeAToB, volumeBToA) {
  if (volumeAToB < MINIMUM_RECIPROCAL_DIRECTION_VOLUME_RAW || volumeBToA < MINIMUM_RECIPROCAL_DIRECTION_VOLUME_RAW) return false;
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
  if (["SETTLEMENT", "RECIPROCAL_SETTLEMENT"].includes(dependency.evidenceType)) {
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
  if (dependency.funder && dependency.buyer && !((from === dependency.funder && to === dependency.buyer) || to === normalize(contracts.deposits))) return false;
  return dependency.amountRaw == null || dataWord(log.data, 0) === BigInt(dependency.amountRaw);
}

function pruneStates(states) {
  const values = [...states.values()].sort(compareState);
  const kept = [];
  for (const candidate of values) {
    if (kept.some((entry) => isSuperset(entry.buyers, candidate.buyers) && entry.volumeRaw >= candidate.volumeRaw && entry.checkpoints.size <= candidate.checkpoints.size)) continue;
    kept.push(candidate);
  }
  return new Map(kept.map((entry, index) => [String(index), entry]));
}

function compareState(left, right) {
  return left.checkpoints.size - right.checkpoints.size || left.entries.length - right.entries.length || canonicalEvidence(left.entries).localeCompare(canonicalEvidence(right.entries));
}

function compareReciprocalState(left, right) {
  return left.windows.length - right.windows.length || right.count - left.count || canonicalEvidence(left.windows.flatMap((entry) => entry.entries)).localeCompare(canonicalEvidence(right.windows.flatMap((entry) => entry.entries)));
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

function windowsForBlocks(blocks) {
  return [...groupBy(blocks.filter(isCheckpointBlock), checkpointBlockNumber).entries()].map(([checkpointBlockNumberValue, targetBlocks]) => ({
    checkpointBlockNumber: checkpointBlockNumberValue,
    targetBlocks: [...targetBlocks].sort(numberAscending),
  })).sort((left, right) => left.checkpointBlockNumber - right.checkpointBlockNumber);
}

function mergeCheckpointWindows(windows) {
  const blocks = new Map();
  for (const window of windows) {
    const values = blocks.get(window.checkpointBlockNumber) ?? new Set();
    for (const block of window.targetBlocks) values.add(block);
    blocks.set(window.checkpointBlockNumber, values);
  }
  return [...blocks.entries()].map(([checkpointBlockNumberValue, targetBlocks]) => ({ checkpointBlockNumber: checkpointBlockNumberValue, targetBlocks: [...targetBlocks].sort(numberAscending) })).sort((left, right) => left.checkpointBlockNumber - right.checkpointBlockNumber);
}

function validateBundle(bundle) {
  if (bundle?.version !== 1 || bundle?.chainId !== 8_453 || !Array.isArray(bundle.claims)) throw new Error("unsupported proof bundle");
}

async function rpc(url, method, params, fetchJson) {
  let lastError;
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const response = await fetchJson(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    if (!response.error) return response.result;
    lastError = new Error(`${method}: ${JSON.stringify(response.error)}`);
    if (![-32_000, -32_005, -32_600, -32_603].includes(response.error.code)) throw lastError;
    await new Promise((resolve) => setTimeout(resolve, 250 * (2 ** attempt)));
  }
  throw lastError;
}

async function rpcBatch(url, requests, fetchJson) {
  const body = requests.map(({ id, method, params }) => ({ jsonrpc: "2.0", id, method, params }));
  const response = await fetchJson(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!Array.isArray(response)) throw new Error("RPC batch returned a non-array response");
  return new Map(response.map((entry) => [entry.id, entry]));
}

async function defaultFetchJson(url, options) {
  let lastError;
  for (let attempt = 0; attempt < 6; attempt += 1) {
    try {
      const response = await fetch(url, { ...options, signal: AbortSignal.timeout(20_000) });
      if (response.ok) return response.json();
      lastError = new Error(`RPC HTTP ${response.status}`);
      if (![429, 500, 502, 503, 504].includes(response.status)) throw lastError;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250 * (2 ** attempt)));
  }
  throw lastError;
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

function directionMask(entries, claim) {
  let mask = 0;
  if (entries.some((entry) => entry.buyer === claim.walletA && entry.seller === claim.walletB)) mask |= 1;
  if (entries.some((entry) => entry.buyer === claim.walletB && entry.seller === claim.walletA)) mask |= 2;
  return mask;
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
function absolute(value) { return value < 0n ? -value : value; }
function normalize(value) { return typeof value === "string" ? value.toLowerCase() : null; }
function topicAddress(topic) { return topic ? `0x${topic.slice(-40)}`.toLowerCase() : null; }
function dataWord(data, index) { return BigInt(`0x${data.slice(2 + index * 64, 2 + (index + 1) * 64)}`); }
function hexNumber(value) { const number = Number(BigInt(value)); if (!Number.isSafeInteger(number)) throw new Error(`unsafe numeric RPC value ${value}`); return number; }
function numberAscending(left, right) { return left - right; }
function isSuperset(left, right) { return [...right].every((value) => left.has(value)); }
function groupBy(values, key) { const result = new Map(); for (const value of values) { const group = key(value); const rows = result.get(group) ?? []; rows.push(value); result.set(group, rows); } return result; }
function dedupe(values) { const result = new Map(); for (const value of values) result.set(value.dependencyId ?? JSON.stringify(value), value); return [...result.values()]; }
function atomicEvidence(value) { return value.evidenceType === "RELAY_PATH" ? [value.sellerPayment, value.relayForward, value.funderReceipt] : [value]; }
function canonicalJson(value) { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`; }
function sha256Hex(value) { return `0x${(awaitableSha256(value))}`; }
function awaitableSha256(value) { return createHash("sha256").update(value).digest("hex"); }
function hexBytes(value) { return Buffer.from(value.slice(2), "hex"); }

export async function planFile({ bundlePath, outPath, rpcUrl, concurrency, claimIds, onProgress }) {
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  const plan = await planProofBundle(bundle, { rpcUrl, concurrency, claimIds, onProgress });
  await writeFile(outPath, `${JSON.stringify(plan, null, 2)}\n`);
  return plan;
}
