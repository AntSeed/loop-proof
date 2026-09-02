const BASIS_POINTS = 10_000n;
const MIN_RELAY_RETAINED_BPS = 2_800n;
const MAX_RELAY_SECONDS = 259_200;
const MAX_RETURN_PATHS = 512;

export function atomicReturnEvidence(evidence) {
  if (evidence.evidenceType !== "RELAY_PATH") return [evidence];
  return evidence.hops ?? [evidence.sellerPayment, evidence.relayForward, evidence.funderReceipt];
}

export function returnPathCreditRaw(evidence) {
  return atomicReturnEvidence(evidence)
    .map((entry) => BigInt(entry.amountRaw))
    .reduce((minimum, amount) => amount < minimum ? amount : minimum);
}

export function requiredReturnRaw(settlementVolumeRaw) {
  const numerator = BigInt(settlementVolumeRaw) * 2_000n;
  return (numerator + BASIS_POINTS - 1n) / BASIS_POINTS;
}

export function selectReturnEvidence(candidates, {
  requiredRaw,
  earliestSettlementTimestamp,
  maxPaths = MAX_RETURN_PATHS,
  reservedKeys = [],
} = {}) {
  const required = BigInt(requiredRaw ?? 0);
  const used = new Set(reservedKeys);
  const valid = candidates
    .filter((candidate) => validReturnEvidence(candidate, earliestSettlementTimestamp))
    .sort(compareReturnEvidence);
  const selected = [];
  let returnedRaw = 0n;
  for (const candidate of valid) {
    if (selected.length >= maxPaths || returnedRaw >= required) break;
    const keys = atomicReturnEvidence(candidate).map(transferKey);
    if (keys.some((key) => used.has(key))) continue;
    keys.forEach((key) => used.add(key));
    selected.push(candidate);
    returnedRaw += returnPathCreditRaw(candidate);
  }
  return {
    evidence: selected,
    returnedRaw,
    requiredRaw: required,
    complete: returnedRaw >= required,
    usedKeys: used,
  };
}

export async function discoverCachedRelayReturns({
  seller,
  funder,
  sellerTrace,
  funderTrace,
  loadTrace,
  earliestSettlementTimestamp,
  requiredRaw,
  maxPaths = MAX_RETURN_PATHS,
  reservedKeys = [],
  traceConcurrency = 32,
}) {
  const normalizedSeller = normalizeAddress(seller);
  const normalizedFunder = normalizeAddress(funder);
  const firstHops = (sellerTrace?.outboundUsdc ?? [])
    .map(normalizeTransfer)
    .filter((entry) => entry.from === normalizedSeller
      && entry.to !== normalizedSeller
      && entry.to !== normalizedFunder
      && entry.amountRaw > 0n
      && entry.timestamp > earliestSettlementTimestamp);
  const byRelay = groupBy(firstHops, (entry) => entry.to);
  const relayAddresses = [...byRelay.keys()].sort();
  const relayTraces = await mapConcurrent(relayAddresses, traceConcurrency, async (relay) => [relay, await loadTrace(relay)]);
  const funderInboundBySender = groupBy(
    (funderTrace?.inboundUsdc ?? [])
      .map(normalizeTransfer)
      .filter((entry) => entry.to === normalizedFunder && entry.amountRaw > 0n),
    (entry) => entry.from,
  );
  for (const entries of funderInboundBySender.values()) entries.sort(compareTransfer);

  const prefixes = [];
  for (const [relay, trace] of relayTraces) {
    if (!trace?.complete) continue;
    const outbound = (trace.outboundUsdc ?? [])
      .map(normalizeTransfer)
      .filter((entry) => entry.from === relay && entry.amountRaw > 0n)
      .sort(compareTransfer);
    for (const first of byRelay.get(relay) ?? []) {
      for (const second of outbound) {
        if (second.timestamp <= first.timestamp) continue;
        if (!retains(second.amountRaw, first.amountRaw)) continue;
        if (second.timestamp - first.timestamp > MAX_RELAY_SECONDS) break;
        prefixes.push({
          first,
          second,
          relay,
          prefixCreditRaw: minRaw(first.amountRaw, second.amountRaw),
        });
      }
    }
  }
  prefixes.sort((left, right) => compareBigIntDescending(left.prefixCreditRaw, right.prefixCreditRaw)
    || compareTransfer(left.first, right.first)
    || compareTransfer(left.second, right.second));

  const used = new Set(reservedKeys);
  const paths = [];
  let returnedRaw = 0n;
  const required = BigInt(requiredRaw ?? 0);
  for (const prefix of prefixes) {
    if (paths.length >= maxPaths || returnedRaw >= required) break;
    const firstKey = transferKey(prefix.first);
    const secondKey = transferKey(prefix.second);
    if (used.has(firstKey) || used.has(secondKey)) continue;

    let hops;
    let creditRaw;
    if (prefix.second.to === normalizedFunder) {
      hops = [prefix.first, prefix.second];
      creditRaw = prefix.prefixCreditRaw;
    } else {
      const finish = bestAvailableFinish(
        funderInboundBySender.get(prefix.second.to) ?? [],
        prefix,
        used,
      );
      if (!finish) continue;
      hops = [prefix.first, prefix.second, finish];
      creditRaw = minRaw(prefix.prefixCreditRaw, finish.amountRaw);
    }
    const keys = hops.map(transferKey);
    if (keys.some((key) => used.has(key))) continue;
    keys.forEach((key) => used.add(key));
    paths.push({
      evidenceType: "RELAY_PATH",
      seller: normalizedSeller,
      funder: normalizedFunder,
      relay: prefix.relay,
      intermediary: hops.length === 3 ? prefix.second.to : null,
      hops: hops.map(serializeTransfer),
    });
    returnedRaw += creditRaw;
  }
  return {
    paths,
    returnedRaw,
    requiredRaw: required,
    complete: returnedRaw >= required,
    usedKeys: used,
  };
}

function validReturnEvidence(evidence, earliestSettlementTimestamp) {
  const atoms = atomicReturnEvidence(evidence);
  if (atoms.length === 0 || atoms.length > 9) return false;
  if (new Set(atoms.map(transferKey)).size !== atoms.length) return false;
  if (earliestSettlementTimestamp != null && atoms[0].timestamp != null
      && Number(atoms[0].timestamp) <= earliestSettlementTimestamp) return false;
  for (let index = 0; index < atoms.length; index += 1) {
    const current = atoms[index];
    if (BigInt(current.amountRaw) <= 0n) return false;
    if (current.from != null && current.to != null && normalizeAddress(current.from) === normalizeAddress(current.to)) return false;
    if (index === 0) continue;
    const previous = atoms[index - 1];
    if (normalizeAddress(previous.to) !== normalizeAddress(current.from)) return false;
    if (compareTransfer(previous, current) >= 0) return false;
    if (!retains(BigInt(current.amountRaw), BigInt(previous.amountRaw))) return false;
  }
  if (atoms.length === 1) return true;
  return Number(atoms.at(-1).timestamp) - Number(atoms[0].timestamp) <= MAX_RELAY_SECONDS;
}

function bestAvailableFinish(entries, prefix, used) {
  let best = null;
  let bestCredit = 0n;
  for (const entry of entries) {
    if (entry.timestamp <= prefix.second.timestamp) continue;
    if (entry.timestamp - prefix.first.timestamp > MAX_RELAY_SECONDS) break;
    if (used.has(transferKey(entry)) || !retains(entry.amountRaw, prefix.second.amountRaw)) continue;
    const credit = minRaw(prefix.prefixCreditRaw, entry.amountRaw);
    if (credit > bestCredit || (credit === bestCredit && best && compareTransfer(entry, best) < 0)) {
      best = entry;
      bestCredit = credit;
    }
  }
  return best;
}

function normalizeTransfer(entry) {
  return {
    ...entry,
    from: normalizeAddress(entry.from),
    to: normalizeAddress(entry.to),
    amountRaw: BigInt(entry.amountRaw),
    timestamp: Number(entry.timestamp),
    txHash: entry.txHash ?? entry.transactionHash,
    logIndex: Number(entry.logIndex),
  };
}

function serializeTransfer(entry) {
  return {
    from: entry.from,
    to: entry.to,
    amountRaw: entry.amountRaw.toString(),
    timestamp: entry.timestamp,
    txHash: entry.txHash,
    logIndex: entry.logIndex,
  };
}

function compareReturnEvidence(left, right) {
  return compareBigIntDescending(returnPathCreditRaw(left), returnPathCreditRaw(right))
    || returnEvidenceIdentity(left).localeCompare(returnEvidenceIdentity(right));
}

function returnEvidenceIdentity(evidence) {
  return atomicReturnEvidence(evidence).map(transferKey).join(">");
}

function compareTransfer(left, right) {
  const leftBlock = left.blockNumber == null ? null : Number(left.blockNumber);
  const rightBlock = right.blockNumber == null ? null : Number(right.blockNumber);
  if (Number.isSafeInteger(leftBlock) && Number.isSafeInteger(rightBlock) && leftBlock !== rightBlock) return leftBlock - rightBlock;
  const leftTimestamp = Number(left.timestamp);
  const rightTimestamp = Number(right.timestamp);
  if (leftTimestamp !== rightTimestamp) return leftTimestamp - rightTimestamp;
  const leftTransactionIndex = left.transactionIndex == null ? null : Number(left.transactionIndex);
  const rightTransactionIndex = right.transactionIndex == null ? null : Number(right.transactionIndex);
  if (Number.isSafeInteger(leftTransactionIndex) && Number.isSafeInteger(rightTransactionIndex)
      && leftTransactionIndex !== rightTransactionIndex) return leftTransactionIndex - rightTransactionIndex;
  const transactionOrder = String(left.txHash ?? left.transactionHash).localeCompare(String(right.txHash ?? right.transactionHash));
  if (transactionOrder !== 0) return transactionOrder;
  return Number(left.logIndex) - Number(right.logIndex);
}

function transferKey(entry) {
  const transaction = entry.txHash ?? entry.transactionHash ?? entry.dependencyId;
  return `${String(transaction).toLowerCase()}:${Number(entry.logIndex ?? 0)}`;
}

function retains(next, previous) {
  return next * BASIS_POINTS >= previous * MIN_RELAY_RETAINED_BPS;
}

function minRaw(left, right) {
  return left < right ? left : right;
}

function compareBigIntDescending(left, right) {
  return left === right ? 0 : left > right ? -1 : 1;
}

function normalizeAddress(value) {
  return String(value).toLowerCase();
}

function groupBy(values, key) {
  const groups = new Map();
  for (const value of values) {
    const id = key(value);
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(value);
  }
  return groups;
}

async function mapConcurrent(values, concurrency, worker) {
  const results = new Array(values.length);
  let nextIndex = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (nextIndex < values.length) {
      const index = nextIndex++;
      results[index] = await worker(values[index], index);
    }
  }));
  return results;
}
