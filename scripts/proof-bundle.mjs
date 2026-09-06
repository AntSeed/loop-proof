import { createHash } from "node:crypto";

export function finalizeClaim(claim) {
  const dependencies = dedupeDependencies(claim.dependencies).map((dependency) => ({
    ...dependency,
    dependencyId: hashCanonical("dependency", dependency),
  })).sort((left, right) => left.dependencyId.localeCompare(right.dependencyId));
  const dependencyRoot = merkleRoot(dependencies.map((entry) => entry.dependencyId));
  const { dependencies: _dependencies, ...claimBody } = { ...claim, dependencyRoot };
  const claimId = hashCanonical("claim-id", claimBody);
  const leaf = { ...claimBody, claimId };
  return { ...leaf, leafHash: hashCanonical("claim-leaf", leaf), dependencies };
}

export function finalizeBundle(bundle) {
  const claims = bundle.claims.map((claim) => claim.leafHash ? claim : finalizeClaim(claim))
    .sort((left, right) => left.claimId.localeCompare(right.claimId));
  return {
    ...bundle,
    claimCounts: {
      P0_CLOSED_LOOP: claims.filter((claim) => claim.type === "P0_CLOSED_LOOP").length,
      P0_RECIPROCAL: claims.filter((claim) => claim.type === "P0_RECIPROCAL").length,
      total: claims.length,
    },
    reportRoot: merkleRoot(claims.map((claim) => claim.leafHash)),
    claims,
  };
}

export function relayDependency(path, seller, funder) {
  const dependency = {
    evidenceType: "RELAY_PATH",
    seller,
    funder,
    relay: normalizeAddress(path.relay),
    intermediary: normalizeAddress(path.intermediary),
    sellerPayment: locator("RELAY_SELLER_PAYMENT", {
      txHash: path.sellerPaymentTx,
      logIndex: path.sellerPaymentLogIndex,
      timestamp: path.sellerPaymentAt,
    }, { from: seller, to: normalizeAddress(path.relay), amountRaw: String(path.sellerPaymentRaw) }),
    relayForward: locator("RELAY_FORWARD", {
      txHash: path.relayForwardTx,
      logIndex: path.relayForwardLogIndex,
      timestamp: path.relayForwardAt,
    }, { from: normalizeAddress(path.relay), to: normalizeAddress(path.intermediary), amountRaw: String(path.relayForwardRaw) }),
  };
  if (path.funderReceiptTx != null) dependency.funderReceipt = locator("RELAY_FUNDER_RECEIPT", {
      txHash: path.funderReceiptTx,
      logIndex: path.funderReceiptLogIndex,
      timestamp: path.funderReceiptAt,
    }, { from: normalizeAddress(path.intermediary), to: funder, amountRaw: String(path.funderReceiptRaw) });
  return dependency;
}

export function returnPathDependency(path, seller, funder) {
  return {
    evidenceType: "RELAY_PATH",
    seller,
    funder,
    hops: path.hops.map((hop, index) => locator(
      index === 0 ? "RELAY_SELLER_PAYMENT" : index === path.hops.length - 1 ? "RELAY_FUNDER_RECEIPT" : "RELAY_FORWARD",
      { transactionHash: hop.tx, blockNumber: hop.blockNumber, transactionIndex: hop.transactionIndex, logIndex: hop.logIndex, timestamp: hop.timestamp },
      { from: hop.from, to: hop.to, amountRaw: hop.amountRaw },
    )),
  };
}

export function locator(evidenceType, source, extra = {}) {
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

export function dedupeDependencies(values) {
  return [...new Map(values.map((entry) => [canonicalJson(entry), entry])).values()]
    .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
}

export function canonicalJson(input) {
  if (input === null || typeof input !== "object") return JSON.stringify(input);
  if (Array.isArray(input)) return `[${input.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(input).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(input[key])}`).join(",")}}`;
}

export function merkleRoot(hashes) {
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

export function hashCanonical(domain, input) {
  return sha256(Buffer.concat([Buffer.from(`${domain}\0`), Buffer.from(canonicalJson(input))]));
}

function sha256(input) {
  return `0x${createHash("sha256").update(input).digest("hex")}`;
}

function normalizeAddress(input) {
  return typeof input === "string" && /^0x[0-9a-f]{40}$/i.test(input) ? input.toLowerCase() : null;
}

function numericOrNull(input) {
  if (input == null) return null;
  const number = Number(input);
  return Number.isSafeInteger(number) ? number : null;
}
