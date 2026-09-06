import { RHO_HOP_BPS, T_PATH_SECONDS } from "./predicate-policy.mjs";

export async function discoverExpandedReturnGraph({ seller, funder, loadTrace, earliest, end, maxPaths = 100_000, maxSteps = 2_000_000 }) {
  if (![maxPaths, maxSteps].every((limit) => Number.isSafeInteger(limit) && limit > 0)) throw new Error("invalid return graph limits");
  const graph = new Map();
  const edges = new Map();
  const loaded = new Set();
  const missing = new Set();
  const add = (hop) => {
    const transfer = { ...hop, from: hop.from.toLowerCase(), to: hop.to.toLowerCase(), txHash: (hop.txHash ?? hop.transactionHash).toLowerCase(), logIndex: Number(hop.logIndex), timestamp: Number(hop.timestamp) };
    if (transfer.timestamp <= earliest || transfer.timestamp > end || transfer.from === transfer.to || BigInt(transfer.amountRaw) <= 0n) return;
    const identity = `${transfer.txHash}:${transfer.logIndex}`;
    if (edges.has(identity)) return;
    edges.set(identity, transfer);
    if (!graph.has(transfer.from)) graph.set(transfer.from, []);
    graph.get(transfer.from).push(transfer);
  };
  const load = async (address) => {
    if (loaded.has(address)) return;
    loaded.add(address);
    const trace = await loadTrace(address);
    if (!trace?.complete) missing.add(address);
    for (const hop of trace?.outboundUsdc ?? []) add(hop);
  };
  const terminalTrace = await loadTrace(funder);
  if (!terminalTrace?.complete) missing.add(funder);
  for (const hop of terminalTrace?.inboundUsdc ?? []) add(hop);
  await load(seller);
  let frontier = new Set((graph.get(seller) ?? []).map((hop) => hop.to));
  for (let depth = 0; depth < 2; depth += 1) {
    const next = new Set();
    for (const address of [...frontier].sort()) {
      if (address === funder || address === seller) continue;
      await load(address);
      for (const hop of graph.get(address) ?? []) next.add(hop.to);
    }
    frontier = next;
  }
  const reverse = new Map();
  for (const edge of edges.values()) {
    if (!reverse.has(edge.to)) reverse.set(edge.to, new Set());
    reverse.get(edge.to).add(edge.from);
  }
  const distance = new Map([[funder, 0]]);
  let reachable = [funder];
  for (let depth = 1; depth <= 9; depth += 1) {
    const next = [];
    for (const address of reachable) for (const previous of reverse.get(address) ?? []) {
      if (!distance.has(previous)) { distance.set(previous, depth); next.push(previous); }
    }
    reachable = next;
  }
  const order = (left, right) => left.timestamp - right.timestamp || left.logIndex - right.logIndex;
  for (const hops of graph.values()) hops.sort(order);
  const destinations = new Map([...graph].map(([address, hops]) => [address, [...new Set(hops.map((hop) => hop.to))]]));
  const canFinish = (address, visited, remaining) => {
    if (address === funder) return true;
    if (remaining === 0 || !distance.has(address)) return false;
    return (destinations.get(address) ?? []).some((next) => !visited.has(next)
      && canFinish(next, new Set([...visited, next]), remaining - 1));
  };
  const paths = [];
  let steps = 0;
  let truncated = false;
  const walk = (address, selected, credit, visited) => {
    if (paths.length >= maxPaths || steps >= maxSteps) { truncated = true; return; }
    if (address === funder) { paths.push({ evidenceType: "RELAY_PATH", hops: selected, creditRaw: credit.toString() }); return; }
    if (selected.length + (distance.get(address) ?? 10) > 9) return;
    const previous = selected.at(-1);
    const outgoing = graph.get(address) ?? [];
    let lower = 0;
    let upper = outgoing.length;
    while (lower < upper) {
      const middle = Math.floor((lower + upper) / 2);
      if (order(previous, outgoing[middle]) >= 0) lower = middle + 1;
      else upper = middle;
    }
    for (let index = lower; index < outgoing.length; index += 1) {
      const hop = outgoing[index];
      steps += 1;
      if (steps >= maxSteps) { truncated = true; break; }
      if (hop.timestamp - selected[0].timestamp > T_PATH_SECONDS) break;
      if (order(previous, hop) >= 0 || visited.has(hop.to)) continue;
      if (BigInt(hop.amountRaw) * 10_000n < BigInt(previous.amountRaw) * RHO_HOP_BPS) continue;
      if (!canFinish(hop.to, new Set([...visited, hop.to]), 8 - selected.length)) continue;
      walk(hop.to, [...selected, hop], BigInt(hop.amountRaw) < credit ? BigInt(hop.amountRaw) : credit, new Set([...visited, hop.to]));
      if (paths.length >= maxPaths || steps >= maxSteps) break;
    }
  };
  const starts = [...(graph.get(seller) ?? [])].sort((left, right) => BigInt(left.amountRaw) === BigInt(right.amountRaw)
    ? order(left, right) : BigInt(left.amountRaw) > BigInt(right.amountRaw) ? -1 : 1);
  for (const hop of starts) {
    walk(hop.to, [hop], BigInt(hop.amountRaw), new Set([seller, hop.to]));
    if (paths.length >= maxPaths || steps >= maxSteps) { truncated = true; break; }
  }
  return { paths, edgeCount: edges.size, loadedTraceCount: loaded.size, missingTraces: [...missing].sort(), truncated, steps, maxPaths, maxSteps, exhaustive: false };
}
