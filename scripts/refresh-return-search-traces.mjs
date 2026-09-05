import { readFile, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export async function refreshReturnSearchTraces({ summaryPath, manifestPath, outputDirectory, endpoint, maxPages = 30, queryStartBlock = null, extraRelayAddresses = [] }) {
  if (!endpoint) throw new Error("BASE_RPC_URL required");
  if (!Number.isSafeInteger(maxPages) || maxPages < 1) throw new Error("invalid page limit");
  const summary = JSON.parse(await readFile(summaryPath, "utf8"));
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  await mkdir(outputDirectory, { recursive: false });
  const results = [];
  const saved = new Map();
  for (const entry of summary.results.filter((result) => result.status === "candidate-shortfall")) {
    const input = JSON.parse(await readFile(entry.sellerInput, "utf8"));
    const startBlock = queryStartBlock ?? input.period_start_block;
    if (!Number.isSafeInteger(startBlock) || startBlock < input.period_start_block || startBlock > input.period_end_block) throw new Error("query start outside original period");
    if (extraRelayAddresses.some((address) => !/^0x[0-9a-f]{40}$/.test(address))) throw new Error("invalid relay address");
    const addresses = [...new Set([entry.seller, entry.funder, ...entry.missingTraces, ...extraRelayAddresses])];
    for (const address of addresses) {
      const direction = address === entry.funder ? "inboundUsdc" : "outboundUsdc";
      const cacheKey = `${address}:${direction}:${startBlock}:${input.period_end_block}`;
      if (saved.has(cacheKey)) continue;
      const transfers = [];
      let pageKey;
      let complete = false;
      let errorMessage;
      try {
        for (let page = 0; page < maxPages; page += 1) {
          const params = { fromBlock: `0x${startBlock.toString(16)}`, toBlock: `0x${input.period_end_block.toString(16)}`,
            [direction === "inboundUsdc" ? "toAddress" : "fromAddress"]: address,
            contractAddresses: ["0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"], category: ["erc20"], withMetadata: true,
            excludeZeroValue: true, maxCount: "0x3e8", order: "asc", ...(pageKey ? { pageKey } : {}) };
          const response = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", id: page, method: "alchemy_getAssetTransfers", params: [params] }), signal: AbortSignal.timeout(60_000) });
          if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
          const payload = await response.json();
          if (payload.error || !Array.isArray(payload.result?.transfers)) throw new Error(`RPC error ${payload.error?.code ?? "invalid transfers"}`);
          transfers.push(...payload.result.transfers.map((transfer) => ({ from: transfer.from.toLowerCase(), to: transfer.to.toLowerCase(),
            amountRaw: BigInt(transfer.rawContract.value).toString(), timestamp: Date.parse(transfer.metadata.blockTimestamp) / 1000,
            txHash: transfer.hash.toLowerCase(), logIndex: Number(transfer.uniqueId.split(":log:")[1]), blockNumber: Number(BigInt(transfer.blockNum)) })));
          pageKey = payload.result.pageKey;
          if (!pageKey) { complete = true; break; }
        }
      } catch (error) { errorMessage = error.message; }
      const path = join(outputDirectory, `${address}-${direction}.json`);
      await writeFile(path, JSON.stringify({ address, complete, completeDirection: direction, inboundUsdc: [], outboundUsdc: [], [direction]: transfers,
        query: { startBlock, endBlock: input.period_end_block }, pageLimit: maxPages, truncated: Boolean(pageKey), error: errorMessage }), { flag: "wx" });
      saved.set(cacheKey, path);
      results.push({ address, direction, complete, records: transfers.length, path, error: errorMessage });
      console.log(JSON.stringify(results.at(-1)));
    }
    const config = manifest.sellers.find((seller) => seller.seller === entry.seller);
    if (!config) throw new Error("manifest missing seller");
    config.traceOverrides = { ...config.traceOverrides };
    for (const address of addresses) {
      const direction = address === entry.funder ? "inboundUsdc" : "outboundUsdc";
      config.traceOverrides[address] = saved.get(`${address}:${direction}:${startBlock}:${input.period_end_block}`);
    }
  }
  await writeFile(join(outputDirectory, "manifest.json"), JSON.stringify(manifest, null, 2), { flag: "wx" });
  await writeFile(join(outputDirectory, "summary.json"), JSON.stringify({ scope: "below-target sellers only", results }, null, 2), { flag: "wx" });
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const value = (flag) => args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined;
  if (!value("--summary") || !value("--manifest") || !value("--out-dir")) throw new Error("require --summary, --manifest, --out-dir; optional --max-pages (default 30)");
  const extraRelayAddresses = args.flatMap((argument, index) => argument === "--relay" ? [args[index + 1]] : []);
  await refreshReturnSearchTraces({ summaryPath: resolve(value("--summary")), manifestPath: resolve(value("--manifest")), outputDirectory: resolve(value("--out-dir")), maxPages: Number(value("--max-pages") ?? 30), endpoint: process.env.BASE_RPC_URL,
    queryStartBlock: value("--from-block") == null ? null : Number(value("--from-block")), extraRelayAddresses });
}
