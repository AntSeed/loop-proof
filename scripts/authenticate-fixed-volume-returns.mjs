import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createWriteStream } from "node:fs";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function hydrateHop(hop, receipt) {
  const txHash = (hop.txHash ?? hop.transactionHash).toLowerCase();
  if (receipt.transactionHash.toLowerCase() !== txHash || BigInt(receipt.status) !== 1n) throw new Error("wrong or reverted receipt");
  const receiptLogIndex = receipt.logs.findIndex((log) => Number(BigInt(log.logIndex)) === Number(hop.logIndex));
  const log = receipt.logs[receiptLogIndex];
  if (!log || log.removed || log.address.toLowerCase() !== USDC || log.topics.length !== 3 || log.topics[0].toLowerCase() !== TRANSFER
    || `0x${log.topics[1].slice(-40)}`.toLowerCase() !== hop.from.toLowerCase()
    || `0x${log.topics[2].slice(-40)}`.toLowerCase() !== hop.to.toLowerCase()
    || BigInt(log.data) !== BigInt(hop.amountRaw)) throw new Error("return transfer metadata mismatch");
  return { ...hop, txHash, blockNumber: Number(BigInt(receipt.blockNumber)), transactionIndex: Number(BigInt(receipt.transactionIndex)), receiptLogIndex };
}

async function rpc(endpoint, method, params) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const response = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(60_000) });
      if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
      const payload = await response.json();
      if (payload.error || !payload.result) throw new Error(`RPC failed: ${payload.error?.code ?? "missing result"}`);
      return payload.result;
    } catch (error) {
      if (attempt === 3) throw error;
      await new Promise((done) => setTimeout(done, 1000 * (attempt + 1)));
    }
  }
}

export async function authenticateFixedVolumeReturns({ summaryPath, outputDirectory, binary, endpoint, sellers = [] }) {
  if (!endpoint) throw new Error("BASE_RPC_URL required");
  const summary = await readJson(summaryPath);
  await mkdir(outputDirectory, { recursive: false });
  const results = [];
  for (const entry of summary.results.filter((result) => result.status === "candidate-target-met-needs-authentication" && (!sellers.length || sellers.includes(result.seller)))) {
    const result = { seller: entry.seller, targetReturnBps: summary.targetReturnBps, guestExecutionCompleted: false };
    try {
      if (hash(await readFile(entry.sellerInput)) !== entry.sellerInputSha256) throw new Error("baseline input hash mismatch");
      const candidate = await readJson(join(resolve(summaryPath, ".."), `${entry.seller}.json`));
      candidate.paths = candidate.paths.map((path) => ({ ...path, hops: path.hops.map((hop) => ({ ...hop, txHash: (hop.txHash ?? hop.transactionHash).toLowerCase() })) }));
      if (candidate.fixedVolumeRaw !== entry.provenWashVolumeRaw || candidate.targetReturnBps !== summary.targetReturnBps) throw new Error("candidate target or V mismatch");
      const receipts = new Map();
      const transactions = [...new Set(candidate.paths.flatMap((path) => path.hops.map((hop) => hop.txHash)))];
      for (let offset = 0; offset < transactions.length; offset += 8) {
        await Promise.all(transactions.slice(offset, offset + 8).map(async (transaction) => {
          receipts.set(transaction, await rpc(endpoint, "eth_getTransactionReceipt", [transaction]));
        }));
      }
      const paths = candidate.paths.map((path) => ({ ...path, hops: path.hops.map((hop) => hydrateHop(hop, receipts.get(hop.txHash))) }));
      const selectionPath = join(outputDirectory, `${entry.seller}.selection.json`);
      const directory = join(outputDirectory, entry.seller);
      await writeFile(selectionPath, JSON.stringify({ ...candidate, paths }), { flag: "wx" });
      console.log(`${entry.seller}: authenticate ${paths.length} paths against unchanged settlements`);
      await new Promise((done, reject) => {
        const log = createWriteStream(join(outputDirectory, `${entry.seller}.log`), { flags: "wx" });
        const child = spawn(binary, [entry.sellerInput, selectionPath, directory], { env: { ...process.env, BASE_RPC_URL: endpoint } });
        child.stdout.pipe(log, { end: false });
        child.stderr.pipe(log, { end: false });
        child.on("error", (error) => { log.end(); reject(error); });
        child.on("close", (code) => { log.end(); code === 0 ? done() : reject(new Error(`native verification exited ${code}`)); });
      });
      const verified = await readJson(join(directory, "native-verification.json"));
      if (!verified.nativeVerified || !verified.independentlyPassesTargetReturnFloor || !verified.settlementsFundingBuyersLedgersUnchanged
        || verified.provenWashVolumeRaw !== entry.provenWashVolumeRaw || verified.totalSellerVolumeRaw !== entry.totalSellerVolumeRaw
        || verified.targetReturnBps !== summary.targetReturnBps) throw new Error("verified result does not preserve V/T and target");
      Object.assign(result, verified, { status: "native-verified-at-target", directory });
      if (hash(await readFile(entry.sellerInput)) !== entry.sellerInputSha256) throw new Error("baseline input changed");
    } catch (error) {
      Object.assign(result, { status: "authentication-failed", error: error.message });
    }
    results.push(result);
    console.log(JSON.stringify(result));
    await writeFile(join(outputDirectory, "progress.json"), JSON.stringify({ results }, null, 2));
  }
  await writeFile(join(outputDirectory, "summary.json"), JSON.stringify({ targetReturnBps: summary.targetReturnBps, complete: true, proverNetworkSubmitted: false, results }, null, 2), { flag: "wx" });
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const value = (flag) => args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined;
  if (!value("--summary") || !value("--out-dir") || !value("--binary")) throw new Error("require --summary, --out-dir and --binary");
  const sellers = args.flatMap((argument, index) => argument === "--seller" ? [args[index + 1]] : []);
  if (sellers.some((seller) => !/^0x[0-9a-f]{40}$/.test(seller ?? ""))) throw new Error("invalid --seller");
  await authenticateFixedVolumeReturns({ summaryPath: resolve(value("--summary")), outputDirectory: resolve(value("--out-dir")), binary: resolve(value("--binary")), endpoint: process.env.BASE_RPC_URL, sellers });
}
