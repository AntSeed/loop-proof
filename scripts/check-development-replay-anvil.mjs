import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, writeFile, rename } from "node:fs/promises";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { sha256 } from "./replay-seller-development.mjs";

const [replayPath, contractsPath, outputPath] = process.argv.slice(2).map((path) => resolve(path));
if (!replayPath || !contractsPath || !outputPath || process.argv.length !== 5) {
  throw new Error("usage: node scripts/check-development-replay-anvil.mjs replay-summary.json contracts-directory output-directory");
}
await mkdir(outputPath, { recursive: true });
const testPath = join(contractsPath, "scripts/wash-trading-development-anvil.test.mjs");
const pinnedFiles = [
  "integrity/AntseedWashTradingRegistry.sol", "interfaces/IAntseedWashTradingRegistry.sol",
  "test/mocks/WashTradingDevelopmentE2E.sol", "scripts/submit-wash-trading-development-anvil.mjs",
  "scripts/wash-trading-development-anvil.test.mjs",
];
const contractSourceSha256 = Object.fromEntries(await Promise.all(pinnedFiles.map(async (path) => [path, await sha256(join(contractsPath, path))])));
const report = { securityMode: "development", productionReady: false, verifierMode: "development-mock",
  blockhashStoreMode: "development-mock", liveChainSubmitted: false,
  startedAt: new Date().toISOString(), contractSourceSha256, results: [], complete: false };
const summaryPath = join(outputPath, "summary.json");
try {
  await readFile(summaryPath);
  throw new Error("Anvil report already exists; use a fresh output directory");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}
async function persist() {
  await writeFile(`${summaryPath}.tmp`, `${JSON.stringify(report, null, 2)}\n`);
  await rename(`${summaryPath}.tmp`, summaryPath);
}
await persist();
const deadline = Date.now() + 3 * 60 * 60 * 1000;
while (true) {
  const replay = JSON.parse(await readFile(replayPath, "utf8"));
  if (replay.securityMode !== "development" || replay.productionReady !== false
    || replay.proverNetworkSubmitted !== false) throw new Error("not a development replay");
  const pending = replay.results.filter((result) => result.success && !report.results.some((entry) => entry.seller === result.seller));
  for (const result of pending) {
    for (const [path, hash] of Object.entries(contractSourceSha256)) {
      if (await sha256(join(contractsPath, path)) !== hash) throw new Error(`contract/test source changed: ${path}`);
    }
    if (await sha256(result.artifact) !== result.artifactSha256) throw new Error("artifact changed before submission test");
    const logPath = join(outputPath, `${result.seller}.log`);
    const log = createWriteStream(logPath);
    console.log(`ANVIL START ${result.label ?? result.seller}`);
    const code = await new Promise((accept, reject) => {
      const child = spawn(process.execPath, ["--test", "--test-reporter=tap", testPath], {
        cwd: contractsPath,
        env: { ...process.env, LOOP_PROOF_DIR: resolve(new URL("..", import.meta.url).pathname), WASH_TRADING_SELLER_PROOF: result.artifact },
        stdio: ["ignore", "pipe", "pipe"],
      });
      child.stdout.pipe(log, { end: false });
      child.stderr.pipe(log, { end: false });
      child.once("error", reject);
      child.once("close", accept);
    }).finally(() => new Promise((accept) => log.end(accept)));
    const text = await readFile(logPath, "utf8");
    const success = code === 0 && /# pass 1\b/.test(text) && /# fail 0\b/.test(text)
      && await sha256(result.artifact) === result.artifactSha256;
    report.results.push({ seller: result.seller, label: result.label, success,
      artifact: result.artifact, artifactSha256: result.artifactSha256, log: logPath });
    await persist();
    console.log(`ANVIL ${success ? "PASS" : "FAIL"} ${result.label ?? result.seller}`);
  }
  if (replay.finishedAt) {
    report.complete = replay.complete && report.results.length === replay.expectedSellerCount && report.results.every((result) => result.success);
    report.finishedAt = new Date().toISOString();
    await persist();
    if (!report.complete) process.exitCode = 1;
    break;
  }
  if (Date.now() > deadline) throw new Error("development replay wait exceeded three hours");
  await delay(5000);
}
console.log(`ANVIL SUMMARY ${summaryPath}: ${report.results.filter((result) => result.success).length} passed`);
