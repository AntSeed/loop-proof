#!/usr/bin/env node
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const value = (flag) => {
  const index = args.indexOf(flag);
  return index < 0 ? null : args[index + 1];
};
const output = resolve(value("--output") ?? "out/development-aggregate-proof.json");
const artifactDir = resolve(value("--artifact-dir") ?? "out/development-proof-artifacts");
const toolchain = process.env.RUSTUP_TOOLCHAIN ?? "1.94";
const guests = ["closed-loop", "reciprocal", "aggregator"];
const skipGuestBuild = args.includes("--skip-guest-build");

await mkdir(artifactDir, { recursive: true });
await run("cargo", ["run", "-q", "-p", "wash-predicate", "--example", "generate_development_fixtures", "--", `--output=${artifactDir}`]);
const closedFixture = JSON.parse(await readFile(resolve(artifactDir, "closed-loop.json"), "utf8"));
const reciprocalFixture = JSON.parse(await readFile(resolve(artifactDir, "reciprocal.json"), "utf8"));
const manifestPath = resolve(artifactDir, "historical-manifest.json");
await writeFile(manifestPath, `${JSON.stringify({
  report_root: `0x${"44".repeat(32)}`,
  period_start_block: Math.min(closedFixture.period_start_block, reciprocalFixture.period_start_block),
  period_end_block: Math.max(closedFixture.period_end_block, reciprocalFixture.period_end_block),
  closed_loop_program_vkey: `0x${"00".repeat(32)}`,
  reciprocal_program_vkey: `0x${"00".repeat(32)}`,
  claims: [
    { source_claim_id: closedFixture.source_claim_id, predicate_id: 1, period_start_block: closedFixture.period_start_block, period_end_block: closedFixture.period_end_block, subjects: [{ seller: closedFixture.seller, proven_wash_volume: "1200000000" }] },
    { source_claim_id: reciprocalFixture.source_claim_id, predicate_id: 2, period_start_block: reciprocalFixture.period_start_block, period_end_block: reciprocalFixture.period_end_block, subjects: [
      { seller: reciprocalFixture.address_a, proven_wash_volume: "500000000" },
      { seller: reciprocalFixture.address_b, proven_wash_volume: "450000000" },
    ] },
  ],
  block_refs: [],
}, null, 2)}\n`);

for (const guest of guests) {
  const elf = guestElf(guest);
  if (!skipGuestBuild) {
    await run("cargo", ["prove", "build"], resolve(root, "program", guest), { RUSTUP_TOOLCHAIN: "succinct" });
    continue;
  }
  try {
    await readFile(elf);
  } catch (error) {
    if (error.code === "ENOENT") throw new Error(`${guest} guest ELF is missing; omit --skip-guest-build`);
    throw error;
  }
}

await mkdir(dirname(output), { recursive: true });
await run("cargo", [
  "run", "-q", "-p", "loop-host", "--features", "sp1", "--bin", "wash-trading-aggregate", "--",
  "--development",
  "--aggregator-elf", guestElf("aggregator"),
  "--closed-loop-elf", guestElf("closed-loop"),
  "--reciprocal-elf", guestElf("reciprocal"),
  "--manifest", manifestPath,
  "--child", `closed-loop:${resolve(artifactDir, "closed-loop.json")}`,
  "--child", `reciprocal:${resolve(artifactDir, "reciprocal.json")}`,
  "--output", output,
]);

const artifact = JSON.parse(await readFile(output, "utf8"));
if (artifact.securityMode !== "development" || artifact.childCount !== 2 || artifact.sellerCount !== 3) {
  throw new Error("development aggregate artifact has unexpected identity");
}
console.log(`development aggregate: ${output}`);

function guestElf(guest) {
  return resolve(root, `program/${guest}/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/${guest}-guest`);
}

async function run(command, commandArgs, cwd = root, extraEnv = {}) {
  console.error(`> ${command} ${commandArgs.join(" ")}`);
  const { stdout, stderr } = await exec(command, commandArgs, {
    cwd,
    env: { ...process.env, RUSTUP_TOOLCHAIN: toolchain, ...extraEnv },
    maxBuffer: 100 * 1024 * 1024,
  });
  if (stdout) process.stdout.write(stdout);
  if (stderr) process.stderr.write(stderr);
}
