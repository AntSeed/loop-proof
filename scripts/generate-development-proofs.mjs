#!/usr/bin/env node
import { execFile } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
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
const artifactDir = resolve(value("--artifact-dir") ?? "out/development-proof-artifacts");
const outputDir = resolve(value("--output-dir") ?? resolve(artifactDir, "sellers"));
const toolchain = process.env.RUSTUP_TOOLCHAIN ?? "1.94";
const skipGuestBuild = args.includes("--skip-guest-build");

await mkdir(artifactDir, { recursive: true });
await mkdir(outputDir, { recursive: true });
await run("cargo", ["run", "-q", "-p", "wash-predicate", "--example", "generate_development_fixtures", "--", `--output=${artifactDir}`]);
const closedFixturePath = resolve(artifactDir, "closed-loop.json");
const reciprocalFixturePath = resolve(artifactDir, "reciprocal.json");
const closedFixture = JSON.parse(await readFile(closedFixturePath, "utf8"));
const reciprocalFixture = JSON.parse(await readFile(reciprocalFixturePath, "utf8"));

const elf = guestElf();
if (!skipGuestBuild) {
  await run("cargo", ["prove", "build", "--workspace-directory", "../.."], resolve(root, "program/seller"), {
    RUSTUP_TOOLCHAIN: "succinct",
  });
} else {
  try {
    await readFile(elf);
  } catch (error) {
    if (error.code === "ENOENT") throw new Error("seller guest ELF is missing; omit --skip-guest-build");
    throw error;
  }
}

const sellers = [...new Set([
  closedFixture.seller,
  reciprocalFixture.address_a,
  reciprocalFixture.address_b,
].map((seller) => seller.toLowerCase()))].sort();
const outputs = [];
for (const seller of sellers) {
  const output = resolve(outputDir, `${seller}.json`);
  const claims = [];
  if (closedFixture.seller.toLowerCase() === seller) claims.push(`closed-loop:${closedFixturePath}`);
  if ([reciprocalFixture.address_a, reciprocalFixture.address_b].map((value) => value.toLowerCase()).includes(seller)) {
    claims.push(`reciprocal:${reciprocalFixturePath}`);
  }
  const command = [
    "run", "-q", "-p", "loop-host", "--features", "sp1", "--bin", "wash-trading-prove-seller", "--",
    "--development",
    "--seller", seller,
    "--seller-elf", elf,
    "--seller-witness", resolve(artifactDir, "seller-witnesses", `${seller}.json`),
    "--output", output,
  ];
  for (const claim of claims) command.push("--claim", claim);
  await run("cargo", [
    ...command,
  ]);
  const artifact = JSON.parse(await readFile(output, "utf8"));
  if (artifact?.version !== 3 || artifact.kind !== "antseed-wash-trading-seller-proof"
      || artifact.proofArchitecture !== "direct-seller-v1" || artifact.securityMode !== "development"
      || artifact.seller.toLowerCase() !== seller || artifact.claimCount !== claims.length) {
    throw new Error(`${seller}: development seller artifact has unexpected identity`);
  }
  outputs.push(output);
}
console.log(`development seller proofs: ${outputs.join(", ")}`);

function guestElf() {
  return resolve(root, "program/seller/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/seller-guest");
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
