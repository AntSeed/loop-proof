import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { loadPackage, unpackArtifact, validateArtifact, encodeChunk, checkDeployment, cast } from "./published-seller-proofs.mjs";

const directory = fileURLToPath(new URL("../proofs/2026-09-06-vt30", import.meta.url));
const manifest = JSON.parse(await readFile(`${directory}/manifest.json`, "utf8"));
const entry = manifest.artifacts[0];
const compressed = await readFile(`${directory}/${entry.file}`);
const { artifact } = unpackArtifact(compressed, entry);

test("read-only cast commands do not inherit the signing password file", () => {
  const previous = process.env.ETH_PASSWORD;
  process.env.ETH_PASSWORD = "/unused/test-password-file";
  try {
    assert.equal(cast(["call", "registry", "verifier()(address)"], (command, args, options) => {
      assert.equal(command, "cast");
      assert.equal(args[0], "call");
      assert.equal(Object.hasOwn(options.env, "ETH_PASSWORD"), false);
      assert.equal(options.env.PATH, process.env.PATH);
      return "0x1234\n";
    }), "0x1234");
    assert.equal(process.env.ETH_PASSWORD, "/unused/test-password-file");
  } finally {
    if (previous === undefined) delete process.env.ETH_PASSWORD;
    else process.env.ETH_PASSWORD = previous;
  }
});

test("published package preserves all 54 production artifacts and totals", async () => {
  const loaded = await loadPackage(directory);
  assert.equal(loaded.artifacts.length, 54);
  assert.equal(loaded.manifest.totalProvenWashVolumeRaw, "146692697298");
  assert.equal(loaded.manifest.totalSellerVolumeRaw, "190205878768");
  assert.equal(loaded.manifest.aip4Compliant, false);
});

test("compressed and original artifact corruption fails closed", () => {
  const damaged = Buffer.from(compressed);
  damaged[damaged.length - 1] ^= 1;
  assert.throws(() => unpackArtifact(damaged, entry), /compressed artifact checksum/);
  assert.throws(() => unpackArtifact(compressed, { ...entry, sha256: `0x${"00".repeat(32)}` }), /original artifact checksum/);
  assert.throws(() => unpackArtifact(compressed, { ...entry, uncompressedBytes: 1 }), /original artifact checksum/);
});

test("development proofs, foreign keys and changed journals are rejected", () => {
  const validate = candidate => validateArtifact(candidate, entry, manifest.configuration);
  assert.throws(() => validate({ ...artifact, securityMode: "development" }), /invalid production/);
  assert.throws(() => validate({ ...artifact, sellerProgramVKey: `0x${"00".repeat(32)}` }), /invalid production/);
  assert.throws(() => validate({ ...artifact, publicValues: artifact.publicValues.slice(0, -2) + "ff" }), /journal/);
  assert.throws(() => validate({ ...artifact, proofBytes: "0x12345678" }), /verifier/);
  assert.throws(() => validate({ ...artifact, provenWashVolumeRaw: "1" }), /journal/);
});

test("chunk encoding preserves the committed references and Merkle proof", () => {
  const chunk = artifact.blockAuthenticationChunks[0];
  let argumentsSeen;
  assert.equal(encodeChunk(entry.proofId, chunk, args => { argumentsSeen = args; return "0xabc"; }), "0xabc");
  assert.deepEqual(argumentsSeen, ["calldata", "authenticateBlockReferences(bytes32,uint32,(uint64,bytes32)[],bytes32[])",
    entry.proofId, "0", `[${chunk.references.map(reference => `(${reference.number},${reference.blockHash})`).join(",")}]`, `[${chunk.proof.join(",")}]`]);
});

function deploymentQuery({ chain = "8453", wrongCode = false, wrongField = null } = {}) {
  const hashes = [manifest.registryRuntimeCodeHash, manifest.verifierRuntimeCodeHash, manifest.blockhashStoreRuntimeCodeHash];
  let hashIndex = 0;
  return args => {
    if (args[0] === "chain-id") return chain;
    if (args[0] === "code") return wrongCode ? "0x" : "0x1234";
    if (args[0] === "keccak") return hashes[hashIndex++];
    const field = args[2].split("(")[0];
    if (field === wrongField) return "0";
    const value = String(manifest.configuration[field]);
    return field.startsWith("period") ? `${value} [formatted annotation]` : value;
  };
}

test("read-only deployment check binds chain, runtime and all six settings", () => {
  const registry = `0x${"12".repeat(20)}`;
  assert.doesNotThrow(() => checkDeployment(manifest, registry, deploymentQuery()));
  assert.throws(() => checkDeployment(manifest, registry, deploymentQuery({ chain: "1" })), /chain ID/);
  assert.throws(() => checkDeployment(manifest, registry, deploymentQuery({ wrongCode: true })), /runtime bytecode/);
  for (const field of Object.keys(manifest.configuration)) {
    assert.throws(() => checkDeployment(manifest, registry, deploymentQuery({ wrongField: field })), /mismatch/);
  }
  assert.throws(() => checkDeployment(manifest, `0x${"00".repeat(20)}`, deploymentQuery()), /real deployed/);
});
