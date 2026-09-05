import test from "node:test";
import assert from "node:assert/strict";
import { validateArtifact, validateManifest } from "./replay-seller-development.mjs";

const seller = {
  seller: `0x${"12".repeat(20)}`, sellerInput: "/saved/input.json",
  provenWashVolumeRaw: "300", totalSellerVolumeRaw: "1000", evidenceDigest: `0x${"34".repeat(32)}`,
};
const manifest = {
  securityMode: "development", productionReady: false, alphaReturnBps: 3000,
  periodStartBlock: 100, periodEndBlock: 200, sellerProgramVKey: `0x${"56".repeat(32)}`, sellers: [seller],
};
const artifact = {
  version: 3, kind: "antseed-wash-trading-seller-proof", proofArchitecture: "direct-seller-v1",
  securityMode: "development", alphaReturnBps: 3000, seller: seller.seller,
  periodStartBlock: 100, periodEndBlock: 200, sellerProgramVKey: manifest.sellerProgramVKey,
  provenWashVolumeRaw: "300", totalSellerVolumeRaw: "1000", evidenceDigest: seller.evidenceDigest,
  proved: true, verified: true, proverNetworkSubmitted: false,
  proofBytes: "0x1234", publicValues: "0x5678", blockAuthenticationChunks: [{}], blockAuthenticationChunkCount: 1,
};

test("development replay accepts the frozen policy and unchanged volumes", () => {
  assert.doesNotThrow(() => validateManifest(manifest));
  assert.doesNotThrow(() => validateArtifact(artifact, seller, manifest));
});

test("development replay rejects legacy guests, unsafe labels and altered results", () => {
  for (const mutation of [
    { alphaReturnBps: 5000 }, { securityMode: "production" }, { proverNetworkSubmitted: true },
    { sellerProgramVKey: `0x${"78".repeat(32)}` }, { periodEndBlock: 201 },
    { provenWashVolumeRaw: "299" }, { totalSellerVolumeRaw: "999" }, { evidenceDigest: "0x00" },
    { seller: `0x${"78".repeat(20)}` }, { proved: false }, { verified: false },
    { proofBytes: "0x" }, { publicValues: "0x" }, { blockAuthenticationChunks: [] },
  ]) assert.throws(() => validateArtifact({ ...artifact, ...mutation }, seller, manifest));
});

test("development replay rejects duplicate sellers and ambiguous input sources", () => {
  for (const mutation of [
    { alphaReturnBps: 5000 }, { securityMode: "production" }, { productionReady: true },
    { periodEndBlock: 99 }, { sellers: [] }, { sellers: [seller, seller] },
    { sellers: [{ ...seller, evidencePath: "/other.json" }] },
    { sellers: [{ ...seller, sellerInput: undefined }] },
  ]) assert.throws(() => validateManifest({ ...manifest, ...mutation }));
});
