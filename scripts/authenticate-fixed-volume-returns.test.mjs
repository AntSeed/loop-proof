import assert from "node:assert/strict";
import test from "node:test";
import { hydrateHop } from "./authenticate-fixed-volume-returns.mjs";

const sender = `0x${"11".repeat(20)}`;
const receiver = `0x${"22".repeat(20)}`;
const transactionHash = `0x${"33".repeat(32)}`;
const hop = { transactionHash, from: sender, to: receiver, amountRaw: "100", timestamp: 10, logIndex: 12 };
const receipt = { transactionHash, status: "0x1", blockNumber: "0xa", transactionIndex: "0x2", logs: [{
  logIndex: "0xc", address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", data: "0x64",
  topics: ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", `0x${sender.slice(2).padStart(64, "0")}`, `0x${receiver.slice(2).padStart(64, "0")}`],
}] };

test("hydrates both planner and trace transaction hash fields with receipt-local indices", () => {
  assert.deepEqual(hydrateHop(hop, receipt), { ...hop, txHash: transactionHash, blockNumber: 10, transactionIndex: 2, receiptLogIndex: 0 });
  assert.equal(hydrateHop({ ...hop, txHash: transactionHash }, receipt).receiptLogIndex, 0);
});

test("rejects wrong transaction, status, token, transfer amount and removed logs", () => {
  assert.throws(() => hydrateHop(hop, { ...receipt, transactionHash: `0x${"44".repeat(32)}` }));
  assert.throws(() => hydrateHop(hop, { ...receipt, status: "0x0" }));
  assert.throws(() => hydrateHop({ ...hop, amountRaw: "101" }, receipt));
  assert.throws(() => hydrateHop(hop, { ...receipt, logs: [{ ...receipt.logs[0], address: receiver }] }));
  assert.throws(() => hydrateHop(hop, { ...receipt, logs: [{ ...receipt.logs[0], removed: true }] }));
});
