#!/usr/bin/env python3
"""Automated wash-trading case builder.

Given a seller address and an RPC URL, scans on-chain data to detect
closed-loop wash trading patterns and produces a case.json file that
loop-host can use to generate a proof.

Usage:
  python3 scripts/build-case.py \
    --seller 0x0329c5d3920e301740f78d6e17b8d1a11cca9b2c \
    --rpc https://base-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --out cases/seller.json

The script:
  1. Scans ChannelSettled events to find all buyers
  2. Traces USDC inflows to identify the common funder
  3. Finds return paths (seller → intermediaries → funder)
  4. Generates a minimal case file
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from typing import Optional
from urllib.request import Request, urlopen

# AIP-4 contract addresses (Base mainnet)
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
CHANNELS = "0xBA66d3b4fbCf472F6F11D6F9F96aaCE96516F09d"
DEPOSITS = "0x0F7a3a8f4Da01637d1202bb5443fcF7F88F99fD2"

# Event signatures
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SETTLED_TOPIC = "0x0b287f37d8bd14ef37f2966734ab387c243cc1a1663616a25a4cc259877736b1"
BUYERS_SELECTOR = "0x97a993aa"

PERIOD_START = 44_471_575
PERIOD_END = 49_936_172
CHUNK = 100_000
ALPHA_FUND_BPS = 9_000
EPSILON_LEDGER_BPS = 500

def addr_topic(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")

def parse_addr(topic: str) -> str:
    return "0x" + topic[-40:]


def ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


class RPC:
    def __init__(self, url: str, delay: float = 0.05):
        self.url = url
        self.delay = delay
        self._id = 0
        self._session = None

    @property
    def session(self):
        if self._session is None:
            try:
                import requests
                self._session = requests.Session()
            except ImportError:
                self._session = False
        return self._session

    def post(self, payload: dict) -> dict:
        if self.session:
            response = self.session.post(self.url, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        request = Request(
            self.url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    def call(self, method: str, params: list, retries: int = 3):
        for attempt in range(retries):
            self._id += 1
            try:
                body = self.post({
                    "jsonrpc": "2.0", "id": self._id,
                    "method": method, "params": params
                })
                if "error" in body and body["error"]:
                    if attempt < retries - 1:
                        time.sleep(0.5 * (attempt + 1))
                        continue
                    raise Exception(f"{method}: {body['error']}")
                time.sleep(self.delay)
                return body["result"]
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(1 * (attempt + 1))
                    continue
                raise

    def get_logs(self, address: str, topics: list, from_block: int, to_block: int) -> list:
        all_logs = []
        b = from_block
        while b <= to_block:
            end = min(b + CHUNK - 1, to_block)
            logs = self.call("eth_getLogs", [{
                "address": address,
                "topics": topics,
                "fromBlock": hex(b),
                "toBlock": hex(end),
            }])
            if logs:
                all_logs.extend(logs)
            b = end + 1
        return all_logs


def find_settlements(rpc: RPC, seller: str) -> dict:
    """Find all ChannelSettled events for this seller. Returns {buyer: [(tx_hash, amount, block)]}."""
    print(f"Scanning settlements for seller {seller}...")
    logs = rpc.get_logs(CHANNELS, [
        SETTLED_TOPIC,
        None,  # channelId
        None,  # buyer (topic[2])
        addr_topic(seller),  # seller (topic[3])
    ], PERIOD_START, PERIOD_END)

    buyers = defaultdict(list)
    for log in logs:
        buyer = parse_addr(log["topics"][2])
        data = log["data"][2:]
        amount = int(data[64:128], 16)  # second word
        block = int(log["blockNumber"], 16)
        buyers[buyer].append({
            "tx": log["transactionHash"],
            "amount": amount,
            "block": block,
        })

    total_vol = sum(s["amount"] for setts in buyers.values() for s in setts)
    print(f"  Found {sum(len(v) for v in buyers.values())} settlements from {len(buyers)} buyers")
    print(f"  Total volume: {total_vol / 1e6:.2f} USDC")
    return buyers


def find_funder(rpc: RPC, buyers: dict, target_funder: Optional[str] = None) -> tuple[str, dict]:
    """For each buyer, find who sent them USDC. Returns (funder, {buyer: [(tx, amount, block)]})."""
    print(f"\nTracing USDC inflows to {len(buyers)} buyers...")
    funder_counts = defaultdict(lambda: {"count": 0, "amount": 0, "buyers": set()})
    buyer_fundings = defaultdict(list)

    for i, buyer in enumerate(sorted(buyers.keys())):
        setts = buyers[buyer]
        first_sett_block = min(s["block"] for s in setts)
        search_start = max(PERIOD_START, first_sett_block - 2_000_000)

        if target_funder:
            logs = rpc.get_logs(USDC, [
                TRANSFER_TOPIC,
                addr_topic(target_funder),
                addr_topic(buyer),
            ], search_start, first_sett_block)
        else:
            logs = rpc.get_logs(USDC, [
                TRANSFER_TOPIC,
                None,
                addr_topic(buyer),
            ], search_start, first_sett_block)

        for log in logs:
            from_addr = parse_addr(log["topics"][1])
            data = log["data"][2:]
            amount = int(data[:64], 16)
            block = int(log["blockNumber"], 16)
            funder_counts[from_addr]["count"] += 1
            funder_counts[from_addr]["amount"] += amount
            funder_counts[from_addr]["buyers"].add(buyer)
            buyer_fundings[(from_addr, buyer)].append({
                "tx": log["transactionHash"],
                "amount": amount,
                "block": block,
            })

        if (i + 1) % 10 == 0:
            print(f"  Traced {i+1}/{len(buyers)} buyers...")

    ranked = sorted(funder_counts.items(), key=lambda x: len(x[1]["buyers"]), reverse=True)
    print(f"\nTop funders:")
    for funder, stats in ranked[:5]:
        print(f"  {funder}: {len(stats['buyers'])} buyers, {stats['amount']/1e6:.2f} USDC, {stats['count']} txs")

    if not ranked:
        print("ERROR: No funding sources found")
        sys.exit(1)

    top_funder = ranked[0][0]
    top_buyers = funder_counts[top_funder]["buyers"]
    print(f"\nSelected funder: {top_funder} ({len(top_buyers)} buyers)")

    fundings = {}
    for buyer in sorted(top_buyers):
        fundings[buyer] = buyer_fundings[(top_funder, buyer)]

    return top_funder, fundings


def find_buyer_end_balances(rpc: RPC, buyers: list[str]) -> dict[str, int]:
    """Read each buyer's protocol balance at the P0 period end."""
    print(f"\nReading period-end protocol balances for {len(buyers)} buyers...")
    balances = {}
    for index, buyer in enumerate(buyers):
        calldata = BUYERS_SELECTOR + buyer.lower().replace("0x", "").rjust(64, "0")
        result = rpc.call("eth_call", [{"to": DEPOSITS, "data": calldata}, hex(PERIOD_END)])
        data = result.removeprefix("0x")
        if len(data) < 64:
            raise ValueError(f"buyers({buyer}) returned malformed data at block {PERIOD_END}")
        balances[buyer] = int(data[:64], 16)
        if (index + 1) % 10 == 0:
            print(f"  Read {index + 1}/{len(buyers)} buyer balances...")
    return balances


def find_returns(rpc: RPC, seller: str, funder: str, max_hops: int = 4, max_paths: int = 50) -> list:
    """Find USDC transfer chains seller → ... → funder."""
    print(f"\nSearching for return paths ({seller[:10]}... → {funder[:10]}...)...")

    # Step 1: Find all USDC outflows from seller
    seller_outflows = rpc.get_logs(USDC, [
        TRANSFER_TOPIC,
        addr_topic(seller),
        None,  # to
    ], PERIOD_START, PERIOD_END)

    print(f"  Seller has {len(seller_outflows)} USDC outflows")

    # Step 2: For each outflow, try to trace through intermediaries to funder
    paths = []
    seen_first_hops = set()

    for out in seller_outflows:
        if len(paths) >= max_paths:
            break

        to_addr = parse_addr(out["topics"][2])
        data = out["data"][2:]
        amount = int(data[:64], 16)
        block = int(out["blockNumber"], 16)

        if amount < 1_000_000:  # < 1 USDC
            continue

        # Direct return
        if to_addr.lower() == funder.lower():
            paths.append([out["transactionHash"]])
            continue

        # Try to find intermediary chain
        tx_key = out["transactionHash"]
        if tx_key in seen_first_hops:
            continue
        seen_first_hops.add(tx_key)

        chain = _trace_chain(rpc, to_addr, funder, amount, block, max_hops - 1)
        if chain is not None:
            paths.append([out["transactionHash"]] + chain)

    print(f"  Found {len(paths)} return paths")
    return paths


def _trace_chain(rpc: RPC, current: str, target: str, prev_amount: int, after_block: int, remaining_hops: int) -> Optional[list]:
    """Recursively trace USDC transfers from current to target."""
    if remaining_hops <= 0:
        return None

    # Search forward from the intermediary
    search_end = min(after_block + 500_000, PERIOD_END)  # ~6 days of blocks
    outflows = rpc.get_logs(USDC, [
        TRANSFER_TOPIC,
        addr_topic(current),
        None,
    ], after_block, search_end)

    for out in outflows:
        to_addr = parse_addr(out["topics"][2])
        data = out["data"][2:]
        amount = int(data[:64], 16)
        out_block = int(out["blockNumber"], 16)

        if amount < prev_amount * 0.20:  # less than 20% retention
            continue
        if amount > prev_amount * 1.05:  # more than received (with 5% tolerance)
            continue

        if to_addr.lower() == target.lower():
            return [out["transactionHash"]]

        if remaining_hops > 1:
            rest = _trace_chain(rpc, to_addr, target, amount, out_block, remaining_hops - 1)
            if rest is not None:
                return [out["transactionHash"]] + rest

    return None


def required_funding(settled: int, balance_end: int) -> int:
    """Minimum funding satisfying balance_end + settled <= funded * (1 + epsilon)."""
    return ceil_div((balance_end + settled) * 10_000, 10_000 + EPSILON_LEDGER_BPS)


def select_case_fundings(funded_buyers: list[str], buyer_settlements: dict,
                         buyer_fundings: dict, buyer_end_balances: dict) -> list[dict]:
    """Select evidence satisfying both per-buyer ledger and aggregate FUND rules."""
    selected = []
    remaining = []
    funded_total = 0

    for buyer in funded_buyers:
        settled = sum(entry["amount"] for entry in buyer_settlements[buyer])
        target = required_funding(settled, buyer_end_balances[buyer])
        candidates = sorted(
            buyer_fundings[buyer],
            key=lambda entry: (-entry["amount"], entry["tx"]),
        )
        if not candidates:
            raise ValueError(f"buyer {buyer} has no funding evidence")

        buyer_total = 0
        selected_count = 0
        while selected_count < len(candidates) and buyer_total < target:
            entry = candidates[selected_count]
            selected.append({"kind": "usdc", "buyer": buyer, **entry})
            buyer_total += entry["amount"]
            funded_total += entry["amount"]
            selected_count += 1

        if buyer_total < target:
            raise ValueError(
                f"buyer {buyer} has {buyer_total} funding but needs {target} for ledger coverage"
            )
        remaining.extend(
            {"kind": "usdc", "buyer": buyer, **entry}
            for entry in candidates[selected_count:]
        )

    settled_total = sum(
        sum(entry["amount"] for entry in buyer_settlements[buyer])
        for buyer in funded_buyers
    )
    aggregate_target = ceil_div(settled_total * ALPHA_FUND_BPS, 10_000)
    remaining.sort(key=lambda entry: (-entry["amount"], entry["tx"]))
    for entry in remaining:
        if funded_total >= aggregate_target:
            break
        selected.append(entry)
        funded_total += entry["amount"]

    if funded_total < aggregate_target:
        raise ValueError(
            f"case has {funded_total} funding but needs {aggregate_target} aggregate coverage"
        )
    return selected


def build_case(seller: str, funder: str, buyer_settlements: dict, buyer_fundings: dict,
               buyer_end_balances: dict, return_paths: list,
               max_settlements_per_buyer: int = 1_000) -> dict:
    """Build a minimal case file."""
    # Only include buyers funded by our funder
    funded_buyers = sorted(set(buyer_fundings.keys()) & set(buyer_settlements.keys()))
    if not funded_buyers:
        print("ERROR: No funded buyers with settlements")
        sys.exit(1)

    selected_settlements = {
        buyer: buyer_settlements[buyer][:max_settlements_per_buyer]
        for buyer in funded_buyers
    }

    settled_total = sum(
        sum(s["amount"] for s in selected_settlements[b])
        for b in funded_buyers
    )
    case_fundings = select_case_fundings(
        funded_buyers,
        selected_settlements,
        buyer_fundings,
        buyer_end_balances,
    )
    funded_total = sum(entry["amount"] for entry in case_fundings)

    print(f"\nCase summary:")
    print(f"  Buyers: {len(funded_buyers)}")
    print(f"  Settled: {settled_total / 1e6:.2f} USDC")
    print(f"  Funded:  {funded_total / 1e6:.2f} USDC ({funded_total/settled_total*100:.1f}%)")
    print(f"  Fundings: {len(case_fundings)}")
    print(f"  Returns: {len(return_paths)} paths")

    return {
        "seller": seller,
        "funder": funder,
        "buyers": funded_buyers,
        "fundings": [
            {"kind": entry["kind"], "buyer": entry["buyer"], "tx": entry["tx"]}
            for entry in case_fundings
        ],
        "returns": return_paths,
        "max_settlements_per_buyer": max_settlements_per_buyer,
    }


def main():
    parser = argparse.ArgumentParser(description="Build wash-trading case file")
    parser.add_argument("--seller", required=True, help="Seller address")
    parser.add_argument("--rpc", required=True, help="Base RPC URL")
    parser.add_argument("--out", required=True, help="Output case file path")
    parser.add_argument("--funder", help="Override funder (skip auto-detection)")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between RPC calls (seconds)")
    parser.add_argument("--max-return-hops", type=int, default=4, help="Max hops in return paths")
    parser.add_argument("--max-return-paths", type=int, default=50, help="Max return paths to find")
    parser.add_argument("--max-settlements-per-buyer", type=int, default=1_000,
                        help="Settlement evidence cap used by loop-host (default: 1000)")
    args = parser.parse_args()

    rpc = RPC(args.rpc, delay=args.delay)

    # Step 1: Find settlements
    buyer_settlements = find_settlements(rpc, args.seller)
    if not buyer_settlements:
        print("No settlements found for this seller")
        sys.exit(1)

    # Step 2: Find funder
    funder, buyer_fundings = find_funder(
        rpc, buyer_settlements,
        target_funder=args.funder.lower() if args.funder else None,
    )

    # Step 3: Bind funding selection to the period-end P0 ledger rule
    funded_buyers = sorted(set(buyer_fundings.keys()) & set(buyer_settlements.keys()))
    buyer_end_balances = find_buyer_end_balances(rpc, funded_buyers)

    # Step 4: Find return paths
    return_paths = find_returns(rpc, args.seller, funder,
                                max_hops=args.max_return_hops,
                                max_paths=args.max_return_paths)

    # Step 5: Build case
    case = build_case(
        args.seller,
        funder,
        buyer_settlements,
        buyer_fundings,
        buyer_end_balances,
        return_paths,
        args.max_settlements_per_buyer,
    )

    # Write output
    with open(args.out, "w") as f:
        json.dump(case, f, indent=2)
    print(f"\nCase written to {args.out}")
    print(f"Run: BASE_RPC_URLS=\"{args.rpc}\" cargo run --release -p loop-host -- fetch --case {args.out} --out fixture.json")


if __name__ == "__main__":
    main()
