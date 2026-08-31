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
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# AIP-4 contract addresses (Base mainnet)
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
CHANNELS = "0xBA66d3b4fbCf472F6F11D6F9F96aaCE96516F09d"
DEPOSITS = "0x0F7a3a8f4Da01637d1202bb5443fcF7F88F99fD2"

# Event signatures
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SETTLED_TOPIC = "0x0b287f37d8bd14ef37f2966734ab387c243cc1a1663616a25a4cc259877736b1"
BUYERS_SELECTOR = "0x97a993aa"
DEPOSITED_TOPIC = "0x2da466a7b24304f47e87fa2e1e5a81b9831ce54fec19055ce277ca2f39ba42c4"

PERIOD_START = 44_471_575
PERIOD_END = 49_936_172
# Smallest span we fall back to, and the span we optimistically start from.
# Address-filtered queries return few logs, so most ranges scan at MAX_CHUNK.
CHUNK = 10_000
MAX_CHUNK = 2_000_000
ALPHA_FUND_BPS = 9_000
EPSILON_LEDGER_BPS = 500

def addr_topic(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")

def parse_addr(topic: str) -> str:
    return "0x" + topic[-40:]


def ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def _is_response_too_large(error: Exception) -> bool:
    """True when the node rejected a range for returning too many logs."""
    message = str(error).lower()
    if "compute unit" in message:  # rate limiting, not an oversized range
        return False
    return "response size" in message or "returned more than" in message or "query timeout" in message


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
        """POST a JSON-RPC payload.

        Nodes report an oversized log range or a rate limit with an error
        status whose body still carries the JSON-RPC error. Return that body
        rather than raising, so the caller can tell those two apart instead
        of seeing an opaque HTTP status.
        """
        if self.session:
            response = self.session.post(self.url, json=payload, timeout=60)
            try:
                return response.json()
            except ValueError:
                response.raise_for_status()
                raise
        request = Request(
            self.url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=60) as response:
                return json.load(response)
        except HTTPError as error:
            try:
                return json.load(error)
            except ValueError:
                raise error

    def call(self, method: str, params: list, retries: int = 8):
        """Call the RPC, backing off exponentially on rate limits and transport errors."""
        for attempt in range(retries):
            self._id += 1
            try:
                body = self.post({
                    "jsonrpc": "2.0", "id": self._id,
                    "method": method, "params": params
                })
                error = body.get("error")
                if error:
                    if error.get("code") == 429 or "compute units" in str(error.get("message", "")):
                        self._backoff(attempt, retries, f"{method}: {error}")
                        continue
                    if attempt < retries - 1:
                        time.sleep(0.5 * (attempt + 1))
                        continue
                    raise Exception(f"{method}: {error}")
                time.sleep(self.delay)
                return body["result"]
            except Exception:
                if attempt < retries - 1:
                    time.sleep(min(2 ** attempt, 30))
                    continue
                raise

    def _backoff(self, attempt: int, retries: int, message: str):
        """Sleep through a rate limit, or raise once the retries are spent."""
        if attempt >= retries - 1:
            raise Exception(f"{message} (rate limited after {retries} attempts)")
        time.sleep(min(2 ** attempt, 60))

    def get_logs(self, address: str, topics: list, from_block: int, to_block: int) -> list:
        """Scan a block range, widening the span while the node keeps up and
        narrowing it whenever a response comes back too large."""
        all_logs = []
        b = from_block
        span = MAX_CHUNK
        while b <= to_block:
            end = min(b + span - 1, to_block)
            try:
                logs = self.call("eth_getLogs", [{
                    "address": address,
                    "topics": topics,
                    "fromBlock": hex(b),
                    "toBlock": hex(end),
                }])
            except Exception as error:
                if span > CHUNK and _is_response_too_large(error):
                    span = max(CHUNK, span // 4)
                    continue
                raise
            if logs:
                all_logs.extend(logs)
            b = end + 1
            if span < MAX_CHUNK:
                span = min(MAX_CHUNK, span * 2)
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


def find_self_fundings(rpc: RPC, seller: str) -> dict:
    """Find buyers the seller financed through Deposits.deposit().

    The USDC transfer lands on the Deposits contract, so the buyer only
    appears in the Deposited log emitted by the same transaction.
    """
    print(f"\nScanning protocol deposits paid by {seller[:10]}...")
    transfers = rpc.get_logs(USDC, [
        TRANSFER_TOPIC,
        addr_topic(seller),
        addr_topic(DEPOSITS),
    ], PERIOD_START, PERIOD_END)
    paid_txs = {log["transactionHash"] for log in transfers}
    paid_total = sum(int(log["data"][2:][:64], 16) for log in transfers)
    print(f"  {len(transfers)} transfers into Deposits, {paid_total / 1e6:,.2f} USDC")
    if not paid_txs:
        return {}

    deposits = rpc.get_logs(DEPOSITS, [DEPOSITED_TOPIC], PERIOD_START, PERIOD_END)
    fundings = defaultdict(list)
    for log in deposits:
        if log["transactionHash"] not in paid_txs:
            continue
        fundings[parse_addr(log["topics"][1])].append({
            "tx": log["transactionHash"],
            "amount": int(log["data"][2:][:64], 16),
            "block": int(log["blockNumber"], 16),
        })
    credited = sum(f["amount"] for txs in fundings.values() for f in txs)
    print(f"  credited {credited / 1e6:,.2f} USDC to {len(fundings)} buyers")
    return dict(fundings)


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
    # Addresses whose forward search already failed, so sibling branches skip them.
    exhausted = set()

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

        chain = _trace_chain(rpc, to_addr, funder, amount, block, max_hops - 1, exhausted)
        if chain is not None:
            paths.append([out["transactionHash"]] + chain)

    print(f"  Found {len(paths)} return paths")
    return paths


# Per hop, only follow the largest candidate transfers. Wash-trading returns move
# most of the value, so the long tail of dust transfers is not worth expanding.
MAX_BRANCH_PER_HOP = 8


def _trace_chain(rpc: RPC, current: str, target: str, prev_amount: int, after_block: int,
                 remaining_hops: int, exhausted: set) -> Optional[list]:
    """Recursively trace USDC transfers from current to target."""
    if remaining_hops <= 0:
        return None

    key = (current.lower(), after_block // 100_000, remaining_hops)
    if key in exhausted:
        return None

    search_end = min(after_block + 500_000, PERIOD_END)  # ~6 days of blocks
    outflows = rpc.get_logs(USDC, [
        TRANSFER_TOPIC,
        addr_topic(current),
        None,
    ], after_block, search_end)

    candidates = []
    for out in outflows:
        amount = int(out["data"][2:][:64], 16)
        if amount < prev_amount * 0.20:  # less than 20% retention
            continue
        if amount > prev_amount * 1.05:  # more than received (with 5% tolerance)
            continue
        candidates.append((amount, out))

    # A direct hop to the target wins regardless of size.
    for amount, out in candidates:
        if parse_addr(out["topics"][2]).lower() == target.lower():
            return [out["transactionHash"]]

    if remaining_hops > 1:
        candidates.sort(key=lambda c: -c[0])
        for amount, out in candidates[:MAX_BRANCH_PER_HOP]:
            rest = _trace_chain(rpc, parse_addr(out["topics"][2]), target, amount,
                                int(out["blockNumber"], 16), remaining_hops - 1, exhausted)
            if rest is not None:
                return [out["transactionHash"]] + rest

    exhausted.add(key)
    return None


def cohort(buyer_fundings: dict, buyer_settlements: dict, funder: str) -> list:
    """Buyers that were both funded and settled, excluding the funder itself."""
    return sorted((set(buyer_fundings) & set(buyer_settlements)) - {funder.lower()})


def required_funding(settled: int, balance_end: int) -> int:
    """Minimum funding satisfying balance_end + settled <= funded * (1 + epsilon)."""
    return ceil_div((balance_end + settled) * 10_000, 10_000 + EPSILON_LEDGER_BPS)


def select_case_fundings(funded_buyers: list[str], buyer_settlements: dict,
                         buyer_fundings: dict, buyer_end_balances: dict,
                         kind: str = "usdc") -> list[dict]:
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
            selected.append({"kind": kind, "buyer": buyer, **entry})
            buyer_total += entry["amount"]
            funded_total += entry["amount"]
            selected_count += 1

        if buyer_total < target:
            raise ValueError(
                f"buyer {buyer} has {buyer_total} funding but needs {target} for ledger coverage"
            )
        remaining.extend(
            {"kind": kind, "buyer": buyer, **entry}
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
               max_settlements_per_buyer: int = 1_000, kind: str = "usdc") -> dict:
    """Build a minimal case file."""
    # Only include buyers funded by our funder. The predicate rejects a cohort
    # containing the funder, which matters when the seller funds itself.
    funded_buyers = cohort(buyer_fundings, buyer_settlements, funder)
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
    if settled_total == 0:
        print("ERROR: funded buyers settled no volume; there is no loop to prove")
        sys.exit(1)
    case_fundings = select_case_fundings(
        funded_buyers,
        selected_settlements,
        buyer_fundings,
        buyer_end_balances,
        kind,
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
    parser.add_argument("--self-fund", action="store_true",
                        help="Build a self-funding case: the seller finances its own buyers "
                             "through Deposits.deposit(). The seller is its own funder, so the "
                             "return leg holds by identity and no return paths are needed.")
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

    # Step 2: Find funder. With --self-fund the seller finances its own buyers
    # through Deposits.deposit(), so it is its own funder and the return leg
    # holds by identity.
    if args.self_fund:
        funder = args.seller
        buyer_fundings = find_self_fundings(rpc, args.seller)
        if not buyer_fundings:
            print("No protocol deposits paid by this seller")
            sys.exit(1)
        kind = "deposit"
    else:
        funder, buyer_fundings = find_funder(
            rpc, buyer_settlements,
            target_funder=args.funder.lower() if args.funder else None,
        )
        kind = "usdc"

    # Step 3: Bind funding selection to the period-end P0 ledger rule
    funded_buyers = cohort(buyer_fundings, buyer_settlements, funder)
    buyer_end_balances = find_buyer_end_balances(rpc, funded_buyers)

    # Step 4: Find return paths
    if args.self_fund:
        return_paths = []
    else:
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
        kind,
    )

    # Write output
    with open(args.out, "w") as f:
        json.dump(case, f, indent=2)
    print(f"\nCase written to {args.out}")
    print(f"Run: BASE_RPC_URLS=\"{args.rpc}\" cargo run --release -p loop-host -- fetch --case {args.out} --out fixture.json")


if __name__ == "__main__":
    main()
