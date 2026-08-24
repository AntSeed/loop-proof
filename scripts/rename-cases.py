#!/usr/bin/env python3
"""Rename cases/agent-<id>.json to cases/<seller-name-slug>.json using the Antscan API."""
import json, re, sys, urllib.request
from pathlib import Path

CASES = Path(__file__).resolve().parent.parent / "cases"
API = "https://antscan.co/api/sellers?limit=300"


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or ""


def seller_names() -> dict:
    request = urllib.request.Request(API, headers={"User-Agent": "curl/8.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    items = body if isinstance(body, list) else body.get("sellers") or body.get("items") or []
    return {s["agentId"]: s.get("sellerName") for s in items}


def main():
    apply = "--apply" in sys.argv
    names = seller_names()

    for path in sorted(CASES.glob("agent-*.json")):
        agent_id = path.stem.removeprefix("agent-")
        name = names.get(agent_id)
        if not name:
            print(f"  keep   {path.name}  (agent {agent_id} has no seller name)")
            continue

        target = CASES / f"{slugify(name)}.json"
        if target.exists():
            print(f"  skip   {path.name} -> {target.name}  (target exists)")
            continue

        print(f"  rename {path.name} -> {target.name}  ({name})")
        if apply:
            path.rename(target)

    if not apply:
        print("\nDry run. Re-run with --apply to rename.")


if __name__ == "__main__":
    main()
