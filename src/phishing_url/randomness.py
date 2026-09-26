"""Generate once, record, and reuse independent sampling/split/model seeds."""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from pathlib import Path


def validate_seed(seed: int) -> int:
    if type(seed) is not int or not 0 <= seed < 2**32:
        raise ValueError("seed must be an integer in [0, 2**32)")
    return seed


def derive_seed(master: int, purpose: str) -> int:
    validate_seed(master)
    return int.from_bytes(hashlib.sha256(f"url-seeds-v1:{master}:{purpose}".encode()).digest()[:4], "big")


def make_seed_plan(master: int | None = None) -> dict:
    generated = master is None
    master = secrets.randbits(32) if generated else validate_seed(master)
    return {"version": 1, "master_seed": master,
            "origin": "system_entropy" if generated else "explicit_master",
            "sampling_seed": derive_seed(master, "sampling"),
            "test_seed": derive_seed(master, "test"),
            "development_seeds": [derive_seed(master, f"development:{i}") for i in range(5)],
            "model_seed": derive_seed(master, "model"),
            "policy": "Generate before outcomes; never regenerate to improve model scores."}


def load_seed_plan(path: Path) -> dict:
    plan = json.loads(path.read_text())
    if plan.get("version") != 1:
        raise ValueError("unsupported seed plan version")
    for key in ("master_seed", "sampling_seed", "test_seed", "model_seed"):
        validate_seed(plan[key])
    seeds = plan["development_seeds"]
    if not isinstance(seeds, list) or len(seeds) < 2 or len(set(seeds)) != len(seeds):
        raise ValueError("at least two distinct development seeds required")
    for seed in seeds: validate_seed(seed)
    return plan


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--master-seed", type=int)
    args = parser.parse_args(argv)
    plan = make_seed_plan(args.master_seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        stream.write(json.dumps(plan, indent=2) + "\n")
    return 0


if __name__ == "__main__": raise SystemExit(main())
