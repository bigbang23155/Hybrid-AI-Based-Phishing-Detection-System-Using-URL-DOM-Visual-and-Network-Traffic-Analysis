"""Freeze a Git-LFS source-file inventory without downloading dataset payloads."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


LFS_OID = re.compile(r"^oid sha256:([0-9a-f]{64})$")
LFS_SIZE = re.compile(r"^size ([0-9]+)$")


def canonical_digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def parse_lfs_pointer(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) > 4096:
        raise ValueError(f"{path} is not a small Git-LFS pointer")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path} is not a UTF-8 Git-LFS pointer") from exc
    if not lines or lines[0].strip() != "version https://git-lfs.github.com/spec/v1":
        raise ValueError(f"{path} does not use the expected Git-LFS pointer format")
    oid = None
    size = None
    for line in lines[1:]:
        oid_match = LFS_OID.match(line.strip())
        size_match = LFS_SIZE.match(line.strip())
        if oid_match:
            oid = oid_match.group(1)
        if size_match:
            size = int(size_match.group(1))
    if oid is None or size is None or size <= 0:
        raise ValueError(f"{path} has an incomplete Git-LFS pointer")
    return {"sha256": oid, "size_bytes": size}


def freeze_inventory(repo: Path, revision: str, output: Path) -> dict:
    repo = repo.resolve()
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if head != revision:
        raise ValueError(f"checked out source revision {head} != expected {revision}")

    all_paths = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "HEAD", "data"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    train_paths = sorted(path for path in all_paths if re.fullmatch(r"data/train-[^/]+\.parquet", path))
    test_paths = sorted(path for path in all_paths if re.fullmatch(r"data/test-[^/]+\.parquet", path))
    if not train_paths:
        raise ValueError("no train parquet files found at pinned revision")

    entries = []
    for relative in train_paths:
        info = parse_lfs_pointer(repo / relative)
        entries.append({"path": relative, **info})

    body = {
        "schema_version": "source-inventory-v1",
        "source": "phreshphish_publication",
        "revision": revision,
        "allowed_split": "train",
        "official_test_split_used": False,
        "train_shard_count": len(entries),
        "train_total_bytes": sum(item["size_bytes"] for item in entries),
        "train_shards": entries,
        "excluded_source_test_file_count": len(test_paths),
        "excluded_source_test_paths": test_paths,
        "payload_downloaded_for_inventory": False,
    }
    body["inventory_sha256"] = canonical_digest(body)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(body, indent=2, sort_keys=True) + "\n")
    return body


def verify_source_frame(inventory: dict, frame: dict) -> dict:
    """Fail closed if a predeclared shard frame disagrees with the exact inventory."""
    identity = frame["source_inventory"]
    if frame["revision"] != inventory["revision"]:
        raise ValueError("source frame revision differs from pinned inventory")
    if identity["inventory_sha256"] != inventory["inventory_sha256"]:
        raise ValueError("source inventory hash mismatch")
    if identity["train_shard_count"] != inventory["train_shard_count"]:
        raise ValueError("source inventory train-shard count mismatch")
    if identity["train_total_bytes"] != inventory["train_total_bytes"]:
        raise ValueError("source inventory train byte total mismatch")
    if inventory["official_test_split_used"] is not False:
        raise ValueError("official source test split cannot be part of source inventory")

    sampling = frame["sampling_frame"]
    excluded = sampling["exclude_pilot_shard"]
    seed = int(sampling["selection_seed"])
    candidates = [r for r in inventory["train_shards"] if r["path"] != excluded]
    if not any(r["path"] == excluded for r in inventory["train_shards"]):
        raise ValueError("excluded pilot shard is not in inventory")
    ranked = sorted(
        candidates,
        key=lambda r: hashlib.sha256(
            f"assignment03:source-shard:{seed}:{r['path']}".encode()
        ).hexdigest(),
    )
    expected = ranked[:int(sampling["fixed_shard_count"])]
    actual = sampling["fixed_shards"]
    if actual != expected:
        raise ValueError("selected bounded shard frame differs from deterministic frozen selection")
    total = sum(r["size_bytes"] for r in expected)
    if total != int(sampling["expected_total_source_bytes"]):
        raise ValueError("bounded source-frame byte total mismatch")
    if sampling["source_split"] != "train" or sampling["official_source_test_split_used"] is not False:
        raise ValueError("only train source shards are allowed")
    return {
        "verified": True,
        "revision": inventory["revision"],
        "inventory_sha256": inventory["inventory_sha256"],
        "selected_shards": len(actual),
        "selected_source_bytes": total,
        "pilot_shard_excluded": excluded,
        "official_test_split_used": False,
        "training_approved": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--frame", type=Path)
    args = parser.parse_args()
    result = freeze_inventory(args.repo, args.revision, args.output)
    if args.frame:
        frame = json.loads(args.frame.read_text(encoding="utf-8"))
        print(json.dumps(verify_source_frame(result, frame)))
    print(json.dumps({
        "revision": result["revision"],
        "train_shard_count": result["train_shard_count"],
        "train_total_bytes": result["train_total_bytes"],
        "official_test_split_used": result["official_test_split_used"],
        "inventory_sha256": result["inventory_sha256"],
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
