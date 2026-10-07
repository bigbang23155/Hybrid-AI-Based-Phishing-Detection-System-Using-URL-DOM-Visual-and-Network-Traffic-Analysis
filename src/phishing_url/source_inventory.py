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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = freeze_inventory(args.repo, args.revision, args.output)
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
