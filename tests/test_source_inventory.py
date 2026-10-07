import json
from pathlib import Path
import subprocess

import pytest

from phishing_url.source_inventory import freeze_inventory, parse_lfs_pointer


def pointer(sha: str, size: int) -> str:
    return (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{sha}\n"
        f"size {size}\n"
    )


def init_repo(tmp_path: Path):
    repo = tmp_path / "source"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "data").mkdir()
    (repo / "data/train-000.parquet").write_text(pointer("a" * 64, 100))
    (repo / "data/train-001.parquet").write_text(pointer("b" * 64, 200))
    (repo / "data/test-000.parquet").write_text(pointer("c" * 64, 300))
    subprocess.run(["git", "-C", str(repo), "add", "data"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "fixture"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return repo, revision


def test_parse_lfs_pointer(tmp_path):
    path = tmp_path / "file.parquet"
    path.write_text(pointer("d" * 64, 1234))
    assert parse_lfs_pointer(path) == {"sha256": "d" * 64, "size_bytes": 1234}


def test_freeze_inventory_uses_train_only_and_records_source_test_exclusion(tmp_path):
    repo, revision = init_repo(tmp_path)
    output = tmp_path / "inventory.json"
    result = freeze_inventory(repo, revision, output)
    assert result["train_shard_count"] == 2
    assert result["train_total_bytes"] == 300
    assert result["official_test_split_used"] is False
    assert result["excluded_source_test_file_count"] == 1
    assert [row["path"] for row in result["train_shards"]] == [
        "data/train-000.parquet", "data/train-001.parquet"
    ]
    assert len(result["inventory_sha256"]) == 64
    assert json.loads(output.read_text()) == result
    with pytest.raises(FileExistsError):
        freeze_inventory(repo, revision, output)


def test_freeze_inventory_rejects_wrong_revision_and_nonpointer(tmp_path):
    repo, revision = init_repo(tmp_path)
    with pytest.raises(ValueError, match="expected"):
        freeze_inventory(repo, "0" * 40, tmp_path / "wrong.json")
    bad = tmp_path / "bad.parquet"
    bad.write_bytes(b"real payload bytes")
    with pytest.raises(ValueError, match="pointer"):
        parse_lfs_pointer(bad)
