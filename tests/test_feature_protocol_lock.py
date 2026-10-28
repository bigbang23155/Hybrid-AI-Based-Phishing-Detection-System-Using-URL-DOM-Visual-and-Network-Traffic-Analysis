import hashlib
import json
from pathlib import Path

from phishing_url.dom_features import DEFINITIONS, REGISTRY_VERSION


def test_feature_protocol_lock():
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / "config/assignment03_feature_protocol_lock_v1.json").read_text())
    assert lock["dom_registry_version"] == REGISTRY_VERSION
    assert lock["feature_definitions"] == [list(row) for row in DEFINITIONS]
    for path, digest in lock["file_sha256"].items():
        assert hashlib.sha256((root / path).read_bytes()).hexdigest() == digest, path
