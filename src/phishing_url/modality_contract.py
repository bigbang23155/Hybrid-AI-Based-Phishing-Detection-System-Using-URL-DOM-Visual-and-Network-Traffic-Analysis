"""Unfitted estimators and strict same-sample development matrix contracts."""
from __future__ import annotations

import json
import gzip
import hashlib
import math
from pathlib import Path

from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier

from .dom_features import DEFINITIONS, REGISTRY_VERSION, DOM_FEATURE_NAMES, DOMFeatureExtractor
from .feature_registry import FEATURE_SETS, FeatureExtractor


def feature_names(modality: str, url_set: str = "baseline") -> tuple[str, ...]:
    if modality not in ("url_only", "dom_only", "url_dom"):
        raise ValueError("unknown modality")
    if url_set not in ("baseline", "no_https", "hostname_only"):
        raise ValueError("URL set not prespecified for this protocol")
    url = tuple("url__" + name for name in FEATURE_SETS[url_set])
    dom = tuple("dom__" + name for name in DOM_FEATURE_NAMES)
    return url if modality == "url_only" else dom if modality == "dom_only" else url + dom


def make_unfitted_model(protocol: dict, model: str, seed: int):
    """Construction only. This module provides no fit/evaluate-test command."""
    if seed not in protocol["model_seeds"]:
        raise ValueError("model seed is not prespecified")
    factories = {"random_forest": RandomForestClassifier, "gradient_boosting": GradientBoostingClassifier}
    if model not in factories:
        raise ValueError("model is not prespecified")
    return factories[model](**protocol["models"][model], random_state=seed)


def _indexed(rows):
    result = {}
    for row in rows:
        sid = row["sample_id"]
        if sid in result:
            raise ValueError("duplicate sample_id")
        result[sid] = row
    return result


def assemble_development(manifest, url_rows, dom_rows, *, partition: str,
                         modality: str, url_set: str = "baseline"):
    """Every modality requires both successful feature rows, even URL-only.

    Caller must first verify the full frozen manifest digest. Inputs are in-memory
    development-only rows; this function deliberately rejects any test feature row.
    Returns sorted sample IDs and ordered finite vectors. Metadata never enters X.
    """
    if partition not in ("train", "validation"):
        raise ValueError("test is sealed; development partitions only")
    feature_names(modality, url_set)
    all_rows = _indexed(manifest)
    expected = {sid: r for sid, r in all_rows.items() if r["partition"] == partition}
    if not expected:
        raise ValueError("empty development partition")
    u, d = _indexed(url_rows), _indexed(dom_rows)
    if set(u) != set(expected) or set(d) != set(expected):
        raise ValueError("both modalities must exactly match frozen partition sample IDs")
    url_extractor = FeatureExtractor(FEATURE_SETS[url_set])
    dom_extractor = DOMFeatureExtractor()
    vectors = []
    ids = sorted(expected)
    for sid in ids:
        ref = expected[sid]
        for row in (u[sid], d[sid]):
            for field in ("label", "final_group", "partition", "html_sha256"):
                if row[field] != ref[field]:
                    raise ValueError(f"pairing metadata mismatch: {field}")
            if row["extraction_status"] != "ok":
                raise ValueError("eligible sample extraction failed; do not silently drop")
        uv = url_extractor.transform_mapping(u[sid]["features"])
        dv = dom_extractor.transform_mapping(d[sid]["features"])
        if not all(math.isfinite(v) for v in uv + dv):
            raise ValueError("all registered values must be finite")
        vectors.append(uv if modality == "url_only" else dv if modality == "dom_only" else uv + dv)
    return ids, vectors


def read_protocol(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def read_locked_manifest(path: str | Path, protocol: dict) -> list[dict]:
    """Verify the entire sanitized membership before choosing development rows."""
    path = Path(path)
    raw = path.read_bytes()
    if path.suffix == ".gz":
        raw = gzip.decompress(raw)
    if hashlib.sha256(raw).hexdigest() != protocol["partition_manifest_sha256"]:
        raise ValueError("frozen membership digest mismatch")
    return [json.loads(line) for line in raw.splitlines()]


def verify_contract(root: Path) -> dict:
    """Offline definition/integrity report, without reading any HTML or fitting."""
    lock = read_protocol(root / "config/assignment03_feature_protocol_lock_v1.json")
    for name, expected in lock["file_sha256"].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"definition lock mismatch: {name}")
    if lock["feature_definitions"] != [list(row) for row in DEFINITIONS]:
        raise ValueError("registry dictionary mismatch")
    protocol = read_protocol(root / "config/assignment03_modeling_protocol_v1.json")
    manifest = read_locked_manifest(root / "results/assignment03/holdout_v1/partition_manifest.jsonl.gz", protocol)
    counts = {p: sum(r["partition"] == p for r in manifest) for p in protocol["sample_counts"]}
    if counts != protocol["sample_counts"]:
        raise ValueError("partition count mismatch")
    return {
        "verification_passed": True, "registry_version": REGISTRY_VERSION,
        "definition_lock_sha256": hashlib.sha256((root / "config/assignment03_feature_protocol_lock_v1.json").read_bytes()).hexdigest(),
        "partition_manifest_sha256": protocol["partition_manifest_sha256"],
        "sample_counts": counts, "feature_definitions": DEFINITIONS,
        "modality_columns": {m: feature_names(m) for m in protocol["modalities"]},
        "full_model_parameters": {m: make_unfitted_model(protocol, m, protocol["primary_model_seed"]).get_params() for m in protocol["models"]},
        "formal_feature_materialization_performed": False,
        "model_training_performed": False, "test_evaluated": False,
        "generalization_or_adversarial_improvement_demonstrated": False,
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify_contract(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("Feature/protocol definitions and original membership verified; no fit or test evaluation.")
