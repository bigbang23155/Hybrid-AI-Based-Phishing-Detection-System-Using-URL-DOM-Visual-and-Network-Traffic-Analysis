import copy
from pathlib import Path

import pytest

from phishing_url.dom_features import extract_dom_features
from phishing_url.features import extract_features
from phishing_url.modality_contract import (
    assemble_development, feature_names, make_unfitted_model, read_locked_manifest, read_protocol,
)

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = read_protocol(ROOT / "config/assignment03_modeling_protocol_v1.json")


def example():
    m = [{"sample_id": "b", "label": 1, "partition": "train", "final_group": "g",
          "html_sha256": "hash", "eligible": True}]
    u = [{**m[0], "extraction_status": "ok", "features": extract_features("https://example.com/")}]
    d = [{**m[0], "extraction_status": "ok", "features": extract_dom_features("<form></form>", "https://example.com/")}]
    return m, u, d


def test_modality_widths_and_exact_concatenation():
    m, u, d = example()
    results = {mode: assemble_development(m, u, d, partition="train", modality=mode)[1][0]
               for mode in ("url_only", "dom_only", "url_dom")}
    assert results["url_dom"] == results["url_only"] + results["dom_only"]
    assert [len(results[x]) for x in results] == [18, 23, 41]
    assert len(feature_names("url_dom", "no_https")) == 40
    assert len(feature_names("url_dom", "hostname_only")) == 27
    assert len(set(feature_names("url_dom"))) == 41


@pytest.mark.parametrize("field,value", [("label", 0), ("final_group", "other"), ("partition", "test"),
                                       ("html_sha256", "other"), ("extraction_status", "failed")])
def test_mismatch_fails_all_modalities(field, value):
    m, u, d = example()
    d[0][field] = value
    with pytest.raises(ValueError):
        assemble_development(m, u, d, partition="train", modality="url_only")


def test_missing_duplicate_and_test_access_rejected():
    m, u, d = example()
    for rows in ([], d + d):
        with pytest.raises(ValueError):
            assemble_development(m, u, rows, partition="train", modality="url_only")
    with pytest.raises(ValueError, match="sealed"):
        assemble_development(m, u, d, partition="test", modality="url_dom")


def test_metadata_not_features_and_nonfinite_rejected():
    m, u, d = example()
    d[0]["features"]["label"] = 1
    with pytest.raises(ValueError):
        assemble_development(m, u, d, partition="train", modality="dom_only")
    m, u, d = example()
    u[0]["features"]["url_length"] = float("nan")
    with pytest.raises(ValueError):
        assemble_development(m, u, d, partition="train", modality="dom_only")


def test_locked_manifest_unchanged_and_hash_gate(tmp_path):
    m = read_locked_manifest(ROOT / "results/assignment03/holdout_v1/partition_manifest.jsonl.gz", PROTOCOL)
    assert len(m) == 5000
    assert {p: sum(r["partition"] == p for r in m) for p in PROTOCOL["sample_counts"]} == PROTOCOL["sample_counts"]
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{}\n')
    with pytest.raises(ValueError, match="digest"):
        read_locked_manifest(bad, PROTOCOL)


def test_models_unfitted_fixed_parameters_no_search():
    for name in PROTOCOL["models"]:
        for seed in PROTOCOL["model_seeds"]:
            model = make_unfitted_model(PROTOCOL, name, seed)
            assert not hasattr(model, "classes_")
            for k, v in PROTOCOL["models"][name].items():
                assert model.get_params()[k] == v
    assert make_unfitted_model(PROTOCOL, "random_forest", 4941401).class_weight is None
    with pytest.raises(ValueError):
        make_unfitted_model(PROTOCOL, "random_forest", 2025)
    assert PROTOCOL["data_access"]["test_evaluation_authorized"] is False
