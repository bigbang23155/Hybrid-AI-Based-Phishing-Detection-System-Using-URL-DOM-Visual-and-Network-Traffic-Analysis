"""Quality-gate tests use only synthetic URL/HTML fixtures."""
import csv
import json
from pathlib import Path

from phishing_url.dom_dataset import materialize_pilot, select_candidates
from phishing_url.paired_quality import audit_paired_dataset


ROOT = Path(__file__).resolve().parents[1]


def pilot_config():
    config = json.loads((ROOT / "config/assignment03_dom_pilot.json").read_text())
    config.update(
        dataset_id="synthetic_quality_fixture",
        source="synthetic_quality_fixture",
        target_candidates_per_label=24,
        per_domain_cap_per_label=1,
        technical_min_pairs_per_label=10,
        technical_min_domains_per_label=10,
    )
    return config


def metadata():
    return [
        {
            "source_row": label * 100 + i,
            "url": f"https://quality-{label}-{i}.example/page/{i}",
            "label": "phish" if label else "benign",
            "date": "2025-06-01",
            "sha256": None,
            "target": "brand" if label else None,
            "lang": "en",
            "lang_score": 0.9,
        }
        for label in (0, 1)
        for i in range(30)
    ]


def make_manifest(tmp_path):
    cfg = pilot_config()
    selected, inventory = select_candidates(metadata(), cfg)
    html = {
        row["source_row"]: (
            f'<html lang="en"><body><p>{row["sample_id"]}</p></body></html>'
        )
        for row in selected
    }
    output = tmp_path / "paired"
    materialize_pilot(selected, html, output, cfg, inventory)
    return output


def policy(tmp_path, *, frozen=False, minimum=10):
    value = json.loads((ROOT / "config/assignment03_paired_release_policy_v1.json").read_text())
    value["sampling"]["minimum_usable_pairs_per_label"] = minimum
    value["quality_gates"]["minimum_registered_domains_per_label"] = 10
    value["quality_gates"]["maximum_largest_domain_share_per_label"] = 0.20
    value["quality_gates"]["maximum_candidate_loss_rate_per_label"] = 0.10
    value["bias_review"]["root_path_rate_gap_review_threshold"] = 1.0
    value["bias_review"]["password_input_rate_gap_review_threshold"] = 1.0
    if frozen:
        value["source"]["inventory_status"] = "frozen_and_hashed"
    path = tmp_path / ("policy-frozen.json" if frozen else "policy.json")
    path.write_text(json.dumps(value))
    return path


def with_formal_split(paired: Path):
    manifest = paired / "paired_manifest.jsonl"
    rows = [json.loads(line) for line in manifest.read_text().splitlines()]
    for row in rows:
        row["formal_split"] = row["pilot_split"]
        row["lang"] = row.get("lang") or "en"
    manifest.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    )
    return rows


def test_real_policy_correctly_rejects_small_pilot_as_formal_dataset(tmp_path):
    paired = make_manifest(tmp_path)
    report = audit_paired_dataset(
        paired / "paired_manifest.jsonl",
        paired,
        ROOT / "config/assignment03_paired_release_policy_v1.json",
    )
    assert report["usable_pair_count"] == 48
    assert report["technical_gate_pass"] is False
    assert report["formal_data_ready_for_research_review"] is False
    assert report["training_approved"] is False
    assert any(
        item["code"] == "usable_pair_volume" and not item["passed"]
        for item in report["findings"]
    )


def test_relaxed_synthetic_fixture_can_reach_research_review_but_not_auto_approval(tmp_path):
    paired = make_manifest(tmp_path)
    with_formal_split(paired)
    report = audit_paired_dataset(
        paired / "paired_manifest.jsonl",
        paired,
        policy(tmp_path, frozen=True),
    )
    assert report["technical_gate_pass"] is True
    assert report["formal_partition_present"] is True
    assert report["bias_review_required"] is False
    assert report["formal_data_ready_for_research_review"] is True
    assert report["research_approval_required"] is True
    assert report["training_approved"] is False
    assert report["model_training_performed"] is False
    assert report["test_evaluated"] is False


def test_pilot_exposed_sample_is_blocked_from_new_formal_test(tmp_path):
    paired = make_manifest(tmp_path)
    rows = with_formal_split(paired)
    test_row = next(row for row in rows if row["formal_split"] == "test")
    exposed = tmp_path / "pilot-exposed.csv"
    with exposed.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["sample_id"])
        writer.writeheader()
        writer.writerow({"sample_id": test_row["sample_id"]})
    report = audit_paired_dataset(
        paired / "paired_manifest.jsonl",
        paired,
        policy(tmp_path, frozen=True),
        exposed_ids_path=exposed,
    )
    partition = next(item for item in report["findings"] if item["code"] == "final_partition_integrity")
    assert partition["passed"] is False
    assert partition["evidence"]["pilot_exposed_in_formal_test"] == 1
    assert report["formal_data_ready_for_research_review"] is False


def test_html_integrity_failure_is_critical(tmp_path):
    paired = make_manifest(tmp_path)
    rows = with_formal_split(paired)
    row = next(row for row in rows if row["usable_pair"])
    (paired / row["html_path"]).write_text("tampered")
    report = audit_paired_dataset(
        paired / "paired_manifest.jsonl",
        paired,
        policy(tmp_path, frozen=True),
    )
    assert report["hard_failures"]["html_hash_mismatches"] == 1
    assert report["technical_gate_pass"] is False


def test_formal_partition_cannot_split_same_domain(tmp_path):
    paired = make_manifest(tmp_path)
    rows = with_formal_split(paired)
    usable = [row for row in rows if row["usable_pair"]]
    first, second = usable[0], usable[1]
    second["registered_domain"] = first["registered_domain"]
    second["formal_split"] = "validation" if first["formal_split"] != "validation" else "train"
    (paired / "paired_manifest.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    )
    report = audit_paired_dataset(
        paired / "paired_manifest.jsonl",
        paired,
        policy(tmp_path, frozen=True),
    )
    partition = next(item for item in report["findings"] if item["code"] == "final_partition_integrity")
    assert partition["passed"] is False
