import csv
from pathlib import Path

from phishing_url.dataset import SCHEMA
from phishing_url.ingestion import read_sources
from phishing_url.prepare import main, prepare_dataset

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_rows():
    return read_sources(
        FIXTURES / "phishtank.csv",
        FIXTURES / "openphish.txt",
        FIXTURES / "tranco.csv",
    )


def test_preparation_counts_duplicates_conflicts_and_rejections():
    result = prepare_dataset(fixture_rows(), target_per_label=2, seed=19)
    total = next(row for row in result.cleaning_summary if row["source"] == "total")
    assert total == {
        "source": "total",
        "raw_records": 16,
        "accepted_records": 4,
        "invalid_or_rejected_records": 12,
        "invalid_records": 5,
        "exact_duplicates": 1,
        "normalized_duplicates": 1,
        "conflicting_label_records": 2,
        "final_phishing": 2,
        "final_legitimate": 2,
        "unique_registered_domains": 4,
    }
    assert [(item.url_clean, item.labels, item.record_count) for item in result.conflicts] == [
        ("https://conflict.test/", "0;1", 2)
    ]
    assert {item.reason for item in result.rejected_records} >= {
        "exact_duplicate", "normalized_duplicate", "conflicting_label", "not_sampled"
    }
    by_source = {row["source"]: row for row in result.source_summary}
    assert by_source["phishtank"]["raw_records"] == 6
    assert by_source["phishtank"]["accepted_before_sampling"] == 3
    assert by_source["openphish"]["raw_records"] == 5
    assert by_source["openphish"]["accepted_before_sampling"] == 1
    assert by_source["tranco"]["raw_records"] == 5
    assert by_source["tranco"]["accepted_before_sampling"] == 3
    assert sum(row["selected_records"] for row in result.source_summary) == 4


def test_sampling_is_reproducible_and_seed_controls_selection():
    first = prepare_dataset(fixture_rows(), target_per_label=2, seed=7)
    again = prepare_dataset(fixture_rows(), target_per_label=2, seed=7)
    different = prepare_dataset(fixture_rows(), target_per_label=2, seed=8)
    assert first.records == again.records
    assert first.records != different.records


def test_cli_writes_expected_files_and_columns(tmp_path):
    raw = tmp_path / "data/raw"
    raw.mkdir(parents=True)
    for filename in ("phishtank.csv", "openphish.txt", "tranco.csv"):
        (raw / filename).write_bytes((FIXTURES / filename).read_bytes())

    assert not (tmp_path / "data/processed").exists()
    assert not (tmp_path / "reports/tables").exists()
    assert main(["--root", str(tmp_path), "--target-per-label", "2", "--seed", "19"]) == 0
    expected = {
        "data/processed/urls.csv",
        "reports/tables/cleaning_summary.csv",
        "reports/tables/source_summary.csv",
        "reports/tables/rejected_records.csv",
        "reports/tables/conflicting_labels.csv",
    }
    assert all((tmp_path / relative).is_file() for relative in expected)
    with (tmp_path / "data/processed/urls.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert tuple(rows[0]) == SCHEMA
    assert len(rows) == 4
    assert {row["label"] for row in rows} == {"0", "1"}
    with (tmp_path / "reports/tables/source_summary.csv").open(newline="", encoding="utf-8") as handle:
        source_rows = list(csv.DictReader(handle))
    assert tuple(source_rows[0]) == (
        "source",
        "label",
        "raw_records",
        "accepted_before_sampling",
        "selected_records",
        "unique_registered_domains",
    )
