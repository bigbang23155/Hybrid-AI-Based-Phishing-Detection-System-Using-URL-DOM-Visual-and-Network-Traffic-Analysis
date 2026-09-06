import csv
import math
import statistics

from phishing_url.dataset import SCHEMA
from phishing_url.feature_analysis import FEATURE_SCHEMA, SUMMARY_SCHEMA, extract_dataset_features
from phishing_url.features import FEATURE_NAMES, extract_features


def _write_input(path):
    rows = [
        ["http://a.test/", "http://a.test/", 0, "legitimate", "a.test"],
        ["https://bb.test/1", "https://bb.test/1", 0, "legitimate", "bb.test"],
        ["http://login.test/", "http://login.test/", 1, "phishing", "login.test"],
        ["https://secure.test/x", "https://secure.test/x", 1, "phishing", "secure.test"],
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(SCHEMA)
        writer.writerows(rows)
    return rows


def test_feature_outputs_preserve_rows_and_schema(tmp_path):
    input_path = tmp_path / "urls.csv"
    original = _write_input(input_path)
    features_path = tmp_path / "url_features.csv"
    summary_path = tmp_path / "feature_summary.csv"
    quality_path = tmp_path / "quality.csv"

    extract_dataset_features(input_path, features_path, summary_path, quality_path, expected_per_label=2)

    with features_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    assert tuple(reader.fieldnames) == FEATURE_SCHEMA
    assert [[row[field] for field in SCHEMA] for row in rows] == [[str(value) for value in row] for row in original]
    assert len(rows) == len(original)

    with quality_path.open(newline="", encoding="utf-8") as handle:
        checks = list(csv.DictReader(handle))
    assert checks
    assert {row["status"] for row in checks} == {"pass"}
    assert {row["check"] for row in checks} >= {"row_alignment", "feature_types", "missing_values", "infinite_values"}


def test_summary_statistics_and_structure(tmp_path):
    input_path = tmp_path / "urls.csv"
    original = _write_input(input_path)
    summary_path = tmp_path / "feature_summary.csv"
    extract_dataset_features(input_path, tmp_path / "features.csv", summary_path, tmp_path / "quality.csv", 2)

    with summary_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        summaries = list(reader)
    assert tuple(reader.fieldnames) == SUMMARY_SCHEMA
    assert len(summaries) == 2 * len(FEATURE_NAMES)
    by_key = {(row["label"], row["feature"]): row for row in summaries}

    lengths = [extract_features(row[1])["url_length"] for row in original[:2]]
    numeric = by_key[("0", "url_length")]
    assert numeric["count"] == "2"
    assert math.isclose(float(numeric["mean"]), statistics.fmean(lengths))
    assert math.isclose(float(numeric["median"]), statistics.median(lengths))
    assert math.isclose(float(numeric["standard_deviation"]), statistics.stdev(lengths))
    assert float(numeric["min"]) == min(lengths)
    assert float(numeric["max"]) == max(lengths)

    binary = by_key[("0", "uses_https")]
    assert binary["count_equal_1"] == "1"
    assert float(binary["proportion_equal_1"]) == 0.5
