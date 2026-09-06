"""Extract URL-only features and produce deterministic summary tables."""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Iterable, Sequence

from .dataset import SCHEMA
from .features import BINARY_FEATURES, FEATURE_NAMES, FLOAT_FEATURES, extract_features

FEATURE_SCHEMA = (*SCHEMA, *FEATURE_NAMES)
SUMMARY_SCHEMA = (
    "label", "feature", "feature_type", "count", "mean", "median",
    "standard_deviation", "min", "max", "count_equal_1", "proportion_equal_1",
)
QUALITY_SCHEMA = ("check", "status", "value", "expected", "details")


def _write_rows(path: Path, columns: Sequence[str], rows: Iterable[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def _read_dataset(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != SCHEMA:
            raise ValueError(f"input header must be exactly {','.join(SCHEMA)}")
        rows = list(reader)
    for number, row in enumerate(rows, 2):
        if row["label"] not in ("0", "1"):
            raise ValueError(f"row {number}: label must be 0 or 1")
    return rows


def _summaries(feature_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for label in (0, 1):
        labelled = [row for row in feature_rows if row["label"] == str(label)]
        for feature in FEATURE_NAMES:
            values = [row[feature] for row in labelled]
            if feature in BINARY_FEATURES:
                ones = sum(value == 1 for value in values)
                summaries.append({
                    "label": label, "feature": feature, "feature_type": "binary",
                    "count": "", "mean": "", "median": "", "standard_deviation": "",
                    "min": "", "max": "", "count_equal_1": ones,
                    "proportion_equal_1": ones / len(values) if values else "",
                })
            else:
                numeric = [float(value) for value in values]
                summaries.append({
                    "label": label, "feature": feature, "feature_type": "numeric",
                    "count": len(numeric),
                    "mean": statistics.fmean(numeric) if numeric else "",
                    "median": statistics.median(numeric) if numeric else "",
                    "standard_deviation": statistics.stdev(numeric) if len(numeric) > 1 else 0.0,
                    "min": min(numeric) if numeric else "", "max": max(numeric) if numeric else "",
                    "count_equal_1": "", "proportion_equal_1": "",
                })
    return summaries


def extract_dataset_features(
    input_path: str | Path,
    features_path: str | Path,
    summary_path: str | Path,
    quality_path: str | Path,
    expected_per_label: int = 2_000,
) -> list[dict[str, object]]:
    """Extract features without changing dataset row order and write validation reports."""
    input_rows = _read_dataset(Path(input_path))
    feature_rows: list[dict[str, object]] = []
    type_errors: list[str] = []
    missing = 0
    infinite = 0
    for number, row in enumerate(input_rows, 2):
        features = extract_features(row["url_clean"])
        if tuple(features) != FEATURE_NAMES:
            raise ValueError(f"row {number}: extractor returned an unexpected feature schema")
        for name, value in features.items():
            expected_type = float if name in FLOAT_FEATURES else int
            if type(value) is not expected_type:
                type_errors.append(f"row {number} {name}: expected {expected_type.__name__}")
            if value is None:
                missing += 1
            elif isinstance(value, (int, float)) and not math.isfinite(value):
                infinite += 1
        feature_rows.append({**row, **features})

    aligned = all(
        tuple(output[field] for field in SCHEMA) == tuple(original[field] for field in SCHEMA)
        for original, output in zip(input_rows, feature_rows, strict=True)
    )
    class_counts = Counter(int(row["label"]) for row in feature_rows)
    checks = [
        {"check": "row_count", "status": "pass" if len(feature_rows) == len(input_rows) else "fail", "value": len(feature_rows), "expected": len(input_rows), "details": "output rows equal input rows"},
        {"check": "row_alignment", "status": "pass" if aligned else "fail", "value": str(aligned).lower(), "expected": "true", "details": "five dataset fields retain input order and values"},
        {"check": "class_count_label_0", "status": "pass" if class_counts[0] == expected_per_label else "fail", "value": class_counts[0], "expected": expected_per_label, "details": "records with label 0"},
        {"check": "class_count_label_1", "status": "pass" if class_counts[1] == expected_per_label else "fail", "value": class_counts[1], "expected": expected_per_label, "details": "records with label 1"},
        {"check": "feature_types", "status": "pass" if not type_errors else "fail", "value": len(type_errors), "expected": 0, "details": "; ".join(type_errors[:5]) or "integer and float types match the feature definitions"},
        {"check": "missing_values", "status": "pass" if missing == 0 else "fail", "value": missing, "expected": 0, "details": "missing extracted feature values"},
        {"check": "infinite_values", "status": "pass" if infinite == 0 else "fail", "value": infinite, "expected": 0, "details": "non-finite extracted feature values"},
    ]
    _write_rows(Path(quality_path), QUALITY_SCHEMA, checks)
    failures = [check["check"] for check in checks if check["status"] != "pass"]
    if failures:
        raise ValueError(f"feature validation failed: {', '.join(failures)}")
    _write_rows(Path(features_path), FEATURE_SCHEMA, feature_rows)
    _write_rows(Path(summary_path), SUMMARY_SCHEMA, _summaries(feature_rows))
    return checks


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--expected-per-label", type=int, default=2_000)
    args = parser.parse_args(argv)
    extract_dataset_features(
        args.root / "data/processed/urls.csv",
        args.root / "data/processed/url_features.csv",
        args.root / "reports/tables/feature_summary_by_label.csv",
        args.root / "reports/tables/feature_quality_summary.csv",
        args.expected_per_label,
    )
    print("Wrote URL features and feature validation summaries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
