"""Deterministic preparation of a balanced URL dataset from local files."""

from __future__ import annotations

import argparse
import csv
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .dataset import SCHEMA, URLRecord
from .ingestion import ParsedRow, read_sources
from .url_cleaning import InvalidURLError, clean_url, registered_domain

SOURCES = ("phishtank", "openphish", "tranco")


@dataclass(frozen=True, slots=True)
class RejectedRecord:
    source: str
    row_number: int
    url_raw: str
    reason: str


@dataclass(frozen=True, slots=True)
class ConflictRecord:
    url_clean: str
    labels: str
    sources: str
    record_count: int


@dataclass(frozen=True, slots=True)
class PreparationResult:
    records: list[URLRecord]
    cleaning_summary: list[dict[str, str | int]]
    source_summary: list[dict[str, str | int]]
    rejected_records: list[RejectedRecord]
    conflicts: list[ConflictRecord]


def _reject(row: ParsedRow, reason: str) -> RejectedRecord:
    return RejectedRecord(row.source, row.row_number, row.url_raw or "", reason)


def prepare_dataset(rows: Iterable[ParsedRow], target_per_label: int = 2_000, seed: int = 42) -> PreparationResult:
    """Validate, deduplicate, remove conflicts, and deterministically balance records."""
    if target_per_label < 1:
        raise ValueError("target_per_label must be at least 1")
    input_rows = list(rows)
    rejected: list[RejectedRecord] = []
    valid: list[tuple[ParsedRow, URLRecord]] = []
    for row in input_rows:
        if row.error or row.url_raw is None:
            rejected.append(_reject(row, f"invalid: {row.error or 'missing URL'}"))
            continue
        try:
            cleaned = clean_url(row.url_raw)
        except InvalidURLError as exc:
            rejected.append(_reject(row, f"invalid: {exc}"))
            continue
        valid.append((row, URLRecord(row.url_raw, cleaned, row.label, row.source, registered_domain(cleaned))))

    groups: dict[str, list[tuple[ParsedRow, URLRecord]]] = defaultdict(list)
    for item in valid:
        groups[item[1].url_clean].append(item)

    candidates: list[URLRecord] = []
    conflicts: list[ConflictRecord] = []
    for cleaned in sorted(groups):
        group = groups[cleaned]
        labels = {record.label for _, record in group}
        if len(labels) > 1:
            conflicts.append(ConflictRecord(
                cleaned,
                ";".join(str(label) for label in sorted(labels)),
                ";".join(sorted({record.source for _, record in group})),
                len(group),
            ))
            rejected.extend(_reject(row, "conflicting_label") for row, _ in group)
            continue

        _, first_record = group[0]
        candidates.append(first_record)
        seen_raw = {first_record.url_raw}
        for row, record in group[1:]:
            reason = "exact_duplicate" if record.url_raw in seen_raw else "normalized_duplicate"
            rejected.append(_reject(row, reason))
            seen_raw.add(record.url_raw)

    by_label = {label: sorted((record for record in candidates if record.label == label), key=lambda r: (r.url_clean, r.source, r.url_raw)) for label in (0, 1)}
    sample_size = min(target_per_label, len(by_label[0]), len(by_label[1]))
    rng = random.Random(seed)
    selected: list[URLRecord] = []
    for label in (0, 1):
        indices = sorted(rng.sample(range(len(by_label[label])), sample_size))
        chosen = {by_label[label][index].url_clean for index in indices}
        selected.extend(by_label[label][index] for index in indices)
        for record in by_label[label]:
            if record.url_clean not in chosen:
                row = next(row for row, candidate in valid if candidate is record)
                rejected.append(_reject(row, "not_sampled"))
    selected.sort(key=lambda record: (record.label, record.url_clean, record.source, record.url_raw))

    accepted_counts = Counter(record.source for record in candidates)
    selected_counts = Counter(record.source for record in selected)
    reason_counts = Counter((record.source, record.reason) for record in rejected)
    conflict_counts = Counter(row.source for cleaned in {item.url_clean for item in conflicts} for row, record in valid if record.url_clean == cleaned)
    summary = []
    for source in (*SOURCES, "total"):
        source_rows = input_rows if source == "total" else [row for row in input_rows if row.source == source]
        source_records = selected if source == "total" else [record for record in selected if record.source == source]
        summary.append({
            "source": source,
            "raw_records": len(source_rows),
            "accepted_records": len(source_records),
            "invalid_or_rejected_records": len(rejected) if source == "total" else sum(1 for item in rejected if item.source == source),
            "invalid_records": sum(count for (item_source, reason), count in reason_counts.items() if (source == "total" or item_source == source) and reason.startswith("invalid:")),
            "exact_duplicates": sum(count for (item_source, reason), count in reason_counts.items() if (source == "total" or item_source == source) and reason == "exact_duplicate"),
            "normalized_duplicates": sum(count for (item_source, reason), count in reason_counts.items() if (source == "total" or item_source == source) and reason == "normalized_duplicate"),
            "conflicting_label_records": sum(conflict_counts.values()) if source == "total" else conflict_counts[source],
            "final_phishing": sum(record.label == 1 for record in source_records),
            "final_legitimate": sum(record.label == 0 for record in source_records),
            "unique_registered_domains": len({record.registered_domain for record in source_records}),
        })
    source_summary = [{
        "source": source,
        "label": 0 if source == "tranco" else 1,
        "raw_records": sum(row.source == source for row in input_rows),
        "accepted_before_sampling": accepted_counts[source],
        "selected_records": selected_counts[source],
        "unique_registered_domains": len({record.registered_domain for record in selected if record.source == source}),
    } for source in SOURCES]
    return PreparationResult(selected, summary, source_summary, rejected, conflicts)


def _write_dicts(path: Path, columns: Sequence[str], rows: Iterable[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def write_outputs(result: PreparationResult, root: str | Path = ".") -> None:
    """Write the dataset and four audit reports beneath *root*."""
    root = Path(root)
    _write_dicts(root / "data/processed/urls.csv", SCHEMA, (record.as_dict() for record in result.records))
    cleaning_columns = tuple(result.cleaning_summary[0])
    _write_dicts(root / "reports/tables/cleaning_summary.csv", cleaning_columns, result.cleaning_summary)
    _write_dicts(root / "reports/tables/source_summary.csv", tuple(result.source_summary[0]), result.source_summary)
    _write_dicts(root / "reports/tables/rejected_records.csv", tuple(RejectedRecord.__dataclass_fields__), (asdict(item) for item in result.rejected_records))
    _write_dicts(root / "reports/tables/conflicting_labels.csv", tuple(ConflictRecord.__dataclass_fields__), (asdict(item) for item in result.conflicts))


def _default_phishtank(raw_dir: Path) -> Path:
    choices = [path for path in (raw_dir / "phishtank.csv", raw_dir / "phishtank.json") if path.exists()]
    if len(choices) != 1:
        raise FileNotFoundError("place exactly one of phishtank.csv or phishtank.json in data/raw/")
    return choices[0]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="project/data root (default: current directory)")
    parser.add_argument("--target-per-label", type=int, default=2_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    raw_dir = args.root / "data/raw"
    rows = read_sources(_default_phishtank(raw_dir), raw_dir / "openphish.txt", raw_dir / "tranco.csv")
    result = prepare_dataset(rows, args.target_per_label, args.seed)
    write_outputs(result, args.root)
    print(f"Wrote {len(result.records)} records ({len(result.records) // 2} per label).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
