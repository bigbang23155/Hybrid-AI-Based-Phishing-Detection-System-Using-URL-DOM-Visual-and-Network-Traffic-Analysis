"""Offline quality audit for paired URL/HTML research datasets.

This module never visits URLs, executes HTML, or trains a model.  It separates
machine-checkable data quality from the human/research approval that is required
before a formal Assignment 03 paired dataset may be used for modeling.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import date, datetime
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from .url_cleaning import clean_url, registered_domain


REQUIRED_RECORD_FIELDS = {
    "sample_id", "url_clean", "registered_domain", "label", "parse_status",
    "html_sha256", "usable_pair", "html_path", "capture_date", "source_revision",
    "source_file", "source_file_sha256",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_path(root: Path, relative: str) -> Path:
    if not relative:
        raise ValueError("empty HTML path")
    root = root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("HTML path escapes dataset root") from exc
    return path


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON at manifest line {line_number}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"manifest line {line_number} is not an object")
        rows.append(value)
    if not rows:
        raise ValueError("paired manifest is empty")
    return rows


def read_exposed_ids(path: Path | None) -> set[str]:
    if path is None:
        return set()
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if "sample_id" not in (reader.fieldnames or []):
            raise ValueError("pilot replay index has no sample_id")
        return {row["sample_id"] for row in reader if row.get("sample_id")}


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _month(value: object) -> str | None:
    if value in (None, "", "null"):
        return None
    text = str(value)
    try:
        parsed = date.fromisoformat(text[:10])
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00")).date()
        except ValueError:
            return None
    return f"{parsed.year:04d}-{parsed.month:02d}"


def _total_variation(left: Counter, right: Counter) -> float | None:
    if not left or not right:
        return None
    lt = sum(left.values())
    rt = sum(right.values())
    keys = set(left) | set(right)
    return 0.5 * sum(abs(left[k] / lt - right[k] / rt) for k in keys)


def _finding(code: str, severity: str, passed: bool, evidence: object, note: str) -> dict:
    return {
        "code": code,
        "severity": severity,
        "passed": bool(passed),
        "evidence": evidence,
        "note": note,
    }


def audit_paired_dataset(
    manifest_path: Path,
    html_root: Path,
    policy_path: Path,
    *,
    exposed_ids_path: Path | None = None,
    formal_split_field: str = "formal_split",
) -> dict:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    records = read_jsonl(manifest_path)
    exposed_ids = read_exposed_ids(exposed_ids_path)
    findings: list[dict] = []

    missing_fields = Counter()
    duplicate_sample_ids = 0
    seen_sample_ids: set[str] = set()
    invalid_urls = 0
    stored_domain_mismatches = 0
    invalid_labels = 0
    unsafe_or_missing_html = 0
    html_hash_mismatches = 0

    normalized_labels: defaultdict[str, set[int]] = defaultdict(set)
    html_labels: defaultdict[str, set[int]] = defaultdict(set)
    usable_by_label = Counter()
    selected_by_label = Counter()
    domains_by_label: defaultdict[int, Counter[str]] = defaultdict(Counter)
    months_by_label: defaultdict[int, Counter[str]] = defaultdict(Counter)
    languages_by_label: defaultdict[int, Counter[str]] = defaultdict(Counter)
    root_by_label = Counter()
    password_by_label = Counter()
    capture_missing_by_label = Counter()
    exposed_by_split = Counter()
    split_by_domain: defaultdict[str, set[str]] = defaultdict(set)
    split_by_html: defaultdict[str, set[str]] = defaultdict(set)
    formal_splits_seen = set()

    for row in records:
        for field in REQUIRED_RECORD_FIELDS:
            if field not in row:
                missing_fields[field] += 1

        sample_id = row.get("sample_id")
        if isinstance(sample_id, str):
            if sample_id in seen_sample_ids:
                duplicate_sample_ids += 1
            seen_sample_ids.add(sample_id)

        label = row.get("label")
        if label not in (0, 1):
            invalid_labels += 1
            continue
        selected_by_label[label] += 1

        url = row.get("url_clean")
        domain = row.get("registered_domain")
        try:
            normalized = clean_url(url)
            if normalized != url:
                invalid_urls += 1
            current_domain = registered_domain(url)
            if current_domain != domain:
                stored_domain_mismatches += 1
        except (TypeError, ValueError):
            invalid_urls += 1
            current_domain = None

        if isinstance(url, str):
            normalized_labels[url].add(label)

        capture_month = _month(row.get("capture_date"))
        if capture_month is None:
            capture_missing_by_label[label] += 1
        else:
            months_by_label[label][capture_month] += 1

        language = row.get("lang")
        if language not in (None, ""):
            languages_by_label[label][str(language)] += 1

        usable = row.get("usable_pair") is True
        if usable:
            usable_by_label[label] += 1
            if domain:
                domains_by_label[label][domain] += 1
            if isinstance(url, str):
                try:
                    root_by_label[label] += urlsplit(url).path in ("", "/")
                except ValueError:
                    pass
            password_by_label[label] += int((row.get("password_input_count") or 0) > 0)

            html_sha = row.get("html_sha256")
            if isinstance(html_sha, str):
                html_labels[html_sha].add(label)

            relative = row.get("html_path")
            try:
                html_path = _safe_path(html_root, relative)
                if not html_path.is_file():
                    unsafe_or_missing_html += 1
                elif html_sha and sha256_bytes(html_path.read_bytes()) != html_sha:
                    html_hash_mismatches += 1
            except (TypeError, ValueError):
                unsafe_or_missing_html += 1

        formal_split = row.get(formal_split_field)
        if formal_split not in (None, ""):
            formal_splits_seen.add(formal_split)
            if usable:
                if domain:
                    split_by_domain[domain].add(formal_split)
                html_sha = row.get("html_sha256")
                if html_sha:
                    split_by_html[html_sha].add(formal_split)
            if sample_id in exposed_ids:
                exposed_by_split[str(formal_split)] += 1

    cross_label_urls = sum(len(labels) > 1 for labels in normalized_labels.values())
    cross_label_html = sum(len(labels) > 1 for labels in html_labels.values())
    domain_split_leaks = sum(len(splits) > 1 for splits in split_by_domain.values())
    html_split_leaks = sum(len(splits) > 1 for splits in split_by_html.values())

    gates = policy["quality_gates"]
    min_pairs = int(policy["sampling"]["minimum_usable_pairs_per_label"])
    min_domains = int(gates["minimum_registered_domains_per_label"])
    max_loss = float(gates["maximum_candidate_loss_rate_per_label"])
    max_domain_share = float(gates["maximum_largest_domain_share_per_label"])
    max_date_missing = float(gates["maximum_missing_capture_date_rate_per_label"])

    per_label = {}
    for label in (0, 1):
        selected = selected_by_label[label]
        usable = usable_by_label[label]
        domain_counts = domains_by_label[label]
        per_label[str(label)] = {
            "selected": selected,
            "usable_pairs": usable,
            "candidate_loss_rate": _rate(selected - usable, selected),
            "registered_domains": len(domain_counts),
            "largest_domain_share": max(domain_counts.values(), default=0) / usable if usable else None,
            "capture_date_missing_rate": _rate(capture_missing_by_label[label], selected),
            "root_path_rate": _rate(root_by_label[label], usable),
            "password_input_rate": _rate(password_by_label[label], usable),
            "month_counts": dict(sorted(months_by_label[label].items())),
            "language_counts": dict(languages_by_label[label].most_common()),
        }

    hard_failures = {
        "missing_required_fields": sum(missing_fields.values()),
        "duplicate_sample_ids": duplicate_sample_ids,
        "invalid_labels": invalid_labels,
        "invalid_or_noncanonical_urls": invalid_urls,
        "stored_domain_mismatches": stored_domain_mismatches,
        "unsafe_or_missing_html_files": unsafe_or_missing_html,
        "html_hash_mismatches": html_hash_mismatches,
        "cross_label_normalized_url_conflicts": cross_label_urls,
        "cross_label_exact_html_conflicts": cross_label_html,
    }

    findings.append(_finding(
        "schema_and_integrity", "critical", not any(hard_failures.values()),
        hard_failures, "Required fields, canonical URL/domain data, local HTML paths, and hashes must be valid."
    ))

    volume_pass = all(per_label[str(y)]["usable_pairs"] >= min_pairs for y in (0, 1))
    findings.append(_finding(
        "usable_pair_volume", "high", volume_pass,
        {str(y): per_label[str(y)]["usable_pairs"] for y in (0, 1)},
        f"Project gate requires at least {min_pairs} usable pairs per label before formal modeling."
    ))

    domain_pass = all(per_label[str(y)]["registered_domains"] >= min_domains for y in (0, 1))
    findings.append(_finding(
        "domain_diversity", "high", domain_pass,
        {str(y): per_label[str(y)]["registered_domains"] for y in (0, 1)},
        f"Project gate requires at least {min_domains} registered domains per label."
    ))

    loss_pass = all(
        per_label[str(y)]["candidate_loss_rate"] is not None and
        per_label[str(y)]["candidate_loss_rate"] <= max_loss for y in (0, 1)
    )
    findings.append(_finding(
        "candidate_loss", "high", loss_pass,
        {str(y): per_label[str(y)]["candidate_loss_rate"] for y in (0, 1)},
        "Failures remain failures; the pipeline does not replace them after HTML inspection."
    ))

    concentration_pass = all(
        per_label[str(y)]["largest_domain_share"] is not None and
        per_label[str(y)]["largest_domain_share"] <= max_domain_share for y in (0, 1)
    )
    findings.append(_finding(
        "domain_concentration", "high", concentration_pass,
        {str(y): per_label[str(y)]["largest_domain_share"] for y in (0, 1)},
        "A small number of domains must not dominate either class."
    ))

    date_pass = all(
        per_label[str(y)]["capture_date_missing_rate"] is not None and
        per_label[str(y)]["capture_date_missing_rate"] <= max_date_missing for y in (0, 1)
    )
    findings.append(_finding(
        "capture_date_completeness", "medium", date_pass,
        {str(y): per_label[str(y)]["capture_date_missing_rate"] for y in (0, 1)},
        "Publisher dates are retained for bias review; unknown dates are not imputed."
    ))

    root_gap = None
    password_gap = None
    if all(per_label[str(y)]["root_path_rate"] is not None for y in (0, 1)):
        root_gap = abs(per_label["1"]["root_path_rate"] - per_label["0"]["root_path_rate"])
    if all(per_label[str(y)]["password_input_rate"] is not None for y in (0, 1)):
        password_gap = abs(per_label["1"]["password_input_rate"] - per_label["0"]["password_input_rate"])
    month_tv = _total_variation(months_by_label[0], months_by_label[1])
    root_threshold = float(policy["bias_review"]["root_path_rate_gap_review_threshold"])
    password_threshold = float(policy["bias_review"]["password_input_rate_gap_review_threshold"])
    bias_flags = {
        "root_path_rate_gap": root_gap,
        "root_path_review_threshold": root_threshold,
        "password_input_rate_gap": password_gap,
        "password_review_threshold": password_threshold,
        "month_distribution_total_variation": month_tv,
        "language_metadata_present": bool(languages_by_label[0] or languages_by_label[1]),
    }
    bias_review_required = (
        root_gap is None or root_gap > root_threshold or
        password_gap is None or password_gap > password_threshold or
        bool(policy["bias_review"].get("date_distribution_review_required")) or
        bool(policy["bias_review"].get("language_distribution_review_required"))
    )
    findings.append(_finding(
        "bias_review", "high", not bias_review_required, bias_flags,
        "Bias flags are review triggers, not phishing labels or automatic features."
    ))

    formal_split_complete = formal_splits_seen == {"train", "validation", "test"}
    split_pass = formal_split_complete and domain_split_leaks == 0 and html_split_leaks == 0
    if exposed_ids:
        split_pass = split_pass and exposed_by_split.get("test", 0) == 0
    findings.append(_finding(
        "final_partition_integrity", "critical", split_pass,
        {
            "formal_splits_seen": sorted(formal_splits_seen),
            "domain_split_leaks": domain_split_leaks,
            "exact_html_split_leaks": html_split_leaks,
            "pilot_exposed_ids_supplied": len(exposed_ids),
            "pilot_exposed_in_formal_test": exposed_by_split.get("test", 0),
        },
        "The final holdout is created only after dataset freeze; pilot-exposed samples may not enter it."
    ))

    source_inventory_frozen = policy["source"].get("inventory_status") == "frozen_and_hashed"
    findings.append(_finding(
        "source_inventory_freeze", "critical", source_inventory_frozen,
        {"status": policy["source"].get("inventory_status"), "revision": policy["source"].get("revision")},
        "The exact set of source train shards and their hashes must be frozen before formal candidate selection."
    ))

    technical_gate_pass = all(
        item["passed"] for item in findings
        if item["code"] in {
            "schema_and_integrity", "usable_pair_volume", "domain_diversity",
            "candidate_loss", "domain_concentration", "capture_date_completeness",
        }
    )
    formal_data_ready_for_research_review = (
        technical_gate_pass and
        source_inventory_frozen and
        split_pass and
        not bias_review_required
    )

    return {
        "schema_version": "paired-quality-audit-v1",
        "dataset_id": policy["dataset_id"],
        "manifest_sha256": sha256_bytes(manifest_path.read_bytes()),
        "record_count": len(records),
        "usable_pair_count": sum(usable_by_label.values()),
        "per_label": per_label,
        "hard_failures": hard_failures,
        "findings": findings,
        "bias_review_required": bias_review_required,
        "technical_gate_pass": technical_gate_pass,
        "formal_partition_present": formal_split_complete,
        "formal_data_ready_for_research_review": formal_data_ready_for_research_review,
        "training_approved": False,
        "research_approval_required": True,
        "model_training_performed": False,
        "test_evaluated": False,
        "interpretation": (
            "An automated pass can only make a dataset ready for research review. "
            "It never grants training approval or validates real-world phishing performance."
        ),
    }


def write_public_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--html-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--pilot-exposed-index", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit_paired_dataset(
        args.manifest, args.html_root, args.policy,
        exposed_ids_path=args.pilot_exposed_index,
    )
    if args.output.exists():
        raise FileExistsError("quality report output already exists")
    args.output.mkdir(parents=True)
    write_public_report(args.output / "quality_report.json", report)
    print(json.dumps({
        "dataset_id": report["dataset_id"],
        "technical_gate_pass": report["technical_gate_pass"],
        "formal_partition_present": report["formal_partition_present"],
        "bias_review_required": report["bias_review_required"],
        "formal_data_ready_for_research_review": report["formal_data_ready_for_research_review"],
        "training_approved": report["training_approved"],
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
