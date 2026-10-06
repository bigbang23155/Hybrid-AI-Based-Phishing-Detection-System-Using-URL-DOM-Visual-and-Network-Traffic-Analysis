"""Offline paired URL/HTML dataset preparation; never visit URLs or execute HTML.

This is a bounded data-feasibility pilot, not model training or final dataset approval.
The Parquet adapter reads published HTML strings, not live webpages or model features.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import platform
from urllib.parse import urlsplit

import pandas as pd

from .experiment import make_split
from .url_cleaning import clean_url, registered_domain


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


class MarkupProbe(HTMLParser):
    """Tolerant syntax probe, not browser rendering or semantic validation."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.counts = Counter()

    def handle_starttag(self, tag, attrs):
        self.counts["tag_count"] += 1
        if tag in {"form", "script", "iframe"}:
            self.counts[tag + "_count"] += 1
        if tag == "input" and str(dict(attrs).get("type", "")).lower() == "password":
            self.counts["password_input_count"] += 1


def probe_html(value: object, max_bytes: int) -> dict:
    if not isinstance(value, str) or not value.strip():
        return {"parse_status": "missing_html", "html_sha256": None}
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        return {"parse_status": "encoding_error", "html_sha256": None}
    result = {"html_sha256": digest(raw), "html_bytes": len(raw)}
    if len(raw) > max_bytes:
        return {**result, "parse_status": "oversize_html"}
    try:
        parser = MarkupProbe()
        parser.feed(value)
        parser.close()
    except (ValueError, AssertionError, RecursionError):
        return {**result, "parse_status": "parse_error"}
    counts = {key: int(parser.counts[key]) for key in
              ("tag_count", "form_count", "password_input_count", "script_count", "iframe_count")}
    return {**result, **counts, "parse_status": "parsed_markup" if counts["tag_count"] else "no_markup"}


def select_candidates(metadata: list[dict], config: dict) -> tuple[list[dict], dict]:
    """Freeze source-row membership before HTML inspection; never backfill failures."""
    target = config["target_candidates_per_label"]
    cap = config["per_domain_cap_per_label"]
    if type(target) is not int or target < 1 or type(cap) is not int or cap < 1:
        raise ValueError("positive integer sample target and domain cap required")
    if type(config["sampling_seed"]) is not int:
        raise ValueError("an explicit integer sampling seed is required")
    if len({row["source_row"] for row in metadata}) != len(metadata):
        raise ValueError("duplicate source row identifiers")
    rejected = Counter()
    by_url = defaultdict(list)
    for row in metadata:
        if row.get("label") not in config["label_mapping"]:
            rejected["unknown_source_label"] += 1
            continue
        raw = row.get("url")
        if not isinstance(raw, str):
            rejected["missing_url"] += 1
            continue
        try:
            url = clean_url(raw)
            domain = registered_domain(url)
            if not domain:
                raise ValueError("missing domain")
        except ValueError:
            rejected["invalid_or_schemeless_url"] += 1
            continue
        row_id = int(row["source_row"])
        sample_id = digest(f'{config["source_file_sha256"]}:{row_id}'.encode())
        date = row.get("date")
        if hasattr(date, "isoformat"):
            date = date.isoformat()
        by_url[url].append({
            "sample_id": sample_id, "source_row": row_id,
            "url_raw": raw, "url_clean": url, "registered_domain": domain,
            "source_label": row["label"], "label": config["label_mapping"][row["label"]],
            "source": config["source"], "capture_date": str(date) if date is not None else None,
            "source_sample_id": row.get("sha256"),
        })
    unique = []
    for records in by_url.values():
        if len({r["label"] for r in records}) > 1:
            rejected["conflicting_url_label"] += len(records)
        else:
            unique.append(min(records, key=lambda r: r["sample_id"]))
            rejected["duplicate_normalized_url"] += len(records) - 1
    chosen = []
    for label in (0, 1):
        candidates = sorted((r for r in unique if r["label"] == label), key=lambda r:
                            digest(f'{config["sampling_seed"]}:{r["sample_id"]}'.encode()))
        counts = Counter()
        selected = []
        for row in candidates:
            if counts[row["registered_domain"]] < cap:
                selected.append(row)
                counts[row["registered_domain"]] += 1
            if len(selected) == target:
                break
        chosen.extend(selected)
    chosen.sort(key=lambda r: r["sample_id"])
    audit = {"source_rows": len(metadata), "unique_eligible_url_rows": len(unique),
             "metadata_exclusions": dict(rejected),
             "selected_per_label": {str(y): sum(r["label"] == y for r in chosen) for y in (0, 1)},
             "selection_precedes_html_inspection": True, "failed_candidate_replacement": False}
    return chosen, audit


def leakage_groups(records: list[dict]) -> dict[str, str]:
    """Connect original/final domains and identical HTML, including transitive links."""
    parent = {r["sample_id"]: r["sample_id"] for r in records}
    if len(parent) != len(records):
        raise ValueError("duplicate sample_id")
    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        a, b = root(a), root(b)
        if a != b:
            parent[max(a, b)] = min(a, b)
    first = {}
    for row in records:
        keys = [("domain", row["registered_domain"]), ("html", row["html_sha256"])]
        if row.get("final_url"):
            keys.append(("domain", registered_domain(clean_url(row["final_url"]))))
        for key in keys:
            if key[1]:
                if key in first:
                    union(row["sample_id"], first[key])
                else:
                    first[key] = row["sample_id"]
    return {sample: root(sample) for sample in parent}


def grouped_partitions(records: list[dict], test_seed: int, development_seed: int) -> dict[str, str]:
    groups = leakage_groups(records)
    frame = pd.DataFrame(sorted(records, key=lambda r: r["sample_id"]))
    if frame.empty:
        raise ValueError("no usable pairs for splitting")
    frame["domain_group"] = frame.sample_id.map(groups)
    split = make_split(frame, test_seed, development_seed)
    return dict(zip(frame.sample_id, split, strict=True))


def materialize_pilot(chosen: list[dict], html_by_row: dict, output: Path, config: dict,
                      inventory: dict) -> dict:
    if output.exists():
        raise FileExistsError("pilot output exists; preserve evidence and use a new directory")
    if config.get("training_approved") is not False:
        raise ValueError("this module only produces unapproved pilot data")
    output.mkdir(parents=True)
    (output / "html").mkdir()
    public = output / "public"
    public.mkdir()
    rows = []
    for selected in chosen:
        html = html_by_row.get(selected["source_row"])
        result = probe_html(html, config["max_html_bytes"])
        record = {**selected, **result, "schema_version": "paired-html-pilot-v1",
                  "label_basis": config["label_policy"], "project_adjudication": "not_performed",
                  "source_revision": config["revision"], "source_file": config["source_file"],
                  "source_file_sha256": config["source_file_sha256"],
                  "final_url": None, "redirect_chain": None, "http_status": None,
                  "source_verification_time": None, "html_path": None,
                  "representation": "UTF-8 serialization of publisher HTML string; not newly captured bytes",
                  "usable_pair": result["parse_status"] == "parsed_markup", "training_approved": False}
        if record["usable_pair"]:
            name = "html/" + record["html_sha256"] + ".html.txt"
            (output / name).write_bytes(html.encode("utf-8"))
            record["html_path"] = name
        rows.append(record)
    labels_by_content = defaultdict(set)
    for row in rows:
        if row["usable_pair"]:
            labels_by_content[row["html_sha256"]].add(row["label"])
    for row in rows:
        if row["usable_pair"] and len(labels_by_content[row["html_sha256"]]) > 1:
            row["usable_pair"] = False
            row["parse_status"] = "conflicting_identical_html_labels"
    usable = [r for r in rows if r["usable_pair"]]
    groups = leakage_groups(usable)
    split, split_error = {}, None
    try:
        split = grouped_partitions(usable, config["test_seed"], config["development_seed"])
    except ValueError as exc:
        split_error = str(exc)
    for row in rows:
        row["leakage_group"] = groups.get(row["sample_id"])
        row["pilot_split"] = split.get(row["sample_id"])
    manifest_bytes = "".join(json.dumps(r, sort_keys=True, allow_nan=False) + "\n" for r in rows).encode()
    (output / "paired_manifest.jsonl").write_bytes(manifest_bytes)
    fields = ["sample_id", "source_row", "label", "parse_status", "html_sha256", "usable_pair",
              "leakage_group", "pilot_split"]
    pd.DataFrame([{k: r.get(k) for k in fields} for r in rows], columns=fields).to_csv(
        public / "replay_index.csv", index=False)
    per_label = {}
    for label in (0, 1):
        part = [r for r in usable if r["label"] == label]
        n = len(part)
        per_label[str(label)] = {
            "usable_pairs": n, "domains": len({r["registered_domain"] for r in part}),
            "password_input_rate": sum(r["password_input_count"] > 0 for r in part) / n if n else None,
            "homepage_url_rate": sum(urlsplit(r["url_clean"]).path in ("", "/") for r in part) / n if n else None,
            "capture_date_missing": sum(r["capture_date"] is None for r in part),
        }
    technical_pass = bool(split) and all(
        p["usable_pairs"] >= config["technical_min_pairs_per_label"] and
        p["domains"] >= config["technical_min_domains_per_label"] for p in per_label.values())
    summary = {
        "dataset_id": config["dataset_id"], "status": "technical_pilot_pass" if technical_pass else "technical_pilot_inadequate",
        "source_inventory": inventory, "candidate_count": len(chosen), "usable_pairs": len(usable),
        "status_counts": dict(Counter(r["parse_status"] for r in rows)), "per_label": per_label,
        "distinct_html": len({r["html_sha256"] for r in usable}), "leakage_components": len(set(groups.values())),
        "pilot_split_counts": dict(Counter(split.values())), "split_error": split_error,
        "paired_manifest_sha256": digest(manifest_bytes), "source_file_sha256": config["source_file_sha256"],
        "config_sha256": digest(json.dumps(config, sort_keys=True).encode()),
        "source_revision": config["revision"], "implementation_sha256": digest(Path(__file__).read_bytes()),
        "python_version": platform.python_version(), "training_approved": False,
        "model_training_performed": False, "test_evaluated": False, "final_dom_dataset_frozen": False,
        "limitations": [
            "A small convenience shard pilot is not a representative benchmark or the authors' evaluation protocol.",
            "Source labels are retained, not independently adjudicated by this project. Live-pilot label-policy-v1 is unchanged.",
            "Parsing nonempty markup does not establish that a page is genuine, malicious, or a complete rendered DOM.",
            "Unknown redirects, HTTP statuses and source verification times remain null. No live requests recover them.",
            "All descriptive pilot diagnostics are exploratory; do not call the pilot holdout a fresh final study holdout.",
            "A final dataset needs separate sampling approval, review exclusions and a new untouched domain-grouped test.",
            "Exact HTML/domain grouping does not remove all near-template, campaign, hosting or temporal leakage.",
            "Candidate losses are retained without replacements. Numerical gates are project heuristics."
        ],
    }
    write_json(public / "pilot_summary.json", summary)
    write_json(public / "source_protocol.json", config)
    return summary


def run(parquet: Path, output: Path, config_path: Path) -> dict:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if output.exists():
        raise FileExistsError("pilot output exists")
    if parquet.stat().st_size > config["max_download_bytes"]:
        raise ValueError("source file exceeds the predeclared size bound")
    if digest(parquet.read_bytes()) != config["source_file_sha256"]:
        raise ValueError("source checksum mismatch; no source substitution allowed")
    import pyarrow.parquet as pq
    source = pq.ParquetFile(parquet)
    required = {"url", "html", "label", "date", "sha256"}
    if not required.issubset(source.schema_arrow.names):
        raise ValueError("published file does not have the required paired URL/HTML schema")
    metadata = source.read(columns=["url", "label", "date", "sha256"]).to_pylist()
    for index, row in enumerate(metadata):
        row["source_row"] = index
    chosen, inventory = select_candidates(metadata, config)
    selected_indices = {r["source_row"] for r in chosen}
    html_by_row = {}
    offset = 0
    for batch in source.iter_batches(batch_size=8, columns=["html"]):
        for local_index, row in enumerate(batch.to_pylist()):
            if offset + local_index in selected_indices:
                html_by_row[offset + local_index] = row["html"]
        offset += batch.num_rows
    if offset != len(metadata):
        raise ValueError("metadata/content row alignment changed")
    return materialize_pilot(chosen, html_by_row, output, config, inventory)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--parquet", type=Path, required=True)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = run(args.parquet, args.output, args.config)
    print(json.dumps({k: result[k] for k in ("dataset_id", "status", "candidate_count", "usable_pairs", "training_approved")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
