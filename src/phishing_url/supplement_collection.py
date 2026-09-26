"""One fixed supplemental batch; preserve and verify the first cloud collection."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

from .legitimate_collection import read_candidates, run as collect
from .url_cleaning import registered_domain

TRANCO_SHA = "831476d0f554af0a5164d6977acc85c95b4cc176b47366be3caa3227f5e63f90"
PRIOR_HASHES = {
    "observed_legitimate_urls.csv": "bb324d27f1e6fc945510303c79f2695fe2aeb1b3af6f1481a2554968f5d5a21a",
    "collection_failures.csv": "1bbb422912e0fd40d7949c4b031c8962207fdc2fa12512852fab668f3cf3d019",
}
PRIOR_RUN = 36224465694
SUPPLEMENT_SEED = 2026092602
BATCH_SIZE = 600


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_table(path):
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        return list(reader.fieldnames or []), list(reader)


def write_table(path, fields, rows):
    with Path(path).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def supplemental_sample(rows, original, size=BATCH_SIZE, seed=SUPPLEMENT_SEED):
    """Exclude every original candidate group, including unsuccessful domains."""
    group = lambda domain: registered_domain("https://" + domain + "/")
    excluded = {group(domain) for _, domain in original}
    # One candidate per remaining registrable domain; best rank is deterministic.
    remaining = {}
    for rank, domain in sorted(rows):
        key = group(domain)
        if key not in excluded:
            remaining.setdefault(key, (rank, domain))
    pool = sorted(remaining.values())
    if len(pool) < size:
        raise ValueError("Insufficient new domain groups for fixed batch")
    return sorted(random.Random(seed).sample(pool, size))


def merge_tables(prior, supplement, output):
    output.mkdir(parents=True, exist_ok=False)
    fields, original = read_table(prior / "observed_legitimate_urls.csv")
    new_fields, new = read_table(supplement / "observed_legitimate_urls.csv")
    if fields != new_fields:
        raise ValueError("Observation schemas differ")
    groups = lambda rows: {registered_domain(row["url_clean"]) for row in rows}
    if groups(original) & groups(new):
        raise ValueError("Supplement overlaps original observed domain groups")
    merged, provenance, seen = [], [], set()
    for batch, rows in (("original", original), ("supplement", new)):
        for row in rows:
            url = row["url_clean"]
            retained = url not in seen
            provenance.append({"url_sha256": hashlib.sha256(url.encode()).hexdigest(),
                               "batch": batch, "retained": retained})
            if retained:
                seen.add(url)
                merged.append(row)
    if max(Counter(registered_domain(r["url_clean"]) for r in merged).values(), default=0) > 3:
        raise ValueError("Combined per-domain cap exceeded")
    write_table(output / "observed_legitimate_urls.csv", fields, merged)
    write_table(output / "provenance.csv", ["url_sha256", "batch", "retained"], provenance)
    ffields, failures = read_table(prior / "collection_failures.csv")
    nfields, new_failures = read_table(supplement / "collection_failures.csv")
    if ffields != nfields:
        raise ValueError("Failure schemas differ")
    write_table(output / "collection_failures.csv", ffields, failures + new_failures)
    summary = {"original_urls": len(original), "supplement_urls": len(new),
               "merged_urls": len(merged), "duplicates_removed": len(original) + len(new) - len(merged),
               "original_failures": len(failures), "supplement_failures": len(new_failures),
               "prior_run_id": PRIOR_RUN, "training_performed": False,
               "input_sha256": {f"{batch}/{name}": digest(folder / name)
                   for batch, folder in (("original", prior), ("supplement", supplement))
                   for name in PRIOR_HASHES}}
    (output / "merge_manifest.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tranco", required=True, type=Path)
    parser.add_argument("--prior", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    if digest(args.tranco) != TRANCO_SHA:
        raise ValueError("Frozen Tranco checksum mismatch")
    for name, expected in PRIOR_HASHES.items():
        if digest(args.prior / name) != expected:
            raise ValueError(f"Prior evidence checksum mismatch: {name}")
    original = read_candidates(args.tranco, 1001, 100000, 1200, 20250926)
    with args.tranco.open(newline="", encoding="utf-8-sig") as stream:
        pool = [(int(r[0]), r[1].strip().lower()) for r in csv.reader(stream)
                if len(r) >= 2 and r[0].isdigit() and 1001 <= int(r[0]) <= 100000]
    selected = supplemental_sample(pool, original)
    args.output.mkdir(parents=True, exist_ok=False)
    candidate_path = args.output / "supplement_candidates.csv"
    write_table(candidate_path, ["rank", "domain"],
                [{"rank": rank, "domain": domain} for rank, domain in selected])
    write_table(args.output / "original_candidates.csv", ["rank", "domain"],
                [{"rank": rank, "domain": domain} for rank, domain in original])
    plan = {"prior_run_id": PRIOR_RUN, "prior_input_sha256": PRIOR_HASHES,
            "tranco_sha256": TRANCO_SHA, "original_seed": 20250926,
            "supplement_seed": SUPPLEMENT_SEED, "new_domain_groups": BATCH_SIZE,
            "rank_range": [1001, 100000], "per_domain_cap": 3,
            "candidate_sha256": digest(candidate_path),
            "policy": "Fixed 600-domain extension after URL-count shortfall; no model results inspected; no replacements or early stopping.",
            "limitations": "Adaptive sample-size extension; source, collection-success and temporal selection effects remain. Basic gate is not Dataset v2 approval."}
    (args.output / "supplement_plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    if args.prepare_only:
        return 0
    supplement = args.output / "supplement"
    collect(argparse.Namespace(tranco=candidate_path, output=supplement,
            seed=SUPPLEMENT_SEED, rank_min=1001, rank_max=100000,
            domains=BATCH_SIZE, per_domain_cap=3, timeout=4.0, workers=20, request_delay=.25))
    summary = merge_tables(args.prior, supplement, args.output / "combined")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
