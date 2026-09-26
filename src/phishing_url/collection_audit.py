"""Audit observed legitimate URL evidence and apply a preregistered suitability gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

import pandas as pd

from .url_cleaning import registered_domain

REQUIRED = ("candidate_rank", "candidate_domain", "url_raw", "url_clean", "observed_from",
            "evidence_url", "retrieved_utc", "same_domain", "label_basis")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(observations_path: Path, failures_path: Path, output: Path,
          min_urls: int = 2_000, min_domains: int = 300, min_inner_rate: float = .20) -> dict[str, object]:
    observations = pd.read_csv(observations_path)
    missing = [name for name in REQUIRED if name not in observations]
    if missing:
        raise ValueError(f"observation table missing columns: {', '.join(missing)}")
    failures = pd.read_csv(failures_path)
    observations["domain_group"] = observations.url_clean.map(registered_domain)
    observations["uses_https"] = observations.url_clean.map(lambda value: urlsplit(value).scheme == "https")
    observations["is_inner_page"] = observations.url_clean.map(lambda value: urlsplit(value).path not in ("", "/"))
    observations["has_query"] = observations.url_clean.map(lambda value: bool(urlsplit(value).query))
    counts = {"urls": len(observations), "domains": int(observations.domain_group.nunique()),
              "candidate_domains_with_evidence": int(observations.candidate_domain.nunique()),
              "https_rate": float(observations.uses_https.mean()) if len(observations) else None,
              "inner_page_rate": float(observations.is_inner_page.mean()) if len(observations) else None,
              "query_rate": float(observations.has_query.mean()) if len(observations) else None,
              "normalized_duplicates": int(observations.url_clean.duplicated().sum()), "failures": len(failures)}
    reasons = []
    if counts["urls"] < min_urls: reasons.append(f"only {counts['urls']} observed URLs; require at least {min_urls}")
    if counts["domains"] < min_domains: reasons.append(f"only {counts['domains']} domain groups; require at least {min_domains}")
    if counts["inner_page_rate"] is None or counts["inner_page_rate"] < min_inner_rate:
        reasons.append(f"inner-page rate below preregistered {min_inner_rate:.0%} minimum")
    decision = "suitable_for_bounded_baseline_with_caveats" if not reasons else "unsuitable"
    result = {"decision": decision, "reasons": reasons, "thresholds": {"min_urls": min_urls,
              "min_domains": min_domains, "min_inner_page_rate": min_inner_rate}, "counts": counts,
              "input_sha256": {"observations": sha256(observations_path), "failures": sha256(failures_path)},
              "interpretation": "Candidate membership and public observation support an assumed-legitimate label, not verified safety."}
    output.mkdir(parents=True, exist_ok=True)
    (output / "suitability_gate.json").write_text(json.dumps(result, indent=2) + "\n")
    def reason_category(reason: object) -> str:
        text = str(reason)
        for category in ("ProxyError", "HTTPError", "ConnectTimeout", "ReadTimeout",
                         "ConnectionError", "SSLError", "ValueError"):
            if text.startswith(category):
                if "DNS failure" in text: return "dns_failure"
                if "non-public destination" in text: return "non_public_destination"
                return category
        return "other"
    failures["reason_category"] = failures.reason.map(reason_category)
    failures.groupby(["stage", "reason_category"], dropna=False).size().reset_index(name="count").sort_values("count", ascending=False).to_csv(output / "collection_failure_summary.csv", index=False)
    observations.groupby("observed_from").agg(url_count=("url_clean", "size"), domain_count=("domain_group", "nunique"),
                                               https_rate=("uses_https", "mean"), inner_page_rate=("is_inner_page", "mean"),
                                               query_rate=("has_query", "mean")).to_csv(output / "legitimate_structure_summary.csv")
    rng = random.Random(20250926); review_rows = []
    for category, subset in (("homepage", observations[~observations.is_inner_page & ~observations.has_query]),
                             ("inner_page", observations[observations.is_inner_page & ~observations.has_query]),
                             ("query", observations[observations.has_query])):
        indices = list(subset.index); chosen = rng.sample(indices, min(5, len(indices)))
        for index in chosen:
            row = observations.loc[index]
            review_rows.append({"category": category, "sample_id": hashlib.sha256(row.url_clean.encode()).hexdigest(),
                                "candidate_domain": row.candidate_domain, "observed_from": row.observed_from,
                                "review_status": "not_reviewed", "review_finding": "",
                                "note": "Seeded queue only; no human verification claimed."})
    pd.DataFrame(review_rows, columns=("category", "sample_id", "candidate_domain", "observed_from", "review_status", "review_finding", "note")).to_csv(output / "manual_review_queue.csv", index=False)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", type=Path, required=True); parser.add_argument("--failures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True); args = parser.parse_args(argv)
    result = audit(args.observations, args.failures, args.output)
    print(json.dumps(result, indent=2)); return 0 if result["decision"] != "unsuitable" else 2


if __name__ == "__main__": raise SystemExit(main())
