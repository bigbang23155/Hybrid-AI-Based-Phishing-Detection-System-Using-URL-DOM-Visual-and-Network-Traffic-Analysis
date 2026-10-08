"""Frozen development-only URL/DOM extraction and common modeling; test stays sealed."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import platform
import time

import joblib
import numpy as np
import sklearn

from .dom_features import DOMFeatureExtractor, extract_dom_features
from .feature_registry import FeatureExtractor, REGISTERED_FEATURE_NAMES
from .formal_candidates import file_sha, json_bytes, sha
from .formal_html import frozen_candidates, selected_html, numeric
from .modality_contract import (assemble_development, feature_names, make_unfitted_model,
                               read_locked_manifest, read_protocol, verify_contract)

DEVELOPMENT = ("train", "validation")


def write_json(path, value):
    path.write_bytes(json_bytes(value))


def jsonl(path, rows):
    with path.open("w") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def weighted_metrics(y, score, weights=None, threshold=.5):
    """Exact weighted binary metrics; tied scores handled as score groups.

    Used with whole-group bootstrap multiplicities, verified against sklearn.
    AP and ROC-AUC are undefined for single-class samples in this protocol.
    """
    y, s = np.asarray(y, dtype=int), np.asarray(score, dtype=float)
    w = np.ones(len(y), dtype=float) if weights is None else np.asarray(weights, dtype=float)
    if (y.ndim != 1 or s.shape != y.shape or w.shape != y.shape or not len(y)
            or not np.isin(y, [0, 1]).all() or not np.isfinite(s).all()
            or not np.isfinite(w).all() or (w < 0).any() or not w.sum()
            or (s < 0).any() or (s > 1).any()):
        raise ValueError("invalid metric input")
    pred = s >= threshold
    tp, fp = float(w[(y == 1) & pred].sum()), float(w[(y == 0) & pred].sum())
    fn, tn = float(w[(y == 1) & ~pred].sum()), float(w[(y == 0) & ~pred].sum())
    pos, neg = tp + fn, tn + fp
    div = lambda a, b: a / b if b else 0.0
    result = dict(accuracy=(tp+tn)/w.sum(), precision=div(tp, tp+fp),
                  recall=div(tp, pos), f1=div(2*tp, 2*tp+fp+fn),
                  fpr=div(fp, neg), tn=tn, fp=fp, fn=fn, tp=tp,
                  brier_score=float(np.dot(w, (s-y)**2)/w.sum()),
                  roc_auc=None, average_precision=None)
    if pos and neg:
        _, groups = np.unique(s, return_inverse=True)
        p = np.bincount(groups, weights=w*y)
        n = np.bincount(groups, weights=w*(1-y))
        result["roc_auc"] = float(np.dot(p, np.cumsum(n)-n/2)/(pos*neg))
        pc, total = np.cumsum(p[::-1]), np.cumsum((p+n)[::-1])
        precision = np.divide(pc, total, out=np.zeros_like(pc), where=total > 0)
        result["average_precision"] = float(np.dot(p[::-1], precision)/pos)
    return result


def extract_development(manifest, chosen, html_items, output):
    """Check membership before converting any supplied page to model features."""
    output.mkdir(parents=True, exist_ok=False)
    expected = {r["sample_id"]: r for r in manifest if r["partition"] in DEVELOPMENT}
    candidates = {r["sample_id"]: r for r in chosen}
    if len(candidates) != len(chosen) or set(candidates) != set(expected):
        raise ValueError("development candidate IDs mismatch")
    url_extractor, dom_extractor = FeatureExtractor(REGISTERED_FEATURE_NAMES), DOMFeatureExtractor()
    urows, drows, statuses, seen, context = [], [], [], set(), {}
    for sid, html in html_items:
        if sid not in expected or sid in seen:
            raise ValueError("unexpected/duplicate payload; test never sent to extractors")
        seen.add(sid)
        ref, source = expected[sid], candidates[sid]
        record = dict(sample_id=sid, partition=ref["partition"], extraction_status="ok")
        try:
            if not ref["eligible"] or source["label"] != ref["label"]:
                raise ValueError("eligibility/label mismatch")
            if (source["source_file"] != ref["source_file"] or source["source_row"] != ref["source_row"]
                    or sha(source["registered_domain"].encode()) != ref["registered_domain_sha256"]):
                raise ValueError("source identity/domain mismatch")
            if not isinstance(html, str) or sha(html.encode("utf-8")) != ref["html_sha256"]:
                raise ValueError("HTML hash mismatch")
            start = time.perf_counter()
            uv = dict(zip(REGISTERED_FEATURE_NAMES, url_extractor.transform_one(source["url_clean"]), strict=True))
            record["url_seconds"] = time.perf_counter()-start
            start = time.perf_counter()
            dv = extract_dom_features(html, source["url_clean"])
            dom_extractor.transform_mapping(dv)
            record["dom_seconds"] = time.perf_counter()-start
            meta = {k: ref[k] for k in ("sample_id", "partition", "label", "final_group", "html_sha256")}
            urows.append({**meta, "extraction_status": "ok", "features": uv})
            drows.append({**meta, "extraction_status": "ok", "features": dv})
            context[sid] = dict(month=(source.get("capture_date") or "missing")[:7],
                                language=str(source.get("lang") or "missing"),
                                target=str(source.get("target") or "missing"),
                                registered_domain_sha256=ref["registered_domain_sha256"],
                                html_bytes=len(html.encode("utf-8")),
                                password_present=dv["password_input_count"] > 0)
        except (ValueError, TypeError, UnicodeError, KeyError) as exc:
            record.update(extraction_status="failed", reason=type(exc).__name__ + ":" + str(exc))
        statuses.append(record)
    for sid in sorted(set(expected)-seen):
        statuses.append(dict(sample_id=sid, partition=expected[sid]["partition"], extraction_status="missing_payload"))
    jsonl(output / "extraction_status.jsonl", sorted(statuses, key=lambda r: r["sample_id"]))
    failures = sum(r["extraction_status"] != "ok" for r in statuses)
    summary = dict(expected_rows=len(expected), payloads_seen=len(seen), successes=len(urows),
                   failures=failures, test_payloads_converted_to_python=0, test_feature_rows=0,
                   no_backfill=True, schema_dimensions={m:len(feature_names(m)) for m in ("url_only", "dom_only", "url_dom")},
                   per_partition=dict(Counter(r["partition"] for r in urows)))
    write_json(output / "feature_integrity.json", summary)
    if failures:
        raise ValueError("development extraction failed; preserve records and stop before training")
    for p in DEVELOPMENT:
        assemble_development(manifest, [r for r in urows if r["partition"] == p],
                             [r for r in drows if r["partition"] == p], partition=p, modality="url_dom")
    return urows, drows, context, summary


def bootstrap_intervals(y, scores, groups, protocol):
    """Identical whole-component draws for all six cells and paired differences."""
    unique, group_idx = np.unique(groups, return_inverse=True)
    rng = np.random.default_rng(protocol["seed"])
    draws = {key: defaultdict(list) for key in scores}
    contrasts = {}
    for model in ("random_forest", "gradient_boosting"):
        for other in ("url_only", "dom_only"):
            left, right = f"{model}/url_dom/baseline", f"{model}/{other}/baseline"
            if left in scores and right in scores:
                contrasts[f"{model}/url_dom-minus-{other}"] = (left, right)
    differences = {key: defaultdict(list) for key in contrasts}
    for _ in range(protocol["resamples"]):
        multiplicity = np.bincount(rng.integers(len(unique), size=len(unique)), minlength=len(unique))
        w = multiplicity[group_idx]
        values = {key: weighted_metrics(y, score, w) for key, score in scores.items()}
        for key, metrics in values.items():
            for metric, value in metrics.items():
                if value is not None:
                    draws[key][metric].append(value)
        for key, (left, right) in contrasts.items():
            for metric in values[left]:
                a, b = values[left][metric], values[right][metric]
                if a is not None and b is not None:
                    differences[key][metric].append(a-b)
    def intervals(data):
        result = {}
        for key, metrics in data.items():
            result[key] = {}
            for name, vals in metrics.items():
                q = np.quantile(vals, [.025, .975])
                result[key][name] = dict(low=float(q[0]), high=float(q[1]), valid_replicates=len(vals))
        return result
    return dict(group_count=len(unique), resamples=protocol["resamples"], seed=protocol["seed"],
                method="paired_whole_final_group_percentile", cells=intervals(draws), paired_differences=intervals(differences))


def feature_profiles(urows, drows):
    profiles = {}
    for p in DEVELOPMENT:
        profiles[p] = {}
        for label in (0, 1):
            profile = {}
            for prefix, rows in (("url", urows), ("dom", drows)):
                selected = [r for r in rows if r["partition"] == p and r["label"] == label]
                for name in selected[0]["features"]:
                    profile[f"{prefix}__{name}"] = numeric([r["features"][name] for r in selected])
            profiles[p][str(label)] = dict(n=len(selected), numeric=profile)
    return profiles


def run_models(manifest, urows, drows, context, protocol, output):
    """No test matrix or prediction path exists; validation never enters fit."""
    output.mkdir(parents=True, exist_ok=False)
    models_dir = output.parent.parent / "private_models"
    models_dir.mkdir(exist_ok=False)
    matrices, ids, labels = {}, {}, {}
    index = {r["sample_id"]:r for r in manifest}
    conditions = [(m, "baseline") for m in ("url_only", "dom_only", "url_dom")]
    conditions += [(m, s) for s in protocol["sensitivity_url_sets"] for m in ("url_only", "url_dom")]
    for p in DEVELOPMENT:
        for modality, url_set in conditions:
            sid, values = assemble_development(manifest, [r for r in urows if r["partition"] == p],
                                              [r for r in drows if r["partition"] == p],
                                              partition=p, modality=modality, url_set=url_set)
            if p in ids and ids[p] != sid:
                raise ValueError("row-order mismatch")
            ids[p], labels[p] = sid, np.array([index[s]["label"] for s in sid], dtype=int)
            matrices[p, modality, url_set] = np.asarray(values, dtype=np.float64)
    metrics_rows, primary_scores, model_evidence = [], {}, []
    with (output / "validation_predictions.jsonl").open("w") as pred_file:
        for model in protocol["models"]:
            for modality, url_set in conditions:
                key = f"{model}/{modality}/{url_set}"
                for seed in protocol["model_seeds"]:
                    estimator = make_unfitted_model(protocol, model, seed)
                    start = time.perf_counter()
                    estimator.fit(matrices["train", modality, url_set], labels["train"])
                    fit_seconds = time.perf_counter()-start
                    assert list(estimator.classes_) == [0, 1]
                    model_path = models_dir / f"{model}-{modality}-{url_set}-{seed}.joblib"
                    joblib.dump(estimator, model_path)
                    evidence = dict(condition=key, seed=seed, fit_seconds=fit_seconds,
                                    model_sha256=file_sha(model_path), parameters=estimator.get_params(),
                                    feature_names=feature_names(modality, url_set))
                    for p in DEVELOPMENT:
                        x, y = matrices[p, modality, url_set], labels[p]
                        start = time.perf_counter()
                        score = estimator.predict_proba(x)[:, 1]
                        elapsed = time.perf_counter()-start
                        metrics_rows.append(dict(condition=key, seed=seed, partition=p, n=len(y),
                                                 **weighted_metrics(y, score, threshold=protocol["threshold"])))
                        if p == "validation":
                            warm = []
                            for _ in range(5):
                                start = time.perf_counter(); estimator.predict_proba(x)
                                warm.append(time.perf_counter()-start)
                            evidence.update(validation_batch_size=len(y), first_validation_batch_seconds=elapsed,
                                            warm_validation_batch_seconds=warm)
                            if seed == protocol["primary_model_seed"] and url_set == "baseline":
                                primary_scores[key] = score
                            for sid, label, value in zip(ids[p], y, score, strict=True):
                                row = dict(condition=key, seed=seed, sample_id=sid, label=int(label), partition=p,
                                           final_group=index[sid]["final_group"], score=float(value),
                                           predicted=int(value >= protocol["threshold"]))
                                pred_file.write(json.dumps(row, sort_keys=True)+"\n")
                    model_evidence.append(evidence)
                    print(json.dumps(dict(completed_fits=len(model_evidence), condition=key, seed=seed)), flush=True)
    with (output / "metrics.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(metrics_rows[0])); writer.writeheader(); writer.writerows(metrics_rows)
    summary = []
    for key in sorted({r["condition"] for r in metrics_rows}):
        for p in DEVELOPMENT:
            rows = [r for r in metrics_rows if r["condition"] == key and r["partition"] == p]
            summary.append(dict(condition=key, partition=p, seeds=[r["seed"] for r in rows],
                                metrics={m:dict(mean=float(np.mean([r[m] for r in rows])),
                                                std_sample=float(np.std([r[m] for r in rows], ddof=1)))
                                         for m in protocol["metrics"]}))
    write_json(output / "seed_summary.json", summary)
    write_json(output / "model_evidence.json", model_evidence)
    bootstrap = bootstrap_intervals(labels["validation"], primary_scores,
                                    [index[s]["final_group"] for s in ids["validation"]], protocol["uncertainty"])
    write_json(output / "bootstrap_intervals.json", bootstrap)
    # Only development evidence; group/domain IDs are hashes, target/language are diagnostic.
    strata, group_errors = [], []
    for key, score in primary_scores.items():
        for facet in ("month", "language", "target", "password_present"):
            values = [str(context[s][facet]) for s in ids["validation"]]
            for value in sorted(set(values)):
                mask = np.array([v == value for v in values])
                strata.append(dict(condition=key, facet=facet, value=value, n=int(mask.sum()),
                                   **weighted_metrics(labels["validation"][mask], score[mask])))
        for facet in ("final_group", "registered_domain_sha256"):
            values = [index[s][facet] if facet == "final_group" else context[s][facet] for s in ids["validation"]]
            for value in sorted(set(values)):
                mask = np.array([v == value for v in values])
                m = weighted_metrics(labels["validation"][mask], score[mask])
                group_errors.append(dict(condition=key, facet=facet, group=value, n=int(mask.sum()),
                                         fp=m["fp"], fn=m["fn"], error_count=m["fp"]+m["fn"]))
    write_json(output / "validation_strata.json", strata)
    jsonl(output / "validation_group_errors.jsonl", group_errors)
    return dict(completed_fits=len(model_evidence), metrics_rows=len(metrics_rows),
                train_rows=len(ids["train"]), validation_rows=len(ids["validation"]),
                test_feature_rows=0, test_predictions=0, test_evaluated=False,
                model_training_performed=True, fit_partition="train", threshold=protocol["threshold"],
                train_id_sha256=sha("\n".join(ids["train"]).encode()),
                validation_id_sha256=sha("\n".join(ids["validation"]).encode()),
                primary_validation=[r for r in metrics_rows if r["partition"] == "validation"
                                    and r["seed"] == protocol["primary_model_seed"] and r["condition"].endswith("/baseline")])


def run(root, source_root, output):
    if output.exists():
        raise FileExistsError("new immutable execution directory required")
    verify = verify_contract(root)
    execution = read_protocol(root / "config/assignment03_development_execution_v1.json")
    if (not execution["development_training_authorized"] or execution["test_evaluation_authorized"]
            or verify["definition_lock_sha256"] != execution["definition_lock_sha256"]):
        raise ValueError("execution authorization/definition lock mismatch")
    protocol = read_protocol(root / "config/assignment03_modeling_protocol_v1.json")
    manifest = read_locked_manifest(root / "results/assignment03/holdout_v1/partition_manifest.jsonl.gz", protocol)
    chosen, frame, _, inventory, _ = frozen_candidates(source_root,
        root / "config/assignment03_paired_source_frame_v1.json", root / "config/assignment03_paired_release_policy_v1.json",
        root / "config/assignment03_formal_candidate_freeze_v1.json")
    allowed = {r["sample_id"] for r in manifest if r["partition"] in DEVELOPMENT}
    selected = [r for r in chosen if r["sample_id"] in allowed]
    if len(selected) != execution["expected_development_rows"]:
        raise ValueError("development count mismatch before HTML")
    output.mkdir(parents=True)
    public = output / "public"; public.mkdir()
    write_json(public / "execution_state.json", dict(status="extracting", training_started=False, test_evaluated=False))
    urows, drows, context, integrity = extract_development(manifest, selected,
        selected_html(source_root, frame, selected), public / "features")
    private = output / "private_features"; private.mkdir()
    jsonl(private / "url_rows.jsonl", sorted(urows, key=lambda r:r["sample_id"]))
    jsonl(private / "dom_rows.jsonl", sorted(drows, key=lambda r:r["sample_id"]))
    write_json(public / "feature_profiles.json", feature_profiles(urows, drows))
    write_json(public / "feature_hashes.json", {p.name:file_sha(p) for p in private.iterdir()})
    write_json(public / "execution_state.json", dict(status="training", training_started=True, feature_gate_passed=True, test_evaluated=False))
    summary = run_models(manifest, urows, drows, context, protocol, public / "models")
    if summary["completed_fits"] != execution["expected_model_fits"]:
        raise ValueError("incomplete prespecified fits")
    summary.update(status="development_complete_test_sealed", feature_integrity=integrity,
                   partition_manifest_sha256=protocol["partition_manifest_sha256"],
                   definition_lock_sha256=verify["definition_lock_sha256"], source_inventory=inventory,
                   implementation_sha256=file_sha(Path(__file__)),
                   environment=dict(python=platform.python_version(), sklearn=sklearn.__version__,
                                    numpy=np.__version__, processor=platform.processor(), platform=platform.platform()),
                   original_exclusions_retained=55, sealed_test_rows=742, no_backfill=True,
                   parquet_note="Parquet pages include neighboring test rows; only development scalars are converted, inspected or featurized.",
                   model_retention=execution["fitted_model_retention"], generalization_or_robustness_demonstrated=False)
    write_json(public / "development_summary.json", summary)
    write_json(public / "execution_state.json", dict(status="complete", training_started=True, feature_gate_passed=True, test_evaluated=False))
    return summary


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(run(a.root, a.source_root, a.output), indent=2))
