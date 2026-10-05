"""Reproducible Assignment 02 audit, domain split, training and evaluation CLI."""

from __future__ import annotations

import argparse
import hashlib
import importlib.resources
import json
import os
import platform
import subprocess
import time
import warnings
from pathlib import Path
from typing import Sequence

import joblib
import numpy as np
import pandas as pd
import sklearn
import tldextract
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.exceptions import ConvergenceWarning

from .dataset import SCHEMA
from .feature_registry import FEATURE_SETS, FeatureExtractor, resolve_feature_set
from .randomness import load_seed_plan
from .url_cleaning import PRIVATE_SUFFIX_POLICY, clean_url, registered_domain

TEST_SEED = 2025
DEV_SEEDS = (11, 23, 37, 53, 71)
METRIC_COLUMNS = ("accuracy", "precision", "recall", "f1", "fpr", "roc_auc", "average_precision")
TARGET_SPLITS = {"train": .70, "validation": .15, "test": .15}
FEATURE_SET_NAMES = ("baseline", "no_https")
SEARCH_GRIDS = {
    "logistic_regression": ({"C": .1}, {"C": 1.0}, {"C": 10.0}),
    "decision_tree": tuple({"max_depth": depth, "min_samples_leaf": leaf}
                           for depth in (3, 5, 8, None) for leaf in (2, 10)),
    "random_forest": tuple(
        {"n_estimators": 100, "max_depth": depth, "min_samples_leaf": 1, "max_features": "sqrt"}
        for depth in (12, None)
    ),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _stable_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def _load(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype={"url_raw": str, "url_clean": str, "source": str, "registered_domain": str})
    missing = [column for column in SCHEMA if column not in frame]
    if missing:
        raise ValueError(f"dataset missing required columns: {', '.join(missing)}")
    if frame["label"].isna().any() or not frame["label"].isin([0, 1]).all():
        raise ValueError("label must contain only 0 (legitimate) and 1 (phishing)")
    frame["label"] = frame["label"].astype(int)
    if frame[list(SCHEMA)].isna().any().any():
        columns = frame[list(SCHEMA)].columns[frame[list(SCHEMA)].isna().any()].tolist()
        raise ValueError(f"dataset contains missing required values in: {', '.join(columns)}")
    invalid = []
    for index, url in frame["url_clean"].items():
        try:
            if clean_url(url) != url:
                invalid.append(f"row {index + 2}: url_clean is not normalized")
        except ValueError as exc:
            invalid.append(f"row {index + 2}: {exc}")
    if invalid:
        raise ValueError("invalid url_clean values: " + "; ".join(invalid[:5]))
    conflicts = frame.groupby("url_clean")["label"].nunique()
    if (conflicts > 1).any():
        raise ValueError("dataset contains normalized URLs with conflicting labels")
    if frame["url_clean"].duplicated().any():
        raise ValueError("dataset contains duplicate normalized URLs; audit/deduplicate before modeling")
    frame["domain_group"] = frame["url_clean"].map(registered_domain)
    if not frame["registered_domain"].eq(frame["domain_group"]).all():
        raise ValueError("stored registered_domain disagrees with the current PSL grouping")
    if frame["source"].str.strip().eq("").any():
        raise ValueError("source must not be empty")
    if any(clean_url(raw) != cleaned for raw, cleaned in zip(frame.url_raw, frame.url_clean, strict=True)):
        raise ValueError("url_raw does not normalize to url_clean")
    if (frame["domain_group"] == "").any():
        raise ValueError("one or more URLs have no deterministic domain group")
    frame["sample_id"] = frame["url_clean"].map(_stable_id)
    return frame.sort_values("sample_id").reset_index(drop=True)


def _choose_groups(frame: pd.DataFrame, fraction: float, seed: int) -> set[str]:
    """Choose groups using only size/class-balance objectives, never model scores."""
    groups = frame.groupby("domain_group").agg(size=("label", "size"), positives=("label", "sum"))
    rng = np.random.default_rng(seed)
    target_n = len(frame) * fraction
    target_p = frame.label.mean()
    best: tuple[float, set[str]] | None = None
    names = groups.index.to_numpy()
    sizes = groups["size"].to_numpy()
    positives_by_group = groups["positives"].to_numpy()
    for _ in range(500):
        order = rng.permutation(len(names))
        stop = int(np.searchsorted(np.cumsum(sizes[order]), target_n)) + 1
        selected_indices = order[:stop]
        selected = set(names[selected_indices])
        count = int(sizes[selected_indices].sum())
        positives = int(positives_by_group[selected_indices].sum())
        ratio = positives / count if count else 0
        score = abs(count / len(frame) - fraction) + abs(ratio - target_p)
        if best is None or score < best[0]:
            best = (score, selected)
    assert best is not None
    return best[1]


def make_split(frame: pd.DataFrame, test_seed: int = TEST_SEED, dev_seed: int = DEV_SEEDS[0]) -> pd.Series:
    test_groups = _choose_groups(frame, .15, test_seed)
    assignment = pd.Series("development", index=frame.index)
    assignment[frame.domain_group.isin(test_groups)] = "test"
    development = frame[assignment == "development"]
    validation_groups = _choose_groups(development, .15 / .85, dev_seed)
    assignment[development.index] = np.where(development.domain_group.isin(validation_groups), "validation", "train")
    validate_split(frame, assignment)
    return assignment


def validate_split(frame: pd.DataFrame, split: pd.Series) -> None:
    if not split.index.equals(frame.index) or split.isna().any() or set(split) != {"train", "validation", "test"}:
        raise ValueError("split must assign every row exactly once to train/validation/test")
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        if set(frame.loc[split == left, "domain_group"]) & set(frame.loc[split == right, "domain_group"]):
            raise ValueError(f"domain leakage between {left} and {right}")
        if set(frame.loc[split == left, "url_clean"]) & set(frame.loc[split == right, "url_clean"]):
            raise ValueError(f"normalized URL leakage between {left} and {right}")
    for part in ("train", "validation", "test"):
        if set(frame.loc[split == part, "label"]) != {0, 1}:
            raise ValueError(f"{part} does not contain both classes")


def _matrix(frame: pd.DataFrame, names: tuple[str, ...]) -> pd.DataFrame:
    extractor = FeatureExtractor(names)
    return pd.DataFrame([extractor.transform_one(url) for url in frame.url_clean], columns=names, index=frame.index)


def _pipeline(model: str, params: dict[str, object], names: tuple[str, ...], seed: int) -> Pipeline:
    if model not in SEARCH_GRIDS:
        raise ValueError(f"unknown model: {model}")
    preprocess = ColumnTransformer([("numeric", Pipeline([
        ("imputer", SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True)),
        ("scale", StandardScaler() if model == "logistic_regression" else "passthrough"),
    ]), list(names))], remainder="drop", verbose_feature_names_out=False)
    if model == "logistic_regression":
        classifier = LogisticRegression(C=float(params["C"]), max_iter=2000, random_state=seed)
    elif model == "decision_tree":
        classifier = DecisionTreeClassifier(
            max_depth=params["max_depth"],
            min_samples_leaf=int(params["min_samples_leaf"]),
            random_state=seed,
        )
    else:
        classifier = RandomForestClassifier(
            n_estimators=int(params["n_estimators"]),
            max_depth=params["max_depth"],
            min_samples_leaf=int(params["min_samples_leaf"]),
            max_features=str(params["max_features"]),
            random_state=seed,
            n_jobs=1,
        )
    return Pipeline([("preprocess", preprocess), ("classifier", classifier)])


def _fit(pipe: Pipeline, X: pd.DataFrame, y: pd.Series) -> Pipeline:
    # A nonconverged candidate must not silently enter the model comparison.
    with warnings.catch_warnings():
        warnings.simplefilter("error", ConvergenceWarning)
        return pipe.fit(X, y)


def _metrics(y: pd.Series, score: np.ndarray, threshold: float = .5) -> dict[str, float | int]:
    prediction = (score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    both_classes = len(set(y)) == 2
    return {"accuracy": accuracy_score(y, prediction), "precision": precision_score(y, prediction, zero_division=np.nan),
            "recall": recall_score(y, prediction, zero_division=np.nan), "f1": f1_score(y, prediction, zero_division=np.nan),
            "fpr": fp / (fp + tn) if fp + tn else np.nan,
            "roc_auc": roc_auc_score(y, score) if both_classes else np.nan,
            "average_precision": average_precision_score(y, score) if y.sum() else np.nan,
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp), "threshold": threshold}


def _git_provenance() -> dict[str, object]:
    status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, check=False).stdout
    patch = subprocess.run(["git", "diff", "--binary", "HEAD"], capture_output=True, check=False).stdout
    return {"revision": subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip(),
            "working_tree_dirty_before_run": bool(status), "status_before_run": status.splitlines(),
            "tracked_patch_sha256_before_run": hashlib.sha256(patch).hexdigest() if patch else None}


def _psl_snapshot() -> dict[str, object]:
    snapshot = Path(str(importlib.resources.files("tldextract").joinpath(".tld_set_snapshot")))
    return {"bundled_snapshot": True, "snapshot_filename": snapshot.name,
            "snapshot_sha256": _sha256(snapshot), "suffix_list_urls": [],
            "private_suffix_policy": PRIVATE_SUFFIX_POLICY}


def _audit(frame: pd.DataFrame, features: pd.DataFrame, output: Path) -> None:
    rows = []
    for label, count in frame.label.value_counts().sort_index().items(): rows.append({"section": "label", "key": str(label), "value": count})
    for (source, label), count in frame.groupby(["source", "label"]).size().items(): rows.append({"section": "source_x_label", "key": f"{source}|{label}", "value": count})
    rows += [
        {"section": "quality", "key": "rows", "value": len(frame)},
        {"section": "quality", "key": "exact_duplicate_raw", "value": int(frame.url_raw.duplicated().sum())},
        {"section": "quality", "key": "normalized_duplicate", "value": int(frame.url_clean.duplicated().sum())},
        {"section": "quality", "key": "conflicting_normalized_labels", "value": int((frame.groupby("url_clean").label.nunique() > 1).sum())},
        {"section": "quality", "key": "missing_domain", "value": int(frame.domain_group.eq("").sum())},
    ]
    for (source, label), part in frame.groupby(["source", "label"]):
        rows.append({"section": "https_rate", "key": f"{source}|{label}", "value": float(features.loc[part.index, "uses_https"].mean())})
        from urllib.parse import urlsplit
        parts = part.url_clean.map(urlsplit)
        rows.append({"section": "root_path_rate", "key": f"{source}|{label}", "value": float(parts.map(lambda p:p.path in ("", "/")).mean())})
        rows.append({"section": "query_rate", "key": f"{source}|{label}", "value": float(parts.map(lambda p:bool(p.query)).mean())})
    for name in features:
        rows.extend(({"section": "feature_missing", "key": name, "value": int(features[name].isna().sum())},
                     {"section": "feature_infinite", "key": name, "value": int(np.isinf(features[name]).sum())},
                     {"section": "feature_unique", "key": name, "value": int(features[name].nunique(dropna=True))}))
    pd.DataFrame(rows).to_csv(output / "dataset_audit.csv", index=False)
    frame.groupby("domain_group").agg(sample_count=("label", "size"), phishing_count=("label", "sum"), sources=("source", lambda x: ";".join(sorted(set(x))))).sort_values("sample_count", ascending=False).to_csv(output / "domain_groups.csv")
    features.assign(label=frame.label).groupby("label").agg(["count", "mean", "median", "std", "min", "max"]).to_csv(output / "feature_distributions.csv")
    features.corr().to_csv(output / "feature_correlations.csv")


def run(input_path: Path, output: Path, overwrite: bool = False, *,
        seed_plan: Path | None = None, feature_sets: tuple[str, ...] = FEATURE_SET_NAMES,
        evaluate_test: bool = False, development_run: Path | None = None) -> None:
    if not feature_sets or len(set(feature_sets)) != len(feature_sets) or any(name not in FEATURE_SETS for name in feature_sets):
        raise ValueError("feature_sets must contain distinct registered set names")
    seeds = load_seed_plan(seed_plan) if seed_plan else {
        "test_seed": TEST_SEED, "development_seeds": list(DEV_SEEDS), "model_seed": TEST_SEED,
        "origin": "legacy_split_seeds_with_fixed_model_seed"}
    test_seed = seeds["test_seed"]; dev_seeds = tuple(seeds["development_seeds"]); model_seed = seeds["model_seed"]
    existing = [path for path in output.glob("*") if path.name != "README.md"] if output.exists() else []
    if existing and not overwrite:
        raise FileExistsError(f"output directory already contains experiment artifacts: {output}; choose a new directory")
    if (output / "final_test_metrics.csv").exists():
        raise FileExistsError("completed test evaluation cannot be overwritten; retain its evidence")
    if existing and overwrite:
        raise FileExistsError("use a new output directory to avoid mixing experiment evidence")
    provenance = _git_provenance()
    dataset_checksum = _sha256(input_path)
    protocol = {"protocol_version": 3, "input": str(input_path), "dataset_sha256": dataset_checksum, "test_seed": test_seed,
                "development_seeds": list(dev_seeds), "model_seed": model_seed, "seed_plan": seeds,
                "evaluate_test": evaluate_test, "target_split_proportions": TARGET_SPLITS,
                "domain_grouping": {"key": "PSL-aware eTLD+1 or normalized IP", "library": "tldextract", **_psl_snapshot()},
                "feature_sets": {name: list(resolve_feature_set(name)) for name in feature_sets},
                "hyperparameter_search": SEARCH_GRIDS, "selection_metric": "mean validation F1",
                "classification_threshold": .5, "positive_class": "1=phishing",
                "implementation_sha256": {name:_sha256(Path(__file__).with_name(name)) for name in
                    ("experiment.py", "feature_registry.py", "features.py", "url_cleaning.py", "randomness.py")},
                "versions": {"python":platform.python_version(), "scikit_learn":sklearn.__version__, "numpy":np.__version__, "pandas":pd.__version__},
                "split_search": "500 random group permutations; size/class balance only, never model scores",
                "planned_final_comparisons": [f"{features}:{model}" for features in feature_sets for model in SEARCH_GRIDS]}
    if evaluate_test:
        if development_run is None:
            raise ValueError("final evaluation requires --development-run with completed frozen development evidence")
        previous = json.loads((development_run / "experiment_config.json").read_text())
        state = json.loads((development_run / "experiment_manifest.json").read_text())
        if state.get("status") != "development_complete" or state.get("test_evaluated") is not False:
            raise ValueError("development evidence is not a completed development-only run")
        comparable = lambda config: {key:value for key,value in config.items() if key not in {"input","evaluate_test"}}
        if json.dumps(comparable(previous), sort_keys=True) != json.dumps(comparable(protocol), sort_keys=True):
            raise ValueError("final protocol differs from frozen development configuration, code, or dataset")
    elif development_run is not None:
        raise ValueError("--development-run is only used with --evaluate-test")
    output.mkdir(parents=True, exist_ok=True); (output / "models").mkdir(exist_ok=True); (output / "figures").mkdir(exist_ok=True)
    (output / "experiment_config.json").write_text(json.dumps(protocol, indent=2) + "\n")
    frame = _load(input_path)
    names_union = tuple(dict.fromkeys(name for key in ("baseline", *feature_sets) for name in resolve_feature_set(key)))
    all_features = _matrix(frame, names_union)
    splits = {seed: make_split(frame, test_seed, seed) for seed in dev_seeds}
    canonical = splits[dev_seeds[0]]
    _audit(frame.loc[canonical != "test"], all_features.loc[canonical != "test"], output)
    (output / "audit_scope.json").write_text(json.dumps({"scope":"development only; test excluded from feature diagnostics"})+"\n")
    split_records = []
    for seed, split in splits.items():
        if not split.eq("test").equals(canonical.eq("test")):
            raise ValueError("test membership changed across development seeds")
        part = frame[["sample_id", "domain_group", "label", "source"]].copy()
        part["split"] = split; part["development_seed"] = seed
        part["test_seed"] = test_seed; part["dataset_checksum"] = dataset_checksum
        split_records.append(part)
    pd.concat(split_records).to_csv(output / "development_split_manifest.csv", index=False)
    manifest = frame[["sample_id", "domain_group", "label", "source"]].copy(); manifest["split"] = canonical
    manifest["random_seed"] = test_seed; manifest["dataset_checksum"] = dataset_checksum; manifest.to_csv(output / "split_manifest.csv", index=False)
    summary = manifest.groupby("split").agg(sample_count=("sample_id", "size"), phishing_count=("label", "sum"), domain_count=("domain_group", "nunique")); summary["legitimate_count"] = summary.sample_count-summary.phishing_count; summary["fraction"] = summary.sample_count/len(frame); summary.to_csv(output / "split_summary.csv")
    grids = SEARCH_GRIDS
    validation_rows = []
    best: dict[tuple[str, str], dict[str, object]] = {}
    for feature_set in feature_sets:
        names = resolve_feature_set(feature_set); X = all_features.loc[:, names]
        for model, candidates in grids.items():
            candidate_scores = []
            for params in candidates:
                scores = []
                for seed in dev_seeds:
                    split = splits[seed]; train = split == "train"; val = split == "validation"
                    pipe = _fit(_pipeline(model, params, names, model_seed), X.loc[train], frame.loc[train, "label"])
                    row = {"feature_set": feature_set, "model": model, "parameters": json.dumps(params, sort_keys=True), "seed": seed, **_metrics(frame.loc[val, "label"], pipe.predict_proba(X.loc[val])[:, 1])}
                    validation_rows.append(row); scores.append(float(row["f1"]))
                candidate_scores.append((float(np.mean(scores)), json.dumps(params, sort_keys=True), params))
            best[(feature_set, model)] = max(candidate_scores, key=lambda item: (item[0], item[1]))[2]
    validation = pd.DataFrame(validation_rows); validation.to_csv(output / "validation_seed_metrics.csv", index=False)
    validation.groupby(["feature_set", "model", "parameters"])[list(METRIC_COLUMNS)].agg(["mean", "std"]).to_csv(output / "validation_summary.csv")
    pd.DataFrame([{"feature_set": feature_set, "model": model, "parameters": json.dumps(params, sort_keys=True),
                   "selection_metric": "mean_validation_f1"} for (feature_set, model), params in best.items()]).to_csv(output / "selected_hyperparameters.csv", index=False)
    selected_rows = pd.concat([validation[(validation.feature_set == fs) & (validation.model == model) &
        (validation.parameters == json.dumps(params, sort_keys=True))] for (fs, model), params in best.items()])
    selected_rows.to_csv(output / "selected_validation_seed_metrics.csv", index=False)
    paired = selected_rows.pivot(index=["feature_set", "seed"], columns="model", values="f1").reset_index()
    reference_model = "logistic_regression"
    if reference_model not in paired:
        raise ValueError("paired validation comparison requires logistic_regression as the reference model")
    for model in grids:
        if model != reference_model:
            paired[f"{model}_minus_{reference_model}_f1"] = paired[model] - paired[reference_model]
    paired.to_csv(output / "paired_validation_comparison.csv", index=False)
    metadata = {"created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "dataset_sha256": dataset_checksum, "git_provenance_at_start": provenance,
                "seed_plan": seeds, "versions": {"python":platform.python_version(), "scikit_learn":sklearn.__version__, "tldextract":tldextract.__version__},
                "status":"development_complete", "test_evaluated":False}
    (output / "experiment_manifest.json").write_text(json.dumps(metadata, indent=2)+"\n")
    (output / "feature_schema.json").write_text(json.dumps(protocol["feature_sets"], indent=2)+"\n")
    if not evaluate_test:
        return
    for filename in ("development_split_manifest.csv", "selected_hyperparameters.csv", "validation_seed_metrics.csv"):
        if _sha256(output / filename) != _sha256(development_run / filename):
            raise ValueError(f"frozen development replay mismatch: {filename}; test remains unevaluated")
    final_rows=[]; importance_rows=[]; error_frames=[]; latency_rows=[]; prediction_frames=[]
    development = canonical != "test"; test = canonical == "test"
    for feature_set in feature_sets:
        names=resolve_feature_set(feature_set); X=all_features.loc[:, names]
        for model in grids:
            params=best[(feature_set, model)]
            train=canonical=="train"; validation_mask=canonical=="validation"
            probe=_fit(_pipeline(model,params,names,model_seed), X.loc[train],frame.loc[train,"label"])
            perm=permutation_importance(probe,X.loc[validation_mask],frame.loc[validation_mask,"label"],scoring="f1",n_repeats=10,random_state=model_seed)
            for name,value,std in zip(names,perm.importances_mean,perm.importances_std,strict=True): importance_rows.append({"feature_set":feature_set,"model":model,"method":"validation_permutation","partition":"validation","seed":model_seed,"feature":name,"importance":value,"std":std})
            pipe=_fit(_pipeline(model, params, names, model_seed), X.loc[development], frame.loc[development,"label"])
            score=pipe.predict_proba(X.loc[test])[:,1]; metric={"feature_set":feature_set,"model":model,"parameters":json.dumps(params,sort_keys=True),**_metrics(frame.loc[test,"label"],score)}; final_rows.append(metric)
            artifact={"pipeline":pipe,"feature_names":list(names),"feature_set":feature_set,"positive_class":1,"threshold":.5,"configuration":{"test_seed":test_seed,"model_seed":model_seed,"parameters":params}}
            joblib.dump(artifact,output/"models"/f"{feature_set}_{model}.joblib")
            classifier=pipe.named_steps["classifier"]
            raw=classifier.coef_[0] if model=="logistic_regression" else classifier.feature_importances_
            kind="standardized_coefficient" if model=="logistic_regression" else "impurity_importance"
            transformed_names = pipe.named_steps["preprocess"].get_feature_names_out()
            for name,value in zip(transformed_names,raw,strict=True): importance_rows.append({"feature_set":feature_set,"model":model,"method":kind,"partition":"full_development_fit","seed":model_seed,"feature":name,"importance":value})
            test_urls=frame.loc[test,"url_clean"].tolist(); test_X=X.loc[test]
            single_X=test_X.iloc[[0]]; single_url=test_urls[0]
            for _ in range(3): pipe.predict_proba(test_X); pipe.predict_proba(single_X); FeatureExtractor(names).transform_one(single_url)
            extraction=[]; inference=[]; single_extraction=[]; single_inference=[]
            for _ in range(30):
                started=time.perf_counter_ns(); [FeatureExtractor(names).transform_one(url) for url in test_urls]; extraction.append((time.perf_counter_ns()-started)/len(test_urls)/1e6)
                started=time.perf_counter_ns(); pipe.predict_proba(test_X); inference.append((time.perf_counter_ns()-started)/len(test_X)/1e6)
                started=time.perf_counter_ns(); FeatureExtractor(names).transform_one(single_url); single_extraction.append((time.perf_counter_ns()-started)/1e6)
                started=time.perf_counter_ns(); pipe.predict_proba(single_X); single_inference.append((time.perf_counter_ns()-started)/1e6)
            timings=(("feature_extraction","batch_throughput",len(test_X),extraction),("model_inference_including_preprocessing","batch_throughput",len(test_X),inference),("feature_extraction","single_request",1,single_extraction),("model_inference_including_preprocessing","single_request",1,single_inference))
            for stage,mode,batch_size,values in timings:
                latency_rows.append({"feature_set":feature_set,"model":model,"stage":stage,"mode":mode,"batch_size":batch_size,"repetitions":30,"median_ms_per_url":float(np.median(values)),"p95_ms_per_url":float(np.percentile(values,95)),"timer":"time.perf_counter_ns"})
            pred=(score>=.5).astype(int)
            predictions=frame.loc[test,["sample_id","domain_group","label","source"]].copy()
            predictions["prediction_probability"]=score; predictions["prediction"]=pred
            predictions["feature_set"]=feature_set; predictions["model"]=model
            prediction_frames.append(predictions)
            errors=frame.loc[test].copy(); errors["prediction_probability"]=score; errors["prediction"]=pred; errors=errors[errors.label!=errors.prediction]
            errors["error_type"]=np.where(errors.label==0,"false_positive","false_negative")
            errors["url_defanged_host"] = errors["url_clean"].map(lambda url: url.split(":", 1)[0].replace("http", "hxxp") + "://" + registered_domain(url).replace(".", "[.]"))
            errors["path_length"] = all_features.loc[errors.index, "path_length"]; errors["query_length"] = all_features.loc[errors.index, "query_length"]
            errors["feature_set"]=feature_set; errors["model"]=model; error_frames.append(errors[["sample_id","label","prediction","feature_set","model","error_type","source","domain_group","prediction_probability","path_length","query_length","url_defanged_host"]])
    final=pd.DataFrame(final_rows); final.to_csv(output/"final_test_metrics.csv",index=False); final.to_csv(output/"model_comparison.csv",index=False)
    pd.DataFrame(importance_rows).to_csv(output/"feature_importance.csv",index=False); pd.concat(error_frames).to_csv(output/"error_analysis.csv",index=False)
    pd.concat(prediction_frames).to_csv(output/"test_predictions.csv",index=False)
    pd.DataFrame(latency_rows).to_csv(output/"latency.csv",index=False)
    schema={name:list(resolve_feature_set(name)) for name in feature_sets}; (output/"feature_schema.json").write_text(json.dumps(schema,indent=2)+"\n")
    metadata={"created_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"input":str(input_path),"dataset_sha256":dataset_checksum,"test_seed":TEST_SEED,"development_seeds":DEV_SEEDS,"positive_class":"1=phishing","threshold":.5,"versions":{"python":platform.python_version(),"scikit_learn":sklearn.__version__,"tldextract":tldextract.__version__},"domain_parser":{"library":"tldextract",**_psl_snapshot()},"hardware":{"platform":platform.platform(),"processor":platform.processor(),"cpu_count":os.cpu_count()},"latency":{"warmup_batches":3,"measured_batches":30,"scope":"single-request and batch local URL-only; model timing includes preprocessing; not hybrid-system latency"},"git_provenance_at_start":provenance,"selection_metric":"mean validation F1; deterministic tie-break","notes":"Feature changes and parameter selection use development data only."}
    metadata.update({"test_seed":test_seed, "development_seeds":dev_seeds, "model_seed":model_seed,
                     "seed_plan":seeds, "test_evaluated":True, "status":"planned_test_comparisons_complete"})
    (output/"experiment_manifest.json").write_text(json.dumps(metadata,indent=2)+"\n")


def predict(model_path: Path, urls: list[str]) -> None:
    artifact=joblib.load(model_path); names=tuple(artifact["feature_names"]); X=pd.DataFrame([FeatureExtractor(names).transform_one(url) for url in urls],columns=names); scores=artifact["pipeline"].predict_proba(X)[:,1]
    for url,score in zip(urls,scores,strict=True): print(json.dumps({"url":url,"phishing_probability":float(score),"prediction":int(score>=artifact["threshold"])}))


def main(argv: Sequence[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest="command",required=True)
    run_parser=sub.add_parser("run"); run_parser.add_argument("--input",type=Path,default=Path("data/processed/urls.csv")); run_parser.add_argument("--output",type=Path,default=Path("results/assignment02")); run_parser.add_argument("--overwrite", action="store_true")
    run_parser.add_argument("--seed-plan", type=Path)
    run_parser.add_argument("--feature-sets", nargs="+", choices=tuple(FEATURE_SETS), default=list(FEATURE_SET_NAMES))
    run_parser.add_argument("--evaluate-test", action="store_true", help="Explicitly execute preregistered final comparisons; default is development only")
    run_parser.add_argument("--development-run", type=Path, help="Frozen completed development directory required for final evaluation")
    pred=sub.add_parser("predict"); pred.add_argument("--model",type=Path,required=True); pred.add_argument("urls",nargs="+")
    args=parser.parse_args(argv)
    if args.command=="run": run(args.input,args.output,args.overwrite, seed_plan=args.seed_plan,
                                feature_sets=tuple(args.feature_sets), evaluate_test=args.evaluate_test, development_run=args.development_run)
    else: predict(args.model,args.urls)
    return 0


if __name__ == "__main__": raise SystemExit(main())
