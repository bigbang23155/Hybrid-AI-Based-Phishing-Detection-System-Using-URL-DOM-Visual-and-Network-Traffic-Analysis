"""Assignment 03 Phase 1 diagnostics using development data only.

This module never evaluates the held-out test set. It reuses the frozen
Assignment 02/03 development split and selected hyperparameters to answer two
limited questions requested for Assignment 03:

1. Does using more of the available training data change validation performance
   or stability?
2. How different is a conventional random URL split from the domain-grouped
   split when the same development pool and fixed model choices are used?
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable

import pandas as pd
from sklearn.model_selection import train_test_split

from .experiment import (
    METRIC_COLUMNS,
    TARGET_SPLITS,
    _choose_groups,
    _fit,
    _load,
    _matrix,
    _metrics,
    _pipeline,
)
from .feature_registry import resolve_feature_set
from .randomness import derive_seed


DEFAULT_FRACTIONS = (0.25, 0.50, 0.75, 1.00)


def _selected_parameters(development: Path, feature_set: str) -> dict[str, dict[str, object]]:
    table = pd.read_csv(development / "selected_hyperparameters.csv")
    table = table[table["feature_set"] == feature_set]
    if table.empty:
        raise ValueError(f"no selected hyperparameters for feature set: {feature_set}")
    if table["model"].duplicated().any():
        raise ValueError("selected_hyperparameters.csv contains duplicate model rows")
    return {
        row.model: json.loads(row.parameters)
        for row in table.itertuples(index=False)
    }


def _assignment_for_seed(
    frame: pd.DataFrame, split_manifest: pd.DataFrame, development_seed: int
) -> pd.Series:
    part = split_manifest[split_manifest["development_seed"] == development_seed]
    if len(part) != len(frame) or part["sample_id"].duplicated().any():
        raise ValueError(f"invalid development split manifest for seed {development_seed}")
    lookup = part.set_index("sample_id")["split"]
    assignment = frame["sample_id"].map(lookup)
    if assignment.isna().any():
        raise ValueError(f"split manifest is missing samples for seed {development_seed}")
    return assignment


def _validate_fractions(fractions: Iterable[float]) -> tuple[float, ...]:
    values = tuple(float(value) for value in fractions)
    if not values or any(not 0 < value <= 1 for value in values):
        raise ValueError("training fractions must be in (0, 1]")
    if len(set(values)) != len(values):
        raise ValueError("training fractions must be distinct")
    return values


def _metric_summary(frame: pd.DataFrame, keys: list[str]) -> pd.DataFrame:
    summary = frame.groupby(keys)[list(METRIC_COLUMNS)].agg(["mean", "std"]).reset_index()
    summary.columns = [
        "_".join(str(part) for part in column if part).rstrip("_")
        if isinstance(column, tuple)
        else str(column)
        for column in summary.columns
    ]
    return summary


def run(
    dataset: Path,
    development: Path,
    output: Path,
    *,
    feature_set: str = "baseline",
    fractions: Iterable[float] = DEFAULT_FRACTIONS,
    compare_random_url_split: bool = True,
) -> None:
    if output.exists():
        raise FileExistsError("diagnostic output already exists; use a new directory")
    fractions = _validate_fractions(fractions)

    config = json.loads((development / "experiment_config.json").read_text())
    state = json.loads((development / "experiment_manifest.json").read_text())
    if state.get("status") != "development_complete" or state.get("test_evaluated") is not False:
        raise ValueError("Phase 1 diagnostics require a completed development-only experiment")

    frame = _load(dataset)
    if config["dataset_sha256"] != hashlib.sha256(dataset.read_bytes()).hexdigest():
        raise ValueError("dataset checksum differs from the frozen development run")

    split_manifest = pd.read_csv(development / "development_split_manifest.csv")
    development_seeds = tuple(int(seed) for seed in config["development_seeds"])
    model_seed = int(config["model_seed"])
    seed_base = int(config.get("seed_plan", {}).get("master_seed", model_seed))
    params_by_model = _selected_parameters(development, feature_set)
    names = resolve_feature_set(feature_set)
    X = _matrix(frame, names)

    # The held-out test membership must remain identical across every development seed.
    test_sets = []
    for seed in development_seeds:
        assignment = _assignment_for_seed(frame, split_manifest, seed)
        test_sets.append(frozenset(frame.loc[assignment == "test", "sample_id"]))
    if len(set(test_sets)) != 1:
        raise ValueError("held-out test membership changed across development seeds")
    frozen_test_ids = test_sets[0]

    size_rows: list[dict[str, object]] = []
    split_rows: list[dict[str, object]] = []
    random_validation_fraction = TARGET_SPLITS["validation"] / (
        TARGET_SPLITS["train"] + TARGET_SPLITS["validation"]
    )

    for dev_seed in development_seeds:
        assignment = _assignment_for_seed(frame, split_manifest, dev_seed)
        grouped_train = assignment == "train"
        grouped_validation = assignment == "validation"
        development_mask = assignment != "test"

        if frozenset(frame.loc[~development_mask, "sample_id"]) != frozen_test_ids:
            raise ValueError("diagnostic attempted to change held-out test membership")

        train_frame = frame.loc[grouped_train]
        for fraction in fractions:
            if fraction == 1.0:
                selected_train = grouped_train.copy()
            else:
                subset_seed = derive_seed(
                    seed_base, f"assignment03:size:{dev_seed}:{fraction:.4f}"
                )
                selected_groups = _choose_groups(train_frame, fraction, subset_seed)
                selected_train = grouped_train & frame["domain_group"].isin(selected_groups)

            if set(frame.loc[selected_train, "label"]) != {0, 1}:
                raise ValueError(
                    f"training fraction {fraction} for seed {dev_seed} does not contain both classes"
                )

            for model, params in params_by_model.items():
                pipe = _fit(
                    _pipeline(model, params, names, model_seed),
                    X.loc[selected_train],
                    frame.loc[selected_train, "label"],
                )
                score = pipe.predict_proba(X.loc[grouped_validation])[:, 1]
                size_rows.append(
                    {
                        "feature_set": feature_set,
                        "model": model,
                        "development_seed": dev_seed,
                        "training_fraction": fraction,
                        "train_rows": int(selected_train.sum()),
                        "train_domains": int(
                            frame.loc[selected_train, "domain_group"].nunique()
                        ),
                        "validation_rows": int(grouped_validation.sum()),
                        "validation_domains": int(
                            frame.loc[grouped_validation, "domain_group"].nunique()
                        ),
                        **_metrics(frame.loc[grouped_validation, "label"], score),
                    }
                )

        for model, params in params_by_model.items():
            grouped_pipe = _fit(
                _pipeline(model, params, names, model_seed),
                X.loc[grouped_train],
                frame.loc[grouped_train, "label"],
            )
            grouped_score = grouped_pipe.predict_proba(X.loc[grouped_validation])[:, 1]
            split_rows.append(
                {
                    "feature_set": feature_set,
                    "model": model,
                    "development_seed": dev_seed,
                    "split_strategy": "domain_grouped",
                    "train_rows": int(grouped_train.sum()),
                    "validation_rows": int(grouped_validation.sum()),
                    "train_domains": int(frame.loc[grouped_train, "domain_group"].nunique()),
                    "validation_domains": int(
                        frame.loc[grouped_validation, "domain_group"].nunique()
                    ),
                    "domain_overlap_count": 0,
                    **_metrics(frame.loc[grouped_validation, "label"], grouped_score),
                }
            )

        if compare_random_url_split:
            development_indices = frame.index[development_mask].to_numpy()
            random_train_idx, random_validation_idx = train_test_split(
                development_indices,
                test_size=random_validation_fraction,
                random_state=dev_seed,
                stratify=frame.loc[development_mask, "label"],
            )
            random_train = frame.index.isin(random_train_idx)
            random_validation = frame.index.isin(random_validation_idx)
            overlap = set(frame.loc[random_train, "domain_group"]) & set(
                frame.loc[random_validation, "domain_group"]
            )

            for model, params in params_by_model.items():
                pipe = _fit(
                    _pipeline(model, params, names, model_seed),
                    X.loc[random_train],
                    frame.loc[random_train, "label"],
                )
                score = pipe.predict_proba(X.loc[random_validation])[:, 1]
                split_rows.append(
                    {
                        "feature_set": feature_set,
                        "model": model,
                        "development_seed": dev_seed,
                        "split_strategy": "random_url",
                        "train_rows": int(random_train.sum()),
                        "validation_rows": int(random_validation.sum()),
                        "train_domains": int(
                            frame.loc[random_train, "domain_group"].nunique()
                        ),
                        "validation_domains": int(
                            frame.loc[random_validation, "domain_group"].nunique()
                        ),
                        "domain_overlap_count": len(overlap),
                        **_metrics(frame.loc[random_validation, "label"], score),
                    }
                )

    output.mkdir(parents=True)
    size = pd.DataFrame(size_rows)
    size.to_csv(output / "training_size_stability.csv", index=False)
    size_summary = _metric_summary(size, ["feature_set", "model", "training_fraction"])
    size_summary.to_csv(output / "training_size_summary.csv", index=False)

    split = pd.DataFrame(split_rows)
    split.to_csv(output / "split_strategy_comparison.csv", index=False)
    split_summary = _metric_summary(split, ["feature_set", "model", "split_strategy"])
    split_summary.to_csv(output / "split_strategy_summary.csv", index=False)

    metadata = {
        "scope": "development only; held-out test rows are never fit or scored",
        "feature_set": feature_set,
        "training_fractions": list(fractions),
        "models": sorted(params_by_model),
        "development_seeds": list(development_seeds),
        "model_seed": model_seed,
        "random_url_split_compared": compare_random_url_split,
        "hyperparameters": "fixed selections from the domain-grouped development run; no diagnostic reselection",
        "random_split_note": (
            "Random URL validation is a diagnostic only. Domain overlap is reported explicitly; "
            "the domain-grouped split remains the primary protocol."
        ),
        "test_sample_count_locked": len(frozen_test_ids),
    }
    (output / "diagnostic_config.json").write_text(json.dumps(metadata, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--development", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--feature-set", default="baseline")
    parser.add_argument("--fractions", type=float, nargs="+", default=list(DEFAULT_FRACTIONS))
    parser.add_argument(
        "--no-random-url-split",
        action="store_true",
        help="skip the optional conventional random URL split diagnostic",
    )
    args = parser.parse_args()
    run(
        args.dataset,
        args.development,
        args.output,
        feature_set=args.feature_set,
        fractions=args.fractions,
        compare_random_url_split=not args.no_random_url_split,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
