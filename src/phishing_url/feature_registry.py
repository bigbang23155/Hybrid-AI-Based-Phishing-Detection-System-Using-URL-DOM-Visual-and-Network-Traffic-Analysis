"""Validated feature sets shared by extraction, training, and inference."""

from __future__ import annotations

from dataclasses import dataclass

from .features import FEATURE_NAMES, extract_features

METADATA_COLUMNS = frozenset(("url_raw", "url_clean", "label", "source", "registered_domain", "sample_id", "split"))

FEATURE_SETS: dict[str, tuple[str, ...]] = {
    "baseline": FEATURE_NAMES,
    "no_https": tuple(name for name in FEATURE_NAMES if name != "uses_https"),
    "hostname_only": tuple(name for name in FEATURE_NAMES if name not in {
        "path_length", "query_length", "slash_count", "question_count",
        "equals_count", "ampersand_count",
    }),
}


def validate_feature_names(names: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Validate a configurable ordered feature schema."""
    result = tuple(names)
    duplicates = sorted({name for name in result if result.count(name) > 1})
    unknown = sorted(set(result) - set(FEATURE_NAMES))
    metadata = sorted(set(result) & METADATA_COLUMNS)
    if not result:
        raise ValueError("feature set must not be empty")
    if duplicates:
        raise ValueError(f"duplicate feature names: {', '.join(duplicates)}")
    if metadata:
        raise ValueError(f"metadata columns cannot be model features: {', '.join(metadata)}")
    if unknown:
        raise ValueError(f"unknown feature names: {', '.join(unknown)}")
    return result


def resolve_feature_set(value: str) -> tuple[str, ...]:
    """Resolve a named set or comma-separated custom ordered list."""
    names = FEATURE_SETS.get(value, tuple(part.strip() for part in value.split(",") if part.strip()))
    return validate_feature_names(names)


@dataclass(frozen=True)
class FeatureExtractor:
    """Pick a stable ordered schema from the complete local extractor."""
    feature_names: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "feature_names", validate_feature_names(self.feature_names))

    def transform_one(self, url: str) -> list[float]:
        values = extract_features(url)  # invalid URL raises; it is not imputed to zero
        return [float(values[name]) for name in self.feature_names]
