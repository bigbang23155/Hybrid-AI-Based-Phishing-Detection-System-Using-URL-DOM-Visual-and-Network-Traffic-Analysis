"""Validated feature sets shared by extraction, training, and inference."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Mapping
from urllib.parse import urlsplit

from .features import FEATURE_NAMES, extract_features
from .url_cleaning import clean_url

EXTRA_FEATURE_NAMES = ("hostname_digit_ratio", "percent_encoded_count", "has_nondefault_port")
REGISTERED_FEATURE_NAMES = FEATURE_NAMES + EXTRA_FEATURE_NAMES

METADATA_COLUMNS = frozenset(("url_raw", "url_clean", "label", "source", "registered_domain", "sample_id", "split"))

FEATURE_SETS: dict[str, tuple[str, ...]] = {
    "baseline": FEATURE_NAMES,
    "no_https": tuple(name for name in FEATURE_NAMES if name != "uses_https"),
    "compact16": tuple(name for name in FEATURE_NAMES if name not in {"uses_https", "suspicious_keyword_count"}),
    "expanded21": REGISTERED_FEATURE_NAMES,
    "hostname_only": ("hostname_length", "subdomain_count", "is_ip_hostname", "hostname_digit_ratio"),
}


def validate_feature_names(names: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Validate a configurable ordered feature schema."""
    result = tuple(names)
    duplicates = sorted({name for name in result if result.count(name) > 1})
    unknown = sorted(set(result) - set(REGISTERED_FEATURE_NAMES))
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
        if set(self.feature_names) & set(EXTRA_FEATURE_NAMES):
            cleaned = clean_url(url); parts = urlsplit(cleaned); host = parts.hostname or ""
            values.update({"hostname_digit_ratio": sum(c.isdecimal() for c in host) / len(host),
                           "percent_encoded_count": len(re.findall(r"%[0-9A-Fa-f]{2}", cleaned)),
                           "has_nondefault_port": int(parts.port is not None)})
        return [float(values[name]) for name in self.feature_names]

    def transform_mapping(self, values: Mapping[str, object], *, allow_missing: bool = False) -> list[float]:
        """Align registered values to the frozen schema; missing is never silently zero.

        Extra registered values may be present when selecting a smaller schema.
        New feature definitions require registration and retraining, not row-wise widths.
        """
        validate_feature_names(list(values))
        result = []
        for name in self.feature_names:
            value = values.get(name)
            if value is None:
                if not allow_missing: raise ValueError(f"missing feature: {name}")
                result.append(float("nan")); continue
            number = float(value)
            if math.isinf(number) or (math.isnan(number) and not allow_missing):
                raise ValueError(f"non-finite feature: {name}")
            result.append(number)
        return result
