"""Dataset schema, validation, conflict detection, and deduplication."""

from __future__ import annotations

import warnings
from dataclasses import asdict, dataclass
from typing import Iterable, Mapping

from .url_cleaning import clean_url, registered_domain

SCHEMA = ("url_raw", "url_clean", "label", "source", "registered_domain")


class ConflictingLabelWarning(UserWarning):
    """Reports that every record for a normalized URL was excluded."""


@dataclass(frozen=True, slots=True)
class URLRecord:
    url_raw: str
    url_clean: str
    label: int
    source: str
    registered_domain: str

    def as_dict(self) -> dict[str, str | int]:
        """Return fields in the documented schema order."""
        return asdict(self)


def prepare_records(rows: Iterable[Mapping[str, object]]) -> list[URLRecord]:
    """Validate rows, exclude label conflicts, and keep first normalized duplicate."""
    unique: dict[str, URLRecord] = {}
    conflicting_urls: set[str] = set()
    for row_number, row in enumerate(rows, start=1):
        raw_value = row.get("url_raw")
        raw = raw_value.strip() if isinstance(raw_value, str) else raw_value
        label = row.get("label")
        source_value = row.get("source")
        source = source_value.strip() if isinstance(source_value, str) else ""
        if type(label) is not int or label not in (0, 1):
            raise ValueError(f"row {row_number}: label must be integer 0 or 1")
        if not source:
            raise ValueError(f"row {row_number}: source must be a non-empty string")
        cleaned = clean_url(raw)  # type: ignore[arg-type]
        record = URLRecord(raw, cleaned, label, source, registered_domain(cleaned))
        if cleaned in conflicting_urls:
            continue
        previous = unique.get(cleaned)
        if previous and previous.label != label:
            del unique[cleaned]
            conflicting_urls.add(cleaned)
            warnings.warn(
                f"excluded normalized URL {cleaned!r} because it has labels "
                f"{previous.label} and {label}",
                ConflictingLabelWarning,
                stacklevel=2,
            )
        else:
            unique.setdefault(cleaned, record)
    return list(unique.values())
