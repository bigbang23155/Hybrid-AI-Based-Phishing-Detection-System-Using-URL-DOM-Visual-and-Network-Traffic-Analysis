"""Parsers for user-provided, local URL source files."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True, slots=True)
class ParsedRow:
    """One source row, before URL validation."""

    source: str
    label: int
    row_number: int
    url_raw: str | None
    error: str | None = None


def _url_row(source: str, label: int, row_number: int, value: object) -> ParsedRow:
    if not isinstance(value, str) or not value.strip():
        return ParsedRow(source, label, row_number, None, "missing URL")
    return ParsedRow(source, label, row_number, value.strip())


def parse_phishtank(path: str | Path) -> list[ParsedRow]:
    """Parse a local PhishTank CSV or JSON export without performing I/O beyond the file."""
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or "url" not in reader.fieldnames:
                raise ValueError("PhishTank CSV must contain a 'url' header")
            return [_url_row("phishtank", 1, number, row.get("url")) for number, row in enumerate(reader, 2)]
    if path.suffix.lower() == ".json":
        with path.open(encoding="utf-8-sig") as handle:
            payload = json.load(handle)
        if isinstance(payload, dict):
            payload = payload.get("data", payload.get("urls"))
        if not isinstance(payload, list):
            raise ValueError("PhishTank JSON must be an array or contain a 'data'/'urls' array")
        rows = []
        for number, item in enumerate(payload, 1):
            value = item.get("url") if isinstance(item, dict) else item
            rows.append(_url_row("phishtank", 1, number, value))
        return rows
    raise ValueError("PhishTank input must have a .csv or .json extension")


def parse_openphish(path: str | Path) -> list[ParsedRow]:
    """Parse a local OpenPhish feed, reporting blank lines as malformed rows."""
    rows = []
    with Path(path).open(encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, 1):
            value = line.strip()
            rows.append(_url_row("openphish", 1, number, value))
    return rows


def parse_tranco(path: str | Path) -> list[ParsedRow]:
    """Parse rank/domain Tranco CSV rows and construct deterministic HTTPS URLs."""
    rows = []
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        for number, columns in enumerate(csv.reader(handle), 1):
            if number == 1 and [value.strip().lower() for value in columns[:2]] == ["rank", "domain"]:
                continue
            if len(columns) < 2 or not columns[0].strip().isdigit() or not columns[1].strip():
                rows.append(ParsedRow("tranco", 0, number, None, "expected numeric rank and domain"))
                continue
            domain = columns[1].strip()
            rows.append(_url_row("tranco", 0, number, f"https://{domain}/"))
    return rows


def read_sources(phishtank: str | Path, openphish: str | Path, tranco: str | Path) -> list[ParsedRow]:
    """Read all sources in a fixed order used by the preparation pipeline."""
    parsers: Iterable[list[ParsedRow]] = (
        parse_phishtank(phishtank),
        parse_openphish(openphish),
        parse_tranco(tranco),
    )
    return [row for parsed_rows in parsers for row in parsed_rows]
