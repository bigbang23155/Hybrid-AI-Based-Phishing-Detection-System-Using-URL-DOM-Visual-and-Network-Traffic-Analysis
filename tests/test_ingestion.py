from pathlib import Path

import pytest

from phishing_url.ingestion import parse_openphish, parse_phishtank, parse_tranco

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_phishtank_csv_assigns_source_and_label_and_keeps_bad_rows():
    rows = parse_phishtank(FIXTURES / "phishtank.csv")
    assert len(rows) == 6
    assert {row.source for row in rows} == {"phishtank"}
    assert {row.label for row in rows} == {1}
    assert rows[0].url_raw == "HTTPS://bad.test:443/login#fragment"
    assert rows[2].error == "missing URL"


def test_parse_phishtank_json_supports_objects_and_string_entries():
    rows = parse_phishtank(FIXTURES / "phishtank.json")
    assert [row.url_raw for row in rows] == [
        "https://json-phish.test/login",
        None,
        "https://string-entry.test/",
    ]
    assert rows[1].error == "missing URL"


def test_parse_openphish_assigns_phishing_label_and_reports_blank_line():
    rows = parse_openphish(FIXTURES / "openphish.txt")
    assert len(rows) == 5
    assert all(row.source == "openphish" and row.label == 1 for row in rows)
    assert rows[3].error == "missing URL"


def test_parse_tranco_constructs_https_urls_and_reports_malformed_rows():
    rows = parse_tranco(FIXTURES / "tranco.csv")
    assert len(rows) == 5
    assert rows[0].url_raw == "https://good.test/"
    assert all(row.source == "tranco" and row.label == 0 for row in rows)
    assert rows[3].error == "expected numeric rank and domain"


def test_phishtank_csv_requires_url_header(tmp_path):
    path = tmp_path / "phishtank.csv"
    path.write_text("id,address\n1,https://example.test\n", encoding="utf-8")
    with pytest.raises(ValueError, match="url.*header"):
        parse_phishtank(path)
