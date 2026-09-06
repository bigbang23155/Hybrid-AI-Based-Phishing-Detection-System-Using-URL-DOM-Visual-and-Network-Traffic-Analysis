import pytest

from phishing_url.dataset import ConflictingLabelWarning, SCHEMA, prepare_records


def test_schema_and_exact_and_normalized_deduplication():
    rows = [
        {"url_raw": "https://example.com", "label": 0, "source": "tranco"},
        {"url_raw": "https://example.com", "label": 0, "source": "tranco"},
        {"url_raw": "HTTPS://EXAMPLE.COM:443/#ignored", "label": 0, "source": "tranco"},
    ]
    records = prepare_records(rows)
    assert len(records) == 1
    assert tuple(records[0].as_dict()) == SCHEMA
    assert records[0].url_clean == "https://example.com/"
    assert records[0].registered_domain == "example.com"


def test_conflicting_labels_are_reported_after_normalization():
    rows = [
        {"url_raw": "http://example.com", "label": 0, "source": "tranco"},
        {"url_raw": "HTTP://EXAMPLE.COM:80/#x", "label": 1, "source": "openphish"},
        {"url_raw": "https://safe.test", "label": 0, "source": "tranco"},
        {"url_raw": "http://example.com", "label": 0, "source": "phishtank"},
    ]
    with pytest.warns(ConflictingLabelWarning, match="labels 0 and 1"):
        records = prepare_records(rows)
    assert [record.url_clean for record in records] == ["https://safe.test/"]


@pytest.mark.parametrize("label", [True, -1, 2, "1"])
def test_label_must_be_binary_integer(label):
    with pytest.raises(ValueError, match="label"):
        prepare_records([{"url_raw": "https://example.test", "label": label, "source": "test"}])
