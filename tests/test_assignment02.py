import pandas as pd
import pytest

from phishing_url.experiment import _load, _metrics, make_split
from phishing_url.feature_registry import FeatureExtractor, resolve_feature_set, validate_feature_names


def dataset():
    rows=[]
    for label in (0,1):
        for number in range(20):
            domain=f"{'bad' if label else 'good'}{number}.example"
            rows.append({"url_clean":f"https://{domain}/x", "domain_group":domain, "label":label})
    return pd.DataFrame(rows)


def test_feature_sets_keep_order_and_reject_metadata_duplicates_unknown():
    baseline=resolve_feature_set("baseline")
    assert resolve_feature_set(",".join(baseline)) == baseline
    assert "uses_https" not in resolve_feature_set("no_https")
    with pytest.raises(ValueError, match="duplicate"): validate_feature_names(["url_length","url_length"])
    with pytest.raises(ValueError, match="metadata"): validate_feature_names(["label"])
    with pytest.raises(ValueError, match="unknown"): validate_feature_names(["made_up"])


def test_absent_query_is_zero_but_extraction_failure_raises():
    names=("query_length",)
    assert FeatureExtractor(names).transform_one("https://example.com/") == [0.0]
    with pytest.raises(ValueError): FeatureExtractor(names).transform_one("not a URL")


def test_domain_split_is_disjoint_and_reproducible():
    frame=dataset(); first=make_split(frame,2025,11); second=make_split(frame,2025,11)
    assert first.equals(second)
    groups={part:set(frame.loc[first==part,"domain_group"]) for part in ("train","validation","test")}
    assert not groups["train"] & groups["validation"]
    assert not groups["train"] & groups["test"]
    assert not groups["validation"] & groups["test"]
    another_development_seed=make_split(frame,2025,71)
    assert set(frame.loc[first == "test", "domain_group"]) == set(
        frame.loc[another_development_seed == "test", "domain_group"]
    )


def test_confusion_matrix_and_fpr():
    result=_metrics(pd.Series([0,0,1,1]),pd.Series([.1,.8,.4,.9]).to_numpy())
    assert (result["tn"],result["fp"],result["fn"],result["tp"]) == (1,1,1,1)
    assert result["fpr"] == .5


def test_loader_rejects_duplicate_normalized_urls(tmp_path):
    path=tmp_path / "urls.csv"
    pd.DataFrame([
        {"url_raw":"https://example.com/", "url_clean":"https://example.com/", "label":0, "source":"test", "registered_domain":"example.com"},
        {"url_raw":"https://example.com/", "url_clean":"https://example.com/", "label":0, "source":"test", "registered_domain":"example.com"},
    ]).to_csv(path,index=False)
    with pytest.raises(ValueError,match="duplicate normalized URLs"):
        _load(path)
