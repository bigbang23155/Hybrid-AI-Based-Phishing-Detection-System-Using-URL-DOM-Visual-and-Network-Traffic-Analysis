import math

from phishing_url.features import extract_features


def test_feature_set_and_values():
    url = "https://login.secure.example.com/a-1?account=22&x=3"
    features = extract_features(url)
    assert set(features) == {
        "url_length", "hostname_length", "path_length", "query_length", "dot_count",
        "subdomain_count", "slash_count", "digit_count", "digit_ratio", "hyphen_count",
        "at_count", "question_count", "equals_count", "ampersand_count", "uses_https",
        "is_ip_hostname", "suspicious_keyword_count", "url_entropy",
    }
    assert features["hostname_length"] == len("login.secure.example.com")
    assert features["path_length"] == 4
    assert features["query_length"] == len("account=22&x=3")
    assert features["subdomain_count"] == 2
    assert features["digit_count"] == 4
    assert math.isclose(features["digit_ratio"], 4 / features["url_length"])
    assert features["hyphen_count"] == 1
    assert features["question_count"] == 1
    assert features["equals_count"] == 2
    assert features["ampersand_count"] == 1
    assert features["uses_https"] == 1
    assert features["is_ip_hostname"] == 0
    assert features["suspicious_keyword_count"] == 3
    assert features["url_entropy"] > 0


def test_ip_hostname_and_http():
    features = extract_features("http://[2001:db8::1]/login")
    assert features["is_ip_hostname"] == 1
    assert features["subdomain_count"] == 0
    assert features["uses_https"] == 0


def test_features_use_cleaned_url_and_user_information_is_counted():
    raw = "  HTTPS://user@example.com:443#fragment  "
    features = extract_features(raw)
    cleaned = "https://user@example.com/"
    assert features["url_length"] == len(cleaned)
    assert features["at_count"] == 1
    assert features["hostname_length"] == len("example.com")
