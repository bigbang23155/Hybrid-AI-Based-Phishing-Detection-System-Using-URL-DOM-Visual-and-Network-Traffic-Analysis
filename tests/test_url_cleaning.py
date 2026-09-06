import pytest

from phishing_url.url_cleaning import InvalidURLError, clean_url, registered_domain


def test_conservative_normalization():
    assert clean_url("  HTTPS://Exämple.COM:443/login?a=2&a=1#section  ") == (
        "https://xn--exmple-cua.com/login?a=2&a=1"
    )


@pytest.mark.parametrize(
    "url",
    ["example.com", "ftp://example.com/a", "https://exa mple.com"],
)
def test_rejects_invalid_or_unsupported_urls(url):
    with pytest.raises(InvalidURLError):
        clean_url(url)


def test_registered_domain_and_ip_are_local_and_deterministic():
    assert registered_domain(clean_url("https://a.b.example.co.uk/x")) == "example.co.uk"
    assert registered_domain(clean_url("http://192.0.2.1/x")) == "192.0.2.1"


def test_user_information_is_preserved_for_string_analysis():
    assert clean_url("HTTPS://user:pass@Example.COM:443/a#x") == (
        "https://user:pass@example.com/a"
    )
