import pytest

from phishing_url.dom_features import (
    DOM_FEATURE_NAMES, DOMExtractionError, DOMFeatureExtractor, extract_dom_features,
)

PAGE = "https://www.example.com/account/"


def test_order_and_absence_not_missing():
    v = extract_dom_features("<html><body><p>Hello</p></body></html>", PAGE)
    assert tuple(v) == DOM_FEATURE_NAMES
    assert len(v) == 23
    assert v["tag_count"] == 3
    assert v["external_link_ratio"] == v["external_form_action_ratio"] == 0
    assert DOMFeatureExtractor(("form_count", "tag_count")).transform_mapping(v) == [0, 3]


def test_forms_hidden_union_and_static_refresh():
    h = '''<form action="/login"><input type=" PASSWORD ">
    <input type="hidden" hidden style="display:none">
    <span style="visibility: hidden !important"></span>
    <div style="--x:display:none; display:none-ish"></div></form>
    <form action="https://elsewhere.org/post"></form><form></form>
    <meta http-equiv=" Refresh " content="not a valid redirect">'''
    v = extract_dom_features(h, PAGE)
    assert v["form_count"] == 3 and v["form_action_count"] == 2
    assert v["external_form_action_ratio"] == .5
    assert v["password_input_count"] == 1 and v["hidden_input_count"] == 1
    assert v["hidden_element_count"] == 2
    assert v["meta_refresh_count"] == 1


def test_links_base_schemes_and_malformed():
    h = '''<a href="relative">x</a><base href="https://external.org/root/">
    <base href="https://ignored.net/"><a href="https://sub.example.com/a">x</a>
    <a href="mailto:a@example.com">x</a><a href="javascript:void(0)">x</a>
    <a href="http://[broken">x</a><a href="//external.org/a">x</a>'''
    v = extract_dom_features(h, PAGE)
    assert v["link_count"] == 6 and v["http_link_count"] == 3
    assert v["external_link_count"] == 2
    assert v["external_link_ratio"] == pytest.approx(2/3)


@pytest.mark.parametrize("base", ["javascript:bad", "http://[broken"])
def test_invalid_base_falls_back_to_page(base):
    v = extract_dom_features(f'<base href="{base}"><a href="/x">x</a>', PAGE)
    assert v["http_link_count"] == 1 and v["external_link_count"] == 0


def test_resources_no_execution_no_recursive_srcdoc():
    h = '''<script>throw Error("never execute");</script>
    <script src="https://cdn.other.org/a.js"></script>
    <script src="data:text/plain,x"></script><img src="/a.png"/>
    <iframe srcdoc="&lt;input type='password'&gt;"></iframe>
    <link href="//cdn.other.org/style"><img srcset="https://ignored.org/a 1x">'''
    v = extract_dom_features(h, PAGE)
    assert v["script_count"] == 3 and v["script_src_count"] == 2
    assert v["resource_count"] == 4 and v["http_resource_count"] == 3
    assert v["external_resource_count"] == 2 and v["external_script_count"] == 1
    assert v["iframe_count"] == 1 and v["password_input_count"] == 0


def test_duplicate_attrs_comments_case_template_and_selfclosing():
    v = extract_dom_features('<!-- <form> --><INPUT type="text" type="PASSWORD"/>'
                            '<template><form></form></template><script>"<input>"</script>', PAGE)
    assert v["tag_count"] == 4 and v["password_input_count"] == 1
    assert v["form_count"] == 1


@pytest.mark.parametrize("html", [None, "", "   ", "plain text", "<p>" + "x"*(2*1024*1024), "\ud800"])
def test_failure_never_zero_vector(html):
    with pytest.raises(DOMExtractionError):
        extract_dom_features(html, PAGE)


def test_invalid_page_url_rejected():
    with pytest.raises(DOMExtractionError):
        extract_dom_features("<p>x</p>", "not a URL")


@pytest.mark.parametrize("names", [(), ("label",), ("form_count", "form_count"), ("future_unknown",)])
def test_bad_schema(names):
    with pytest.raises(ValueError):
        DOMFeatureExtractor(names)


@pytest.mark.parametrize("value", [None, float("nan"), float("inf"), -1, .2])
def test_invalid_count(value):
    with pytest.raises((ValueError, TypeError)):
        DOMFeatureExtractor(("form_count",)).transform_mapping({"form_count": value})


def test_missing_and_out_of_range_ratio():
    with pytest.raises(ValueError):
        DOMFeatureExtractor(("form_count",)).transform_mapping({"tag_count": 1})
    with pytest.raises(ValueError):
        DOMFeatureExtractor(("external_link_ratio",)).transform_mapping({"external_link_ratio": 2})


def test_harmless_metamorphic_variants_not_robustness_claim():
    original = '<form action="/x"><input type="password" name="secret"></form>'
    variants = [
        '<FORM action="/x"><INPUT name="secret" type="password"></FORM>',
        '<!-- inert comment -->' + original,
        '<form action="/x">\n<input type="password" name="secret">\n</form>',
    ]
    reference = extract_dom_features(original, PAGE)
    assert all(extract_dom_features(v, PAGE) == reference for v in variants)
