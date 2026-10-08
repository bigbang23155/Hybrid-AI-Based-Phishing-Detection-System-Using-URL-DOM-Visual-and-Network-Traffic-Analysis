"""Versioned passive structural features; no browser, network, CSS or JS execution."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from html.parser import HTMLParser
import math
import re
from typing import Mapping
from urllib.parse import urljoin, urlsplit

from .url_cleaning import clean_url, registered_domain

REGISTRY_VERSION = "static_dom_v1"
MAX_HTML_BYTES = 2 * 1024 * 1024
RESOURCE_ATTRIBUTES = {
    "script": "src", "img": "src", "iframe": "src", "link": "href",
    "source": "src", "audio": "src", "video": "src", "embed": "src", "input": "src",
}
# The order is the model contract, not the order in which tags occur.
DEFINITIONS = (
    ("tag_count", "count", "All start/start-end tags emitted by HTMLParser, once each."),
    ("form_count", "count", "form start tags, including forms without action."),
    ("input_count", "count", "input start tags of any type."),
    ("password_input_count", "count", "input with stripped case-insensitive type=password."),
    ("hidden_input_count", "count", "input with stripped case-insensitive type=hidden."),
    ("link_count", "count", "a tags with an href attribute; empty and non-HTTP values included."),
    ("http_link_count", "count", "Link references resolvable to a valid HTTP(S) URL."),
    ("external_link_count", "count", "HTTP(S) links with registered domain different from page URL."),
    ("external_link_ratio", "ratio", "external_link_count / http_link_count; zero if denominator zero."),
    ("resource_count", "count", "One reference per resource tag with its declared src/href attribute."),
    ("http_resource_count", "count", "Resource references resolvable to a valid HTTP(S) URL."),
    ("external_resource_count", "count", "HTTP(S) resources with different registered domain."),
    ("external_resource_ratio", "ratio", "external_resource_count / http_resource_count; zero if denominator zero."),
    ("script_count", "count", "All script tags; does not imply executable JavaScript."),
    ("script_src_count", "count", "script tags with src, including empty/invalid/non-HTTP values."),
    ("external_script_count", "count", "script src references resolving to an external HTTP(S) domain."),
    ("iframe_count", "count", "iframe tags; content/srcdoc is not recursively parsed."),
    ("hidden_element_count", "count", "Union per tag of hidden attribute, input type=hidden, or explicit inline display:none / visibility:hidden declaration."),
    ("meta_refresh_count", "count", "meta with stripped case-insensitive http-equiv=refresh, regardless of content validity."),
    ("form_action_count", "count", "form tags explicitly carrying action; includes empty values."),
    ("http_form_action_count", "count", "Explicit action references resolvable to HTTP(S)."),
    ("external_form_action_count", "count", "Explicit HTTP(S) form actions with different registered domain."),
    ("external_form_action_ratio", "ratio", "external_form_action_count / http_form_action_count; zero if denominator zero."),
)
DOM_FEATURE_NAMES = tuple(x[0] for x in DEFINITIONS)
_RATIOS = frozenset(name for name, unit, _ in DEFINITIONS if unit == "ratio")
_HIDDEN_STYLE = re.compile(r"(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:!\s*important\s*)?(?=;|$)", re.I)


class DOMExtractionError(ValueError):
    """Extraction failure must never be substituted by an all-zero row."""


class _Probe(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.counts = Counter()
        self.references = []
        self.base = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)  # deterministic last duplicate attribute wins
        c = self.counts
        c["tag_count"] += 1
        if tag in ("form", "input", "script", "iframe"):
            c[tag + "_count"] += 1
        kind = (a.get("type") or "").strip().lower()
        c["password_input_count"] += tag == "input" and kind == "password"
        c["hidden_input_count"] += tag == "input" and kind == "hidden"
        c["hidden_element_count"] += bool(
            "hidden" in a or (tag == "input" and kind == "hidden")
            or _HIDDEN_STYLE.search(a.get("style") or ""))
        c["meta_refresh_count"] += tag == "meta" and (a.get("http-equiv") or "").strip().lower() == "refresh"
        if tag == "base" and self.base is None and "href" in a:
            self.base = a["href"] or ""
        if tag == "a" and "href" in a:
            c["link_count"] += 1
            self.references.append(("link", a["href"] or "", tag))
        attr = RESOURCE_ATTRIBUTES.get(tag)
        if attr and attr in a:
            c["resource_count"] += 1
            c["script_src_count"] += tag == "script"
            self.references.append(("resource", a[attr] or "", tag))
        if tag == "form" and "action" in a:
            c["form_action_count"] += 1
            self.references.append(("form_action", a["action"] or "", tag))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def _http_url(base: str, value: str) -> str | None:
    resolved = urljoin(base, value.strip())
    if urlsplit(resolved).scheme.lower() not in ("http", "https"):
        return None
    return clean_url(resolved)


def extract_dom_features(html: str, page_url: str) -> dict[str, float]:
    """Compute v1 from a published HTML string and its paired URL context.

    Counts inside template/noscript markup are lexical, not rendered nodes.
    The first base[href] is applied document-wide if valid HTTP(S); otherwise
    page_url is used. Non-HTTP or malformed references are omitted from HTTP
    denominators, not counted as internal. Repeated references are not deduped.
    """
    if not isinstance(html, str) or not html.strip():
        raise DOMExtractionError("missing_or_empty_html")
    try:
        if len(html.encode("utf-8")) > MAX_HTML_BYTES:
            raise DOMExtractionError("oversize_html")
        page_url = clean_url(page_url)
        page_domain = registered_domain(page_url)
        p = _Probe()
        p.feed(html)
        p.close()
        if not p.counts["tag_count"]:
            raise DOMExtractionError("no_markup")
        base = page_url
        if p.base is not None:
            try:
                base = _http_url(page_url, p.base) or page_url
            except (ValueError, TypeError):
                pass
        for kind, value, tag in p.references:
            try:
                resolved = _http_url(base, value)
                if resolved is None:
                    continue
                external = registered_domain(resolved) != page_domain
            except (ValueError, TypeError):
                continue
            p.counts["http_" + kind + "_count"] += 1
            p.counts["external_" + kind + "_count"] += external
            p.counts["external_script_count"] += kind == "resource" and tag == "script" and external
        result = {name: float(p.counts[name]) for name in DOM_FEATURE_NAMES}
        for kind in ("link", "resource", "form_action"):
            den = result["http_" + kind + "_count"]
            result["external_" + kind + "_ratio"] = result["external_" + kind + "_count"] / den if den else 0.0
        return result
    except (ValueError, TypeError, UnicodeError, AssertionError, RecursionError) as exc:
        if isinstance(exc, DOMExtractionError):
            raise
        raise DOMExtractionError("invalid_url_or_parse_error") from exc


def validate_dom_names(names) -> tuple[str, ...]:
    names = tuple(names)
    if not names or len(names) != len(set(names)) or set(names) - set(DOM_FEATURE_NAMES):
        raise ValueError("DOM schema must be a nonempty unique registered ordered subset")
    return names


@dataclass(frozen=True)
class DOMFeatureExtractor:
    feature_names: tuple[str, ...] = DOM_FEATURE_NAMES

    def __post_init__(self):
        object.__setattr__(self, "feature_names", validate_dom_names(self.feature_names))

    def transform_one(self, html: str, page_url: str) -> list[float]:
        return self.transform_mapping(extract_dom_features(html, page_url))

    def transform_mapping(self, values: Mapping[str, object]) -> list[float]:
        validate_dom_names(values.keys())
        output = []
        for name in self.feature_names:
            if name not in values or values[name] is None:
                raise ValueError(f"missing DOM feature: {name}")
            number = float(values[name])
            if not math.isfinite(number) or number < 0:
                raise ValueError(f"invalid DOM feature: {name}")
            if (name in _RATIOS and number > 1) or (name not in _RATIOS and not number.is_integer()):
                raise ValueError(f"invalid DOM feature range/unit: {name}")
            output.append(number)
        return output
