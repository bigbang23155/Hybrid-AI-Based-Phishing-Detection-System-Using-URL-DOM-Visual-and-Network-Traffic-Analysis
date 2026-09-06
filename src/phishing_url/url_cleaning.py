"""Conservative, entirely local URL validation and normalization."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit

_FORBIDDEN = re.compile(r"[\s\x00-\x1f\x7f]")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_COMPOUND_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "com.br", "com.cn",
})


class InvalidURLError(ValueError):
    """Raised when a value is not an absolute, safe-to-parse HTTP(S) URL."""


def _normalized_hostname(hostname: str) -> str:
    try:
        return hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidURLError("hostname cannot be encoded with IDNA") from exc


def clean_url(value: str) -> str:
    """Validate and deterministically normalize an absolute HTTP(S) URL."""
    if not isinstance(value, str):
        raise InvalidURLError("URL must be a string")
    value = value.strip()
    if not value or _FORBIDDEN.search(value):
        raise InvalidURLError("URL is empty or contains whitespace/control characters")

    try:
        parts = urlsplit(value)
        port = parts.port  # Access validates malformed/out-of-range ports.
    except ValueError as exc:
        raise InvalidURLError(f"malformed URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidURLError("only http and https schemes are accepted")
    if not parts.hostname:
        raise InvalidURLError("URL must contain a hostname")
    hostname = _normalized_hostname(parts.hostname)
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
        if len(hostname) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in hostname.split(".")):
            raise InvalidURLError("hostname contains an invalid DNS label")
    if ip and ip.version == 6:
        host_for_netloc = f"[{hostname}]"
    else:
        host_for_netloc = hostname
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host_for_netloc += f":{port}"

    # Preserve user-information for lexical analysis. Nothing in this package
    # dereferences a URL, so retaining it cannot result in authentication or I/O.
    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0]
        host_for_netloc = f"{userinfo}@{host_for_netloc}"

    return urlunsplit(SplitResult(scheme, host_for_netloc, parts.path or "/", parts.query, ""))


def registered_domain(cleaned_url: str) -> str:
    """Return an IP unchanged or a domain using the documented fixed suffix rule."""
    hostname = urlsplit(cleaned_url).hostname or ""
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        labels = hostname.rstrip(".").split(".")
        suffix_width = 2 if ".".join(labels[-2:]) in _COMPOUND_SUFFIXES else 1
        width = min(len(labels), suffix_width + 1)
        return ".".join(labels[-width:])


def subdomain_count(cleaned_url: str) -> int:
    """Count labels preceding the registered domain; return zero for IP hosts."""
    hostname = urlsplit(cleaned_url).hostname or ""
    try:
        ipaddress.ip_address(hostname)
        return 0
    except ValueError:
        domain_labels = registered_domain(cleaned_url).count(".") + 1
        return max(0, len(hostname.rstrip(".").split(".")) - domain_labels)
