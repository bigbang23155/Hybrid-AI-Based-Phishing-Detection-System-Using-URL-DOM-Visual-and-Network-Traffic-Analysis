"""Bounded collection of observed public URLs from a frozen ranked-domain list."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit
from urllib.robotparser import RobotFileParser
from xml.etree import ElementTree

import requests

from .url_cleaning import InvalidURLError, clean_url, registered_domain

USER_AGENT = "PhishingURLResearch/0.2 (public-pages-only; no forms)"
TOKEN_KEYS = frozenset({"access_token", "auth", "authorization", "code", "jwt", "key",
                        "password", "session", "sessionid", "sid", "sso", "ticket", "token"})
ALLOWED_CONTENT = ("text/html", "application/xhtml+xml", "application/xml", "text/xml")


@dataclass(frozen=True)
class Observation:
    candidate_rank: int
    candidate_domain: str
    url_raw: str
    url_clean: str
    observed_from: str
    evidence_url: str
    retrieved_utc: str
    same_domain: bool = True
    label_basis: str = "assumed_legitimate_tranco_candidate_public_observation"


@dataclass(frozen=True)
class Failure:
    candidate_rank: int
    candidate_domain: str
    stage: str
    reason: str


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def public_addresses(hostname: str) -> list[str]:
    """Resolve *hostname* and reject any non-global destination (SSRF guard)."""
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)})
    except socket.gaierror as exc:
        raise ValueError(f"DNS failure: {exc}") from exc
    if not addresses:
        raise ValueError("DNS returned no addresses")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError(f"non-public destination: {address}")
    return addresses


def suitable_url(url: str, domain_group: str) -> tuple[bool, str]:
    """Apply public-URL, same-domain, credential, and token exclusion policy."""
    try:
        cleaned = clean_url(url)
    except InvalidURLError as exc:
        return False, f"invalid_url:{exc}"
    parts = urlsplit(cleaned)
    if parts.username or parts.password:
        return False, "credentials_in_url"
    if registered_domain(cleaned) != domain_group:
        return False, "cross_domain"
    keys = {key.casefold() for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
    if keys & TOKEN_KEYS or any(fragment in key for key in keys for fragment in ("token", "session", "auth")):
        return False, "sensitive_query_key"
    return True, cleaned


def safe_get(session: requests.Session, url: str, timeout: float, max_bytes: int = 2_000_000,
             required_domain_group: str | None = None) -> tuple[requests.Response, bytes]:
    """GET with DNS validation before every bounded redirect and response read."""
    current = url
    for _ in range(6):
        parts = urlsplit(current)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("redirect is not a public HTTP(S) URL")
        if required_domain_group is not None and registered_domain(clean_url(current)) != required_domain_group:
            raise ValueError("redirect crossed registrable-domain boundary")
        public_addresses(parts.hostname)
        session.cookies.clear()  # Never carry server-issued sessions between requests.
        response = session.get(current, timeout=timeout, allow_redirects=False, stream=True,
                               headers={"User-Agent": USER_AGENT})
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise ValueError("redirect has no Location")
            current = urljoin(current, location)
            continue
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_content(65536):
            body.extend(chunk)
            if len(body) > max_bytes:
                response.close()
                raise ValueError(f"response exceeds {max_bytes} bytes")
        return response, bytes(body)
    raise ValueError("redirect limit exceeded")


def _robots(session: requests.Session, home: str, timeout: float) -> tuple[RobotFileParser, list[str]]:
    robots_url = urljoin(home, "/robots.txt")
    parser = RobotFileParser(); parser.set_url(robots_url)
    sitemaps: list[str] = []
    try:
        response, body = safe_get(session, robots_url, timeout, 500_000)
        text = body.decode(response.encoding or "utf-8", errors="replace")
        parser.parse(text.splitlines())
        for line in text.splitlines():
            if line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
    except Exception:
        # An unavailable robots file is not permission to crawl arbitrary paths:
        # only the observed homepage is retained and link/sitemap traversal stops.
        parser.parse(["User-agent: *", "Disallow: /"])
    return parser, sitemaps[:3]


def collect_domain(rank: int, domain: str, cap: int, timeout: float,
                   request_delay: float) -> tuple[list[Observation], list[Failure]]:
    observations: list[Observation] = []; failures: list[Failure] = []
    session = requests.Session()
    home_response = None; home_body = b""; requested_home = ""
    for scheme in ("https", "http"):
        requested_home = f"{scheme}://{domain}/"
        try:
            requested_group = registered_domain(clean_url(requested_home))
            home_response, home_body = safe_get(session, requested_home, timeout,
                                                required_domain_group=requested_group)
            break
        except Exception as exc:
            failures.append(Failure(rank, domain, f"homepage_{scheme}", type(exc).__name__ + ":" + str(exc)[:180]))
    if home_response is None:
        return observations, failures
    group = registered_domain(clean_url(home_response.url))
    if group != registered_domain(clean_url(requested_home)):
        failures.append(Failure(rank, domain, "redirect", "final destination crossed registrable-domain boundary"))
        return observations, failures
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    ok, value = suitable_url(home_response.url, group)
    if not ok:
        failures.append(Failure(rank, domain, "homepage_filter", value)); return observations, failures
    observations.append(Observation(rank, domain, home_response.url, value, "homepage_response", requested_home, timestamp))
    time.sleep(request_delay)
    robots, sitemap_urls = _robots(session, home_response.url, timeout)
    candidates: list[tuple[str, str, str]] = []
    content_type = home_response.headers.get("Content-Type", "").lower()
    if any(kind in content_type for kind in ALLOWED_CONTENT[:2]):
        parser = LinkParser(); parser.feed(home_body.decode(home_response.encoding or "utf-8", errors="replace"))
        candidates.extend((urljoin(home_response.url, link), "homepage_link", home_response.url) for link in parser.links)
    for sitemap_url in sitemap_urls:
        ok, cleaned_or_reason = suitable_url(sitemap_url, group)
        if not ok or not robots.can_fetch(USER_AGENT, sitemap_url):
            continue
        try:
            time.sleep(request_delay)
            response, body = safe_get(session, cleaned_or_reason, timeout,
                                      required_domain_group=group)
            root = ElementTree.fromstring(body)
            candidates.extend((node.text.strip(), "sitemap", response.url) for node in root.iter() if node.tag.endswith("loc") and node.text)
        except Exception as exc:
            failures.append(Failure(rank, domain, "sitemap", type(exc).__name__ + ":" + str(exc)[:180]))
    seen = {observations[0].url_clean}
    for candidate, evidence, evidence_url in candidates:
        if len(observations) >= cap:
            break
        ok, cleaned_or_reason = suitable_url(candidate, group)
        if not ok or cleaned_or_reason in seen:
            continue
        if not robots.can_fetch(USER_AGENT, cleaned_or_reason):
            failures.append(Failure(rank, domain, "robots", "disallowed_observed_url")); continue
        seen.add(cleaned_or_reason)
        observations.append(Observation(rank, domain, candidate, cleaned_or_reason, evidence, evidence_url, timestamp))
    return observations, failures


def read_candidates(path: Path, rank_min: int, rank_max: int, sample_size: int, seed: int) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for columns in csv.reader(handle):
            if len(columns) >= 2 and columns[0].strip().isdigit():
                rank = int(columns[0]); domain = columns[1].strip().lower()
                if rank_min <= rank <= rank_max:
                    rows.append((rank, domain))
    if len(rows) < sample_size:
        raise ValueError(f"ranking range contains {len(rows)} candidates, fewer than requested {sample_size}")
    return sorted(random.Random(seed).sample(rows, sample_size))


def run(args: argparse.Namespace) -> None:
    candidates = read_candidates(args.tranco, args.rank_min, args.rank_max, args.domains, args.seed)
    observations: list[Observation] = []; failures: list[Failure] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(collect_domain, rank, domain, args.per_domain_cap, args.timeout, args.request_delay): (rank, domain) for rank, domain in candidates}
        for future in as_completed(futures):
            try:
                found, failed = future.result(); observations.extend(found); failures.extend(failed)
            except Exception as exc:
                rank, domain = futures[future]; failures.append(Failure(rank, domain, "unexpected", repr(exc)[:180]))
    observations.sort(key=lambda row: (row.candidate_rank, row.url_clean)); failures.sort(key=lambda row: (row.candidate_rank, row.stage, row.reason))
    args.output.mkdir(parents=True, exist_ok=True)
    for filename, rows, cls in (("observed_legitimate_urls.csv", observations, Observation), ("collection_failures.csv", failures, Failure)):
        with (args.output / filename).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=cls.__dataclass_fields__); writer.writeheader(); writer.writerows(asdict(row) for row in rows)
    manifest = {"created_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), "tranco_path": str(args.tranco),
                "tranco_sha256": sha256(args.tranco), "candidate_seed": args.seed, "rank_range": [args.rank_min, args.rank_max],
                "sampled_domains": len(candidates), "per_domain_url_cap": args.per_domain_cap, "timeout_seconds": args.timeout,
                "workers": args.workers, "user_agent": USER_AGENT, "observations": len(observations),
                "domains_with_observations": len({row.candidate_domain for row in observations}), "failures": len(failures),
                "label_claim": "assumed legitimate under collection policy; not individually verified",
                "policy": {"public_http_only": True, "same_registrable_domain": True, "robots_required_for_inner_urls": True,
                           "forms_or_login": False, "same_domain_request_delay_seconds": args.request_delay,
                           "token_query_keys_excluded": sorted(TOKEN_KEYS), "max_redirects": 5,
                           "max_response_bytes": 2_000_000}}
    (args.output / "collection_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tranco", type=Path, required=True, help="frozen local rank,domain CSV")
    parser.add_argument("--output", type=Path, required=True); parser.add_argument("--seed", type=int, default=20250926)
    parser.add_argument("--rank-min", type=int, default=1001); parser.add_argument("--rank-max", type=int, default=100000)
    parser.add_argument("--domains", type=int, default=1200); parser.add_argument("--per-domain-cap", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=6.0); parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--request-delay", type=float, default=.25, help="minimum delay between same-domain requests")
    args = parser.parse_args(argv)
    if args.per_domain_cap < 1 or args.domains < 1 or args.workers < 1 or args.request_delay < 0: parser.error("caps, domains, and workers must be positive; delay cannot be negative")
    run(args); return 0


if __name__ == "__main__": raise SystemExit(main())
