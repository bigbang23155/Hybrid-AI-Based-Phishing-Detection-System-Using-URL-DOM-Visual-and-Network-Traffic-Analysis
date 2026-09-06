# URL-only phishing detection — Assignment 1, Milestone 1

This repository contains the data preparation and hand-written URL feature layer for
Assignment 1. It deliberately does **not** download data, contact URLs, resolve DNS,
extract page content, or train a model.

The eventual dataset is intended to contain roughly 2,000 phishing URLs from
PhishTank/OpenPhish and 2,000 legitimate URLs from Tranco. Dataset acquisition is
outside this milestone. Labels are `1` for phishing and `0` for legitimate. When a
modeling milestone is started, records should be grouped by `registered_domain` and
those groups split 70%/15%/15% into train/validation/test to prevent domain leakage.

## Installation

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The implementation has no runtime dependencies and parsing never makes an external
request. For this milestone, a registered domain is the final two hostname labels,
except for the fixed common compound suffixes `co.uk`, `org.uk`, `ac.uk`, `com.au`,
`net.au`, `org.au`, `co.nz`, `co.jp`, `com.br`, and `com.cn`, where it is the final
three. This deliberately small, reproducible rule is suitable for the synthetic
tests; a later dataset milestone should version a complete Public Suffix List.

## Dataset preparation

Input records are represented by `URLRecord` and exported with exactly these columns:

| column | definition |
|---|---|
| `url_raw` | Source URL after removal of surrounding whitespace only |
| `url_clean` | Validated, deterministic normalized URL used for deduplication/features |
| `label` | Integer `1` (phishing) or `0` (legitimate) |
| `source` | Non-empty source name, e.g. `phishtank`, `openphish`, or `tranco` |
| `registered_domain` | Domain produced by the fixed suffix rule above; an IP address is kept as-is |

Use `prepare_records` on dictionaries containing `url_raw`, `label`, and `source`.
Cleaning accepts only absolute HTTP(S) URLs. It strips surrounding whitespace,
rejects embedded whitespace/control characters, lowercases the scheme and IDNA
hostname, removes a fragment, removes default ports, and supplies `/` for an empty
path. User-information (the text before the final `@` in the authority) is retained
so it can be analyzed lexically; the package never dereferences the URL. Cleaning
does not unescape, sort, or discard query parameters.

Deduplication keeps the first record for duplicate normalized URLs (which also
covers exact duplicates). If both labels occur for a normalized URL, every record
for that URL is excluded and a `ConflictingLabelWarning` reports the conflict rather
than silently selecting one label.

```python
from phishing_url.dataset import prepare_records

records = prepare_records([
    {"url_raw": "HTTPS://Example.COM:443/login#top", "label": 1, "source": "synthetic"},
])
```

## URL-only features

`extract_features(url)` first applies `clean_url`. **All 18 features are therefore
calculated from `url_clean`, never `url_raw`.** Complete-URL character counts and
entropy use that cleaned string; hostname/path/query lengths use components parsed
from the same cleaned string.

| feature | definition |
|---|---|
| `url_length` | Number of Unicode characters in the complete cleaned URL |
| `hostname_length` | Characters in the normalized hostname (port excluded) |
| `path_length` | Characters in the path (always at least `/`) |
| `query_length` | Characters after `?`, excluding the `?` |
| `dot_count` | Literal `.` characters in the complete cleaned URL |
| `subdomain_count` | Host labels before the registrable domain; `0` for IPs/localhost |
| `slash_count` | Literal `/` characters in the complete cleaned URL |
| `digit_count` | Unicode decimal digit characters in the complete cleaned URL |
| `digit_ratio` | `digit_count / url_length` (zero only for an empty string, which validation prevents) |
| `hyphen_count`, `at_count`, `question_count`, `equals_count`, `ampersand_count` | Counts of literal `-`, `@`, `?`, `=`, and `&` in the complete cleaned URL |
| `uses_https` | `1` when the scheme is HTTPS, otherwise `0` |
| `is_ip_hostname` | `1` when the entire hostname is a valid IPv4 or IPv6 address |
| `suspicious_keyword_count` | Case-insensitive, overlapping-free substring occurrences of `account`, `bank`, `confirm`, `login`, `password`, `secure`, `signin`, `update`, and `verify` in the complete cleaned URL |
| `url_entropy` | Shannon entropy in bits per character over Unicode characters: `-sum(p(c) * log2(p(c)))` |

No feature performs network I/O.

## Testing

Tests use synthetic URLs only:

```bash
pytest
```
