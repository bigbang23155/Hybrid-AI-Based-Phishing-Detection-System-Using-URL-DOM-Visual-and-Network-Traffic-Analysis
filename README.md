# URL-only phishing detection — Assignment 1, Milestone 2

This repository contains local dataset ingestion, reproducible preparation, and the
hand-written URL feature layer from Milestone 1. It deliberately does **not** download
data, contact URLs, resolve DNS, extract page content, split modeling data, calculate
feature statistics, or train a model.

The eventual dataset is intended to contain roughly 2,000 phishing URLs from
PhishTank/OpenPhish and 2,000 legitimate URLs from Tranco. Dataset acquisition is
manual. Labels are `1` for phishing and `0` for legitimate. Train/validation/test
splitting is intentionally not implemented in this milestone.

## Installation

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
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

### Local raw files

Obtain each dataset yourself, review its current terms, and place the files under
`data/raw/`. The preparation command does not download anything and expects exactly:

| filename | accepted local format | assigned source and label |
|---|---|---|
| `phishtank.csv` **or** `phishtank.json` | CSV with a header containing `url`; or a JSON array of URL strings/objects with a `url` field (also accepted inside a top-level `data` or `urls` array) | `phishtank`, `1` |
| `openphish.txt` | UTF-8 text containing one URL per line | `openphish`, `1` |
| `tranco.csv` | CSV rows containing `rank,domain`; an optional literal `rank,domain` header is accepted | `tranco`, `0` |

Place only one PhishTank format in `data/raw/`; having both is treated as ambiguous.
Blank or malformed records are preserved in the audit counts and rejected rather
than causing URLs to be contacted.

**Licensing and redistribution:** PhishTank, OpenPhish, and Tranco have their own
licenses or usage terms. Verify those terms at the time you obtain the files. Do not
commit or redistribute third-party source data through this repository unless its
terms explicitly permit that use. Only small invented fixtures belong in `tests/fixtures/`.

Tranco supplies ranked **domains**, not complete observed URLs. Preparation constructs
`https://<domain>/` solely as a reproducible string representation. This creates an
important source-related HTTPS bias: every Tranco record has HTTPS syntax even though
the pipeline neither verifies HTTPS support nor observes a real page. Account for this
bias when interpreting the `uses_https` feature in later milestones.

### Run preparation

From the repository root, after placing the three source files as described above:

```bash
python -m phishing_url.prepare
```

The default target is 2,000 records per label and the default random seed is `42`.
When fewer valid unique records exist, the largest possible balanced dataset is
written. Both values can be set explicitly while retaining deterministic behavior:

```bash
python -m phishing_url.prepare --target-per-label 2000 --seed 42
```

Input is processed in the fixed order PhishTank, OpenPhish, then Tranco. Candidate
records are sorted before seeded sampling, and final records are sorted before being
written. Exact duplicates have identical stripped `url_raw` values; normalized
duplicates have distinct raw values but the same `url_clean`. Same-label duplicates
keep their first record. If a normalized URL occurs with both labels, all of its
records are excluded.

The command creates these files:

| output | contents |
|---|---|
| `data/processed/urls.csv` | Balanced records in the five-field dataset schema |
| `reports/tables/cleaning_summary.csv` | Per-source and total raw, accepted, invalid/rejected, duplicate, conflict, label, and unique-domain counts |
| `reports/tables/source_summary.csv` | Raw, accepted-before-sampling, final selected, and final unique-domain totals for each source |
| `reports/tables/rejected_records.csv` | Source row, raw value, and reason for every excluded record |
| `reports/tables/conflicting_labels.csv` | Normalized URLs seen with both labels, their sources, and record counts |

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

Tests and committed fixtures use synthetic URLs only:

```bash
pytest
```
