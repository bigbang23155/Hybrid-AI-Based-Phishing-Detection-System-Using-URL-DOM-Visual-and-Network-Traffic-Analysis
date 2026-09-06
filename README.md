

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

## URL feature extraction and statistics

After preparing `data/processed/urls.csv`, extract the existing lexical URL
features and write label-level statistics and quality checks with:

```bash
PYTHONPATH=src python -m phishing_url.feature_analysis --root . --expected-per-label 2000
```

This command treats URLs only as text and does not perform network requests. It
retains the five input dataset columns in their original order, appends the fixed
features from `phishing_url.features`, and writes:

- `data/processed/url_features.csv`
- `reports/tables/feature_summary_by_label.csv`
- `reports/tables/feature_quality_summary.csv`

Numeric summaries contain count, mean, median, sample standard deviation, minimum,
and maximum. Binary summaries contain the count and proportion equal to one.
Because preparation constructs every Tranco record with an `https://` scheme, the
`uses_https` feature contains source-specific collection bias and must not be
interpreted as an independently observed security property for those records.



```bash
pytest
```
