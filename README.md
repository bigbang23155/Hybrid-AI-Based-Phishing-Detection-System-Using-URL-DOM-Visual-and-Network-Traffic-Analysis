

## Installation

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

```

URL parsing never visits a URL. Registered domains use `tldextract`'s packaged
Public Suffix List snapshot with network updates disabled and private suffixes
excluded. The exact parser version and policy are saved in the experiment manifest.

## Dataset preparation

Input records are represented by `URLRecord` and exported with exactly these columns:

| column | definition |
|---|---|
| `url_raw` | Source URL after removal of surrounding whitespace only |
| `url_clean` | Validated, deterministic normalized URL used for deduplication/features |
| `label` | Integer `1` (phishing) or `0` (legitimate) |
| `source` | Non-empty source name, e.g. `phishtank`, `openphish`, or `tranco` |
| `registered_domain` | PSL-aware eTLD+1 produced offline; a normalized IP address is kept as-is |

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

## Assignment 02: reproducible baseline experiment

The preferred input is the archived Assignment 01 file
`data/processed/urls.csv`; when it exists, run the experiment directly and do
not rebuild it. Only if that processed file is unavailable, reconstruction needs
the following local inputs (not committed because feeds may be licensed/sensitive):

* exactly one of `data/raw/phishtank.csv` or `data/raw/phishtank.json`;
* `data/raw/openphish.txt`;
* `data/raw/tranco.csv`.

To reconstruct a missing processed file, run the first command. Then run the
second command for the audit, locked domain-aware split, five-seed validation,
both models, and required no-HTTPS sensitivity comparison:

```bash
PYTHONPATH=src python -m phishing_url.prepare --root . --target-per-label 2000 --seed 42
PYTHONPATH=src python -m phishing_url.experiment run \
  --input data/processed/urls.csv --output results/assignment02
```

The second command creates `dataset_audit.csv`, domain groups and feature
distribution/correlation tables, `split_manifest.csv`, `split_summary.csv`,
`validation_seed_metrics.csv`, `validation_summary.csv`, `final_test_metrics.csv`,
`model_comparison.csv`, feature importance, defanged error analysis, the experiment
manifest, feature schemas, and fitted pipelines under `results/assignment02/models/`.
Seed 2025 locks the test domains; seeds 11, 23, 37, 53 and 71 are development-only.
The positive class is phishing (`1`) and the baseline threshold is 0.5.

Predict locally with an artifact (no network access):

```bash
PYTHONPATH=src python -m phishing_url.experiment predict \
  --model results/assignment02/models/baseline_logistic_regression.joblib \
  'https://example.com/'
```

Named feature sets are `baseline`, `no_https`, and `hostname_only`; library callers
may pass any comma-separated ordered subset through `resolve_feature_set`. Unknown,
duplicate, empty, and metadata columns are rejected. The saved artifact is a dict
containing the fitted sklearn pipeline and its exact ordered schema.

The runner refuses to replace a populated result directory. Preserve the old
run or select a new output directory. `--overwrite` is available only for an
explicitly intentional replacement. The protocol is frozen in
`experiment_config.json` before model fitting; the execution manifest includes
the bundled PSL snapshot SHA-256 and Git state captured before result files are
created. Serialized pipelines and raw URL datasets should normally remain local.

See `docs/feature_rationale.md`, `docs/dataset_bias_and_limitations.md`, and the
English/Traditional-Chinese progress reports. No formal results are claimed unless
the real input checksum and generated manifest accompany them.

## Observed legitimate URL acquisition

The bounded collector accepts a **frozen local** Tranco CSV, samples candidate
domains with a recorded seed, and retains only URLs actually observed as a final
homepage response, same-site homepage link, or sitemap entry. It does not submit
forms or visit phishing URLs. It validates public DNS destinations, limits
redirects and response sizes, applies robots rules to inner-URL discovery, rejects
credentials/token-like query keys, and enforces a per-domain cap.

```bash
PYTHONPATH=src python -m phishing_url.legitimate_collection \
  --tranco data/raw/tranco-top-1m-2026-09-26.csv \
  --output data/collection/legitimate_v2 \
  --seed 20250926 --rank-min 1001 --rank-max 100000 \
  --domains 1200 --per-domain-cap 3 --timeout 4 --workers 20 \
  --request-delay 0.25

PYTHONPATH=src python -m phishing_url.collection_audit \
  --observations data/collection/legitimate_v2/observed_legitimate_urls.csv \
  --failures data/collection/legitimate_v2/collection_failures.csv \
  --output results/assignment02/legitimate_collection_pilot
```

The audit exits with status 2 when its preregistered suitability gate fails.
Candidate membership is evidence for sampling, not proof of safety; retained
records are described as assumed legitimate under the collection policy.

For Windows execution, use `docs/windows_collection_guide.md`. The PowerShell
helpers keep diagnostic and full outputs separate, verify the frozen candidate
snapshot, refuse to overwrite evidence, and package returned outputs. The preserved
configuration is also recorded in `config/legitimate_collection_windows.json`.

For cloud execution, a maintainer may manually dispatch **Collect observed
legitimate URLs** in GitHub Actions. The workflow verifies the stable Tranco list
ID/checksum, runs the fixed diagnostic first, skips the full run when connectivity
is inadequate, and uploads all evidence as an Actions artifact. Committing the
workflow does not mean that collection or Dataset v2 has completed.



```bash
pytest
```
