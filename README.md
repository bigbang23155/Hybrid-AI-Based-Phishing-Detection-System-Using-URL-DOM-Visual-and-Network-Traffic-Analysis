

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

## Assignment 02: model and sampling foundation

Current status (September 26, 2026): the existing Assignment 02 implementation is
preserved and revised. No approved Dataset v2 exists and no formal model metrics
are claimed. Do not repeat the closed Assignment 01 recovery search.

See [current report](docs/assignment02_progress_report_en.md),
[model/sampling methods](docs/model_sampling_method.md),
[feature rationale](docs/feature_rationale.md), and
[final data protocol](docs/final_research_protocol.md).

For a prospective study, generate one recorded seed plan before inspecting outcomes:

```bash
PYTHONPATH=src python -m phishing_url.randomness --output config/study_seeds.json
```

This uses system entropy once, derives independent sampling/test/development/model
seeds, and refuses to overwrite the plan. Use `--master-seed INTEGER` for an explicit
reproducible plan. Never regenerate seeds to seek a better score. Without a plan,
legacy split seeds 2025 and 11/23/37/53/71 remain available.

Once approved original data and provenance are available, the existing preparation
CLI accepts `--seed-plan config/study_seeds.json` instead of `--seed`. Its original
PhishTank/OpenPhish/Tranco parsers remain; the Tranco parser constructs roots and
must not be confused with observed URL ingestion. No new source is automatically approved.

Development only, after dataset approval and freezing:

```bash
PYTHONPATH=src python -m phishing_url.experiment run \
  --input data/processed/urls.csv --output results/assignment02/development \
  --seed-plan config/study_seeds.json --feature-sets baseline no_https
```

This saves all shared split manifests, development-only feature audits,
validation metrics/mean/SD, selected parameters and paired model differences.
It does not evaluate test or create final models. Named schemas also include
`compact16`, `expanded21`, and genuinely `hostname_only` (4 features). Declare
optional comparisons before final evaluation; every row has the same schema.

Explicit finalization requires the completed development evidence and the same
input hash, source-code hashes, dependency versions, seeds and configuration:

```bash
PYTHONPATH=src python -m phishing_url.experiment run \
  --input data/processed/urls.csv --output results/assignment02/final \
  --seed-plan config/study_seeds.json --feature-sets baseline no_https \
  --evaluate-test --development-run results/assignment02/development
```

It replays and verifies development splits, selections and validation metrics before
planned test comparisons, then saves actual test metrics, importance, errors,
latency and model artifacts. Threshold is 0.5 and phishing is class 1. It refuses
to overwrite populated evidence, including with the retained legacy `--overwrite`
argument. Research discipline is still required: these checks are not access control.

Predict with a finalized trusted artifact without visiting the URL:

```bash
PYTHONPATH=src python -m phishing_url.experiment predict \
  --model results/assignment02/final/models/baseline_logistic_regression.joblib \
  'https://example.com/'
```

## Assignment 03 Phase 1: complete and freeze the URL baseline

Assignment 03 starts by completing the URL-only baseline before DOM work. The
development protocol now compares Logistic Regression, Decision Tree, Random
Forest, and scikit-learn Gradient Boosting (GBDT) on the same domain-grouped splits. Model/feature decisions remain
validation-only; the held-out test set is not used for Phase 1 development.

Run a fresh development experiment with the updated protocol:

```bash
PYTHONPATH=src python -m phishing_url.experiment run \
  --input data/processed/urls.csv \
  --output results/assignment03/phase1_development \
  --seed-plan config/study_seeds.json \
  --feature-sets baseline no_https
```

After that development run is frozen, run the Assignment 03 diagnostics:

```bash
PYTHONPATH=src python -m phishing_url.phase1_diagnostics \
  --dataset data/processed/urls.csv \
  --development results/assignment03/phase1_development \
  --output results/assignment03/phase1_diagnostics
```

The diagnostic produces a domain-aware training-size stability comparison at
25/50/75/100% of the available training data and an optional conventional random
URL split comparison. Both use only the development pool. Hyperparameters are
held fixed from the domain-grouped development run, random-split domain overlap
is reported explicitly, and the frozen test membership is never scored.

Do not run `--evaluate-test` for Assignment 03 development. A real experiment
also requires the approved dataset to be available in the execution environment;
the repository's pull-request workflow can validate software behavior without
claiming research metrics.

## Prospective observation pilot checkpoint — September 27, 2026

The new [label policy](docs/label_policy_v1.md),
[observation protocol](docs/observation_pilot_v1.md) and
[schema](schemas/observation_v1.schema.json) were exercised in GitHub Actions.
The repaired run recorded all 16 candidates and passed schema/integrity checks;
complete captures were 6/8 official controls and 3/8 source-reported phishing candidates.
The fixed completeness gate failed, so no expansion, Dataset v2 or model training occurred.
Read the [actual run report](docs/observation_pilot_results_en.md) before using the data.
Source assertions remain separate from adjudicated labels. Future live pilots require
explicit workflow dispatch; report commits do not initiate collection.

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
