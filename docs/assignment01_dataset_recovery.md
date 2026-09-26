# Assignment 01 dataset recovery record

## Outcome

The original Assignment 01 dataset was **not recoverable from the current execution
environment** on 2026-09-26. No archive has been created, and no replacement data
has been downloaded or generated. In particular, the tiny files under
`tests/fixtures/` and pytest's temporary directories are synthetic test fixtures;
they are not the reported 4,000-record research dataset.

## Locations and retained state checked

The recovery attempt checked the entire accessible filesystem for:

- `data/processed/urls.csv` and `data/processed/url_features.csv`;
- the three expected raw feeds under `data/raw/`;
- `reports/tables/` directories;
- archive names containing the project, phishing, or Assignment 01; and
- CSV files large enough to plausibly contain the historical dataset.

It also inspected all local Git refs, commit history, reflogs, unreachable objects,
and historical paths. PR #3 (merge `2345f3b`) contains only a preparation-code
change; PR #4 (merge `15bbae8`) contains feature-analysis code, documentation, and
tests. No data or report artifact is present in either merge tree or any other local
Git object. This is consistent with `.gitignore`, which excludes the raw data,
processed data, and generated report-table directories.

The checkout's `FETCH_HEAD` identifies the upstream GitHub repository, but it is
private from this environment: there is no configured remote or GitHub
authentication, and anonymous repository/API requests fail. No MCP resources or
resource templates expose retained task artifacts. Consequently, a release,
workflow artifact, or earlier task workspace could not be retrieved and no claim
is made that a downloadable dataset archive exists.

## Required recovery input

Provide the unchanged original Assignment 01 processed file at:

```text
data/processed/urls.csv
```

Its expected header is:

```text
url_raw,url_clean,label,source,registered_domain
```

The expected 2,000/2,000 class counts are validation expectations, not values that
will be forced. If only the historical `url_features.csv` or a project archive is
available, place it in the repository without modifying it and inspect its metadata
before reconstructing anything. A fresh feed must not be represented as the
Assignment 01 dataset.

Once supplied, preserve the source file byte-for-byte, compute SHA-256 checksums,
validate its schema/counts/labels, and package the processed dataset with any
available cleaning/source summaries. The archive should be delivered through the
session's actual downloadable-artifact mechanism rather than merely referenced by
a local path.
