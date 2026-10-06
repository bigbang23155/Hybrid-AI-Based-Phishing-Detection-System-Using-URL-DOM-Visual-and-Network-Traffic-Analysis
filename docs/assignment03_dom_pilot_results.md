# Assignment 03 DOM data preparation: actual pilot results

## Result

The first offline paired URL/HTML data-preparation pilot completed in GitHub
Actions. The fixed public source file passed its preregistered SHA-256 check.
There were 256 selected candidates and 255 technically parseable URL/HTML pairs.
One source-labeled benign HTML payload exceeded the 2 MiB limit; it was recorded
and not replaced. This is a **technical feasibility result**, not final dataset
approval or model performance evidence.

Execution: commit `a3674730c586a73a0066b0b75c8e15004dccb24b`, workflow run
37396035696, job 112052093592. The full offline software suite passed:
**84 tests in 37.06 seconds**. Frozen URL implementation and seed-plan hashes
were among the tested invariants. The old live observation pilot was skipped,
not restarted. URL tuning, live page visits, DOM training and test scoring did not
occur in the data-preparation run.

## Data and exclusions

| Check | Actual result |
|---|---:|
| Verified train-shard source rows | 1,000 |
| Invalid/schemeless URL metadata exclusions before selection | 12 |
| Eligible unique normalized URL rows | 988 |
| Selected source-labeled benign / phishing | 128 / 128 |
| Parseable benign / phishing pairs | 127 / 128 |
| Oversized HTML exclusions after selection | 1, no replacement |
| Benign / phishing registered-domain counts | 116 / 106 |
| Distinct HTML hashes among 255 usable pairs | 253 |
| Connected leakage groups | 220 |

These are counts for the one selected shard and pilot, not the full published
PhreshPhish corpus. Published labels are retained as source assertions; no
independent project human adjudication is claimed. Static parsing demonstrates
readability of markup, not completeness of browser-rendered content or correctness
of a phishing label.

## Provisional split verification

| Pilot partition | Benign | Phishing | Total |
|---|---:|---:|---:|
| Train | 88 | 89 | 177 |
| Validation | 19 | 19 | 38 |
| Test | 20 | 20 | 40 |

The downloaded replay index has 256 unique sample IDs. All 255 usable pairs have
one partition, and no leakage component or exact HTML hash crosses partitions.
The 256th record is the oversized HTML exclusion. The grouping connects domains
and exact HTML hashes transitively, not merely individual URLs.

This split tests the preparation machinery. Exploratory pilot-wide diagnostics
mean its test partition is not advertised as the final untouched study holdout.
Before the final paired study, specify the sampling frame and exclude or otherwise
explicitly handle pilot-reviewed domains/content, then reserve a new test set and
keep it outside development. Exact-content grouping does not solve all
near-template, campaign or temporal leakage.

## Bias observations requiring investigation

Root-path URL proportions are 7/127 (5.51%) in the benign pilot subset and 63/128
(49.22%) in the phishing subset. Root path means URL path is empty or `/`; it is
not a verified semantic homepage classification. Password inputs appear in 20/127
(15.75%) versus 34/128 (26.56%) of the static HTML strings. These differences do
not establish causal security indicators or justify automatically relabeling rows.
They identify aspects to review before the formal same-sample model comparison.

All usable pairs include a publisher-provided source date. Unknown final URL,
HTTP status, redirect chain and per-URL source verification time remain null.
Current live content was not fetched to fill those gaps. No source-dependent
missingness flag is approved as a model feature in this change.

## Evidence retention and integrity

Machine-readable results: `results/assignment03/dom_data_pilot_v1/verification.json`.
Original public artifact: `assignment03-dom-data-pilot-37396035696`,
artifact ID **11382518633**, 25,939 bytes. Its downloaded ZIP hash is:

`c6c1237bb11f74308799203d6470f1e0f9abb3c84c49d0cfe50bc772b00c8be3`.

Source-file hash:
`9a9c693a95daeddb127c4446df4c5673b3f1a39e457ffe964b9849069bd739fe`.

The artifact contains the source protocol, source integrity record, execution
commit, container image ID, aggregate summary and hashed source-row replay index.
It does not contain republished raw URLs or HTML. The pinned public file and
source-row index support deterministic reconstruction. The full derived paired
manifest/HTML existed during the isolated job; do not claim they are permanently
archived in this public artifact. The manifest hash is recorded for replay checking.

## Status and next step

- Historical URL development baseline: frozen; PR #10 remains a separate merge decision.
- DOM data-preparation implementation and bounded real-data pilot: complete.
- Final paired DOM dataset: not yet frozen or approved for training.
- DOM model-facing feature registry, DOM-only model and URL+DOM model: not yet implemented.

Next work is the final paired-data sampling/label/content/bias and retention
protocol, followed by the structural DOM extractor and the professor's required
same-sample URL-only / DOM-only / URL+DOM comparison. YARA and deeper content
forensics are later optional modules, not reasons to resume URL-only tuning.
The broader roadmap is in `docs/assignment03_scope_and_dom.md`.

Source: authors' PhreshPhish dataset card and pinned revision recorded in
`config/assignment03_dom_pilot.json`. This run used only a public train shard;
it does not reproduce the authors' benchmark or use their official test split.
