# Assignment 03: frozen URL baseline and paired DOM preparation

## Status and meaning of freeze

`config/assignment03_phase1_freeze.json` records the completed historical URL-only
development baseline, its execution commit, dataset and code hashes, fixed seeds,
four model families, and archived evidence. The verified source head is
`9850fb06b67e51b6eb842e9dc3180e10a1d7386d`; GitHub Actions run 37393358105
executed PR merge commit `f74bd6f90f28a85cf7cf80cc059a03fd35725d42`.

The recovered 4,000-row CSV has SHA-256
`a45a5609dec304be42616b4f100b731c8d7fe315d93e5d758afb6aae1e8df549`.
No further URL-only parameter or feature search is planned for this checkpoint.
RF is the primary development reference and GBDT is retained as the boosting
comparator, without a claim of statistically established or universal superiority.

This is a research-protocol freeze, not a main-branch merge, Git release/tag,
production deployment, or saved final fitted model. PR #10 was still open and
unmerged when this record was created. This DOM branch is based on its exact head;
its changes are reviewed separately. Frozen URL implementation and seed-plan
hashes are checked by software tests. Necessary corrections require a newly
versioned experiment, not silently overwriting the frozen evidence.

Important qualification: Phase 1 did not evaluate the historical test again, but
Assignment 02 had already evaluated that same historical holdout. It must not be
called an entirely unseen final test. DOM/hybrid development needs separately
versioned paired data and a new, unused final holdout. The training-size diagnostic
varied subsets of the existing training pool; it was not a new external-data
expansion, and its subsets were not nested.

## Professor's required next step

Assignment 03 sections 2-4 require data with paired URL and HTML/DOM, documented
sources, failures, redirects and bias, a reproducible structural feature extractor,
and URL-only / DOM-only / URL+DOM comparisons using the same samples and the same
domain-grouped partitions. Validation supports development; the new test is
reserved for later final evaluation. Public paired data is permitted when live
collection is insufficient. Numerical pilot targets below are our engineering
choices, not requirements imposed by the professor.

We do not revisit historical URLs and label their present pages as if they were
the historical captured content. The previous live observation pilot and its
label-policy-v1 adjudication gates remain unchanged and are not restarted here.

## Current step: bounded offline feasibility pilot, not approved training data

The selected candidate source is the authors' PhreshPhish published URL/HTML
corpus. We pin one train shard and its revision/hash in
`config/assignment03_dom_pilot.json`. This first, relatively small shard is a
convenience choice for bounded engineering validation, not a representative random
sample of the full corpus or reproduction of the paper's evaluation protocol.
The source's test files are not requested.

Before inspecting HTML, normalize URL metadata, reject invalid/schemeless URLs,
remove conflicting URL labels, resolve exact normalized duplicates, and select at
most 128 candidates per source class with a cap of three per domain per class.
Selection uses a fixed hash ordering and recorded seed. Missing/oversized/unusable
HTML is retained as failure evidence and is never replaced by a more convenient
candidate. HTML payloads are limited to 2 MiB per selected candidate.

Source `benign` and `phish` map to 0 and 1 only as published source labels in this
separate offline pilot context. They are not independently human-adjudicated
project labels. Every paired record and the summary explicitly retain
`training_approved=false`. No technical pass authorizes model training, dataset
expansion, or a change to the existing live observation labeling policy.

## Pairing and evidence

The adapter reads URL, label, date and publisher sample ID from the verified
Parquet file and binds them to the HTML string at the exact same source-row
ordinal. Sample identity includes the immutable source-file hash and row ordinal.
We never join unrelated datasets using a similar URL, brand or label.

Each selected record records raw/normalized URL, source label and label basis,
registered domain, source revision/file/hash/row, source date, a content hash,
HTML path, parsing status, and provisional leakage-group/split. Original HTML is
stored as the UTF-8 serialization of the published string, not claimed to be a
new capture or the original HTTP transport bytes. `HTMLParser` performs a static,
tolerant markup probe; it neither renders DOM nor executes JavaScript. Nonempty
markup is not proof that a page is usable, benign, or phishing.

The source shard does not provide the full original navigation/HTTP evidence used
by this adapter. Final URL, redirect chain, HTTP status and per-URL source
verification time remain null. Missing information does not become zero, and an
unavailable or failed page does not become a benign example. The date supplied by
the publisher is kept as a source date, not invented as our verification time.

Pilot partitions connect original domains, known final domains, and identical
HTML transitively before applying the existing grouped split procedure. Exact
HTML shared across conflicting labels is quarantined. This does not eliminate all
near-template/campaign/hosting/temporal leakage. The exploratory pilot reports
class coverage, parsing losses, domain diversity, password-input presence and
homepage-URL proportions to expose possible login-page versus homepage bias.

The provisional pilot split is for testing the preparation machinery. Its global
exploratory audits mean it is not advertised as the final untouched study test.
For a later approved study, reserve new domain/content groups outside pilot review,
record all sampling/exclusion decisions, and keep the new test out of development.
Any final holdout overlap with pilot-reviewed domains/content must be excluded or
explicitly handled before freezing the final sampling protocol, not after scores.

## Cloud execution and artifacts

The `Assignment 03 offline DOM data pilot` workflow runs offline unit tests,
downloads only the pinned public dataset shard, verifies its exact SHA-256, then
runs the adapter in a non-root, read-only-root container with no network, dropped
capabilities and bounded memory/process resources. No dataset URL is visited; no
browser, authentication, form submission, executable download from a webpage or
script execution is performed.

The container image ID and project commit are recorded. The optional Parquet
reader is pinned in `requirements-dom.txt`; the frozen URL requirements are not
modified. The base image and indirect dependencies are not a fully digest-locked
reproducible environment, so recorded versions/image identity remain relevant.

The job creates a local `paired_manifest.jsonl` and hash-named HTML payloads, but
public Actions artifacts deliberately retain only source protocol/integrity,
aggregate audit results and the hashed source-row replay index. Raw URLs/HTML are
not republished in public PR text or public artifacts. The original pinned public
source, configuration and replay index allow deterministic reconstruction; this
pilot does not claim permanent private storage of all derived HTML payloads.
A final dataset release requires a deliberate access/retention and license review.

Cloud entry points are the workflow and:

```bash
python -m pip install -r requirements-dom.txt
PYTHONPATH=src python -m phishing_url.dom_dataset \
  --parquet /input/source.parquet \
  --config config/assignment03_dom_pilot.json \
  --output /output/pilot
```

A completed workflow means the pipeline ran. Read `pilot_summary.json` for actual
technical suitability; a passing technical pilot still has no training approval.
No URL, DOM or hybrid model is trained by the dataset-preparation command.

## Preserved expansion roadmap

| Module | Current implementation status | Appropriate milestone |
|---|---|---|
| URL lexical features, LR/DT/RF/GBDT | Completed historical development baseline, now frozen | Keep as fixed reference; use the same pipeline on new paired training data for a fair hybrid comparison |
| Paired URL/HTML ingestion and audit | This change: bounded offline pilot infrastructure | Assignment 03 data preparation, before final data approval |
| DOM structural features | Static pilot probes only; full model-facing feature registry not yet implemented | Assignment 03 required core after paired-data readiness |
| URL-only / DOM-only / URL+DOM | Not implemented for the new paired dataset | Assignment 03 core, same samples/splits and validation-only selection |
| YARA HTML/JS signatures | Planned, not implemented | Optional after the required structural URL+DOM comparison works |
| Hex arrays, encoding/obfuscation and lightweight decoder analysis | Planned, not implemented | Later content-forensics module; separately defined and evaluated features |
| Deep reverse engineering / kit fingerprints | Planned, not implemented | Analyst-mode extension, not a required automatic real-time step |
| Visual similarity | Planned, not implemented | Remaining project scope; needs properly paired screenshots and provenance |
| Web network/redirect evidence | Earlier capture framework is separate; no integrated classifier feature layer | Remaining scope; actual captured evidence, no fabricated redirects/status from HTML alone |
| Evil Twin | Planned, not implemented | Optional network-sensor extension requiring endpoint/Wi-Fi observations unavailable from a normal cloud HTTP collector |
| AiTM indicators, phishing-resistant MFA and session protection | Planned, not implemented | Optional identity/authentication integration; browser/identity/session evidence and authorized controls, not claims made from YARA or a URL score alone |

The long-term defense workflow remains pre-authentication detection ->
authentication protection -> post-authentication session monitoring/containment.
These are architectural phases, not a claim that the current URL model can enforce
MFA, inspect Wi-Fi, observe stolen server sessions, or block every attack.

Assignment 03 critical path is frozen historical URL baseline -> paired-data
feasibility -> approved/versioned paired dataset and new holdout -> DOM structural
extractor -> same-sample URL/DOM/hybrid validation -> report and achievable
visual/network plan. Optional modules do not reopen or delay Phase 1.

## Source references

- Professor-provided Assignment 03, sections 1-6.
- PhreshPhish authors' dataset card: https://huggingface.co/datasets/phreshphish/phreshphish
- Pinned source revision: https://huggingface.co/datasets/phreshphish/phreshphish/tree/eabec4b7a66324b79cc8a0ad856d1731dc26fe1a
- Authors' paper: https://arxiv.org/abs/2507.10854
- Python static HTML parser: https://docs.python.org/3/library/html.parser.html
- Apache Arrow Parquet reader: https://arrow.apache.org/docs/python/parquet.html

Preserve attribution and the publication's CC-BY-4.0 and anti-phishing research
usage statement. No safety of a currently live URL is established by this pilot.
