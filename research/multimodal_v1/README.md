# Four-modality evidence foundation v1

This extension runs offline on a **decrypted existing urlscan Collector run**.
It does not collect URLs, submit scans, change labels, fit models, or read the
sealed test data. Existing Assignment 03 definitions and evaluation remain frozen.
All outputs stay research-only and `eligible_for_training=false`.

## Delivered components

| Component | Implemented now | Boundary |
|---|---|---|
| Network-HTTP | Versioned 20-feature registry, nested Result JSON extractor, per-field coverage | HTTP metadata, not full HAR/PCAP; no provider verdict/reputation features |
| Four modalities | URL/DOM adapters, Visual quality/signature adapter, Network adapter; numeric values, reasons, time and masks | No visual semantic model, learned fusion, imputation or attention training |
| Content Forensics | 13 byte-level indicators and 4 compiled YARA rules, bounded offsets and source/rule hashes | Lexical signals, not execution evidence, phishing labels or verdict probabilities |
| Integration | Collector checkpoint integrity/identity checks, offline batch CLI, private JSONL + sanitized attrition summary | No historical snapshot replacement or equivalence claim |

## Reproduce

From the repository root, with Python 3.12:

```bash
python -m pip install -r research/multimodal_v1/requirements.txt
PYTHONPATH=src REQUIRE_YARA=1 python -m unittest discover -s research/multimodal_v1 -p 'test_*.py' -v
PYTHONPATH=src python -m research.multimodal_v1.pipeline \
  --run /absolute/path/to/decrypted-collector-run \
  --output /absolute/path/to/new-private-feature-run \
  --as-of 2026-10-17T03:00:00Z \
  --max-age-seconds 86400
```

The timestamp and **one-day cutoff above are an example, not a calibrated research
threshold**. Both parameters are required. Lock them before downstream comparisons;
never select them using held-out performance. Use the identical reference time to
reproduce masks. `retrieved_at`, publication date and original HTML snapshot date
are not substituted for the scan capture time.

The output directory must be new, outside the repository and input run. It is
created with mode 0700. The command refuses to overwrite files. Interrupted or
invalid batches retain `run.json: complete=false`; consumers must reject these
batches. No resume is implemented: rerun to a new directory after fixing input.

Outputs:

- `private/features.jsonl`: fixed four-modality records, quality states, evidence
  provenance, visual hashes and forensic sidecars. No raw HTML, cookie values,
  request bodies or matched strings are copied.
- `private/fusion_inputs.jsonl`: explicit ordered columns, nullable values,
  feature masks, modality masks and `all_missing`. This is an unfitted handoff,
  not a model-ready imputed matrix.
- `public/summary.json`: acquisition, extraction, freshness and YARA status counts.
- `public/feature_quality.json`: all 64 columns' observed/usable/zero counts,
  nullable fractions, missing reasons, known support totals and same-scan alignment.
- `public/network_http_registry.json`: definitions, units, source paths, limits
  and null policy. Source of truth is `network_http.py::DEFINITIONS`.
- `run.json`: fixed time policy, runtime/dependency versions, implementation hashes,
  registry/rule hashes and output hashes. Feature order survives JSON sorting.

Detailed outputs remain private even though raw payloads are omitted. The offline
CLI has no upload operation. The CI offline job uses synthetic data and no Secrets;
a separate bounded public-control job described below uses the existing encrypted
evidence store. Historical acquisition remains paused.

## Coverage and existing public-scan validation

Coverage denominators include **every attempted record**, including absent artifacts.
No complete-case filtering silently improves reported coverage. Observed zeros are
counted separately from nulls; stale values remain observed but are not usable.
Support totals include only records whose expected denominator is known. Missing
reasons and quality flags in this report use fixed allowlists; unknown text becomes
`other_reason` or `other_quality_flag` and cannot leak provider content.

Before export, the pipeline recomputes and checks stored masks and exact registry
versions/order. Acquired modalities must bind to the same checkpoint hash; DOM,
Visual and HTTP must agree on scan UUID, capture time and submitted/final URL
hashes. Artifact hashes and the HTTP representation/registry are required. A
conflict aborts the batch with `complete=false`. Missing modalities are instead
reported as `incomplete`, preserving the attempted record and explicit nulls.
Pairing proves consistent evidence provenance, not authenticity of page content.

The `public-evidence-smoke` CI job runs after offline tests on the existing research
branch only. It uses the fixed `https://example.com/` positive control, searches
existing public scans, and GETs verified JSON/DOM/screenshot evidence. It never
submits scans or reads historical candidate Secrets. The client has a 15-request
budget and 12-second request interval. No historical collection config is changed.

```bash
PYTHONPATH=src python -m research.multimodal_v1.smoke \
  --work /absolute/path/to/new-private-smoke \
  --publish /absolute/path/to/new-publish-directory
```

The job requires `URLSCAN_API_KEY` and validates the existing RSA recipient before
any request. All raw evidence, feature rows and manifests are encrypted together
with the existing authenticated evidence format. CI uploads only ciphertext,
encryption receipt, execution identifiers and allowlisted quality/readiness JSON;
artifacts expire after 30 days and plaintext is removed in an always-run cleanup.
Failed or partial captures are retained encrypted for diagnosis and fail the job.

Pass requires one aligned record, a usable feature in all four modalities, nonzero
HTTP request counts, usable main HTTP status and successful YARA execution.
`PASS_WITH_GAPS` explicitly lists optional unavailable columns (for example cookie
ratios with zero cookies). The seven-day freshness cutoff is a provisional public
control policy, **not a learned reliability threshold**. The exact reference time,
implementation hashes, rules and dependencies are saved for reproducibility.
The same scan may age out or become unavailable, so later live runs need not pass.
This is one provider integration control, not dataset coverage, detection accuracy,
proof of a benign label, or a substitute for independent human review.

## Missingness and reliability contract

Each modality has independent `acquisition_status`, `extraction_status` and
`temporal.status`; a single `COMPLETE` flag is insufficient.

| Situation | Acquisition | Extraction / freshness | Feature behavior |
|---|---|---|---|
| Valid numeric zero | available | ok or partial / fresh | `0`, observed mask 1, usable mask 1 |
| Screenshot never supplied | not_supplied | unavailable | all null, both masks 0 |
| Screenshot endpoint 404/410 | not_found | unavailable | all null; does not mean page is benign |
| Timeout or failed download | download_failed | unavailable | all null; specific Collector error retained |
| Earlier failure prevented attempt | not_attempted | unavailable | all null |
| Corrupt content reported by Collector | invalid_artifact | unavailable | all null |
| Hash/path/identity verification fails | integrity_failed | unavailable | all null; no forensic analysis of unverified bytes |
| File present but extractor fails | available | failed | all null; acquisition remains successful |
| Required optional engine unavailable | available | dependency_missing, or YARA dependency_missing | no fabricated no-hit result |
| Scan older than explicit maximum | available | stale | audit values retained, usable mask 0 |
| Unknown / future capture time | as observed | unknown / future | unusable for fusion |
| Submitted URL lexical features | available if valid | not_applicable freshness | records string analysis, not live site observation |

`modality_available_mask=1` means at least one numeric feature was observed;
`modality_usable_mask=1` means at least one survives the time/availability gate.
It does **not** mean the modality is complete, trustworthy or semantically useful.
Retain the feature mask, observed fraction, quality flags and raw freshness fields
alongside the modality mask. These are inputs for a future reliability model, not
calibrated attention weights. For example, a flat screenshot is flagged and still
has observable dimensions; it is not automatically assigned a classification score.

Missing values remain JSON `null`. Future imputers/scalers must fit on training folds
only and keep masks. Quality flags and provider/time metadata are audit inputs, not
automatically appended to the predictive feature vector. All-missing input requires
an explicit abstention/fallback policy downstream. The current view sets
`all_missing=true` and provides no prediction.

## HTTP registry semantics

There are 20 fixed columns:

| Group | Features |
|---|---|
| Request structure | request_record_count, http_request_count, unique_http_host_count |
| Request composition | https_request_ratio, cross_host_request_ratio, post_request_ratio, xhr_fetch_request_ratio |
| Responses | response_3xx_ratio, response_4xx_ratio, response_5xx_ratio, unique_mime_count, javascript_response_ratio |
| Reported lengths | encoded_bytes_total, decoded_bytes_total |
| Cookie metadata | cookie_count, secure_cookie_ratio, httponly_cookie_ratio |
| Main document | main_status, main_uses_https, main_host_changed |

The nested request path is `data.requests[].request.request`; response fields are
in `data.requests[].response.response`, while aggregate byte lengths are on
`data.requests[].response`. No fallback to a flattened guessed schema is used.
Unknown provider fields are ignored. Missing/malformed fields null the affected
aggregate and retain `{observed, expected}` support. Available partial sums are
not presented as complete totals. Malformed request elements count toward the
raw record count but invalidate dependent aggregates. Empty arrays produce zero
counts/sums; ratios with no denominator are null. Missing arrays are not empty arrays.
Byte lengths must be integers in [0, 2^53-1].

HTTP hostname comparisons are case-normalized exact host comparisons (including
subdomains); they do not claim organizational ownership or campaign linkage.
Distinct host counts do not use DNS or a changing PSL. Valid non-HTTP URLs are
excluded from HTTP URL denominators. The other request ratios cover all recorded
transactions. Missing response status is unknown, not successful HTTP 200.
`response_3xx_ratio` is not redirect depth; the provider's request records may
represent redirect chains in nested fields not expanded by v1.

Lengths, status codes and page complexity can reflect collection/source bias.
Their predictive usefulness is untested. Registry columns are candidate research
features; these tests establish extraction semantics, not detection performance.
The allowlist excludes provider verdicts, labels, tags, processor reputation,
raw IP/ASN identity, cookies' values, request bodies and response bodies.

## Static forensic signals

All analysis is on exact source bytes: no JS evaluation, browser launch, embedded
URL visit, recursive decoding, decompression or payload execution. The byte limit
is 2 MiB. Empty/oversized input has null metrics and no fabricated YARA result.

| Indicator | Definition |
|---|---|
| byte_length | Number of input bytes |
| byte_entropy | Shannon entropy over 256 byte symbols, bits/byte |
| percent_escape_count | `%` plus two hexadecimal digits |
| js_hex_escape_count | Literal backslash-x plus two hex digits |
| js_unicode_escape_count | Literal backslash-u plus four hex digits |
| html_numeric_entity_count | Semicolon-terminated decimal (1–7 digits) or hex (1–6 digits) entity |
| eval_call_count, atob_call_count, unescape_call_count | Case-sensitive lexical token + optional whitespace + `(` |
| fromcharcode_call_count | `String.fromCharCode(` with optional whitespace around dot / parenthesis |
| document_write_call_count | `document.write(` with optional whitespace around dot / parenthesis |
| base64_like_run_count | Non-overlapping runs of 80+ base64 alphabet bytes, optional 0–2 padding characters |
| base64_like_byte_ratio | Bytes in those runs / all input bytes |

Base64-like runs are not proof of valid encoded content. Comments, strings,
minification, benign embedded assets and legitimate authentication pages can
trigger indicators. Metrics are raw-byte lexical counts, not parsed JS behavior.
Regex case behavior and exact definitions are frozen in `PATTERNS`.

YARA rules: `CF_Decode_And_Eval_v1`, `CF_Packed_JavaScript_v1`,
`CF_Encoded_HTML_v1`, `CF_Decode_And_Write_v1`. They detect lexical co-occurrence
or shapes only; they do not prove data flow, execution or phishing. The ruleset
is versioned and hashed; includes are disabled and matching has a five-second
timeout. YARA 4.5.4 is pinned for CI. Successful no-hit scans use `matches=[]`;
unavailable engine, compile error or timeout use `matches=null` plus status.
Only IDs/tags/versions and up to 32 byte spans per rule are returned, without
matched plaintext. Regex metrics retain full counts and at most 32 spans each.
Rules require a reviewed, versioned change to alter; no downloaded rule packs.

## Validation and next integration gate

Synthetic tests cover hand-calculated HTTP values, schema drift, unknown-versus-zero,
partial field coverage, malformed numeric data, empty denominators, missing cookies,
provider-label leakage, timestamps/timezones, masks and serialization order,
YARA positive/negative/error controls, resource caps, Collector end-to-end handoff,
integrity/path checks, deterministic reruns and all 75 frozen file hashes.

The public-control job separately checks real provider evidence using the contract
above. Real historical packet extraction and detection quality are not claimed by
these tests. Historical collection remains paused and those packets lack matched recent
evidence. Once authorized evidence is present, run this offline adapter, inspect
coverage and temporal alignment, and complete independent human review before
any training eligibility, threshold choice or model comparison. Existing Visual
hashes are retrieval signatures, not semantic embeddings; attention remains future work.

Implementation references, checked 2026-10-17:

- [urlscan Result API fields](https://docs.urlscan.io/pages/result-api-reference)
- [IBM urlscan integration example with nested request/response shape](https://ibmresilient.github.io/resilient-community-apps/fn_urlscanio/README.html)
- [YARA Python compilation, includes and timeout](https://yara.readthedocs.io/en/stable/yarapython.html)
