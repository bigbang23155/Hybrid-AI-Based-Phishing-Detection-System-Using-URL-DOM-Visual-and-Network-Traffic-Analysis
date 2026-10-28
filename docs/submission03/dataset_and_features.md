# Assignment 03 Dataset and Feature Documentation

Current submission snapshot: 21 October 2026. Implementation base: `7d8223f4a72e1b48c83453d507dacb7881385dbe`. Historical checkpoint documents remain unchanged; this document states their cumulative status.

## Dataset provenance and pairing

The historical 4,000-row URL baseline and the new 5,000-candidate URL/HTML cohort are separate datasets. The baseline freeze identifies its source as `assignment02_ebbu2017_historical_v2`; it must not be described as a newly collected PhishTank/Tranco experiment.

DOM source: authors' PhreshPhish corpus, revision `eabec4b7a66324b79cc8a0ad856d1731dc26fe1a`; six fixed train shards (`train-022`, `train-007`, `train-032`, `train-001`, `train-051`, `train-054`). Exact files, bytes and SHA-256 are in `config/assignment03_paired_source_frame_v1.json`. This is a bounded subset, not the full published benchmark.

URL and HTML are bound by source-file hash and source-row ordinal. Source labels benign/phish map to 0/1; they are publisher labels, not independent human review. Publisher dates are not independently verified capture times. Original HTTP status, final URL and redirect chain are unavailable in this adapter and remain null. No live page was visited for A03 feature extraction.

| Stage | Benign | Phishing | Total |
|---|---:|---:|---:|
| Fixed candidates | 2500 | 2500 | 5000 |
| Usable pairs | 2456 | 2489 | 4945 |
| HTML above 2 MiB excluded | 44 | 11 | 55 |
| Train | 1718 | 1743 | 3461 |
| Validation | 369 | 373 | 742 |
| Test | 369 | 373 | 742 |

No missing/empty HTML, parser failures or cross-label exact-HTML conflicts occurred at materialization. All 55 oversize failures remain recorded and were not replaced. Development extraction succeeded for all 4,203 train/validation rows.

## Groups and exposure

Registered-domain, identical HTML and the frozen qualifying ordered-tag signature are connected transitively: 3,669 final groups. Exact-HTML repetition comprises 73 groups / 269 rows; the structure guard is a conservative proxy, not campaign identity. Pilot matches and transitive links force 464 rows / 96 components into training. Train/validation/test have 2,525/556/588 groups, with no overlap under the defined domain/content/structure rules. Near-template, campaign and temporal independence remain unproven.

Partition-manifest SHA-256: `49e9dc599fe11e243ac6ba18307900ddc854eeabb3cd700eb9f39fbf05f2deb0`.

The test was excluded from development feature extraction, model fitting and diagnostics. It was subsequently evaluated once under the frozen final protocol and is now consumed. Rechecking archived validation predictions does not create a fresh holdout. The submission report presents development results; post-test strengthening analysis is kept outside it.

## URL feature schema

Baseline ordered names (18): `url_length`, `hostname_length`, `path_length`, `query_length`, `dot_count`, `subdomain_count`, `slash_count`, `digit_count`, `digit_ratio`, `hyphen_count`, `at_count`, `question_count`, `equals_count`, `ampersand_count`, `uses_https`, `is_ip_hostname`, `suspicious_keyword_count`, `url_entropy`.

Length/count fields use normalized URL characters; hostname/path/query fields use their parsed components. Digit ratio is decimal digits / URL length. HTTPS and IP-host indicators are binary. Keyword count sums occurrences of account, bank, confirm, login, password, secure, signin, update and verify. Entropy is Shannon character entropy in bits. Registered domains use the packaged PSL without runtime downloads and exclude private suffixes. Exact formulas: `src/phishing_url/features.py` and `url_cleaning.py`.

Registry alternatives support compact16, expanded21, no_https (17), hostname_only (4) and ordered custom subsets. These are schema options, not a different feature width for each page. The A03 primary comparison uses 18 URL features. Sensitivity experiments use no_https and hostname_only; compact16/expanded21 are not claimed as trained A03 comparisons. The three extra registered URL fields were extracted for sensitivity support, not all fed into the main hybrid.

## DOM feature dictionary

Version `static_dom_v1`. Feature order below is the model contract.

| Feature | Unit | Definition |
|---|---|---|
| `tag_count` | count | All start/start-end tags emitted by HTMLParser, once each. |
| `form_count` | count | form start tags, including forms without action. |
| `input_count` | count | input start tags of any type. |
| `password_input_count` | count | input with stripped case-insensitive type=password. |
| `hidden_input_count` | count | input with stripped case-insensitive type=hidden. |
| `link_count` | count | a tags with an href attribute; empty and non-HTTP values included. |
| `http_link_count` | count | Link references resolvable to a valid HTTP(S) URL. |
| `external_link_count` | count | HTTP(S) links with registered domain different from page URL. |
| `external_link_ratio` | ratio | external_link_count / http_link_count; zero if denominator zero. |
| `resource_count` | count | One reference per resource tag with its declared src/href attribute. |
| `http_resource_count` | count | Resource references resolvable to a valid HTTP(S) URL. |
| `external_resource_count` | count | HTTP(S) resources with different registered domain. |
| `external_resource_ratio` | ratio | external_resource_count / http_resource_count; zero if denominator zero. |
| `script_count` | count | All script tags; does not imply executable JavaScript. |
| `script_src_count` | count | script tags with src, including empty/invalid/non-HTTP values. |
| `external_script_count` | count | script src references resolving to an external HTTP(S) domain. |
| `iframe_count` | count | iframe tags; content/srcdoc is not recursively parsed. |
| `hidden_element_count` | count | Union per tag of hidden attribute, input type=hidden, or explicit inline display:none / visibility:hidden declaration. |
| `meta_refresh_count` | count | meta with stripped case-insensitive http-equiv=refresh, regardless of content validity. |
| `form_action_count` | count | form tags explicitly carrying action; includes empty values. |
| `http_form_action_count` | count | Explicit action references resolvable to HTTP(S). |
| `external_form_action_count` | count | Explicit HTTP(S) form actions with different registered domain. |
| `external_form_action_ratio` | ratio | external_form_action_count / http_form_action_count; zero if denominator zero. |

Static `HTMLParser` performs no JavaScript execution, CSS computation or browser DOM reconstruction. Counts include lexical template/noscript markup; script text/comments do not create tags. Repeated references count repeatedly. The first base[href] is used if valid HTTP(S), otherwise page URL is used. Relative URLs are resolved before comparing registered domains. External does not mean a different browser origin. DOM-only uses URL context for reference resolution, but no lexical URL features or domain identity as predictors.

Hidden means hidden attribute, hidden input, or explicit inline display:none/visibility:hidden, counted once per element. It is not computed visibility. Meta refresh is a markup marker, not an observed navigation. Resource counts are static references, not HTTP requests. See the locked registry for supported tag/attribute pairs.

Model ratios are 0 when the HTTP denominator is 0; the associated count exposes the absent denominator. The earlier materialization audit uses null for undefined diagnostic ratios. These conventions intentionally differ and must not be mixed. Missing/invalid/oversize HTML fails extraction rather than producing all zeros. Any eligible-row failure blocks the shared experiment; no modality-specific row deletion or backfill.

## Modeling contract

URL/DOM/concatenated dimensions are 18/23/41. Columns have url__/dom__ prefixes and join one-to-one on sample ID, label, final group, partition and HTML hash. Source, language, dates, target brand, IDs, hashes and group assignments are excluded from predictors.

RF: 100 trees, max_features=sqrt, bootstrap=True, no depth limit, min_samples_leaf=1, class_weight=None, n_jobs=1. GBDT: 100 stages, learning_rate=0.1, max_depth=3, subsample=1. Parameters and defaults are recorded under scikit-learn 1.7.2. No scaling, imputation, calibration, resampling, feature selection or hyperparameter search. Fit train only; no train+validation refit.

Seeds 4941401–4941405 vary model randomness on the same partitions; primary seed 4941401. Positive class=1, threshold=0.5. Six main cells plus eight URL sensitivity cells yield 70 fits across five seeds. Primary uncertainty uses 2,000 paired whole-group bootstrap draws, seed 4941490. Seed SD is not a confidence interval. Six primary cells, full metrics and all seeds are preserved in the result CSVs.

## Bias and interpretation

Usable benign/phishing median HTML bytes are 192,382/36,859; HTTPS rates 99.43%/76.34%; query-bearing rates 0%/10.25%. Dates, languages and page complexity differ by class. Normal login pages can contain password inputs and external form actions. These are confounders, not automatic phishing rules. Balanced historical precision does not estimate live low-prevalence precision; external, later-time and adversarial evaluation require new evidence.

## Source and evidence locations

- Dataset and paper: https://huggingface.co/datasets/phreshphish/phreshphish and https://arxiv.org/abs/2507.10854
- Frozen source/partition/feature/model files: `config/assignment03_*`.
- Detailed development results: `results/assignment03/development_v1/`; review: `results/assignment03/review_v1/`.
- Current results index: `docs/submission03/README.md`.
