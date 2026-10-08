# Assignment 03: frozen static DOM registry and common modality protocol v1

## Scope and status

This implements feature definitions, a passive extractor, strict development join
contracts and unfitted estimator construction. It does **not** run extraction on
the formal cohort, train models, inspect test feature distributions, or evaluate
test performance. The 5,000 candidates, 4,945 usable pairs, 55 retained exclusions,
3,669 final groups and 3,461/742/742 split remain exactly as frozen in PR #13.

Controlling machine-readable files are `assignment03_modeling_protocol_v1.json`
and `assignment03_feature_protocol_lock_v1.json` under `config/`. The latter locks
the registry definitions/order, implementation and dependency inputs with SHA-256.
The original URL baseline and earlier audits/policies are not rewritten.

## Feature dictionary and interpretation

`src/phishing_url/dom_features.py::DEFINITIONS` and the lock contain every feature's
name, order, unit and formula. The number 23 is an engineering scope, not a claimed
optimal number or a literature-mandated count. Custom ordered subsets are supported
but require a separately versioned experiment; per-row schema width never changes.

| Family | Ordered feature names | Rationale and limitation |
| --- | --- | --- |
| Structure/forms | tag_count, form_count, input_count, password_input_count, hidden_input_count | Page complexity and credential-entry structure; normal login pages also contain these. |
| Links | link_count, http_link_count, external_link_count, external_link_ratio | Relationship of HTML links to paired page domain; CDNs, SSO and legitimate external links are confounders. |
| Resources | resource_count, http_resource_count, external_resource_count, external_resource_ratio | Dependency structure, not proof of malicious hosting. |
| Scripts/frames | script_count, script_src_count, external_script_count, iframe_count | Static embedding patterns; no inference that a script executes or a frame steals credentials. |
| Concealment/refresh | hidden_element_count, meta_refresh_count | Explicit lexical indicators only, not computed visibility or an observed redirect. |
| Form actions | form_action_count, http_form_action_count, external_form_action_count, external_form_action_ratio | Explicit destination relationships; absent action differs from an explicit empty action. |

Professor examples motivate the feature families (previously verified assignment
sections 2–4; document hash in `assignment03_professor_verification.json`).
[PhreshPhish](https://arxiv.org/html/2507.10854v1) motivates leakage/base-rate and
dynamic-page cautions, not this exact feature list. Predictive usefulness remains
to be tested on development only; literature support is not proof of superiority.

### Parsing and domain rules

- Python 3.12 `HTMLParser(convert_charrefs=True)`; capture Python patch version and
  dependencies in each run. It is tolerant static markup parsing, **not HTML5
  browser DOM reconstruction**. No network, script evaluation, CSS computation,
  recursive iframe/srcdoc content, shadow DOM, or runtime mutation observation.
- Each emitted start/start-end tag counts once. Comments and script text do not
  become tags. Template/noscript markup counts lexically even when not rendered.
  Tag/attribute names follow HTMLParser normalization; duplicate attributes use
  the last value, a deterministic rule not claimed equivalent to every browser.
- Count repeated references, not unique destinations. Links are `a[href]` only.
  Resources are script/img/iframe/source/audio/video/embed/input `src` and link
  `href`. Do not infer `srcset`, CSS URLs, object data, video posters or JS fetches.
- The first `base[href]` applies document-wide if it resolves to valid HTTP(S).
  Invalid or non-HTTP base falls back to page URL; later base elements are ignored.
  Relative and scheme-relative references use that base. Explicit empty references
  resolve normally. Missing attributes do not create a reference.
- HTTP(S) validity uses the frozen URL cleaner; malformed and non-HTTP references
  do not enter HTTP denominators and are not classified as internal. The full
  reference counts remain observable. Original audit unresolved-reference fields
  remain diagnostics, not predictors.
- External means different PSL-aware registered domain using the existing offline
  suffix rules, private suffix excluded and IP handling unchanged. It does not mean
  different browser origin: subdomains/schemes/ports may share the same group.
- DOM-only uses page URL solely to resolve relative references and determine these
  domain relationships. It has no URL lexical features or domain identity input;
  it is therefore contextual HTML structure, not URL-independent content.
- Hidden count is a **union per element**: hidden attribute, input type=hidden,
  explicit inline display:none or visibility:hidden (optional !important). No
  external stylesheet/inherited visibility inference. Meta refresh counts the
  attribute marker even if its content is malformed; no JS/HTTP redirect claim.

### Absence, failure and preprocessing

True structural absence gives count 0. Ratios use external / valid HTTP reference
count, or 0 for a zero denominator; the associated count exposes absence. This
explicit v1 modeling convention differs from the earlier diagnostic audit's null
ratio convention; the audit stays unchanged. Counts are nonnegative integers,
ratios are within [0,1], and the model vector is finite float64-compatible values.

Missing/empty/non-string/oversize HTML, encoding failure, invalid page URL or parser
failure raises an extraction status rather than producing zeros. On a newly found
failure in any of the 4,945 eligible pairs: stop, preserve evidence, fix/version the
extractor, and rerun consistently. No unilateral modality row deletion, backfill,
schema truncation, or source-label change. Train/validation only is inspected first.

V1 uses no imputation, scaling, missingness indicators, automatic feature selection,
calibration or class resampling. All features must be defined and finite. A later
registry with genuinely unavailable measurements needs a new train-fitted missing
data policy, not silent use of the old URL pipeline's missingness indicators.

## Fixed common experiment

| Condition | Main input | Dimensions |
| --- | --- | ---: |
| URL-only | Existing baseline lexical registry | 18 |
| DOM-only | static_dom_v1 in fixed order | 23 |
| URL+DOM | URL vector followed by DOM vector | 41 |

Prefix columns with `url__` / `dom__`. Verify the complete frozen manifest hash,
join one-to-one on sample_id, and verify label, final_group, partition and HTML
hash against it. Both modalities must succeed even for URL-only; row order is
sorted sample_id. Date, language, target, IDs, hashes, source shard, flags, exposure,
group and partition are never predictors. The development assembly function rejects
test and rejects extra/missing/duplicate or inconsistent feature rows.

Keep RF as primary and GBDT as secondary, with the earlier fixed 100-tree/stage
configurations. Exact parameters are in the JSON. RF has class_weight=None (not
balanced), matching the actual frozen implementation. Library defaults not explicitly
overridden are pinned by scikit-learn 1.7.2 and recorded through full get_params().
No XGBoost/LightGBM switch, parameter search or best-seed selection in this version.

Model seeds 4941401–4941405 vary only estimator randomness; all use the same frozen
partitions. Seed 4941401 is the primary reference. Report all five values and mean/
sample standard deviation separately, not a confidence interval over new datasets.
All 6 primary modality/model cells are reported, not only the winning one.

Prespecified source-shortcut sensitivities are no_https and hostname_only for
URL-only and URL+DOM, with the same models/seeds/samples. DOM-only is not needlessly
rerun for unchanged inputs. Hostname-only is a **joint removal of path/query and
other non-host lexical information**, not a causal estimate of query alone. Total
planned fits: (6 primary + 4 no-HTTPS + 4 hostname-only) × 5 seeds = 70. None run now.

Decision rule is phishing score >= 0.5; no threshold search. Primary development
comparison is validation F1. Report accuracy, precision, recall, F1, FPR, ROC-AUC,
average precision, confusion counts and Brier score. Zero-positive precision is 0
with its denominator shown; undefined single-class AUC is not silently 0.

Primary-seed uncertainty: 2,000 paired whole-final-group bootstrap draws, seed
4941490, percentile 95% intervals. Use the same drawn groups for model/modality
comparisons and retain all rows of each sampled group with multiplicity. Report
valid replicate counts for metrics requiring both classes. Paired differences
URL+DOM minus each unimodal model are descriptive, not multiple-testing-adjusted
proof of superiority. Also report group error counts and extraction/prediction
latency separately with hardware, threads, batch size and cold/warm conditions.

Development review by date/language/HTML size/login/target stays in train/validation.
The balanced source cohort does not estimate deployment precision or prevalence.
With only 369 benign validation/test rows each, a 0.1% FPR performance claim is not
supported by sample size; use a new sufficiently large external benign cohort.

## Test and execution gates

The current change authorizes **definition freeze only**, not automatic training.
Next implement/run bounded development feature materialization with per-row
integrity/coverage checks, then the common development runner. Any fit must use
train only, not train+validation; validation is evaluation/development, not fitting.
Any later adaptive choice is a versioned protocol amendment before final test.

Test remains sealed. A separate approved final-evaluation entry point must bind
feature/partition/model/threshold hashes and report all prespecified primary cells
once. No retraining/feature changes driven by test errors. A test extraction issue
blocks release; document any corrective patch, do not secretly remove the row or
reroll membership. Do not promote this historical holdout to an external or zero-day
benchmark. The separate extension roadmap defines evidence still needed for that.

## References

- [Python HTMLParser](https://docs.python.org/3.12/library/html.parser.html): parser semantics, not browser equivalence.
- [scikit-learn 1.7 RF](https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.RandomForestClassifier.html): pinned estimator semantics.
- [PhreshPhish v1](https://arxiv.org/html/2507.10854v1): related-page leakage and real-world evaluation limitations.
- See `extensions/open_world_robustness.md` for recent threat evidence and staged robustness work.
