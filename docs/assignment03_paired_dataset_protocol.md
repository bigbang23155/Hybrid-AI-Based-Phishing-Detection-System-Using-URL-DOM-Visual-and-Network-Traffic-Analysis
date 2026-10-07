# Assignment 03 formal paired dataset and experiment protocol

## 1. Scope

This protocol is the next step after the bounded DOM feasibility pilot. It does
not reopen the historical URL baseline. It defines how a new paired URL+HTML
dataset can become eligible for the professor-required URL-only / DOM-only /
URL+DOM comparison.

The source is the pinned PhreshPhish publication revision already used by the
pilot. Only the publication's **train** split is eligible for this project
dataset. The publication's official test split is not imported as this project's
final test. A new holdout is reserved only after this project's final sampling,
deduplication, conflict quarantine, and leakage grouping are complete.

The source provides URL, HTML, label, date, language and related metadata. The
project retains the publication labels as **source labels**. It does not claim
independent human adjudication or current-live-page truth.

## 2. Why the pilot is not promoted directly

The pilot selected 128 candidates per source label and observed 255 usable pairs.
That demonstrated the ingestion/parser machinery, but its class-level root-path
and password-input rates were already inspected. Its provisional test partition
therefore cannot become the final untouched study test.

All 256 pilot-selected source-row sample IDs are treated as exposed. The formal
sampling frame excludes them before candidate selection. This avoids pretending
that previously reviewed samples are unseen.

## 3. Source inventory freeze

Before formal sampling:

1. enumerate the exact allowed train shards at the pinned source revision;
2. record each shard path, byte size and SHA-256;
3. save an immutable source-inventory manifest;
4. verify required columns: sha256, url, label, date, html, target, lang,
   lang_score;
5. refuse source substitution if a hash changes.

Formal sampling does not start while
`source.inventory_status != frozen_and_hashed`.

## 4. Candidate selection

The preregistered policy is
`config/assignment03_paired_release_policy_v1.json`.

Planned engineering target:

- 2,500 selected candidates per source label;
- minimum 2,000 usable URL/HTML pairs per label after retained failures;
- at most 3 selected URLs per registered domain per label;
- deterministic metadata-only selection using seed 4941301;
- selection occurs before HTML inspection;
- no replacement after missing, oversized or unparsable HTML;
- pilot-exposed sample IDs are excluded before formal selection.

The 2,000-per-label minimum is a project heuristic, not a professor requirement.
It preserves a scale comparable to the frozen historical URL baseline while
leaving room for failed pairs.

## 5. Label and exclusion policy

Allowed numerical labels:

- publication benign -> 0;
- publication phish -> 1.

The following are quarantined before modeling:

- invalid or schemeless URLs;
- duplicate normalized URLs after deterministic representative selection;
- a normalized URL appearing with both source labels;
- identical HTML appearing with both source labels;
- missing/empty HTML;
- content above the declared 2 MiB bound;
- parser/integrity failures.

An excluded row is not replaced after HTML inspection. This prevents collection
success from becoming an unrecorded selection criterion.

## 6. Data-quality gates

The automated audit in `phishing_url.paired_quality` checks:

### Critical integrity

- required fields exist;
- sample IDs are unique;
- URLs remain canonical;
- stored registered domains agree with the offline PSL parser;
- retained HTML paths cannot escape the dataset root;
- retained HTML SHA-256 matches bytes;
- no usable cross-label URL or exact-HTML conflict.

### Coverage and concentration

Per label:

- >= 2,000 usable pairs;
- >= 500 registered domains;
- candidate loss <= 10%;
- largest single-domain share <= 2%;
- missing publisher date <= 1%.

These numerical values are project engineering gates, not universal phishing
dataset standards.

### Bias review

Before modeling, report at minimum:

- root-path URL rate by label;
- password-input rate by label;
- month/date distribution by label;
- language distribution by label;
- HTML-size distribution by label;
- domain concentration by label;
- target-brand distribution for phishing rows when present;
- missingness for every candidate model field.

A large class-correlated difference is treated as a **bias review trigger**, not
as evidence that the field is malicious. No source-dependent missingness flag is
automatically approved as a feature.

## 7. Leakage groups and final split

Hard leakage components connect samples transitively when they share:

1. registered domain; or
2. exact HTML SHA-256.

Near-template similarity is calculated as a diagnostic before final freeze. It is
not silently added as a hard grouping key because an overly coarse template rule
can incorrectly merge unrelated pages. If a near-template rule is promoted, its
definition and threshold must be frozen before final splitting.

After the full dataset is frozen, create exactly one final 70/15/15
train/validation/test partition with the preregistered split seeds.

Rules:

- one leakage component belongs to one partition only;
- no exact HTML crosses partitions;
- no registered domain crosses partitions;
- no pilot-exposed sample can enter final test;
- final test membership is saved and not regenerated for a better result.

The final test remains outside feature design, feature selection, model
selection, threshold tuning and error-driven code changes.

## 8. DOM feature development

After paired-data research approval, implement a versioned structural feature
registry. Required first-wave candidates are based on the professor's Assignment
03 examples:

- form count;
- password-input count;
- link count;
- external-link count/ratio;
- external-resource count/ratio;
- script count and external-script count;
- iframe count;
- hidden-element count;
- static redirect indicators.

Every feature needs:

- exact definition;
- deterministic missing-data policy;
- unit tests;
- fixed output order;
- train-only preprocessing when applicable.

Missing HTML or extraction failure is not converted into a vector of zeros. Those
states remain explicit data-quality/extraction statuses.

YARA, obfuscation/decoder features and reverse engineering are not part of this
first structural registry. Their specifications are in `docs/extensions/`.

## 9. Same-sample experiment design

The primary Assignment 03 comparison uses **the same paired sample IDs and the
same partitions** for all three conditions:

### A. URL-only

Use the existing URL feature registry on the new paired dataset. This retrains a
URL-only comparator on the new paired samples; it does not reuse the old
4,000-row model score as if datasets were comparable.

Primary URL schema: frozen baseline lexical set.
Sensitivity: no-HTTPS URL schema because HTTPS/source bias was previously
identified as a concern.

### B. DOM-only

Use only the preregistered structural DOM feature set.

### C. URL + DOM

Concatenate the exact A and B feature vectors at sample ID level. A merge is
rejected if one modality is missing or sample labels/groups disagree.

## 10. Models

To isolate modality effects without restarting a broad model search:

Primary model:
- Random Forest;
- 100 trees;
- unlimited depth;
- min_samples_leaf=1;
- max_features=sqrt.

Secondary sensitivity model:
- Gradient Boosting;
- 100 stages;
- learning_rate=0.1;
- max_depth=3;
- min_samples_leaf=1.

These settings come from the frozen historical URL development baseline and are
treated as fixed reference configurations. If later validation evidence justifies
new tuning, that becomes a separately versioned experiment; the old freeze is not
overwritten.

## 11. Validation and metrics

Development uses train + validation only.

Report for each modality/model condition:

- Accuracy;
- Precision;
- Recall;
- F1;
- FPR;
- ROC-AUC;
- Average Precision;
- confusion counts.

Primary development comparison: validation F1.

Because predictions are paired on the same validation sample IDs, report paired
per-sample errors and domain-level error counts. Where uncertainty intervals are
used, resample at leakage-group level rather than pretending individual URLs are
independent.

## 12. Error and bias analysis

Development-only review includes:

- false positives and false negatives by registered domain;
- publisher date/month;
- language;
- root-path status;
- password-input presence;
- major phishing target categories when source metadata provides them;
- HTML size/complexity strata;
- URL and DOM feature importance with correlation caveats.

A discovered shortcut can cause a feature to be removed or a dataset protocol to
be revised **before final test use**. Such a change creates a new versioned
development experiment and is documented.

## 13. Test policy

The new final test is evaluated once only after:

1. paired dataset is frozen;
2. quality and bias review is documented;
3. DOM feature registry is frozen;
4. modality definitions are frozen;
5. primary and sensitivity model configurations are frozen;
6. thresholds and metrics are frozen.

Assignment 03 development may stop before this final test if the professor expects
the held-out set to remain for later final evaluation.

## 14. Approval states

The project uses distinct states:

1. `technical_pilot_pass` — parser/data machinery works;
2. `quality_gate_pass` — automated integrity/coverage checks pass;
3. `ready_for_research_review` — quality + partition requirements are satisfied;
4. `paired_dataset_approved_for_development` — explicit research decision;
5. `paired_dataset_frozen` — membership, source hashes and partitions fixed.

CI never jumps automatically from state 2 or 3 to state 4.

## 15. Current next action

The source frame, selected-HTML audit, research decisions and cloud-verified holdout freeze
are complete. The additive holdout policy includes an explicitly documented
conservative structural guard and training-only pilot exposure. See
`docs/assignment03_holdout_results.md`. Eligibility is unchanged: 4,945 pairs and
55 retained oversize exclusions. Actions 37703227484 reproduced the exact frozen
partition hash. The immediate next action is DOM registry and modeling protocol
finalization. Training approval remains false; test has not been evaluated.
