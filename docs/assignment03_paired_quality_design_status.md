# Assignment 03 paired-data quality and experiment-design status

## Decision status

Current checkpoint: the development error/bias review is complete, all six fitted
model hashes and validation probabilities match the earlier experiment, and the
final evaluation specification is frozen. See
`assignment03_development_error_bias_review.md` and
`assignment03_final_evaluation_freeze.md`. Test remains sealed; no correctness
blocker was found, while external/temporal generalization limitations are explicit.


Latest execution checkpoint: the user authorized development-only extraction and
common modeling. Actions **37725422890**, execution commit
`7153f06cd719d393686e7cc8ceff8591f64b3bf6`, passed **158 tests**, extracted all
**4,203 development rows with zero failures**, and completed **70 fixed fits**.
Independent validation metric and paired F1 interval recomputation passed locally
and in the cloud. The 742 test rows remain sealed and the original 55 exclusions
remain unchanged. See `assignment03_development_results.md` and
`config/assignment03_development_checkpoint_v1.json`.

Earlier definition checkpoint: `assignment03_dom_feature_modeling_protocol.md` fixes
the 23-feature static registry and common URL/DOM/hybrid modeling contract.
Extractor/join/schema tests use synthetic fixtures; no formal feature extraction,
training or test evaluation is performed. The separate open-world robustness
roadmap states future evidence gates without claiming current generalization.
Actions 37706988097 passed 148 tests; the cloud contract report matches local
verification and preserves the original partition digest.

The historical URL development baseline remains frozen and unchanged. Optional
YARA/content-forensics, visual/network, Evil Twin and identity/session work is now
kept under `docs/extensions/` and does not block Assignment 03.

The paired-data work has moved from an informal pilot to a preregistered quality
and experiment protocol, with **eligible membership and grouped partitions now frozen and cloud-verified**.
Definitions remain fixed. The authorized development run is complete; test
evaluation remains disabled. Historical definition-only authorization flags are
preserved, with current scope recorded in the additive development execution file.

## Cloud validation

Latest holdout checkpoint: content/source decisions and cross-pilot checks are
complete; 4,945 eligible rows are frozen into 3,461/742/742 train/validation/test
rows using 3,669 components. All 464 pilot-exposed component members are training
only. Actions **37703227484**, commit `372b48003f4dff90c0a85503e9e8c7c0cea54a9a`,
passed **112 tests** and reproduced the full local partition manifest byte-for-byte.
Domain, exact-HTML and qualifying structural overlap between partitions is zero.
No models or test performance have been evaluated. See
`assignment03_holdout_results.md` and `config/assignment03_holdout_freeze_v1.json`.

Earlier selected-HTML checkpoint (run **37698952013**, commit
`bf1674c5d14e3b2f9f30108596d46c71e442d58d`):

- full cloud suite: **105 passed**;
- original candidate membership: **5,000**, verified byte-identically;
- technically usable: **2,456 benign / 2,489 phishing**;
- retained losses: **44 benign / 11 phishing**, all above the fixed 2 MiB cap;
- parse failures and cross-label exact-HTML conflicts: **0**;
- technical quality gate: **pass**;
- descriptive content/bias audit: complete, research decision still pending;
- hard domain/exact-HTML components: **4,079**;
- final dataset freeze, partition, training approval and test evaluation: **false**.

See `docs/assignment03_selected_html_results.md` for results and limitations,
`docs/assignment03_selected_html_audit.md` for variable definitions, and
`config/assignment03_selected_html_checkpoint_v1.json` for execution/hash evidence.
Run 37698201811 is superseded for aggregate numeric missingness; the corrected
run preserved candidate, per-sample audit and paired-manifest identities.

Earlier source-design checkpoint:

- full offline project tests: **93 passed**;
- pinned source revision:
  `eabec4b7a66324b79cc8a0ad856d1731dc26fe1a`;
- source train inventory: **56 shards**, **27,400,613,420 bytes**;
- publication source test files excluded: **21**;
- canonical source-inventory SHA-256:
  `137dca2bb7b457a37fbb2e87bc5ab8567f4fe7750cd30db20870b81cc9614523`;
- bounded formal frame: **6 deterministic train shards**, **2,903,636,775 bytes**;
- pilot shard `data/train-000.parquet`: excluded from the formal source frame;
- official publication test split used by this project: **false**;
- training approved: **false**.

Source-inventory/frame verification run: 37574672904.

## Pilot under the new formal quality gate

The 256-candidate engineering pilot was replayed through the new formal quality
audit after retaining publisher language/target metadata.

Automated result:

- records: 256;
- usable URL/HTML pairs: 255;
- schema/integrity gate: pass;
- candidate-loss gate: pass;
- capture-date completeness: pass;
- formal usable-pair volume: fail;
- formal domain-diversity gate: fail;
- formal domain-concentration gate: fail;
- bias review: required;
- final formal partition: not created;
- formal data ready for research review: false;
- training approved: false.

Observed pilot details:

| Check | benign | phish |
|---|---:|---:|
| usable pairs | 127 | 128 |
| registered domains | 116 | 106 |
| candidate loss | 0.78% | 0.00% |
| largest domain share | 2.36% | 2.34% |
| missing publisher date | 0% | 0% |
| root-path URL rate | 5.51% | 49.22% |
| password-input rate | 15.75% | 26.56% |

The absolute root-path-rate gap is about 43.71 percentage points, above the
predeclared 20-point bias-review trigger. The class month-distribution total
variation in this small pilot is about 0.547. These are reasons to review sampling
bias, not reasons to label a page as phishing.

The formal project heuristics require at least 2,000 usable pairs and 500
registered domains per label, so the pilot is intentionally unable to pass.

Quality-preflight run: 37574672801.

## Frozen source frame for the next data step

The complete allowed train inventory is too large to process casually, so the
project preregistered a bounded subset without inspecting outcomes. From the 56
allowed train shards, `train-000` is excluded because it powered the reviewed
pilot. Remaining shard paths are ranked by SHA-256 of:

`assignment03:source-shard:4941301:<path>`

The first six are frozen:

1. `data/train-022.parquet`
2. `data/train-007.parquet`
3. `data/train-032.parquet`
4. `data/train-001.parquet`
5. `data/train-051.parquet`
6. `data/train-054.parquet`

Each path, Git-LFS SHA-256 and byte size is recorded in
`config/assignment03_paired_source_frame_v1.json`.

If this fixed frame cannot supply the preregistered 2,500 metadata candidates per
source label, the run records a shortfall and stops. It does **not** substitute an
extra shard after observing the shortfall.

## Formal paired dataset sequence

The sequence is fixed; steps 1–8 are complete at the selected-HTML checkpoint:

1. download and SHA-verify only the six frozen source shards;
2. read URL/label/date/language/target metadata only;
3. exclude invalid/conflicting/duplicate normalized URLs;
4. deterministically select up to 2,500 candidates per label with domain cap 3;
5. freeze selected sample IDs **before reading selected HTML**;
6. read selected HTML and retain failures without replacements;
7. verify HTML hashes, conflict quarantine, pair coverage and source metadata;
8. run the automated quality/bias report;
9. document the manual research review;
10. only after approval, freeze membership and create the new domain/exact-HTML
    grouped 70/15/15 split;
11. keep the new final test outside development.

## Experiment after data approval

All modality comparisons use identical paired samples and partitions.

Primary model:
- Random Forest, fixed frozen reference settings.

Sensitivity model:
- Gradient Boosting, fixed frozen reference settings.

Required conditions:

1. URL-only;
2. DOM-only;
3. URL + DOM.

Primary development metric: validation F1. Also report accuracy, precision,
recall, FPR, ROC-AUC, average precision and confusion counts.

The URL-only comparator is retrained on the new paired samples. The historical
4,000-URL score is retained as background evidence only and is not compared
directly as though it came from the same dataset.

## Files defining this checkpoint

- `config/assignment03_paired_release_policy_v1.json`
- `config/assignment03_paired_source_frame_v1.json`
- `src/phishing_url/paired_quality.py`
- `src/phishing_url/source_inventory.py`
- `docs/assignment03_paired_dataset_protocol.md`
- `docs/extensions/`

Development feature materialization and the common modeling runner are complete.
The next research work is a versioned development error/bias review and separately
designed temporal/source/campaign and semantic-preserving robustness experiments.
Final test requires its separately authorized evaluation entry point and remains
outside these development decisions. Cloud holdout replay passed the exact hash gate.
The existing 55 losses are not replaced; optional extensions remain separate.
