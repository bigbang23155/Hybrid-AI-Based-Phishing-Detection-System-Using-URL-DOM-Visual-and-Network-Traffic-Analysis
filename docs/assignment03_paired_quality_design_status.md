# Assignment 03 paired-data quality and experiment-design status

## Decision status

The historical URL development baseline remains frozen and unchanged. Optional
YARA/content-forensics, visual/network, Evil Twin and identity/session work is now
kept under `docs/extensions/` and does not block Assignment 03.

The paired-data work has moved from an informal pilot to a preregistered quality
and experiment protocol, but **the formal paired training dataset is not yet
approved or frozen**.

## Cloud validation

Latest verified checkpoint:

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

The remaining sequence is now fixed:

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

The next implementation checkpoint is metadata-only formal candidate selection
over the six fixed shards. No DOM model should be trained before that selection,
HTML audit, quality review and new holdout are frozen.
