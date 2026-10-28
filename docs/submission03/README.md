# Assignment 03 submission

Current snapshot: 21 October 2026. Latest implementation base: `7d8223f4a72e1b48c83453d507dacb7881385dbe` on `research/urlscan-readonly-v1`. Submission branch: `submission/assignment03-20261021` (contains that code plus the submission documents/results index).

## Read first

- [English progress report](progress_report.md): completed URL baseline, paired-data preparation, DOM extraction, initial hybrid comparison, limitations and remaining plan.
- [Dataset and feature dictionary](dataset_and_features.md): exact 18/23/41 feature contract, sources, losses, splits, null/zero rules and model settings.
- [Selected result tables](../../results/assignment03/submission_v1/): Phase 1 comparisons, primary paired validation table and fresh independent verification outputs.
- [Full paired development results](../../results/assignment03/development_v1/) and [development error review](../../results/assignment03/review_v1/): all seeds, predictions, uncertainty and review evidence.

These documents supersede the *current-status wording* in earlier milestone reports, without rewriting their historical results or locks. Historical fields such as `model_training_performed=false` describe the definition-only stage, not this completed submission.

The paired test stayed outside development and was later evaluated once. It is now consumed. No test inference, fitting, threshold selection, feature changes or collection was performed for this submission. Post-test strengthening analysis is not incorporated into the progress report. The original final-test evidence remains in its existing repository location.

## Code map

| Task | Implementation |
|---|---|
| URL normalization and lexical extraction | `src/phishing_url/url_cleaning.py`, `features.py`, `feature_registry.py` |
| Historical URL comparisons and diagnostics | `experiment.py`, `phase1_diagnostics.py` |
| Paired source selection and HTML audit | `formal_candidates.py`, `formal_html.py` |
| Domain/content/structure partitions and exposure | `formal_holdout.py` |
| Static DOM feature definitions and extraction | `dom_features.py` |
| Common modality schema and locked estimator construction | `modality_contract.py` |
| Development extraction and 70 fixed training fits | `paired_development.py` |
| Development error and bias review | `development_review.py` |
| Independent validation-only verification | `scripts/verify_paired_development.py`, `scripts/verify_development_review.py` |
| Frozen specifications and provenance | `config/assignment03_*`, result checkpoint JSONs |
| Optional future evidence foundation | `research/urlscan_v1/`, `research/multimodal_v1/` |

## Reproduction

Use Python 3.12 and the pinned dependencies. The archived modeling run used Python 3.12.15, scikit-learn 1.7.2 and NumPy 2.2.6; exact package/image/hardware records are in its cloud artifact. The repository does not contain raw HTML or distributable fitted model files.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dom.txt
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python -m phishing_url.modality_contract --output /absolute/new/contract.json
```

Run from the repository root. Create output parents first; never overwrite archived evidence. To verify existing public development evidence without fitting or test inference, use the public output directory from archived Actions run 37725422890 (also included under `archived_development_public` in the submission package):

```bash
python scripts/verify_paired_development.py \
  --repository . --public /absolute/path/archived_development_public \
  --output /absolute/new/development_verification.json
```

The submission contains a fresh successful recheck of all 51,940 validation predictions, six primary F1 intervals and four paired F1 contrasts. Training metrics were not independently recomputed from private models/features.

For an authorized *development-only* reconstruction, the cloud workflow `.github/workflows/assignment03-paired-development.yml` verifies/acquires only the six pinned source shards, then performs extraction and fitting in an offline bounded container. Its source acquisition command is:

```bash
PYTHONPATH=src python -m phishing_url.formal_candidates --download \
  --source-root /absolute/input \
  --frame config/assignment03_paired_source_frame_v1.json \
  --policy config/assignment03_paired_release_policy_v1.json
```

After acquisition, the offline entry point is:

```bash
PYTHONPATH=src python -m phishing_url.paired_development \
  --root . --source-root /absolute/input --output /absolute/new/development-run
```

This is a reproducibility recipe; this submission does not rerun those fits. Do not rerun the consumed final-test workflow. No current collector credentials are required to inspect A03 validation results.

## Evidence runs

| Milestone | GitHub Actions run |
|---|---:|
| URL baseline and size/split diagnostics | 37393358105 |
| Final paired grouping and pilot overlap | 37703227484 |
| Feature and modeling contract | 37706988097 |
| Paired development extraction and fitting | 37725422890 |
| Development error and bias review | 37898355594 |
| Subsequent one-time final evaluation, consumed | 38006867242 |
| Separate four-modality public control | 39007335998 |

Run links use the repository's `/actions/runs/<ID>` path. These milestones have distinct execution commits, recorded by their checkpoint JSONs. Software-test counts and control-field coverage are not detection accuracy.

## Remaining scope

The report's staged plan prioritizes independent review, paired screenshot/HTTP coverage, simple additional-modality baselines and fusion, then a demonstration and independently versioned external evaluation. Existing HTTP features are not PCAP. Visual quality/signatures are not semantic embeddings. Learned reliability/attention remains optional and untrained. Keep historical collection paused and human labels separate from AI annotations.
