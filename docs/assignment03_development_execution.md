# Development-only execution of the frozen paired protocol

The user explicitly authorized development extraction, integrity checks and common
modeling on 2026-10-07 America/Chicago. The additive execution file records that
authorization. Earlier `automatic_training_authorized=false` fields describe the
definition-only checkpoint and are not rewritten. Test remains unauthorized.

The execution uses the exact 3,461 train and 742 validation rows from the 5,000-row
frozen manifest. The original 55 exclusions and 742 test rows remain as recorded.
The six pinned shards are verified by exact byte length and SHA-256. Candidate
reconstruction must reproduce the earlier metadata/replay hashes before HTML is
selected. Only development HTML scalars are converted to Python and sent to the
extractor. Parquet physical page decoding includes neighboring rows; this is not
reported as physical exclusion of all test bytes from downloaded source files.

For each development row, verify source file/ordinal, label, domain hash and HTML
hash. Extract the registered URL fields (including the existing hostname-only
sensitivity field) and 23 frozen DOM fields. Both must be finite and join exactly
to the frozen metadata. Any missing, duplicate, failed or changed row stops the
run before training with status records retained. No row dropping or backfill.

The original definition lock is verified, not updated. Ratios, hidden-element and
resource semantics remain exactly as fixed in the registry. Feature profiles
report train/validation separately by class, including missingness, zero counts,
quantiles and ranges; these are descriptive audit results, not automatic feature
selection or thresholds.

Train RF and GBDT on train only for the 14 prespecified conditions and 5 model
seeds (70 fits). No validation fitting, resampling, search, calibration or threshold
tuning. Report training metrics as overfit context and validation metrics as
development evidence. The primary reference seed and all 5-seed results are shown;
no best-seed or best-test selection. The 2,000-draw paired bootstrap resamples entire
final groups. Tied scores are handled explicitly for weighted ROC-AUC/AP and checked
against scikit-learn; single-class resamples omit those two undefined metrics.

Raw URLs, HTML, feature vectors and fitted models are not published in the public
Actions artifact. It contains aggregate profiles, per-row extraction status,
sanitized validation predictions, metrics, uncertainty, grouping errors, source and
implementation hashes, seeds, full model parameters and environment/latency records.
Fitted-model hashes are evidence, not a retained production model release. Recreate
from pinned sources and commit when a separately approved inference artifact is
needed. Predictions are validation-only; no test feature matrix is created.

`scripts/verify_paired_development.py` independently recomputes all validation
metrics using scikit-learn and headline F1 confidence/difference intervals using
explicit resampled rows, rather than the runner's weighted metric implementation.
It also checks all 4,203 success records, all 70 prediction cohorts and zero sealed
test overlap. Training scores are not independently recomputed without private
features/models; report that limit explicitly.

This is an internal, class-balanced, historical-cohort development experiment.
Observed performance does not establish open-world precision, very-low-FPR safety,
future-time/campaign generalization, adversarial robustness or zero-day detection.
The separate extension roadmap still requires new evidence and independent tests.

Execution entry point (offline after acquisition):

```bash
PYTHONPATH=src python -m phishing_url.paired_development \
  --root . --source-root /input --output /output/new-run
```

The command requires a new output directory and has no test-evaluation switch.
