# Assignment 03 final evaluation specification v1

The development error review is complete with documented limitations. The final
specification is frozen for the internal historical-cohort benchmark. This does
not authorize test execution or certify deployment performance.

Use the exact locked 5,000-row manifest: 3,461 train, 742 validation, 742 sealed
test and 55 retained exclusions. Reconstruct from the six pinned source shards.
No backfill, new split, relabeling, feature selection, threshold search or seed
selection is allowed within this version. Train only on the original 3,461 rows;
never refit on train+validation for this specification.

Evaluate exactly RF/GBDT × URL-only/DOM-only/URL+DOM baseline, seed 4941401,
threshold 0.5 (positive iff score >= 0.5). Feature order and complete parameters
are explicit in the JSON. Recreated fitted-model bytes must match the six locked
SHA-256 values before any test feature access. All six equal the earlier models.
Pin the recorded Linux amd64 Python base image digest and complete dependency
versions using docker/Dockerfile.assignment03-final and the dedicated requirements
file. Any reproduction failure blocks access; it is not resolved by changing the
expected hashes without a newly documented version and development validation.

Report all six cells, not a selected winner: accuracy, precision, recall, F1, FPR,
ROC-AUC, average precision, TN/FP/FN/TP and Brier score. RF and F1 remain primary.
Use 2,000 whole-final-group percentile bootstrap draws, seed 4941490, and paired
hybrid-minus-URL/DOM contrasts within each model. Intervals remain descriptive,
without confirmatory multiple-comparison claims. Seed sensitivity and URL ablations
remain development evidence; no additional test condition search is authorized.

A future separately authorized executor must preserve identical test IDs across
all six conditions, retain prediction/status/model/environment hashes, and record
one complete evaluation receipt. Technical failure before test prediction may be
repaired with a documented retry. If any test predictions or outcomes were already
exposed, preserve that fact and stop; never silently rerun a revised model as a
new untouched test. Do not tune, calibrate or choose models after seeing test.

The only entry point added here is offline preflight:

    PYTHONPATH=src python -m phishing_url.final_evaluation_contract --root . --output /tmp/final-preflight.json

It verifies the freeze and development review without loading test features or
running inference. Test-execution authorization remains false. The actual
one-time test executor is still a subsequent task, not falsely marked complete.

Known limits travel with the final results: complexity reliance; uncertain
password-subgroup gaps; source/time/language composition; published, non-adjudicated
labels; 55 size-related exclusions; static lexical HTML rather than rendered DOM;
no prospective, external-source, adversarial or zero-day validation. These restrict
interpretation, not the integrity of the documented same-sample comparison.
