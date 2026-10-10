# Development error/bias review v1

This review is authorized by the user's request to complete steps 1 and 2 on
2026-10-09 America/Chicago. It is a post-development diagnostic, fixed before this
review run; it is not described as part of the original experiment preregistration.
No test feature inspection, final test evaluation, relabeling, model selection,
threshold tuning, feature selection, new splits, or train+validation refit occurs.

## Reproduction gates

Verify the existing definition lock, partition manifest, six source shards and
candidate replay. Re-extract the exact 3,461 train and 742 validation samples.
Both serialized URL/DOM feature files must match the original execution hashes.
Rebuild all six baseline model/modality cells using primary seed 4941401 and fit
train only. All 4,452 validation probabilities must match the original sanitized
artifact within absolute tolerance 1e-12. A discrepancy stops the review.
The reference predictions are an unmodified six-cell subset of the verified
original artifact; its ZIP digest and the subset digest are recorded in config.

## Questions and fixed diagnostics

1. Count FP/FN and the samples the hybrid fixes or breaks relative to each single
   modality. Preserve a hashed-ID ledger and class/password/complexity composition.
   Record ten highest-confidence FP and FN IDs for each hybrid model with ties
   broken by sample ID. These are inspection queues, not human label adjudication.
2. Use train-only tag_count quartiles to define complexity bins. Apply the same
   edges to validation. Report per-class composition and confusion denominators;
   ties can make bin sizes unequal. Report all language, month and source-shard
   slices, plus password-by-complexity cells. Shards are file partitions of one
   published corpus, not six independent external data sources.
3. For each baseline cell, estimate password-present minus password-absent F1,
   recall and FPR gaps with 2,000 whole-final-group bootstrap draws. These are
   exploratory, unadjusted intervals, not multiple-testing-corrected causal tests.
4. Standardize password-group FPR and FNR over common complexity bins using
   pooled validation class counts as weights. Require at least five observations
   of the relevant class in both password groups; report retained support and
   omitted coverage. This is descriptive adjustment, not confounding elimination.
5. Apply 30 deterministic joint block permutations for URL, all DOM, the nine
   complexity/resource/script fields, and eight credential/form fields when that
   block exists in the modality. Report F1/AUC loss and Brier increase. The same
   draws are used across compatible blocks/models. Repeat both unconditionally
   and within password presence × English/other-or-missing × source-shard cells.
   Labels are never used to define permutation cells. Singletons stay fixed and
   exchangeable/index-changed row counts are reported.

Feature blocks are defined exhaustively in `assignment03_development_review_v1.json`.
Joint permutation preserves within-block relationships but can break cross-block
relationships and create unrealistic feature combinations. Conditional permutation
controls only its listed observed strata. Low importance under correlated inputs
is not proof of irrelevance. Shuffle ranges/std are Monte Carlo variability, not
population confidence intervals, valid HTML transformations, or attack success.

## Decision rule

A source, schema, pairing, leakage-rule implementation or reproduction error is a
correctness blocker. Preserve evidence, stop and version any necessary correction
before test access. Uneven segment performance or feature reliance is documented
as a limitation of the frozen internal benchmark, not a reason to hide samples,
search seeds or silently optimize against validation. If only scope limitations
remain, retain all six cells and freeze the final evaluation specification with
these limitations attached. Test execution still requires the subsequent step.
