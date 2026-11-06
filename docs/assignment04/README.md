# Assignment 04: offline foundation progress

Status: **partial implementation, not a completed A04 submission**. No reviewed new
cohort, learned Visual/HTTP model, model comparison on that cohort, or independent
new test partition is claimed. Historical acquisition remains paused. This work
implements the professor's core scope without expanding content forensics or sandboxing.

## A03 evaluation disclosure

The paired A03 test was accessed at **2026-10-10 00:02:06 UTC** and completed at
**00:02:37 UTC** (October 9, 2026, 7:02 PM America/Chicago). Run:
[38006867242](https://github.com/bigbang23155/Hybrid-AI-Based-Phishing-Detection-System-Using-URL-DOM-Visual-and-Network-Traffic-Analysis/actions/runs/38006867242).
Execution commit: `5be2c41d484a207a2effece5828a6c0ccd145565`. There were 742 rows,
588 groups, six model/input cells, 4,452 predictions and one evaluation. The
threshold was 0.5. This foundation reads archived aggregate results; it does not
rerun inference on those samples.

| Model | Inputs | Archived test F1 | Archived test FPR |
|---|---|---:|---:|
| RF | URL | 83.47% | 13.55% |
| RF | DOM | 85.41% | 15.99% |
| RF | URL + DOM | 89.92% | 8.40% |
| GBDT | URL | 84.75% | 14.63% |
| GBDT | DOM | 84.57% | 16.53% |
| GBDT | URL + DOM | 90.09% | 8.67% |

The archived checkpoint records no subsequent changes to the frozen models or
threshold. However, the test was inspected and strengthening directions were
subsequently discussed, including simple benign/complex phishing coverage and
page-complexity bias. We cannot claim the later research agenda was independent
of that exposure. The earlier report omitted the post-test discussion; this
addendum makes the distinction explicit. Existing development diagnostics already
identified complexity issues, so the test was not their sole origin. The new
analysis below is a **post-exposure, descriptive validation reanalysis**, not an
independent confirmation. The old holdout is consumed permanently. The new A04
holdout has **not yet been established**, and cannot be created merely by
reshuffling exposed samples.

Sources: `config/assignment03_final_test_checkpoint_v1.json`,
`results/assignment03/final_test_v1/{test_access_started,test_summary}.json`.

## Controlled complexity comparison

We reuse the archived primary validation predictions on the same 742 rows for
all six cells. No model is refitted. Training-defined tag-count quartile cuts
are 106, 475 and 1083. Each of the eight class x complexity-bin cells receives
weight 1/8. Thus both classes have identical bin distributions and 50% prevalence.
We recompute weighted confusion totals and F1; we do not average bin F1 scores.
All rows remain in the analysis. This is a hypothetical standardized population,
not measured deployment performance or a causal estimate.

| Model | URL F1, unadjusted | Hybrid F1, unadjusted | URL F1, standardized | Hybrid F1, standardized | Standardized gain |
|---|---:|---:|---:|---:|---:|
| RF | 85.13% | 91.28% | 82.75% | 86.91% | +4.16 pp |
| GBDT | 86.44% | 90.41% | 84.28% | 84.69% | +0.41 pp |

Paired whole-group bootstrap (1,000 draws, seed 4940401, re-standardization per
draw) gives RF gain interval **+0.42 to +7.85 pp**, GBDT **-2.41 to +3.18 pp**.
All 1,000 draws retained the eight required cells. These are descriptive percentile
intervals with no multiple-comparison correction. The RF benefit persists under
this coarse complexity control; the GBDT benefit is much less clear.

**Unfinished:** joint HTML-byte-size and complexity control. Retained review
artifacts contain complexity bins, not per-row HTML byte sizes. Reconstruct the
approved development-only feature table before making that claim. No test
features should be reconstructed for this work. Source, capture time and residual
within-bin differences remain possible confounders. The sparse simplest benign
and most complex phishing strata make weighted estimates more variable.

## The 464 rows and the train-validation gap

The partition manifest verifies **464 rows in 96 connected components** were
previously exposed or transitively linked to pilot exposure. Every one is assigned
to training, not validation/test. The rationale was to prevent known exposure from
entering holdout groups while retaining usable training information; it does not
make the training sample representative or prove campaign independence.

Primary RF hybrid training F1 is 100%, versus validation 91.28% (**8.72 pp gap**).
GBDT hybrid is 95.51% versus 90.41% (**5.10 pp gap**). RF URL and DOM gaps are 14.24
and 11.92 pp respectively. RF uses unrestricted tree depth and leaf size one;
near-perfect training fit is consistent with overfitting but does not by itself
identify its cause. Domain/content grouping and source differences can also
contribute. Seed stability is not evidence of cross-source generalization.

An exclusion sensitivity experiment would refit on training with the 96 exposed
components removed, retaining identical validation membership and fixed settings.
That experiment is **not executed**: model-ready development features are not in
this checkout. No claim is made that the 464 rows caused or resolved the gap.
Do not spend the remainder of A04 optimizing this historical baseline.

## Dataset inventory

Counts below are **historical publisher labels**, not newly adjudicated labels.
Unknown coverage is deliberately not reported as zero.

| Evidence cohort | Benign | Phishing | URL + HTML | Matched screenshot / HTTP |
|---|---:|---:|---|---|
| A03 training | 1718 | 1743 | 3461 paired | Not established by archived manifest |
| A03 validation | 369 | 373 | 742 paired | Not established by archived manifest |
| A03 consumed test | 369 | 373 | 742 paired, historical metadata only | Not established |
| Oversize exclusions | 44 | 11 | Excluded by 2 MiB limit | Not established |
| Review queue (subset of historical validation) | 296 | 360 | 656 snapshots previously verified | No aligned cohort established |
| New A04 cohort | Unknown | Unknown | Not materialized | Not materialized |

The archived review import records 656 pending decisions and zero human entries;
this is a repository snapshot, not a claim about reviews the user has completed
but not synchronized. The material summary records zero exact capture timestamps.
The review queue is a subset, not 656 additional independent samples. AI suggestions
and publisher labels remain separate from human decisions. One earlier public
control proves provider integration, not benign/phishing cohort coverage.

Reproducible inventory and source hashes:
`results/assignment04/foundation_v1/repository_inventory.json`.

## Visual extraction and integration

A new fixed **104-feature** screenshot representation has 48 RGB histogram bins,
48 spatial RGB cell means and eight magnitude-weighted unsigned gradient bins.
It has no learned weights. The new adapter uses verified existing Collector
checkpoints, keeps URL18/DOM23/HTTP20 unchanged, and exports **165 ordered fields**
with observed/usable masks. It replaces only the visual representation in a
separate A04 output; it does not overwrite the earlier 64-field contract.

The integration is currently an **unfitted feature handoff**, not a multimodal
classifier. Inventory counts every supplied attempt and records missing, failed,
stale and usable states by optional source assertion. Missing values remain null;
no imputer/scaler is fitted. Source labels are not predictors or accepted labels.
The evidence preview explicitly says prediction unavailable and shows availability
and usable-field counts. The committed demo uses a clearly marked synthetic fixture.

Local validation passed 20 focused software tests in the pinned environment; all
75 frozen-file hashes remained unchanged. The audit and inventory reproduced exactly.
HTML rendering could not be visually verified because local Chromium cannot create
its process socket in this environment; the preview is not claimed as visually QA-approved.

See [implementation and commands](../../research/assignment04_v1/README.md).

## Remaining A04 work and evaluation plan

1. Synchronize human review evidence and identify a manageable, time-aligned
   URL/DOM/screenshot/HTTP cohort. Do not join old HTML to an unrelated recent scan.
   Keep missing/error/takedown records and record provider/source/capture conditions.
2. Build connected domain/content groups and compare them with all historical
   exposures. Unknown campaign status is not evidence of novelty. Freeze a genuinely
   independent new holdout and keep its feature artifacts/labels out of development.
3. Fit simple Visual and HTTP models only after eligibility is established. Fit
   preprocessing on training only. Retrain URL, DOM and URL+DOM on the same cohort;
   compare a predefined complete-case validation cohort across all modalities, and
   separately report missing-modality behavior with explicit denominators.
4. Start with feature concatenation or fixed probability averaging. Select any
   thresholds/parameters using training/validation only. Preserve test for final
   project evaluation, with a versioned protocol, hashes and access log.
5. Add trained predictions to the evidence demo; produce the final 4-6 page A04
   report, figure, results and runnable documentation. A future final evaluation,
   report and presentation should distinguish engineering checks, validation
   findings and truly independent final results.

Current contribution is reproducible evidence handling, explicit missingness,
transparent evaluation disclosure and a simple visual representation. Detection
improvement from Visual/HTTP is still untested. Complex attention, additional
security scenarios and advanced content forensics remain deferred.
