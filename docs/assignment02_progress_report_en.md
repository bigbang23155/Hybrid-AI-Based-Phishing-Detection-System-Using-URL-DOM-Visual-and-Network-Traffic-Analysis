# Assignment 02: URL-only research foundation

## Objective and status

This revision uses the existing Assignment 02 code as the base and fixes sampling,
feature-schema flexibility and model evaluation before committing to the final data
population. It retains prior code/history and failed acquisition evidence. It does
not reopen Assignment 01 recovery, retry collection, freeze Dataset v2, or train a
formal real-data experiment. Software-test scores are not research results.

## URL-only method and model comparison

Original URLs are validated and conservatively normalized; exact/normalized duplicates
and conflicting labels are audited. PSL-aware registrable domains (or normalized IPs)
keep related URLs in one partition using the bundled fixed snapshot, excluding private
suffixes. The 70/15/15 domain-disjoint target and five development splits remain.

The unchanged 18-feature baseline now has working 16/21-feature alternatives, the
17-feature no-HTTPS ablation and a corrected hostname-only schema. These are documented
hypotheses, not optimal feature counts. All rows share a frozen ordered schema; unknown
features fail and missing values require explicit handling. Original URL extraction
still raises on invalid inputs. Extra features are computed from URL text, not source
precomputed columns. See feature_rationale.md for definitions and limitations.

Logistic Regression and Decision Tree retain their existing search grids. LR uses
training-only imputation/scaling; the tree does not require scaling. Mean validation
F1 selects parameters, with all seed results and paired model differences saved. LR
provides a compact linear baseline but misses nonlinear interactions; trees capture
interactions but can overfit and vary with data. No winner is asserted without approved
real-data evidence. Threshold 0.5, phishing=1, FPR and confusion counts remain explicit.

The loader rejects fractional labels and provenance inconsistencies. Model fitting
stops on convergence warnings. Missing-indicator feature names are included correctly
in importance. Default execution stops after development. Final evaluation requires
matching frozen development data/configuration/code/version evidence and verified
replayed splits, selected parameters and validation metrics. See model_sampling_method.md.

## Random sampling and reproducibility

Preparation was already random. The revision makes duplicate representatives and
training order independent of input file ordering, separates per-class sampling RNG
streams, and records pool/input/output hashes and shortfalls. A master seed can be drawn
once from system entropy, then recorded and used to derive distinct sampling, test,
development and model seeds. Fixed documented seeds are reproducible randomization;
rerunning until a high score appears is not an acceptable selection method.

The existing 500-permutation split search balances only size and class proportions.
It is constrained random group allocation, not uniform over all possible splits. It is
now cached per seed and exported for all comparisons. Model seed is held fixed to isolate
split variability; LR with lbfgs is deterministic. Repeated development SD does not cover
all sampling/estimator uncertainty and is not an independent confidence interval.

## Actual candidate data audit

GitHub Actions run 36227969493 completed the fixed supplement. The retained artifact's
31 file checksums verified. Follow-up offline audit using the existing cleaner found:

| Measure | Observed assumed-legitimate | PhiUSIIL phishing candidate |
|---|---:|---:|
| Rows / valid URLs | 2,643 / 2,643 | 100,945 / 100,945 |
| Domain groups | 1,043 | 43,512 |
| Exact / normalized duplicates beyond first | 0 / 0 | 425 / 1,106 |
| Maximum rows in one group | 3 | 5,754 |
| HTTPS | 96.82% | 48.74% |
| Inner paths | 59.67% | 27.20% |
| Query present | 3.71% | 6.02% |
| Median URL/path/query length | 30 / 7 / 0 | 34 / 1 / 0 |

All observed labels are explicitly *assumed* legitimate; the 15-row manual queue remains
unreviewed. Observations span September 26, 2026, 06:45:29–07:51:19 UTC. There were 1,800
candidate domains and 11,541 logged failure events, not that many distinct failed domains.
The two source pools share no normalized URL, but share three domain groups. Full PhiUSIIL
has one normalized cross-label conflict; this must be excluded before any approved sampling.
Its 134,850 legitimate reference rows are all HTTPS root URLs and were not adopted as
replacement benign data. Original PhiUSIIL 0=phishing and 1=legitimate would require explicit
mapping to the project's opposite convention. No precomputed features were used in the audit.

Detailed measured profiles and provenance are preserved under
results/assignment02/candidate_audit_20260926/. The original audit code/notebook/raw archives
are in the separately delivered supplement audit ZIP, SHA-256
429571a3e8764ca2136a5106b43ddde428b12b4f7f05f7de36e3fd924860cb7b.
The requested ISCX original-URL archive was unavailable to that audit; its domain-only
benign removal and original structure were not independently verified. A feature-only
All.csv is insufficient for original-URL/domain-disjoint evaluation.

## Why the final data design changes

The user chose to prioritize the final research question over treating a weak-label,
mixed-period dataset as the main benchmark. Accordingly, the current pools remain
pilot/context evidence. Passing 2,000 URLs, 300 domains and 20% inner pages only meets
project heuristics; these are not professor requirements or final approval. No thresholds
were relaxed. HTTPS ablation and random seeds cannot remove source/time confounding.

The final protocol calls for overlapping collection windows, explicit label evidence,
matched observations across URL/DOM/visual/network, immutable raw snapshots, failure and
modality-availability reporting, and later unseen-domain temporal evaluation. These are
planned extensions, not claims that the current URL-only runner already implements them.
The next data milestone is an end-to-end observation/label pilot, followed by an audited
freeze once suitability is established. See final_research_protocol.md.

## Validation and limits

The automated suite covers original behavior plus sampling/order/seed invariance,
legacy split equivalence, schema changes, missing values, train-only preprocessing,
explicit finalization, model persistence and inference. Exact verification output is
included in the delivered package. Tests use reserved example URLs, not fabricated
research data. No formal Accuracy/F1 or final model importance is claimed here.

URL-only timing is not complete Hybrid latency. Importance is associational; label
noise, source/period differences, collection success and cross-domain templates remain
risks. Final effectiveness must be established with the planned data/evaluation design.

## Observation pilot checkpoint — September 27, 2026

The next milestone described above has now been attempted in cloud. Label-policy-v1,
the observation schema, isolated browser collection and evidence packaging are implemented.
After a documented sandbox compatibility repair, run 36289927306 recorded all 16
fixed candidates; 106 file hashes and all record validations passed. Complete captures
were 6/8 official controls and 3/8 source-reported phishing candidates, so the declared
gate failed. All labels remain unadjudicated. No expansion or model training occurred.
The existing URL model/feature/randomness foundation remains unchanged. See
[the actual pilot report](observation_pilot_results_en.md) for content problems,
retained failures, network-modality limits and the next acquisition-design work.

## References

- UCI, PhiUSIIL Phishing URL (Website): https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset . Original label mapping and March 3, 2024 donation; donation is not per-URL collection time.
- scikit-learn 1.7, leakage and randomness: https://scikit-learn.org/1.7/common_pitfalls.html .
- Le et al., URLNet: https://arxiv.org/abs/1802.03162 . General lexical URL motivation, not validation of these exact feature sets.
- Public Suffix List: https://publicsuffix.org/ .
