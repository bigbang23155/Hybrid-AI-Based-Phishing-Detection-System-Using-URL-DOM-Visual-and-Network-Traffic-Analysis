# Assignment 03 Progress Report
DOM Feature Extraction and Initial Hybrid Modeling
Yuchiao Hu | IT 494 | October 21 2026

## Progress and scope
I completed the remaining URL baseline work, implemented static HTML feature extraction, and trained initial DOM-only and URL + DOM models. The main comparison uses the same paired samples and domain/content groups for all three modalities. On validation data, the primary Random Forest hybrid reached 91.28% F1, compared with 85.13% for URL-only. This supports adding DOM structure within this historical dataset, while source and page-complexity biases still limit generalization.

This report presents development and validation evidence. The new test set was excluded throughout development and was subsequently evaluated once under the frozen final protocol. It is now consumed and cannot be reused as an unseen holdout. Post-test strengthening analysis is outside this report; no test-driven changes were made to the frozen experiment.

## Completed URL baseline
I retained the frozen 4,000-row historical URL dataset and compared Logistic Regression, Decision Tree, Random Forest and scikit-learn Gradient Boosting. Training and validation supported model comparisons; the previously exposed Assignment 02 test was not reused for Phase 1 development. The following results summarize five recorded development splits.

| Model | Validation F1 mean | Sample SD in percentage points |
|---|---:|---:|
| Logistic Regression | 87.77% | 2.65 |
| Decision Tree | 86.72% | 2.61 |
| Random Forest | 90.41% | 1.47 |
| Gradient Boosting | 90.09% | 1.57 |

RF remained the primary reference and GBDT the comparator. Their small difference does not establish general superiority. Using 25%, 50%, 75% and 100% of the existing training pool gave RF mean validation F1 of 88.32%, 89.20%, 89.96% and 90.41%. This suggests a modest benefit from more training rows, but it was not an external-data expansion and the subsets were not nested.

A random URL split gave RF 91.29% mean F1 versus 90.41% with domain grouping. I retained domain grouping to reduce related-domain leakage. These Phase 1 scores are from a different dataset and split procedure from the paired experiment below, so they are not a direct before-and-after hybrid comparison.


## Paired dataset preparation
I used a pinned subset of the authors’ PhreshPhish URL/HTML corpus because historical URLs cannot reliably be revisited to recover their original pages. Six published train shards were verified by file size and SHA-256 before reconstructing the fixed 5,000-candidate list. Each URL is paired with HTML from the same source-file hash and row ordinal. Labels are the publisher’s benign/phishing labels, not independently reviewed project labels.

| Dataset stage | Benign | Phishing | Total |
|---|---:|---:|---:|
| Fixed candidates | 2500 | 2500 | 5000 |
| Usable pairs | 2456 | 2489 | 4945 |
| Oversize exclusions | 44 | 11 | 55 |
| Train | 1718 | 1743 | 3461 |
| Validation | 369 | 373 | 742 |
| Test | 369 | 373 | 742 |

All 55 exclusions exceeded the fixed 2 MiB HTML limit and were retained without replacement. Materialization found no missing/empty HTML, parser failures or cross-label identical-HTML conflicts. The available source does not supply the original redirect chain, final URL or HTTP status; these remain unknown. Static markup availability does not establish complete browser rendering or current page activity.

Grouping connects registered domains, identical HTML and a predefined qualifying tag-sequence signature transitively. This produced 3,669 groups. Pilot overlap checks forced 464 exposed or transitively related rows into training only. The final train/validation/test partitions contain 2,525/556/588 groups, with no overlap under those rules. This reduces measured leakage but does not prove independence of all templates or campaigns.

## DOM extraction and hybrid construction
The reproducible static_dom_v1 extractor uses Python HTMLParser and 23 ordered features: forms and inputs; links and external-link ratios; resources and external-resource ratios; scripts and iframes; explicit hidden elements; meta refresh; and form-action destinations. Page URL provides context for relative links and registered-domain comparisons. It does not become a domain-identity predictor in DOM-only models.

Structural absence produces a real zero. Undefined external-reference ratios use zero with their denominator counts retained, as fixed by the modeling protocol. Missing or invalid HTML is an extraction failure rather than an all-zero page. All 4,203 development rows passed extraction and integrity checks. The models use 18 URL features, 23 DOM features, or their 41-feature concatenation. Source dates, language, target brands, IDs and grouping metadata are excluded from predictors.

The 23-feature scope is an engineering choice motivated by the assignment’s structural examples and related phishing research, not a literature-mandated optimum. Static parsing does not observe JavaScript execution, computed CSS visibility, runtime redirects or actual network traffic. Full ordered definitions and parsing rules are supplied in dataset_and_features.md.


## Initial modeling results
RF and GBDT were fitted on the same 3,461 training rows and evaluated on the same 742 validation rows. RF uses 100 trees; GBDT uses 100 stages, depth 3 and learning rate 0.1. The fixed threshold is 0.5. No parameter search, calibration, row resampling or train-plus-validation fitting was performed.

| Model | Input | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|
| RF | URL | 85.31% | 86.67% | 83.65% | 85.13% | 13.01% |
| RF | DOM | 88.01% | 88.59% | 87.40% | 87.99% | 11.38% |
| RF | URL + DOM | 91.37% | 92.80% | 89.81% | 91.28% | 7.05% |
| GBDT | URL | 86.39% | 86.56% | 86.33% | 86.44% | 13.55% |
| GBDT | DOM | 86.39% | 85.79% | 87.40% | 86.59% | 14.63% |
| GBDT | URL + DOM | 90.57% | 92.44% | 88.47% | 90.41% | 7.32% |

These are validation scores at the predefined primary seed 4941401. FPR uses 369 benign rows and recall uses 373 phishing rows. RF hybrid confusion counts are TN=343, FP=26, FN=38 and TP=335. Full ROC-AUC, average precision, Brier score, train metrics and all five seeds are included in the experimental results.

RF hybrid improved F1 by 6.15 percentage points over URL-only. Its paired whole-group bootstrap 95% interval was +3.71 to +8.68 points; hybrid F1 itself had an 88.02–93.92% interval. GBDT hybrid improved over URL-only by 3.97 points. These are descriptive comparisons within one source cohort, without multiple-comparison correction.

Across five model seeds on the same split, RF hybrid validation F1 averaged 90.63% with sample SD 0.59 percentage points. RF training F1 was 100%, so the train-validation gap remains substantial. Seed stability does not establish stability across new datasets. Removing HTTPS reduced RF hybrid F1 to 90.31%; restricting URL input to hostname features gave 89.57%. These are retrained sensitivity comparisons, not adversarial attack tests.

## Development errors and limitations
The RF hybrid corrected 63 URL-only errors but introduced 18 new errors. Its F1 on pages with password inputs was 87.12%, versus 92.47% without them. The descriptive interval for that gap includes zero, and page composition differs, so I cannot attribute the gap to password fields alone.

Page complexity is a clearer concern. Using train-defined tag-count strata, RF hybrid FPR was 26.67% on the simplest benign pages (8/30), while recall on the most complex phishing pages was 75.00% (24/32). Development permutation diagnostics also showed reliance on complexity-related features. Scripts and resources therefore may reflect source composition as well as useful structure.

Benign/phishing median HTML sizes were 192,382/36,859 bytes, and usable HTTPS rates were 99.43%/76.34%. Language and month distributions also differed. The balanced historical cohort cannot establish real-world precision, low-FPR deployment readiness, future-time generalization or zero-day detection.


## Repository and reproducibility
The updated submission branch contains the latest code, frozen protocols, dataset and feature documentation, and development results. Earlier milestone documents are preserved as historical checkpoints; the submission index states the cumulative status.

Repository
https://github.com/bigbang23155/Hybrid-AI-Based-Phishing-Detection-System-Using-URL-DOM-Visual-and-Network-Traffic-Analysis

Submission branch
submission/assignment03-20261021

Code modules and reproduction commands are indexed in the submission README. Archived development and review runs are GitHub Actions 37725422890 and 37898355594; dependencies, source hashes and execution commits are retained.

For this submission, I independently rechecked 70 validation cohorts (51,940 predictions), primary paired F1 intervals and review aggregates. Metrics agreed to numerical precision. No fitting or test evaluation was repeated. Raw URLs, HTML and fitted models are not redistributed; the pinned-source workflow supports reconstruction.

## Remaining project scope
The priority is an achievable integration and demonstration, with the frozen URL + DOM experiment retained as the reference.

| Stage | Remaining work and completion evidence |
|---|---|
| Next week | Finish independent human review and historical URL/template/campaign overlap checks. Keep AI annotations separate from human labels. Confirm pairing, capture times and retention before expanding collection. |
| Following week | Complete paired screenshot and HTTP evidence coverage checks. Start with a simple visual representation and the existing 20-feature Network-HTTP extractor; retain explicit missing/failed/stale states. |
| Before final integration | Compare additional modalities only on a newly versioned development cohort. Start with a simple fusion method and evaluate whether added inputs help. Learned reliability weighting or attention is optional and requires sufficient paired labeled evidence. |
| Final project stage | Lock the new protocol before evaluating an independent later-time/source cohort. Build a small demonstration showing a prediction, available evidence and missingness; document limitations and reproducible commands. |

As of the latest research code, the read-only urlscan collector, four-modality evidence interface, HTTP feature extractor and passive content-forensics foundation exist separately. One public control demonstrated integration, not phishing detection accuracy or historical dataset coverage. Visual semantic modeling and learned fusion/attention are not yet trained. Network-HTTP is HTTP metadata, not PCAP. Historical collection remains paused while review is incomplete.

YARA/encoding signals are not labels. Deep reverse engineering, dynamic sandbox analysis, Evil Twin and AiTM defenses remain optional later work.

## References and supporting files
Assignment 03 handout, sections 1–6; PhreshPhish dataset and paper (https://arxiv.org/abs/2507.10854); Python HTMLParser and scikit-learn 1.7 estimator documentation. Full source links are in dataset_and_features.md. Scores derive from the archived project experiments.

Supporting files: dataset_and_features.md, submission README, primary_validation.csv and complete development_v1/review_v1 results.
