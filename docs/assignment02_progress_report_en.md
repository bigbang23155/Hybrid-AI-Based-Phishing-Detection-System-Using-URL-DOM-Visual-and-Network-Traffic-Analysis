# Assignment 02 Progress Report: URL Baseline Modeling and Evaluation

## Objective and work completed

This milestone turns the Assignment 01 URL preparation work into a reproducible modeling workflow while
remaining strictly URL-only. I retained cleaning, validation, conflict removal, deduplication, and seeded
balanced sampling. I added configurable ordered feature schemas, PSL-aware domain grouping, a locked-test
and repeated-development split protocol, logistic-regression and decision-tree pipelines, auditing,
importance/error outputs, model persistence, and local prediction.

## Data audit and bias

The runner reports label and source-by-label counts; exact and normalized duplicates; conflicting labels;
missing domains; group sizes; feature missing/infinite/unique counts; distributions; and correlations.
It explicitly measures HTTPS and root-URL rates by source and label. Tranco ingestion constructs
`https://domain/`; phishing feeds preserve paths and queries. Thus scheme and URL depth can reveal source.
Where sources and labels are one-to-one, source-label confounding prevents a strong generalization claim.

## Splitting and randomness

The normalized eTLD+1 (or normalized IP) is the only group key. tldextract uses its installed PSL snapshot,
never updates at runtime, and excludes private suffixes. Seed 2025 fixes approximately 15% as test. Seeds
11, 23, 37, 53, and 71 repeatedly split the remaining development data to approximately 70/15 train/
validation overall. Candidate splits minimize only predeclared sample-ratio and class-balance differences,
not model scores. Automated checks require disjoint domains and normalized URLs, complete assignment, and
both classes in every partition. The manifest stores stable SHA-256 sample IDs, dataset checksum and seeds.

## Features and models

The original 18 measurements are the initial baseline rather than a proven optimum. The required ablation
removes only `uses_https`; an optional hostname-oriented set supports further sensitivity analysis. Any
ordered subset is allowed after schema validation, while metadata is rejected. An absent query has length
zero; an invalid URL raises instead of silently becoming zero. Median imputation and scaling are fit inside
each sklearn pipeline on that training partition only.

Logistic regression searches C in {0.1, 1, 10}, with standardized inputs and 2,000 maximum iterations.
The tree searches max depth {3, 5, 8, unrestricted} and minimum leaf size {2, 10}. Selection uses mean
validation F1, with all variants sharing each seed's split. Threshold 0.5 and positive class 1 (phishing)
are fixed. Accuracy, precision, recall, F1, FPR, ROC-AUC, average precision and TN/FP/FN/TP are produced.

## Results and analysis status

The requested real files were absent from this checkout: `data/raw/{phishtank.csv|phishtank.json}`,
`data/raw/openphish.txt`, `data/raw/tranco.csv`, and `data/processed/urls.csv`. I therefore did not run or
invent a formal experiment. Once supplied, one command produces validation mean/standard deviation,
one-time test comparisons, standardized logistic coefficients, tree impurity importance, validation-set
permutation importance, and defanged false-positive/false-negative rows. Test error inspection is
for reporting only and must not drive this assignment's model changes.

### Dataset-v2 acquisition update

Assignment 01 established normalization and the initial lexical features; Assignment 02 then identified
that constructed Tranco HTTPS roots can make scheme and URL depth proxies for source. The completed
PhiUSIIL audit described in the task context did not resolve this: all 134,850 legitimate records were
HTTPS roots, whereas phishing records contained more paths and queries. The attached audit package was
not mounted here, so I did not claim to reverify its manifest or reuse it as Dataset v2.

I implemented and executed a bounded observed-URL collector using a frozen Tranco daily list only as a
candidate frame. With seed 20250926 it sampled 1,200 domains in ranks 1,001–100,000 and allowed at most
three observations per domain. Public-destination, redirect, same-domain, robots, response-size, timeout,
credential, and token-query controls were applied. The outbound proxy blocked almost all arbitrary-site
traffic: the run retained 3 URLs from 1 domain and logged 2,398 failures. All retained URLs were HTTPS,
all three had non-root paths, and none had a query. These tiny counts are not a legitimate sample.

The preregistered gate requires at least 2,000 URLs, 300 domain groups, and a 20% inner-page rate. Although
the observed inner-page rate was 100%, the count and diversity criteria failed. The explicit decision is
**unsuitable**. No Dataset v2 was constructed, no phishing records were combined, and the locked test set
was not evaluated. The smallest next step is to run the same frozen-list command in a network environment
that permits public-site retrieval, or supply a licensed original-full-URL benign corpus. The PhiUSIIL
package must also be uploaded into this workspace if its manifest is to be independently verified.

The separately inspected ISCX-URL2016 `All.csv` was reported to contain 36,707 records, 79 precomputed
features, and one class column, with neither original URLs nor domain identifiers. It was unavailable in
this workspace for independent checksum/class-count verification. It cannot support our normalization,
feature extraction, or domain-disjoint evaluation and was not used. A complete Windows-ready project
export now preserves the collector, audit, model code, frozen Tranco frame, PSL evidence, failed pilot,
tests, documentation, and local Git history; Windows instructions gate the full run behind a fixed-subset
connectivity diagnostic and keep new output separate.

## Limitations and next steps

The current data design cannot establish cross-source performance. URL-only local timing/performance would
not represent the proposed hybrid system. Importance is associational: correlated predictors destabilize
coefficients and permutation effects, while impurity importance can favor continuous predictors. Next work
is to obtain the archived inputs, freeze their checksums, execute this preregistered workflow once, review
convergence logs and measured extraction/inference latency, and later collect overlapping-source benign
full URLs before adding DOM, visual, or traffic modalities.

## References

1. Ma et al. (2009), *Beyond Blacklists*, [doi:10.1145/1557019.1557153](https://doi.org/10.1145/1557019.1557153).
2. Le et al. (2018), *URLNet*, [arXiv:1802.03162](https://arxiv.org/abs/1802.03162).
3. Pochat et al. (2019), *Tranco*, [doi:10.14722/ndss.2019.23386](https://doi.org/10.14722/ndss.2019.23386).
4. Mozilla, [Public Suffix List](https://publicsuffix.org/).
