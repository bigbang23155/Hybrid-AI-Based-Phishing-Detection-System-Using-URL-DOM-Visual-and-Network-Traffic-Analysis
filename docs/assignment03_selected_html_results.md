# Assignment 03 selected-HTML results

This records the earlier materialization checkpoint. The subsequent local research
decision, pilot overlap and holdout freeze are in `assignment03_holdout_results.md`;
their cloud replay remains pending. Counts and content findings below are preserved.

## Outcome

All 5,000 frozen candidates were materialized or assigned a retained exclusion record. The candidate replay hash matched the previous lock before any HTML inspection. There were no replacements or source changes. The technical quality gate passed, with **4,945 technically usable pairs**. Research approval, final dataset freeze, final partitions, modeling and test evaluation remain pending.

`Usable` means bounded, statically parsed markup with verified bytes and no exact-content label conflict. It does not certify a complete rendered page, current phishing activity, or independent label accuracy.

## Candidate accounting

| Item | Benign | Phishing |
| --- | ---: | ---: |
| Frozen selected | 2,500 | 2,500 |
| Usable pairs | 2,456 | 2,489 |
| Oversize exclusions (>2 MiB) | 44 | 11 |
| Candidate loss | 1.76% | 0.44% |
| Registered domains, usable | 2,167 | 2,079 |
| Largest domain count | 3 | 3 |
| Missing/empty HTML | 0 | 0 |
| Parser failures / no-markup | 0 | 0 |

All 55 exclusions were oversized HTML. The existing 2 MiB cap was not relaxed after seeing outcomes. Loss is class-dependent (1.32 percentage points higher for benign). The largest excluded HTML strings were 9,132,424 benign bytes and 8,833,418 phishing bytes. Full-cohort HTML-size distributions include these records; parsed/usable distributions do not. Rows remain in the manifest with null structural counts and an oversize reason.

## Descriptive content characteristics

The following denominators are **2,456 benign / 2,489 phishing usable pairs**, unless stated otherwise. Byte values are UTF-8 serialized publisher strings. These are source-cohort characteristics, not general phishing rules.

| Variable | Benign | Phishing |
| --- | ---: | ---: |
| HTML size, median bytes | 192,382.0 | 36,859.0 |
| Start tags, median | 873.0 | 165.0 |
| Script tags, median | 34.0 | 5.0 |
| Link references, median | 111.0 | 4.0 |
| Form tags, median | 1.0 | 1.0 |
| Iframe tags, median | 2.0 | 0.0 |
| Static text characters, median | 6,903.5 | 676.0 |
| At least one password input | 364 / 2,456 (14.82%) | 543 / 2,489 (21.82%) |
| Static text <100 characters | 104 / 2,456 (4.23%) | 487 / 2,489 (19.57%) |
| Root-path URL | 187 / 2,456 (7.61%) | 1,238 / 2,489 (49.74%) |
| HTTPS | 2,442 / 2,456 (99.43%) | 1,900 / 2,489 (76.34%) |
| Query present | 0 / 2,456 (0.00%) | 255 / 2,489 (10.25%) |

Benign pages are larger and contain more tags, scripts and links in this source frame. Password inputs occur in only 21.82% of phishing rows, so password presence is not a necessary phishing condition. Script or iframe counts alone must not be described as malicious behavior. Static text excludes script/style/noscript/template/title but may include CSS-hidden content.

External-link ratios are especially skewed: benign mean 0.15276 versus phishing 0.31726, but medians are 0.09524 versus 0.05714. The ratio is defined for 2,355 benign and 1,801 phishing pages; 101 and 688 respectively have no valid HTTP(S) link denominator. Such ratios stay null rather than being converted into zero. External-resource-ratio means are much closer (0.42865 / 0.41905); resource references are static proxies, not captured network requests.

## Content-review flags

| Flag | Benign count | Phishing count |
| --- | ---: | ---: |
| Access-error phrase | 4 | 31 |
| Challenge phrase | 1 | 5 |
| Parking phrase | 0 | 10 |
| Any of the three flags | 5 | 46 |

The flags match a declared English phrase list in normalized title plus the first 2,000 static text characters. They are not confirmed error pages and do not trigger automatic exclusions. Low-static-content flags affect 104 benign / 487 phishing rows and can also indicate dynamic pages or sparse static snapshots. Review the meaning before introducing any content-quality exclusion. Small exploratory review sets must be marked exposed and kept out of a future untouched holdout if used for feature or model design.

## Exact duplicates and grouping

- Cross-label exact-HTML conflicts: **0** across all selected content hashes, including oversized rows.
- Usable distinct HTML hashes: **4,749** across **4,945** rows.
- Repeated exact-HTML groups: **73**, covering **269** rows; excess duplicate rows: **196**.
- Exact-HTML groups spanning multiple domains: **56**; largest identical-content group: **23** rows.
- Hard connected components (registered domain OR exact HTML, transitive): **4,079**; largest: **26** rows.
- Fourteen hard components contain both source labels through shared domains/transitive links. This is not an identical-HTML label conflict; future splitting must keep the entire component together.
- Coarse start-tag-sequence matching on parsed pages with >=20 tags identifies **219** repeated structural groups / **854** rows, including **183** cross-domain groups and **2** cross-label groups; largest group **77**.

The structural diagnostic ignores text and attributes and is not a complete near-duplicate or campaign search. Its matches are not automatically merged. Registered-domain-only splits would miss some exact-content duplication; the final protocol must retain the existing combined hard grouping.

## Bias and attrition implications

1. URL shortcuts remain pronounced: usable root-path gap is 42.12 percentage points and HTTPS gap is 23.09 points. Query-bearing URLs occur in 0 benign versus 255 phishing rows. Retain no-HTTPS sensitivity; explicitly assess query/path shortcuts before final feature/evaluation design. Do not infer that HTTPS or query absence proves legitimacy.
2. The initial metadata date/language imbalance persists. November 2024 through April 2025 accounts for 0% of usable benign and 32.58% of usable phishing. Source-English proportions are 88.03% / 60.10%; Japanese 5.70% / 18.08%; language-metadata missingness 0.53% / 6.23%. Source dates/languages/targets/shards are audit metadata, not approved predictors.
3. Source target metadata is absent for every benign row and populated for every usable phishing row, including broad categories such as other/unknown. This is a direct source-label shortcut and must stay outside model input. Preserve original brand strings; aliases are not silently merged.
4. Oversize attrition is limited but differential. Selection-versus-usable URL rates change little: root-path 7.56/49.72% to 7.61/49.74%; HTTPS 99.44/76.40% to 99.43/76.34%. This does not establish absence of HTML-size or language selection bias. The artifact contains label-by-month/language/shard/root-path selected, usable and loss denominators.
5. No tuning, causal conclusion or deployment-level accuracy claim follows from these descriptive differences. The dataset is technically viable for continued research review, with source and static-content limitations.

## Reproducibility and correction history

Corrected cloud run **37698952013** succeeded at `bf1674c5d14e3b2f9f30108596d46c71e442d58d`; the complete cloud suite passed **105 tests**. Candidate replay and per-sample audit are byte-identical to the first run; the full paired-manifest SHA is unchanged. Every numeric distribution was independently recomputed and satisfies n + missing = cohort size.

Execution, source checksums, candidate lock, per-sample audit hashes and immutable artifact identifiers are recorded in `config/assignment03_selected_html_checkpoint_v1.json`.

The first materialization run 37698201811 had an aggregate numeric missing-count bug: `missing` incorrectly equaled the cohort count even when values were present. Per-sample data, content/manifest hashes, exclusions, counts, means and quantiles were unaffected. The corrected run adds invariants requiring n + missing = cohort size. The first run remains historical evidence and must not be used for missingness reporting.

Public artifacts contain aggregate reports and sanitized per-sample replay/audit rows, not raw URLs or HTML. Cloud HTML files are ephemeral and reproducible from the pinned source. The artifact is evidence for a materialization checkpoint, not a redistributed self-contained raw dataset.

## Next checkpoint

Complete a documented source/label/content-bias research decision, define any additional template-similarity rule before splitting, and determine whether content-review exclusions or sensitivity cohorts need a separately versioned protocol. Before claiming an unexposed holdout, also check formal candidates against prior pilot domain/content evidence: excluding the pilot shard prevents reuse of its source rows but does not by itself prove absence of equivalent pages or domains in other shards. That cross-pilot equivalence check has not been performed in this checkpoint. Do not backfill the original 55 losses. Only after the membership/exclusion decisions are fixed should final grouped partitions and the DOM feature registry be approved. URL-only, DOM-only and URL+DOM must use identical paired samples and partitions.
