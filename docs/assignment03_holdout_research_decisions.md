# Assignment 03: evidence-based content and holdout decisions

## Scope and evidence hierarchy

The decision is to freeze an **internal same-cohort modality-comparison dataset**,
not claim a prospective, independently adjudicated or deployment-ready benchmark.
The original 5,000 candidate membership, source frame, 55 oversize failures and
frozen historical URL baseline remain unchanged. This is an additive protocol
version in `config/assignment03_holdout_policy_v1.json`; the earlier frozen
source/selection policies are not overwritten.

Evidence is cross-checked by role rather than by counting votes:

1. The archived project protocol carries the Assignment 03 same-samples,
   domain-grouped modality-comparison requirement. The professor PDF was initially unavailable, then materialized and verified
   before GitHub publication. Its sections 2 and 4 directly confirm grouped
   partitions, same-sample modality comparison and unused test. The verification
   addendum records its hash; no policy, seed or partition changed.
2. The pinned dataset card establishes source revision/version context.
3. The PhreshPhish paper explains the authors' leakage and content-cleaning logic.
4. TESSERACT and scikit-learn independently corroborate evaluation principles.
5. The checksum-verified pilot and formal artifacts determine actual counts and
   whether the proposed rules can be applied to this particular cohort.

The PhreshPhish card and paper are one author/source family, not independent
replications. Links, response hashes and retrieval date are in
`assignment03_holdout_source_ledger.json`.

## External sources and applicability

**PhreshPhish paper v1**, sections 2.2, 3.3 and 4.1:
[paper](https://arxiv.org/html/2507.10854v1).
The authors recognize shared entities/kits, use temporal separation plus
similarity filtering, and combine heuristics with prototype inspection for
content cleaning. This supports grouping related pages and treating content
quality as more than parse success. We do not reproduce their TF-IDF/LSH
benchmark filtering or import thresholds they did not prescribe for our project.

**Pinned PhreshPhish dataset card**:
[fixed revision](https://huggingface.co/datasets/phreshphish/phreshphish/blob/eabec4b7a66324b79cc8a0ad856d1731dc26fe1a/README.md).
It describes v1.0.1 adding 2025 data and changing temporal sampling. This differs
from the original paper's collection period. Its stated test total (168,060)
also differs from the displayed class-count sum (168,136). Therefore use actual
verified shard counts and dates, not aggregate prose or v1 paper counts, for this
freeze. The official source test remains excluded.

**TESSERACT**, USENIX Security 2019:
[primary publication page](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury).
This independent malware study identifies spatial and temporal evaluation bias.
It supports restricting claims from a historical grouped random split; its
Android malware results do not determine numerical phishing thresholds.

**scikit-learn common pitfalls**, section 12.2:
[official documentation](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage).
Model choices must not use test data, and learned preprocessing must fit on
training data only. This supports reserving the test now and restricting all
subsequent imputation, feature decisions, threshold selection and tuning to
development. Group construction here is deterministic data partitioning, not a
predictive feature fit.

## Decisions and alternatives

| Question | Decision | Cross-check and tradeoff |
| --- | --- | --- |
| Remove marker/low-text pages? | Retain all 4,945 technically usable pairs in the primary cohort. Keep flags for development-only review/sensitivity. | Our 5/46 marker flags and 104/487 low-text flags are class- and language-dependent. PhreshPhish's cleaning included more evidence than our English phrase list. Blind keyword removal could introduce new selection bias. |
| Relabel source samples? | No. Preserve source labels and their uncertainty. | Static markers do not establish true class. There has been no independent page adjudication. |
| Relax 2 MiB or backfill? | No. Keep all 55 failure records and the fixed cap. | Frozen policy, 44/11 observed losses and source-selection reproducibility agree. |
| Hard grouping? | Connect registered domain, exact HTML, and identical ordered start-tag sequences for parsed pages with at least 20 tags. | The formal audit found 56 exact-content groups across domains and 219 repeated structural groups. Entity/similarity leakage in PhreshPhish motivates a conservative additional structural guard. It can overgroup unrelated pages, so it is disclosed as an engineering rule, not a verified near-duplicate detector. |
| Why change structural matches from diagnostic to guard? | Explicit protocol amendment before generating any partition. No sample is removed or relabeled. | This prefers conservative blocking over a larger apparently independent holdout. A component exceeding 10% of usable rows stops the run; no giant component is silently cut. Twenty tags and 10% are project heuristics, not literature-derived constants. |
| Pilot exposure? | Compare all 256 pilot candidates by ID, URL, domain, exact HTML and qualifying structural signature; propagate to the entire formal component and assign it to training only. | This addresses direct and transitive reuse, including the oversized pilot candidate's domain/content hash. An excluded pilot shard alone is insufficient. No exposed component may enter validation or test. |
| Temporal versus grouped holdout? | Retain preregistered 70/15/15 grouped primary evaluation; explicitly disclaim prospective generalization. | The assignment's immediate purpose is a controlled modality comparison. PhreshPhish/TESSERACT justify a separately designed temporal sensitivity on development later, not silently replacing the primary experiment after inspecting this cohort. |
| Source shortcuts as predictors? | Ban date, language, target, source IDs/shards, labels, grouping, exposure and quality-review metadata. Keep no-HTTPS sensitivity. Review query/path shortcuts on development before test evaluation. | Actual target metadata is perfectly class-associated; query presence is 0 versus 255. These findings plus test-separation guidance prohibit treating source metadata as model evidence. |
| What does freeze approve? | Membership and partitions only. Model training remains unapproved until the DOM registry and modeling protocol are fixed. | Separates data acceptance from predictive validity. No test metrics are produced. |

## Fixed allocation rule

The original test seed 4941302 and development seed 4941303 remain. Components
that touch pilot evidence are training-only. From remaining whole components,
choose test then validation using 500 seeded permutations each. Minimize only
absolute deviations from global per-label 15% sample targets. Never use DOM
feature distributions, predicted scores or performance to choose a partition.

Both classes must occur in every partition. Overall and per-class split
fractions must be within two percentage points of 70/15/15. Failure stops the
run without resampling candidates, changing seeds or removing components.
The tolerance is a project engineering allowance for indivisible groups.

No URL, exact-HTML hash, qualifying structural signature or final component can
span partitions. All 5,000 rows remain in the export: eligible rows get a single
partition; the original 55 losses are explicitly `excluded`.

## Remaining validity limits

Whole-cohort aggregate quality diagnostics were observed before splitting.
This is a newly reserved internal holdout, not a blind external test. Structural
hash equality is deliberately conservative but does not detect all similar kits,
campaigns, hosting relationships or temporal dependence. Source labels and static
page completeness remain unverified. Future individual sample review used to
change a model must stay in training/validation; test membership is not regenerated
to improve outcomes. Final test evaluation requires a separately locked modeling
protocol and reports these limitations alongside its metrics.

## Execution status

The policy and implementation are recorded before inspecting cross-pilot overlap
or partition results. Final execution evidence is recorded separately in the
holdout freeze output and result checkpoint. Local execution must not be described
as a GitHub Actions run when the GitHub connector is unavailable.

## Original assignment verification addendum

The original two-page Assignment 03 PDF was read after local execution and before
publication. It agrees with the archived requirements and with the adopted rules.
It does not prescribe the numerical engineering thresholds used here.
`assignment03_professor_verification.json` records the document hash and exact
requirement mapping. The immutable policy/source ledger retain their original
bytes; their temporary-access note is historical and superseded by this addendum.

## Cloud verification addendum

Actions 37703227484 at commit `372b48003f4dff90c0a85503e9e8c7c0cea54a9a`
passed 112 tests and independently reproduced the full frozen 5,000-row partition
manifest byte-for-byte. No eligibility, grouping, seed or membership decision was
changed after observing overlap or partitions. Result counts and artifact evidence
are recorded in `assignment03_holdout_results.md` and the freeze checkpoint.
