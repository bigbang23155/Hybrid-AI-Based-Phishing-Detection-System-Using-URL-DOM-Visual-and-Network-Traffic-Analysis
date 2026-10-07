# Assignment 03: cross-pilot review and internal holdout freeze

## Execution and authority

This checkpoint was executed **locally**, at preregistered code commit
`e7f4ff1` (full SHA in `config/assignment03_holdout_freeze_v1.json`).
The complete suite passed **112 tests**. GitHub push failed because no
authenticated CLI write credential was available. Connected GitHub/Library tools
were initially unavailable, then recovered. A new PR and exact cloud replay are
being prepared; cloud success is recorded only after its verification finishes.

The research decisions were recorded before examining overlap or partitions.
Source cross-checks, alternatives and the applicability limits of each source
are in `assignment03_holdout_research_decisions.md` and its source ledger.
The professor PDF was initially unavailable and subsequently verified before
publication, without changing the policy or partition. See the professor
verification addendum. Original source/candidate/URL baseline locks remain unchanged.

## Verified inputs

All six frozen formal shards were downloaded and size/SHA-verified. The original
pilot shard was downloaded and verified separately. Formal metadata reconstruction
matched the original candidate manifest/replay hashes before joining the locked
5,000-row HTML audit.

The pilot's 256-row replay hash matches the original artifact. The enriched
pilot manifest differs only by the subsequently added target/lang/lang_score
fields: removing exactly those documented additions reproduces the original
complete manifest hash. Every retained pilot HTML file matches its content hash.
The oversized pilot candidate's domain and content hash remain exposure evidence.

## Pilot overlap

| Match type | Formal usable rows matching pilot |
| --- | ---: |
| Sample ID | 0 |
| Normalized URL | 0 |
| Registered domain | 192 |
| Exact HTML SHA-256 | 52 |
| Identical qualifying ordered tag sequence | 207 |
| Union of direct matches | 388 |

The match counts overlap and must not be added together. They count formal
rows, not the number of unique shared domains or distinct HTMLs.

Propagation through the final connected components makes **464 rows in 96
components training-only**, including **76 additional transitive rows**.
No pilot-exposed component enters validation or test. This empirically confirms
why excluding the pilot's shard or source-row IDs alone was insufficient.

## Final groups and partition

Eligibility remains **4,945 pairs**, with the original **55 oversize exclusions**
retained and no backfill. Adding the explicitly documented conservative structure
guard changes 4,079 domain/exact-HTML components into **3,669 final components**.
The largest contains **97 rows (1.96%)**, below the preregistered 10% stop gate.

| Partition | Benign | Phishing | Total | Fraction | Components |
| --- | ---: | ---: | ---: | ---: | ---: |
| Train | 1,718 | 1,743 | 3,461 | 69.99% | 2,525 |
| Validation | 369 | 373 | 742 | 15.01% | 556 |
| Test | 369 | 373 | 742 | 15.01% | 588 |

Only the preregistered seeds were used. The 500 candidate group permutations per
stage optimize class/sample counts only, not model scores or feature distributions.
Every eligible row appears exactly once; every original failure remains excluded.
The test estimates performance on the pilot-unexposed portion of this historical
source cohort. It is not a uniformly random draw from all 4,945 rows and not a
prospective or external benchmark.

Cross-partition overlap is zero for registered domains, exact HTML, qualifying
structural signatures and final components. Pilot exposure in validation/test is
zero under the defined exact-domain/content/structure rules. Near-template,
campaign or temporal independence is not claimed beyond those checks.

## Independent verification

A separate verification used raw source URL columns to reconstruct domain hashes,
an independent minimal HTMLParser to reconstruct pilot tag signatures, and graph
traversal rather than the production union-find. It reproduced every final group,
direct-match count, exposed-component assignment and partition count.

Partition manifest SHA-256:
`49e9dc599fe11e243ac6ba18307900ddc854eeabb3cd700eb9f39fbf05f2deb0`.

The complete sanitized 5,000-row manifest is preserved as
`results/assignment03/holdout_v1/partition_manifest.jsonl.gz` together with the
summary and independent verification. It contains IDs, hashes, eligibility,
exposure and partitions, not raw URLs/HTML or DOM feature vectors.

## State and next step

Local eligible membership and partitions are frozen. Training approval remains
false; no models were trained and no test metrics were evaluated. The new Actions
workflow must reproduce the exact committed partition hash after authenticated
GitHub access is restored; a mismatch stops rather than replacing this freeze.

After cloud agreement is recorded, implement/freeze the DOM registry and the
same-sample URL-only/DOM-only/URL+DOM modeling protocol. Learn any imputation or
preprocessing from training only, develop using validation, and leave test
performance untouched until the final evaluation protocol is fixed.
