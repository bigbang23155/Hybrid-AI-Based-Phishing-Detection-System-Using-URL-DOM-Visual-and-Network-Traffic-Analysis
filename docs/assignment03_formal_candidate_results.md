# Assignment 03 formal metadata candidate selection — executed checkpoint

## Outcome

The frozen six-shard frame supplied all 5,000 preregistered candidates (2,500 per source label), with no shortfall or source substitution. This freezes candidate membership only. HTML quality, usable-pair counts, exact-content conflicts, near-template diagnostics, final partitions and research approval remain pending.

## Execution evidence

- GitHub Actions run: 37694449692; job: 113042528368; conclusion: success.
- Execution commit: 47b4427b666738a551a8e34603d77336d675f2af.
- Full cloud software suite: 97 passed in 37.90 seconds.
- Source revision: eabec4b7a66324b79cc8a0ad856d1731dc26fe1a.
- Six source files: 2,903,636,775 bytes; every file matched its frozen size and SHA-256.
- Complete source inventory was regenerated and matched the preregistered inventory hash before acquisition.
- Artifact: assignment03-formal-candidates-37694449692; ID 11514374137.
- ZIP SHA-256: 2a403aee9a0e4ba8b9e3f9d7d9fb6d1f04d5373287f2c7f87921e24de41541b9.
- Candidate replay SHA-256: 4f4ab4fd6567e84f0de91e061d61cf905574643e771ebf59504861843188a955.
- Private candidate manifest SHA-256: 82d1b01fc4c1548087279fc604c57bbdf99af4de1cc5b39b95d5b96b6c536444.
- Source frame SHA-256: 2dc4eabe9498db672e26a44850a77c1198eec08f7724f13585497f44dde295b9.
- Release policy SHA-256: 432b1797189404d81aa105643ea561674faed511368cdf81dc95bb8993e59424.

The downloaded artifact was independently checked for ZIP/replay hashes, 5,000 unique IDs, class counts, six-shard membership, pilot-shard exclusion and sample ID derivation from source SHA + row number. The public artifact retains replay IDs and aggregate evidence, not raw URLs or HTML. A persistent copy of the ZIP was saved for the project in addition to the 90-day Actions artifact.

## Selection procedure

The selector reads only publisher metadata columns, after checking file hashes and the paired schema. Downloaded Parquet files contain HTML, but the HTML column is not decoded or inspected. The selection container has no network access.

The existing pilot sample-ID convention is retained: SHA-256 of source-file SHA plus source row. Normalized URL deduplication and cross-label conflict exclusion are global across all six files. Duplicate representatives use the lowest sample ID. Within each label, candidates are ranked by SHA-256 of seed 4941301 plus sample ID, then capped at three URLs per registered domain per label and truncated to 2,500. Sorting input rows differently does not change membership. No failed candidate will be replaced after content inspection.

## Observed counts

| Measure | Benign (0) | Phishing (1) |
| --- | ---: | ---: |
| Eligible unique URLs before domain cap | 28,701 | 23,262 |
| Eligible registered domains | 15,900 | 6,930 |
| Capacity after domain cap, before target truncation | 19,561 | 8,504 |
| Selected candidates | 2,500 | 2,500 |
| Selected registered domains | 2,201 | 2,088 |
| Shortfall | 0 | 0 |
| Maximum candidates per domain | 3 | 3 |
| Largest domain share | 0.12% | 0.12% |
| Missing publisher capture date | 0 | 0 |

Across the frame: 52,399 source rows; 430 invalid/schemeless URLs excluded; six duplicate normalized-URL rows excluded; zero observed cross-label normalized-URL conflicts. Remaining eligible unique URLs: 51,963. Counts above describe candidates, not HTML-verified usable pairs.

## Metadata bias review required

| Measure | Benign | Phishing |
| --- | ---: | ---: |
| Root-path URL rate | 7.56% | 49.72% |
| HTTPS rate | 99.44% | 76.40% |
| Publisher language: English | 87.96% | 60.20% |
| Publisher language: missing | 0.52% | 6.20% |
| Publisher date: Nov 2024–Apr 2025 | 0% | 32.48% |

The root-path gap is 42.16 percentage points, exceeding the existing 20-point review trigger. The HTTPS gap is 23.04 points. Dates and language distributions also differ by class. These are descriptive findings, not proof of causal source bias or reliable real-world phishing signals. Publisher language metadata is used for this audit; this project has not read HTML to infer language.

Keep the preregistered no-HTTPS sensitivity comparison. Review root-path, date, and language strata before modeling; do not choose replacement samples, new seeds, or extra shards to make these distributions look better. Any changed sampling rule requires a separately versioned protocol. Root-path sensitivity is a possible future documented development diagnostic, not a newly executed experiment.

## State and next checkpoint

- Historical URL development baseline: unchanged and frozen.
- Candidate membership: frozen.
- HTML inspected: false.
- Official source test split used: false.
- Pilot shard train-000: excluded.
- Final paired dataset frozen: false.
- Final partition created: false.
- Training approved: false.
- Model training performed: false.
- Test evaluated: false.

Next: recover exactly these replay IDs from the same pinned files, verify replay/manifest hashes before reading content, materialize only selected HTML, and retain every failed candidate without backfill. Then run size/parser/integrity checks, cross-label exact-HTML conflict quarantine, content and bias audits, and near-template diagnostics. Only after the appropriate research decisions should the final dataset and new grouped holdout be frozen. Do not report candidate success as a full technical-quality or training-approval pass.
