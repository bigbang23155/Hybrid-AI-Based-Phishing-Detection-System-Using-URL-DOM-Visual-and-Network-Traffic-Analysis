# Observation pilot v1: actual cloud results

The collection-to-archive path worked after a targeted sandbox compatibility repair.
The predeclared completeness gate did **not** pass, so collection was not expanded.
No Dataset v2 was frozen, no final labels were approved, and no models were trained.

## Execution and preservation

- Base: merged main `6e30ba528e6eba8a0ad9126cb4708411fdd0e851`.
- Draft PR: #8. Capture head: `c7af78eb2f2041c341fbe494c629a1efe96fda84`.
- Initial run 36289739946: browser launch failed at namespace-local chroot; zero candidate observations. Failure logs and original artifact are preserved.
- Repaired run 36289927306: Actions succeeded; all 16 observations recorded and archived. Actions success means execution/archive success, not dataset acceptance.
- Repair appended only the required chroot syscall allowance. No container capability was granted; non-root execution, Chromium sandbox, destination checks and internal network were retained. Isolation/connectivity preflight passed.
- Same pinned feed bytes, candidate identities/order, seed and thresholds were verified across both runs. No failed candidate was replaced.
- All 59 offline software tests passed in cloud. Existing model runner, feature registry and independent randomness implementation remain unchanged.

## Actual results

| Candidate source stratum | Planned / recorded | Complete | Partial | Skipped | Complete rate |
|---|---:|---:|---:|---:|---:|
| Curated official controls | 8 / 8 | 6 | 0 | 2 | 75% |
| OpenPhish source-reported candidates | 8 / 8 | 3 | 1 | 4 | 37.5% |
| Total | 16 / 16 | 9 | 1 | 6 | 56.25% |

All 16 records passed schema, URL/domain identity, timestamp and asset-integrity
validation. All 106 checksum-manifest entries matched. Ten observations have all
four artifact types, but one is a 403 provider warning and is correctly partial.
The nine technically complete observations are **not** nine accepted research examples.

Reasons: robots HTTP 403 (2), robots HTTP 307 (1), robots HTTP 302 (1), robots read
timeout (1), robots disallow (1), and captured HTML HTTP 403 (1). A robots 403 may
originate from the destination or gateway; the recorded status alone does not prove
which. Redirected robots responses remain unresolved under the frozen policy.

## Content audit

Automated preliminary inspection of captured DOM and the four phishing-stratum
screenshots found: a branded human-verification screen; a mostly blank Roblox-styled
viewport; a Netflix-styled signup/email page whose title says Netflix Clone; and a
Cloudflare suspected-phishing warning. None was assigned a final project label.
The clone requires adjudication and could be a demonstration; the capture does not
establish credential theft. No forms, CAPTCHA or access restrictions were bypassed.
Official-control DOM titles/text were consistent with the selected organizations,
but this is preliminary evidence rather than final benign adjudication.

This directly shows why HTTP 200, feed membership and complete file sets cannot
substitute for content review. The immutable review queue contains all 16 records.
The separate private review cards and automated notes preserve evidence references.

## Sampling and source limits

Eight official controls were purposefully selected for engineering checks. They are
not a random benign population. Eight phishing candidates were sampled uniformly
over eligible PSL groups, then uniformly over eligible URLs in each selected group.
Seed: 2026092701. The source snapshot had 299 unique eligible URLs in 123 domain
groups; one row was excluded for a sensitive query key. Exact cross-source URL
conflicts were zero. The 16 selected raw and normalized URLs were all unique, with
eight distinct domain groups per stratum. Private PSL suffixes were excluded.

Both strata were 8/8 HTTPS. Inner-page counts were 3/8 official and 6/8 phishing;
query counts were 0/8 and 1/8. URL lengths (minimum/median/maximum) were 20/23.5/51
and 29/50/158 characters. This small, purpose-built batch does not estimate broad
population distributions or provide a representative 2026 benchmark.

OpenPhish commit: `085ed226813bf76ff73df5b0f908a932805ce332`, committed at
2026-09-27T00:00:06Z. It was retrieved at 02:56:28 UTC; per-URL source verification
times are unavailable and remain null. Original feed SHA-256:
`88a444823b729be7a441c837db487c3f3dc6b37c477dd0fc72b3bb36284b2cfa`.
The original 14,095 bytes are preserved privately. Feed labels are not relabeled
spam/malware categories, and no precomputed features were substituted for URLs.

Browser network artifacts contain HTTP events, not PCAP/Zeek or full DNS/TLS flows.
DOM and screenshot are near-synchronous. Two-second settling and request budgets
can leave visual content incomplete. Robots decisions are retained, but full raw
robots response bodies and per-hop evidence are not yet archived. Proxy connection
logs do not provide observation-linked packet features. These are explicit gaps
before claiming a complete network modality for the final research design.

## Gate and next development step

The fixed engineering requirement was at least six complete captures per stratum,
all 16 records present and valid, and a passing isolation preflight. The phishing
stratum had three, so technical_pass=false. The six-per-stratum rule is a configurable
project heuristic, not a professor requirement. It was not lowered after observing
results. label_gate_pass=false and expansion_allowed=false; no expansion occurred.

Final adjudication under the proposed label-policy-v1 requires a named human
reviewer. All 16 remain pending, all project labels are null and training eligibility
is false. A validated append-only adjudication ingestion/derived-label tool is still
needed before this can become a production labeling workflow; the present collector
only emits immutable raw assertions and a review queue.

Next, revise and version the acquisition design using these failure causes: preserve
raw robots/redirect evidence; evaluate a bounded same-origin robots redirect rule;
define a uniform, logged visual-readiness criterion; and establish sources with
capture-time content evidence and a diverse benign sampling frame. Any changed
policy gets a new prospective pilot and its own fixed plan. Do not bypass explicit
denials, selectively lengthen waits by source, replace failures, or reuse successful
controls to manufacture diversity. A later 50-per-stratum batch remains conditional
on the declared gates and completed labeling review.

Collection is now manual-dispatch only, preventing report/review commits from
silently triggering new live observations. The currently pinned feed expires under
the 48-hour age rule; a future source refresh is a new prospective batch.

## Download evidence

Repaired cloud artifact: 4,895,225 bytes; SHA-256
`62bf49d6f5b17d3536753f5f2ae605fc43ee259ebecfa1a7a97a2142deef79ad`.
Initial failed artifact: 552,458 bytes; SHA-256
`5686eb8e400a6a12b8171b5d7e9cfc90c76a338362bd77d08e6d00f2c1c4e65f`.
Both were actually downloaded and ZIP-tested. The full delivery additionally contains
current source, preserved local Git history, English report, Traditional Chinese
brief, aggregate inspection results and private inert review cards. Raw source and
page evidence must remain private. Actions artifacts have seven-day retention.
