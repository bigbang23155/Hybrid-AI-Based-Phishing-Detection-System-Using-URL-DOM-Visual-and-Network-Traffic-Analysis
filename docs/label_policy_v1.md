# Label policy v1: evidence before training labels

Effective for observation-pilot-v1. This policy does not relabel existing candidates
or approve a final Dataset v2. Source labels, observations and adjudicated research
labels are separate fields. A retrieval success, rank, valid TLS certificate or
absence from a blacklist is not proof of benignness.

| State | Meaning | Training label |
|---|---|---|
| assumed_benign | Curated official-site control or rank-based candidate, without completed observation review | null |
| source_reported_phishing | Original URL explicitly appears in the preserved phishing-only feed | null |
| uncertain | Evidence insufficient, content unavailable, changed, challenge/parking page or mismatched redirect | null |
| conflicting | Sources/reviewers disagree on the same normalized URL within the defined observation context | null |
| adjudicated_benign | Reviewed organization/URL ownership and captured ordinary content agree, with evidence and adjudicator recorded | 0 |
| adjudicated_phishing | Feed evidence plus captured deceptive impersonation/credential solicitation agree, with evidence and adjudicator recorded | 1 |

For this pilot the eight official controls are purposefully curated engineering
controls, not a representative random benign sample. OpenPhish supplies an explicit
phishing source label; the public feed does not provide a per-URL verification time.
Record that time as null, and separately record feed commit time, retrieval time and
capture time. Never substitute retrieval time for original verification time.
Do not map spam, malware or defacement into phishing. Never fabricate URLs or fill
class shortfalls with replacements selected by collection success.

Review the immutable captured evidence, not a later live page. Every decision must
include reviewer ID/type (human or automated), review timestamp, evidence artifact
paths/hashes, reason, original source assertion and policy version. An automated
review is explicitly preliminary and must never be called human verification.
Final adjudication under v1 requires a named human reviewer; disagreements go to
a second review and remain excluded until resolved. This is a project policy choice,
not a professor requirement. Human review also does not guarantee perfect labels.

Benign checklist: canonical official URL/domain evidence; expected organization and
content in the captured page; no deceptive off-domain credential destination seen;
redirects explained; no challenge, error, parked or placeholder page mistaken for
ordinary content. Phishing checklist: exact feed membership; captured target-brand
impersonation or deceptive collection of credentials/payment; evidence-backed reason.
Do not submit forms, authenticate, download executables, or claim a page malicious
solely because its URL contains words such as login. A dead source-reported URL can
remain historical URL evidence, but cannot be a contemporaneous four-modality example.

Each observation retains the original status; reviews are append-only separate
records. A derived label table is versioned and hashed. No source assertion or URL
feature automatically overwrites an adjudicated label. The current collector emits
null project labels and training_eligible=false for every new candidate.

OpenPhish community data is used for this user's academic research. Preserve the
original snapshot privately; do not redistribute the feed, URLs or content artifacts
in public source/PR text. The repository was verified private before the pilot;
the workflow also checks visibility before capture. Source code and aggregate
findings can be reviewed separately from restricted original evidence.

Sources checked September 27, 2026 UTC: https://openphish.com/phishing_feeds.html
and https://openphish.com/terms.html . The feed documentation lists a 12-hour community
update interval; this pilot's 48-hour commit-age gate is a configurable project
freshness heuristic, not an assurance that each URL is currently phishing.
