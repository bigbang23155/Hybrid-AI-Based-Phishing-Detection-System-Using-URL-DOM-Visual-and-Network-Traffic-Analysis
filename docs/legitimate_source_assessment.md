# Legitimate full-URL source assessment

## Decision

No readily accessible research snapshot in this workspace supplied licensed,
original benign inner-page URLs with the metadata needed for this experiment.
The PhiUSIIL audit described in the task context was specifically rejected as a
solution: its legitimate class is entirely HTTPS root URLs. The referenced audit
ZIP was not mounted, so neither its manifest nor source license could be checked
here. It was not used as Dataset v2.

A bounded live-observation pilot was therefore selected. The official Tranco daily
list downloaded on 2026-09-26 is a candidate sampling frame only. It is not a URL
label source and does not establish that every page on a listed domain is benign.
The pilot retains an assumed-legitimate label only for public URLs observed in a
same-registrable-domain homepage response, homepage link, or sitemap under the
documented policy.

## Collection and labeling evidence

- Candidate ranks: 1,001–100,000.
- Sampling: 1,200 domains without replacement, Python `random.Random`, seed
  20250926; selection is independent of all model results.
- Per-domain cap: three URLs.
- Same-domain request delay: 0.25 seconds.
- Evidence types: final homepage response, same-domain homepage link, and public
  sitemap entry.
- Network controls: HTTP(S) only, global-IP DNS check, bounded redirects,
  same-eTLD+1 redirect enforcement, response-size and timeout limits.
- Interaction controls: no login, forms, submission, cookies supplied by the
  researcher, or phishing-page access.
- Privacy controls: URLs containing credentials or token/session/auth-like query
  keys are excluded.
- Robots policy: an unavailable robots file prevents inner-URL traversal; observed
  candidates disallowed for the collector user agent are excluded.
- Human review: none completed. The seeded review file is only a queue and every
  row is marked `not_reviewed`.

## Executed-pilot conclusion

The environment allowed only three observations from one candidate domain and
logged 2,398 failed homepage attempts. The gate requires at least 2,000 URLs, 300
domain groups, and a 20% inner-page rate. Count and diversity failed, so the data
is **unsuitable**. The pilot must not be combined with phishing records, used for
model evaluation, or characterized as Dataset v2. The failures also produce strong
network-access selection effects; simply keeping the reachable sites would bias
the sample.

The smallest operational next step is to run the frozen-list command in an
environment whose outbound policy permits public-site retrieval. Alternatively,
provide a licensed benign dataset containing original full URLs and explicit
provenance. Either route still requires manual review, deduplication, conflict
removal, domain-concentration audit, and the same suitability gate.
