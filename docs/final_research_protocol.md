# Final research data design: prospective protocol draft

Status: design revision, not a frozen final dataset. Current code implements the
URL-only foundation. Multimodal capture, chronological splits and external testing
below are future work, not implemented capabilities of the current runner.

## Research question and observation unit

On matched website observations, does combining URL, DOM, visual and network data
improve phishing detection over single modalities at acceptable FPR and latency?
Use a timestamped observation ID linking URL/redirect chain, source evidence, label
and all modalities. Preserve immutable original inputs and version derived datasets.
Capture modalities in one instrumented cloud-browser session where practical;
historical URL text cannot reconstruct historical DOM, screenshots or traffic.

## Labels, sources and collection

Record original/project labels and mapping, source record ID, evidence, label time,
observation time, review status and policy version. Separate confirmed under the
declared policy, assumed, uncertain and conflicting labels. Candidate rank or absence
from a blacklist is not proof of benignness. Define review/adjudication criteria and
record disagreements before final data use; no policy guarantees perfect ground truth.
Do not map spam, malware or defacement automatically to phishing.

Collect recent phishing candidates and multiple legitimate candidate sources within
overlapping time windows. Audit source-by-class composition. Seek class overlap across
source categories where feasible; source-holdout evaluation requires both classes in
the held-out population. Existing assumed-legitimate observations and historical
PhiUSIIL remain pilot/context data, not automatically the final benchmark.

Capture browser/build, viewport, locale, wait/timeout rules, duration and per-modality
times. Define network measurements before extraction. Use isolated fresh cloud sessions
without personal accounts/cookies, no form submission and controlled public destinations.
Preserve snapshots subject to permissions and document redaction/redistribution limits.

Log every candidate and failure: DNS/HTTP/robots/timeout, unavailable sites, redirects
and missing modalities. Do not silently replace failures. Report reached-sample versus
candidate-frame composition and modality availability by source/class/time. Complete-case
comparisons answer a conditional question; separately assess intended fallback behavior
when modalities are missing.

## Pilot, audit and freeze

Validate a small end-to-end acquisition pilot before scaling. Set collection duration
and sample targets using feasible source/domain coverage and desired FPR/recall precision,
not attractive preliminary accuracy. The former 2,000/class, 300-domain and 20%-inner-page
values are project heuristics, not professor requirements. Do not relax them to approve
unsuitable data. Predeclare any concentration cap or source stratification before sampling,
retain uncapped profiles and inclusion denominators, and do not force equal HTTPS/path/query
distributions across classes.

Audit URL validity, exact/normalized duplicates, conflicts, PSL groups, campaign/template
concentration, sources/times, HTTPS/root/inner/query proportions and URL/path/query length
distributions. Keep exclusions and lineage. Domain grouping alone cannot remove campaigns
spanning domains; any template clustering must be defined without test-outcome tuning.
Freeze input/output hashes, selected IDs, label policy, PSL snapshot, seed plan, feature
schemas, split manifests and code before formal modeling.

## Evaluation and delivery

The URL-only stage retains domain-disjoint 70/15/15 targets and reports achieved ratios.
The final study should predeclare chronological cutoffs: earlier development, later test.
For unseen-domain temporal testing, later observations with development domains must be
excluded from that test or reported separately as known-domain evaluation; do not move
observations across time to improve balance. Use common eligible samples/splits for paired
single-modality/Hybrid comparisons and also report full-population coverage/fallback results.

Select features, hyperparameters and thresholds on development only. Preserve one locked
test and later external/temporal evaluation if feasible. Predeclare group-aware uncertainty
estimation; overlapping development-seed SD is not an independent confidence interval.
Report class counts, false alarms, precision/recall/F1, ranking metrics, errors and latency.
Separate URL inference time from browser capture plus Hybrid inference. Balanced-sample
precision does not establish deployment precision at a different class prevalence.

Deliver permitted original inputs, provenance, processed data, exclusions, splits,
configurations, dependency/code revisions, models, actual results and English/Traditional
Chinese reports. Review source/aggregates in a draft PR and verify archive downloads.
Passing a basic acquisition gate does not constitute final dataset approval.
