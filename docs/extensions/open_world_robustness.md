# Separate open-world generalization and adversarial-robustness track

Status: researched roadmap, not implemented or empirically validated. Evidence
reviewed 2026-10-08 UTC (2026-10-07 America/Chicago). No live malicious site visits,
exploit execution, new capture, automatic monitoring or online retraining is started.
This track does not change the frozen Assignment 03 cohort or internal holdout.

## What the system must eventually demonstrate

| Goal | Required independent evidence | What does not establish it |
| --- | --- | --- |
| New-time generalization | Timestamped future cohorts; cutoff before acquisition/use; predict before delayed labels become available | Random split of an old corpus |
| New-source generalization | Separate collection source/pipeline, both classes, audited labels, domain/content/campaign overlap checks | Different shards from the same publisher |
| Unseen phishing kit/campaign | Campaign-held-out or defensibly annotated kit-held-out cohorts, strict temporal ordering | A new domain alone, or exact-tag inequality |
| Dynamic-page coverage | Sample-aligned initial HTML, rendered states, frame/redirect/network events under authorized isolated capture | Static HTML tag counts or invented HTTP/redirect fields |
| Adversarial robustness | Valid problem-space transformations, bounded threat model, independent operator/family holdouts, clean-versus-robust comparison | Adding arbitrary noise/FGSM to discrete tabular counts |
| Software zero-day relevance | Vendor/CVE advisory, affected product/version, exploitation/disclosure timeline, observable telemetry and authorized replay evidence | A phishing label, novelty score, KEV addition date or high DOM accuracy |

Unseen phishing is not synonymous with a software zero-day. CVE/KEV intelligence
supports prioritization, not labels saying that every page using a product is
malicious. Presence in KEV means known exploitation evidence, not necessarily
exploitation before disclosure. Current features cannot demonstrate generic
browser/OS zero-day detection or prevention.

## Cross-checked recent evidence and bounded decisions

| Primary source | Verified scope | Decision for this project / limit |
| --- | --- | --- |
| [Barracuda browser-resident phishing](https://blog.barracuda.com/2026/09/09/browser-based-phishing-blob-urls-microsoft-redirects) | September 2026 report describes blob-rendered pages, trusted-service redirects and service-worker/browser behavior. URL contains Sep 9; page displays Updated Sep 4: record both rather than inventing a unique disclosure day. | Later collect browser-state/network evidence. A static URL/HTML snapshot may lack decisive content. Do not infer exploitation of a software zero-day from this report. |
| [Proofpoint TA419](https://www.proofpoint.com/us/blog/threat-insight/hallucinating-credibility-china-aligned-ta419-impersonates-its-way-us-ai-policy) | Published Oct 1, 2026; observed activity includes February/July 2026 and group activity since 2025. Describes AiTM/BitB and session theft. | Separate disclosure from observation date; later identity/session and rendered-state evidence. Static iframe/script counts cannot prove token theft. |
| [NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) | March 2025 taxonomy distinguishes attack life-cycle stages, goals, capabilities and knowledge. | Separate evasion from training-data poisoning; freeze threat model and label controls before adversarial experiments. No claimed universal mitigation. |
| [Robustness, Cost, and Attack-Surface Concentration, v1](https://arxiv.org/html/2603.19204v1) | March 19, 2026 preprint on engineered UCI website features and constrained feature-space edits. | Supports examining low-cost manipulable cues; its numerical results do not transfer to our raw HTML or prove realizable web edits. Require extraction from valid artifacts instead. |
| [TESSERACT](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury) and [PhreshPhish](https://arxiv.org/html/2507.10854v1) | Independent malware evaluation-bias principles and domain-specific phishing data/benchmark design. | Use new temporal/source/campaign cohorts and operational base rates. Neither supplies our project's tuning thresholds. |
| [CISA official KEV mirror](https://github.com/cisagov/kev-data) | CISA-maintained versioned mirror; website catalog retrieval was unavailable during this review. | Future pin snapshot/commit and vendor advisory for each candidate CVE; no unverified 'latest CVE' list added to the model or this report. |

Vendor observations are threat evidence, not controlled head-to-head benchmarks.
PhreshPhish card/paper share a source family. We do not count their agreement as
independent replications. The new reports motivate coverage requirements; they do
not justify changing test membership or guaranteeing detection of those campaigns.

## Staged experiments and promotion gates

1. **Clean internal reference (now defined):** finish Assignment 03 development
   materialization and the fixed three-modality RF/GBDT comparisons. Keep all clean
   artifacts, IDs, versions and per-sample predictions. No robustness claim yet.
2. **External/temporal v2:** preregister capture and source cutoffs before new
   acquisition. Retain actual capture, first-seen, label-observed, disclosure and
   ingestion times separately. Train on past labeled data; validate on subsequent
   development time; reserve strictly later untouched time/source/campaign groups.
   Quarantine components crossing boundaries rather than moving future samples
   backward. Record excluded overlap and uncertainty; unknown kit is not proof of
   unseen kit. Keep v1 untouched as an internal reference.
3. **Coverage and drift:** separate feature-distribution drift, class prevalence
   shift and conditional/error drift. Version fixed feature meanings; new features
   require registry/retraining, not per-row schema changes. Monitor missingness,
   capture failure, reference ratios, score distribution and delayed-label errors.
   Freeze window sizes, minimum counts, multiple-testing controls and alert
   persistence on historical development streams before prospective use. An
   unlabeled drift alert alone is not proof of lower accuracy or maliciousness.
4. **Controlled robustness v2:** use the clean frozen reference as control; train
   a separate augmented variant on training parents only. Preregister operators,
   realistic edit budgets, allowed attacker knowledge/query budget and validation
   criteria. Derive features from mutated artifacts, never independent count edits
   that violate ratios or relationships. Recompute both URL/DOM when either input
   changes. Do not modify live attacker sites or deploy phishing kits.
5. **Shadow deployment, then gated adaptation:** log predictions before outcomes,
   include capture failures/abstentions in coverage, preserve delayed human/source
   adjudication and audit disagreement. Drift-triggered candidate retraining uses
   reviewed labels, replay buffers for old cohorts, rollback and a fresh future
   evaluation window. Never auto-train on the model's own predictions as ground
   truth. Monitor poisoning and label contamination separately from evasion.

### Adversarial training and evaluation contract to preregister in v2

- Start with harmless offline metamorphic fixtures (attribute ordering, HTML tag
  case, comments where semantically inert). Verify feature invariance where
  expected; these are engineering tests, **not adversarial training evidence**.
- Later constrained document/URL transformations must preserve intended content,
  credential-flow semantics and label under an authorized isolated validation
  procedure. Changes to case in case-sensitive paths, query removal, form removal,
  or arbitrary added elements are not presumed semantics-preserving. Invalid or
  unverified transformations are counted and excluded from valid-attack claims.
- Split parents/components before augmentation. A parent and every descendant
  inherit one partition. No test parent, sibling or derivative enters training;
  validation derivatives are never used for fitting. Separate operator/family
  holdouts probe transfer beyond the augmentation recipes used for training.
- Keep clean benign and phishing examples. Record parent ID, transform/version,
  random seed, edits/budget, input/output hashes and validity adjudication. Report
  augmentation ratio and parent-weight normalization so heavily mutated parents
  do not dominate class balance. Compare matched training-compute/sample budgets.
- Evaluate at frozen thresholds on clean and altered paired cohorts. Report robust
  phishing recall over all evaluated phishing parents and ASR over originally
  correctly detected phishing parents with valid attacks. Show both denominators,
  invalid-generation rate, per-family/budget results and worst-case-over-valid-
  variants per parent. Failed generation is not evidence of resistance.
- Include clean FPR/recall cost, extraction/capture coverage, latency and paired
  group-level uncertainty. Higher robust recall alone cannot justify deployment
  if clean false positives or abstentions become unacceptable. Freeze concrete
  acceptance bounds using operational capacity before reading external test.

### Open-environment metrics and zero-day intelligence

Use recall at a preregistered operational FPR plus FPR confidence bounds, precision
at observed prevalence, PR-AUC, Brier/reliability, alerts per 1,000 pages, decision
latency and coverage/abstention. Pure prevalence reweighting may be a clearly labeled
scenario, not actual deployment evidence. A very low FPR needs substantially more
independent benign evidence than the current 369 benign holdout examples; account
for domain/campaign clustering when sizing and estimating uncertainty.

For each new intelligence item retain advisory URL/publisher, publication/revision
and observed dates, CVE if applicable, affected version, zero-day-at-exploitation
evidence/unknown, relevant sensor/modality, confidence, licensing and local capture
authorization. Cross-check vendor advisory with CVE/CISA records where applicable.
Map only observable behavior to future test fixtures. Patch and isolate browser
collectors; classifier output is not a replacement for software vulnerability
management, phishing-resistant authentication or identity-session controls.

No periodic job or new attack collection is enabled by this document. Numerical
windows, attack budgets, deployment thresholds and acceptance bounds are deliberately
pending separate preregistration against the future data and operational objective.
