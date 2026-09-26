# Fixed cloud supplement after the first acquisition run

Run 36224465694 on commit c460c403627004d10b56906d77b9fe5e859e5289
collected 1,735 assumed-legitimate URLs across 686 domain groups.
The existing basic suitability gate rejected only the count below 2,000.
No model outcomes have been inspected.

The next batch is fixed in advance at 600 new registrable-domain groups,
with seed 2026092602, from frozen Tranco L5PZ4 ranks 1001–100000.
The entire original 1,200-candidate sample is reconstructed, including failures.
All its registrable-domain groups are excluded. Remaining candidates are grouped
by the existing offline PSL policy, retaining the best-ranked candidate per group,
then sampled uniformly without replacement. This is a documented sampling change
to control group overlap, not a model-performance-based selection.

The existing collector is reused with cap 3, timeout 4 seconds, 20 workers,
and request delay 0.25 seconds. The whole batch is attempted without early stopping,
replacement of failures, or retries selected by outcome. This extension responds
to an observed count shortfall; it is not claimed to be the original fixed sample.
Source, temporal, success-selection and assumed-label limitations remain.

After review and merge, manually run **Supplement observed legitimate URLs**
on main. The workflow downloads artifact 10899969152 from the first run and
verifies both the ZIP and source CSV checksums before collecting. If the artifact
has expired (currently scheduled for October 10, 2026), it fails closed: restore
the saved exact artifact through an authorized cloud transfer and update the
retrieval step; never silently repeat the original collection.

The artifact contains unchanged prior evidence, both new raw tables, frozen
candidate lists, a pre-collection plan, combined tables, provenance, checksums,
installed dependency versions and audit results. Full Tranco CSV redistribution
is excluded as before. Requested retention is 90 days, subject to repository policy;
download and preserve the artifact after the run.

The basic gate retains 2,000 URLs, 300 groups and 20% inner pages. These are project
heuristics, not professor requirements or universal standards. A green job can
still report unsuitable. Passing does not approve Dataset v2: label review,
phishing-source integration, conflict/deduplication checks, class/source/period
analysis, feature distributions and concentration checks must precede the locked
model protocol. This workflow does not train models or fabricate metrics.

The original workflow and all previous evidence remain unchanged. The new workflow
pins Ubuntu 24.04 and uses Node 24 versions of checkout/setup-python; the retained
upload-artifact v4 may continue to display the known Node deprecation warning.
