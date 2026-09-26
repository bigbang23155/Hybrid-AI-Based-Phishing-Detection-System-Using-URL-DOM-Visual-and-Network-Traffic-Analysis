# Export redistribution and credential review

## Existing archive

The original complete export remains unchanged at
`artifacts/assignment02_complete_windows_export_adf0bb7.zip`, with SHA-256
`a1ad53fb4877d0a7f37091cbcd61cc8c1fcc521633c9076a6307f56b4066c21a`.
Archive integrity passed `unzip -t`. Filename and text-content scans found no
credential files, private keys, bearer tokens, API-key assignments, passwords, or
environment files. The Git bundle was excluded from text scanning but independently
verified with `git bundle verify`; its reachable history contains this project only.

## Redistribution decision

The original export embeds the complete Tranco snapshot. The Tranco site makes the
list publicly downloadable and identifies several upstream inputs with different
licenses, including CC BY, CC BY-SA, and CC BY-NC terms, but the inspected page did
not provide a single explicit redistribution license for repackaging the combined
daily list. Consequently, the original archive is preserved locally but is **not**
added to GitHub delivery.

A separately named GitHub-permitted export excludes the complete Tranco snapshot
and raw crawl evidence derived from its candidate rows. It retains project source,
tests, documentation, aggregate non-sensitive audit results, the MPL-2.0-noticed PSL
snapshot, configuration, and Git history. The exact frozen Tranco list remains
recoverable from its stable list ID (`L5PZ4`) and is accepted only after SHA-256
verification; this retrieval is automated by the manually triggered workflow.

## Scope limitations

This review is a conservative engineering decision, not legal advice. The permitted
export does not claim that Dataset v2 exists and contains no formal model metrics.
The GitHub workflow is manual and has not been run. Repository Actions must be
enabled, a maintainer must select **Actions → Collect observed legitimate URLs → Run
workflow**, and GitHub-hosted runners must be able to reach the listed public sites.
Workflow artifacts expire after 14 days under the committed configuration.
