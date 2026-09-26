# Result availability

Formal Assignment 02 results are not committed because this checkout contained no research input at
`data/processed/urls.csv` (nor the three expected raw feeds) on 2026-09-26. Synthetic fixtures were used
only by automated tests and were not presented as research results. Run the documented command after
placing the real archived inputs; the runner writes all requested CSV/JSON artifacts and fitted pipelines
to this directory without overwriting raw data.

To unblock the formal evaluation, upload the original Assignment 01 processed file as
`data/processed/urls.csv`. Its required header is
`url_raw,url_clean,label,source,registered_domain`. Do not replace it with a newly downloaded feed.
The filesystem, Git-object, archive, and retained-resource search is documented in
`docs/assignment01_dataset_recovery.md`; no downloadable recovery archive currently exists.

## Legitimate collection pilot

`legitimate_collection_pilot/` contains aggregate evidence from the executed 1,200-domain acquisition
attempt. The suitability decision is **unsuitable**: only 3 observed URLs from 1 domain were retained,
while 2,398 homepage attempts failed because this environment cannot reach nearly all sampled public sites.
Consequently, no Dataset v2 or formal model result was produced. Raw observations, failures, and the frozen
Tranco snapshot are kept out of Git; the reproducibility archive is generated separately.
