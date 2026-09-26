# Dataset bias and limitations

The preparation code was verified to use seeded random sampling (`--seed`, default 42); it does **not**
take the first 2,000 rows. However, randomness does not repair source bias. The ingestion code constructs
every Tranco entry as `https://domain/`, whereas phishing feeds retain full submitted URLs. Consequently,
`uses_https`, path/query lengths, slash and delimiter counts may identify collection procedure rather
than phishing. The required no-HTTPS experiment tests only one symptom; it does not remove this bias.

If all label-0 records are Tranco and label-1 records are PhishTank/OpenPhish, source and label are
confounded. Results are an in-dataset baseline, not evidence of deployment generalization. Future data
should contain benign full URLs and phishing/benign observations from overlapping collection settings.
Tranco is a research-oriented aggregated top-sites ranking; see its methodology paper, Pochat et al.,
*Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation* (NDSS 2019),
[DOI 10.14722/ndss.2019.23386](https://doi.org/10.14722/ndss.2019.23386).

Assignment 01 used a short handcrafted suffix list. Assignment 02 replaces it with `tldextract` and its
packaged PSL snapshot, disables network updates (`suffix_list_urls=()`), and excludes private suffixes.
This is reproducible but means hosts beneath services on the PSL private section are grouped by the ICANN
registrable domain. The manifest records parser/version/policy. Dataset audit outputs counts, duplicates,
conflicts, missing domains, domain group sizes, HTTPS/root-URL rates, missing/infinite/constant features,
distributions, and correlations.

No raw or processed research dataset was present in this checkout on 2026-09-26. Therefore no formal
metrics are reported or fabricated here; `results/assignment02/README.md` records the missing inputs.
The required upload is the original Assignment 01 `urls.csv`, placed without modification at
`data/processed/urls.csv`. It must contain `url_raw,url_clean,label,source,registered_domain`. A previously
generated `url_features.csv` may instead be supplied for inspection, but it is not automatically treated
as equivalent when source metadata is absent. Fresh feeds are not a substitute for the archived dataset.

## PhiUSIIL audit and observed-URL pilot

The supplied task context reports that the completed PhiUSIIL audit found 134,850 legitimate URLs that
were all HTTPS roots, while its phishing URLs included more non-root and query-bearing records. Those
findings confirm that PhiUSIIL does not solve the root-versus-full-URL construction bias. The referenced
`PhiUSIIL_Audit_Package.zip` existed only as a Windows IDE path and was not mounted in this execution
environment, so its manifest and source snapshot could not be independently reverified or reused. It is
not treated as Dataset v2 or as recovered Assignment 01 data.

A frozen Tranco daily list was downloaded solely as a candidate sampling frame (CSV SHA-256
`831476d0f554af0a5164d6977acc85c95b4cc176b47366be3caa3227f5e63f90`). A seed-20250926 sample of
1,200 domains from ranks 1,001–100,000 was attempted with a cap of three URLs per domain. The environment's
outbound proxy denied nearly all arbitrary-domain requests: only three observed URLs from one domain were
retained and 2,398 homepage attempts failed. The suitability gate therefore failed (minimum 2,000 URLs and
300 domain groups). This is an observed acquisition failure, not evidence about the websites themselves.

No Dataset v2 was built and no model test set was opened. The three retained records are assumed legitimate
only because they were public same-domain observations from a sampled candidate; they were not manually
verified. A seeded review queue exists but is explicitly marked `not_reviewed`. Collection from an
environment permitted to reach public sites, or provision of an appropriately licensed full-URL corpus,
is required. Even a successful crawl would retain candidate-label, temporal, and source confounding.

## ISCX-URL2016 assessment

The user-reported inspection of `All.csv` found 36,707 rows, 79 precomputed feature columns, and one class
column, but no original URL or domain identifier. The file was not mounted in this workspace, so these are
contextual rather than independently verified findings. Without original URLs the project cannot rerun its
normalization/features or construct eTLD+1-disjoint splits. The table must not be used to fabricate URLs,
substitute third-party feature definitions for the baseline, build Dataset v2, or run the experiment.
