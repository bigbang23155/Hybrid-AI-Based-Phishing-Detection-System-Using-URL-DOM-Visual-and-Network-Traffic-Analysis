# Formal selected-HTML materialization: audit definitions

This checkpoint preserves the 5,000 candidates from run 37694449692. Before
reading HTML, verify six source sizes/SHA-256, the unchanged policy/frame hashes,
and byte-identical reconstruction of both frozen candidate manifest and replay.
Any mismatch aborts. Reconstruction is deterministic metadata replay, not a new
sampling decision. No replacements, additional shards, live fetches, training,
final split, or changes to the historical URL baseline are permitted.

## Content representation and statuses

HTML size and content SHA-256 refer to UTF-8 encoding of the publisher's stored
string, not original HTTP response bytes. The publisher `sha256` field remains a
source sample identifier; it is not assumed to use our content hash definition.
The unchanged bound is 2,097,152 bytes, inclusive. Unknown final URL, redirects,
HTTP status and verification time remain null.

Parquet decoding may include neighboring rows in a compressed page. Only the
frozen selected rows are converted to Python HTML strings, inspected and saved.
HTML runs in a network-disabled, read-only container with bounded resources.
No JavaScript, browser rendering, or external resource retrieval occurs.

Each candidate receives one original parse status: missing_html,
non_string_html, empty_html, encoding_error, oversize_html, parse_error,
no_markup, or parsed_markup. A tolerant standard-library HTMLParser accepting
start tags does not prove well-formedness or a complete, relevant page.
Content above the limit is hashed/sized but not parsed or persisted. Bounded
content is retained locally even for no_markup or parse_error for reproducibility.
Missing/failed extraction counts remain null, never a zero feature vector.

All selected rows with the same non-null HTML hash and different source labels
are quarantined. Their parse status is retained; exclusion_reasons separately
records the conflict. Same-label duplicates remain, connected by hard leakage
groups with registered domains, including transitive links. No split is made.

## Precisely defined descriptive variables

These diagnostics are not yet an approved model feature registry.

| Variable | Definition |
| --- | --- |
| tag_count | Start tags emitted by HTMLParser, including self-closing tags once |
| form/input/script/iframe_count | Start tags with the corresponding name |
| password_input_count | input type, stripped/case-insensitive, equal to password |
| link_count | a tags with an href attribute, including empty/non-HTTP references |
| resource_count | src on script/img/iframe/source/audio/video/embed/input and href on link; a static reference proxy, not actual requests; srcset/CSS/object data excluded |
| http_link/resource_count | References resolving to HTTP(S) with a hostname |
| external_link/resource_count | Resolved HTTP(S) registered domain differs from candidate URL's registered domain; subdomains are not external |
| external_link/resource_ratio | External count / valid HTTP(S) reference count; null if denominator zero |
| external_script_count | External HTTP(S) src on script tags |
| external_form_action_count | HTTP(S) form actions to a different registered domain |
| unresolved counts | URL resolution/domain parsing errors, distinct from valid non-HTTP references |
| hidden_attribute_count | Elements with hidden attribute, irrespective of its value |
| hidden_input_count | input type=hidden |
| inline_hidden_style_count | Whitespace-normalized inline style contains display:none or visibility:hidden; lexical indicator, no CSS cascade evaluation |
| meta_refresh_count | meta http-equiv=refresh, regardless of whether its content is valid |
| static_text_chars | Whitespace-normalized text outside script/style/noscript/template/title; may include CSS-hidden text, never called rendered visible text |
| low_static_content_flag | static_text_chars < 100; review trigger only |
| has_html_tag / has_body_tag | Corresponding start tag observed, not browser-inserted elements |

Relative references resolve against the first base href if present; otherwise the
candidate URL. Domain comparison uses the existing offline PSL implementation.
No unknown final URL is inferred. Base/redirect uncertainty is a limitation.

Challenge, access-error and parking markers match the declared phrase list in
`formal_html.MARKERS` against normalized title plus the first 2,000 static text
characters. Script/style source is excluded. These are fallible review markers,
not verified error-page labels and not automatic exclusions. Phrase matching is
English-oriented and can vary with source language.

An exact hash of ordered start-tag names, for parsed pages with at least 20 tags,
identifies coarse structural-template candidates. It ignores text/attributes
and is neither a complete near-duplicate search nor proof of shared campaigns.
It does not change grouping. Any future similarity rule requires its own version.

## Denominators and bias analysis

Profiles are reported separately for selected, parsed (before conflict removal),
and usable cohorts, and separately by label. Each binary rate reports numerator,
nonmissing denominator and missing count. Numeric distributions report n,
missing, zeros, mean, population SD, min, quartiles, p90/p95/p99 and max (NumPy
linear quantiles). Differences are phishing minus benign, descriptive rather
than causal or generalization claims. No independent-URL significance claims.

Date month, source language, source target and shard distributions retain missing
categories. Attrition tables report selected, usable, loss count and loss rate
within label x month/language/shard/root-path strata. Small strata are descriptive.
Date/language/target/shard metadata are not approved predictors. Root-path,
HTTPS, query, password, static-content and marker gaps are potential shortcuts
or cohort characteristics, not inherently phishing indicators.

The original engineering quality gates are unchanged. The mandatory date,
language and HTML-size research review remains pending even if numerical gates
pass. Public evidence includes every sample's ID, source row, statuses, hashes,
numeric audit and exclusion reasons, plus aggregates and source provenance.
Raw URLs, HTML and source targets per sample are not republished. Cloud ephemeral
HTML can be reconstructed from the pinned source and replay; public evidence is
not a self-contained raw paired dataset download.

`training_approved`, `final_partition_created`, `model_training_performed`,
`test_evaluated` and `final_dom_dataset_frozen` stay false. The whole-cohort audit
is exploratory dataset review before final holdout creation; features and
evaluation choices must subsequently be locked without test-specific inspection.
