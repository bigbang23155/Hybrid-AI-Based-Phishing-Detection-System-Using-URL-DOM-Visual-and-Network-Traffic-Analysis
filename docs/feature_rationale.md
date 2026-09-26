# Assignment 02 feature rationale

## Status and selection rule

The 18 columns below are the **initial baseline**, not an optimal set. They are deterministic,
local lexical/structural measurements: they need no DNS, WHOIS, or page visit, and can therefore
be reproduced safely. `baseline`, `no_https`, `hostname_only`, or any validated ordered comma-separated
subset may be selected. Feature changes must be justified on development data only. The model artifact
stores the ordered names, set name, preprocessing pipeline, threshold, and class definition.

The general rationale follows URL-classification research showing that lexical URL properties can be
used for malicious-URL detection, while not claiming that these papers used our exact definitions:
Ma et al., *Beyond Blacklists* (KDD 2009), DOI [10.1145/1557019.1557153](https://doi.org/10.1145/1557019.1557153),
and Le et al., *URLNet* (2018), [arXiv:1802.03162](https://arxiv.org/abs/1802.03162). The eTLD+1 grouping
uses the [Public Suffix List](https://publicsuffix.org/) through tldextract's bundled snapshot.

| Feature | Exact definition | Why it may help | Limitation / possible bias |
|---|---|---|---|
| `url_length` | Characters in normalized URL | Long obfuscated URLs may hide intent | Benign applications also have long URLs |
| `hostname_length` | Characters in hostname | Long hostnames can encode deceptive terms | Hosting/CDN names can be long |
| `path_length` | Characters in path (`/` is length 1) | Long paths can obscure a landing page | Tranco inputs are constructed root URLs |
| `query_length` | Characters after `?`; absent query is valid 0 | Tracking/payload queries can be long | Collection/source-dependent |
| `dot_count` | `.` in complete URL | Many labels/dotted components may indicate complexity | Dots can occur in paths |
| `subdomain_count` | Host labels before PSL-aware eTLD+1 | Deep hosts can imitate brands | Shared hosting and private suffix policy affect meaning |
| `slash_count` | `/` in complete URL | Proxy-like or deep paths add slashes | Root/full-URL source bias |
| `digit_count` | Unicode-decimal characters in URL | Generated hosts/paths often contain digits | Legitimate IDs do too |
| `digit_ratio` | digit count divided by URL length | Normalizes digit use for length | Correlated with count and length |
| `hyphen_count` | `-` in URL | Hyphenated lookalike names are possible | Common in benign slugs |
| `at_count` | `@` in URL | User-info can visually disguise authority | Rare; likely near-constant |
| `question_count` | `?` in URL | Indicates query delimiter/use | Usually binary and source-dependent |
| `equals_count` | `=` in URL | Proxy for query assignments | Correlated with query length |
| `ampersand_count` | `&` in URL | Proxy for number of query parameters | Encodings can vary |
| `uses_https` | 1 iff normalized scheme is HTTPS | Scheme historically supplied a weak signal | **Strong bias:** Tranco URLs are constructed as HTTPS |
| `is_ip_hostname` | 1 iff hostname parses as IPv4/IPv6 | Direct IP hosting may be suspicious | Legitimate appliances/services use IPs |
| `suspicious_keyword_count` | Case-insensitive substring occurrences of nine documented words | Credential/action language may signal phishing | English-only and context-blind |
| `url_entropy` | Shannon entropy over normalized URL characters | Random/encoded strings may have higher entropy | Length and alphabet affect entropy |

Correlated variables are retained to document the initial baseline, then examined through correlations,
standardized logistic coefficients, tree impurity importance, and permutation importance. Coefficients
refer to class `1 = phishing`; impurity importance may prefer features with more split points, and
permutation importance can understate correlated variables. None is a causal effect.
