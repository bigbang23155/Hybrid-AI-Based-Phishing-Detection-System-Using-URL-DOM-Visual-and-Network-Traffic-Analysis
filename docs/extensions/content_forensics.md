# Content-forensics extension specification

## Scope

This extension adds static content forensics after the required structural DOM
baseline. It is not part of the current paired-dataset release gate.

### CF-1 YARA HTML/JavaScript signatures

Inputs:
- retained HTML text and embedded/static JavaScript text;
- rule-set version and SHA-256;
- paired sample ID.

Outputs are evidence features, not automatic labels:
- `yara_rule_match_count`;
- versioned rule IDs;
- category flags such as credential-form, redirect, or obfuscation signature.

Rules must be evaluated on development data only before a final test. No rule
may be created from final-test errors.

### CF-2 encoding / obfuscation indicators

Candidate features:
- long hex-string count and ratio;
- Base64-like string count;
- encoded array count;
- `String.fromCharCode`, `atob`, `eval`, `Function` and similar static call counts;
- script/string entropy;
- decoded URL count when a deterministic safe decoder supports the encoding.

Obfuscation alone is not a phishing label. Every feature requires a definition,
unit test, missing-data policy, and provenance.

### CF-3 lightweight decoder analysis

Only deterministic, bounded static transformations are allowed in the automatic
pipeline. Do not execute page JavaScript. Decoded artifacts receive their own
hash and are scanned again with the versioned rule set.

### CF-4 deep reverse engineering / kit fingerprints

This is analyst mode, not a required real-time stage. The goal is to study
repeated decoder structure, template/code fingerprints, or kit families and feed
new hypotheses back into later rule versions. New rules require a new experiment
version; they do not overwrite earlier evidence.

## Promotion gate

This extension can enter a scored model only after the required URL/DOM baseline
is frozen and a preregistered feature/rule set is evaluated on the same
development partitions.
