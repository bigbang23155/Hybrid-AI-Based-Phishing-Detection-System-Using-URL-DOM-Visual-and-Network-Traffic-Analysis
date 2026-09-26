# Draft pull request

## Title

Prepare Assignment 02 cloud collection and tracked project export

## Description

### Why

The Assignment 02 implementation and failed acquisition pilot existed only in a
local workspace export. This update makes a conservatively redistributable project
backup available through GitHub and adds a manually triggered cloud acquisition
path without treating workflow preparation as a successful collection.

### What changed

- Transport the checksum-verified permitted project export as numbered, wrapped
  Base64 UTF-8 chunks because the draft-PR interface rejects binary files. The ZIP
  remains physically preserved but is removed from the current tracked tree.
- Include a JSON manifest and standard-library reconstruction script that verify
  every text chunk and the reconstructed ZIP size and SHA-256.
- Add a manual GitHub Actions workflow that retrieves the exact Tranco list ID,
  verifies its frozen checksum, runs the fixed diagnostic, and proceeds to the
  bounded full collection only if the connectivity gate passes.
- Upload diagnostic evidence, observations, failures, configuration, and any audit
  as a short-retention Actions artifact.
- Record the credential scan and conservative redistribution decision.
- Retain ISCX-URL2016 `All.csv` as unsuitable because it lacks original URLs and
  domain identifiers.

### Actual status

The workflow has not run. Dataset v2 has not been created, the test set has not
been opened, and no new model metrics are reported. The earlier Linux pilot remains
unsuitable and unchanged.

### Validation

- Full unit test suite passes.
- ZIP integrity and internal checksums pass.
- The included Git bundle verifies as complete.
- The preserved ZIP bytes match the tracked SHA-256 file and transfer manifest.
- Reconstructing from the tracked text chunks is byte-for-byte identical to the
  preserved ZIP, and the reconstructed archive passes an integrity test.

### Remaining limitations

GitHub-hosted runner connectivity is unknown. Tranco membership is only a candidate
signal, manual review remains required, and successful collection would not remove
source, label, or temporal confounding.
