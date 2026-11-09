# A04 offline foundation v1

The integration CLI has no model fitting, label adoption, live collection or test
evaluation command. The separate sensitivity CLI refits only historical A03
training data and evaluates the unchanged validation cohort. Use this alongside the [progress and evidence](../../docs/assignment04/README.md).

## Environment and validation

Use Python 3.12 and a separate environment (the earlier research folders have
historical dependency pins). From repository root:

```bash
python -m venv .venv-a04
source .venv-a04/bin/activate
python -m pip install -r research/assignment04_v1/requirements.txt
PYTHONPATH=src:. python -m unittest research.assignment04_v1.test_foundation -v
PYTHONPATH=src:. python -m research.assignment04_v1.audit_a03 --output /tmp/a03-audit-new.json
PYTHONPATH=src:. python -m research.assignment04_v1.repository_inventory --output /tmp/a04-inventory-new.json
```

Output files must not already exist. Audit outputs are aggregate, with input hashes.
The audit reads archived consumed-test **aggregates** only for mandatory disclosure;
controlled comparisons use the validation ledger only. It never calls fitting or
prediction. The inventory reads historical partition metadata, not new test evidence.

## Actual verified checkpoint extraction

Use an existing decrypted development Collector checkpoint on local private storage.
No download is performed. Supply an explicit reference time and predeclared age
policy (the values below are an example, not a selected research cutoff).

```bash
PYTHONPATH=src:. python -m research.assignment04_v1.integration extract \
  --checkpoint /private/run/record.json --as-of 2026-11-06T00:00:00Z \
  --max-age-seconds 86400 --output /private/a04-record.json
PYTHONPATH=src:. python -m research.assignment04_v1.integration fusion \
  --input /private/a04-record.json --output /private/a04-fusion.json
PYTHONPATH=src:. python -m research.assignment04_v1.integration demo \
  --input /private/a04-record.json --output /private/a04-demo.html
```

`extract` writes one JSON object; `inventory` takes JSONL (one compact JSON object
per line). Convert a record to JSONL with Python's json.load/json.dumps, or assemble
multiple extraction outputs without changing fields, then run:

```bash
PYTHONPATH=src:. python -m research.assignment04_v1.integration inventory \
  --input /private/a04-records.jsonl --output /private/a04-coverage.json
```

Optional `source_label: 0|1` is an **unadopted source assertion**, used only for
coverage buckets. `label` must stay null and `eligible_for_training` false. Unknown
source labels get their own denominator. Duplicate IDs and mixed schemas fail.
Do not upload raw private features/checkpoints. Open the HTML locally; it has no
external assets, scripts, requests or raw URL content.

The committed `results/assignment04/foundation_v1/synthetic_demo.html` is a runnable
evidence preview using a synthetic software fixture. It does not predict phishing
or demonstrate accuracy. It must not be shown as a trained model demonstration.

## Visual registry and limitations

`visual-rgb16-grid4-gradient8-v1`, exactly 104 fields, fixed order:

| Fields | Count | Definition |
|---|---:|---|
| r/g/b_hist_00..15 | 48 | Per-channel 16-bin histogram over [0,1], normalized by pixel count |
| grid_y_x_c_mean | 48 | 4x4 spatial cells, row-major order, RGB mean per cell |
| gradient_orientation_0..7 | 8 | Unsigned angle [0,pi), gradient-magnitude weighted, normalized sum; zero for flat image |

Only PNG, JPEG and single-frame WEBP are accepted; max 20 MB and 16 million pixels.
EXIF orientation is applied, alpha is composited over white, then RGB is resized to
128x128 with bilinear interpolation. Grayscale = .299R + .587G + .114B; NumPy
central differences (`gradient`) produce dx/dy. Width/height and flat-image flags
are audit metadata, not extra predictors. Corrupt/over-limit/missing images are
unavailable rather than all-zero vectors. Runtime library versions matter for
resampling, so use the pinned environment.

This deliberately simple representation is not an embedding, OCR, logo/brand
recognizer or semantic phishing detector. Aspect distortion, screenshot crop,
viewport, fonts, cookie banners, error pages and collection source can dominate
features. Future model claims require real paired eligible samples and validation.
A valid flat screenshot has observed zero gradients; that differs from missing data.

## Boundaries

The new adapter retains existing checkpoint/hash/identity/freshness checks; its
outputs remain research-only. Serialized masks are recomputed and compared before
inventory/fusion. Acquired modalities must share checkpoint, scan and capture time.
A04 source data and the new holdout are not yet approved/materialized. Commands
reject declared test/unknown partitions before artifact extraction and allow only
existing development/smoke scopes. This is a guard against accidental use, **not
security access control**: mislabeled files cannot be detected by metadata alone.
Store any future test artifacts separately with restricted permissions and never
supply them to these tools. This module does not create or certify a grouped split.

Future fitting must independently verify review decisions, domain/content disjointness,
historical exposure and consistent registry/provenance. Train-only preprocessing,
paired validation comparisons, missing-modality fallbacks and calibration remain
future model work. An all-missing view gives nulls and no prediction.

## Completed development reconstruction and sensitivity

See [results and interpretation](../../docs/assignment04/development_sensitivity.md).
Use Python 3.12 with `requirements-dom.txt` for this separate analysis; it does not
need the Visual environment. The immutable source download is about 2.9 GB:

```bash
PYTHONPATH=src:. python -m phishing_url.formal_candidates --download \
  --source-root /private/a04-source --frame config/assignment03_paired_source_frame_v1.json \
  --policy config/assignment03_paired_release_policy_v1.json
PYTHONPATH=src:. python -m research.assignment04_v1.sensitivity \
  --source-root /private/a04-source --output /private/a04-sensitivity
PYTHONPATH=src:. python -m research.assignment04_v1.verify_sensitivity \
  --directory /private/a04-sensitivity/public --output /private/verified.json
```

The workflow runs parsing/fitting in a network-disabled Docker container. Source
HTML is passive input, never browser-executed. Only selected development scalars
are featurized. Baseline prediction replay must match the archive within 1e-12
before continuing. All twelve conditions retain fixed parameters/seed/validation;
no tuning or independent-test evaluation occurs. These are post-exposure analyses.
Raw URLs, HTML, full feature vectors and fitted models are not published.

After successful results are retained, CI independently verifies those predictions
and intervals instead of repeating model fits. Changes to the implementation or
hashed inputs require reconstruction. The cloud and local executions in the receipt
are reproductions, not separate statistical experiments.
