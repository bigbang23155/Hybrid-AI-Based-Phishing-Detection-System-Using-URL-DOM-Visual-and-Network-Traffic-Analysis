# Optional extension specifications

These modules are intentionally separated from the Assignment 03 critical path.
They do not reopen the frozen URL baseline and they do not block the required
paired URL/DOM work.

## Core before extensions

1. Freeze/version the paired URL+HTML dataset and reserve a new holdout.
2. Implement the structural DOM feature registry.
3. Run same-sample URL-only / DOM-only / URL+DOM development comparisons.
4. Complete error/bias analysis and the Assignment 03 report.

Only after that core works should extensions be promoted into experiments.

| Extension | Status | Earliest entry point | Required evidence |
|---|---|---|---|
| YARA HTML/JS signatures | planned | after structural URL+DOM baseline | versioned rules + static HTML/JS |
| Obfuscation / hex / decoder indicators | planned | after YARA/static content layer | encoded-string and script evidence |
| Reverse engineering / kit fingerprinting | planned analyst mode | after suspicious-content triage | retained sample/code provenance |
| Visual similarity | planned | after paired screenshots exist | sample-aligned screenshots |
| Web network / redirect analysis | planned | after captured network evidence exists | redirects/TLS/request metadata |
| Evil Twin detection | separate sensor track | after web hybrid core | Wi-Fi/AP observations |
| AiTM / MFA / session protection | separate identity track | after web hybrid core | authorized identity/session telemetry |

The design rule is: **no module is credited with evidence it cannot observe**.
For example, an HTML signature does not prove an Evil Twin exists, and a URL
score does not prove a session token was stolen.

The staged [open-world and adversarial-robustness roadmap](open_world_robustness.md)
adds temporal/source/campaign evaluation, dynamic capture, reviewed-label drift
adaptation and constrained adversarial training. These are separate future
experiments, not demonstrated capabilities of the current static registry.
