# Visual, network, wireless, and identity extension specification

## Visual track

Use only screenshots paired to the same sample IDs as URL/DOM evidence. Preserve
capture configuration and image hashes. Candidate work includes visual embeddings,
logo/brand similarity, layout similarity, and screenshot-quality checks. Visual
features are evaluated only after the required URL/DOM baseline works.

## Web-network track

Use captured evidence only:
- redirect count/chain;
- request destinations and external-domain ratios;
- TLS/certificate metadata when actually captured;
- response status and selected passive timing/count features.

Unknown network values remain missing. They are never inferred from HTML alone.

## Evil Twin track

Evil Twin detection is a separate network-sensor problem. A normal cloud webpage
collector cannot observe RF/AP state. Required future inputs include authorized
SSID/BSSID/channel/security/RSSI and trusted-network reference data. Possible
outputs include known-SSID/new-BSSID, security downgrade, unexpected gateway/DNS,
and multi-AP anomalies. This track is not an Assignment 03 dependency.

## AiTM / identity track

AiTM, phishing-resistant MFA, and session protection require authorized browser,
identity-provider, device, or session telemetry. Future evidence can include login
origin/domain mismatch, session/device anomalies, token replay controls, and
phishing-resistant authentication support. The web classifier may contribute a
risk signal but must not claim to observe token theft directly.

## Integration order

1. Required URL+DOM hybrid.
2. Visual and web-network modalities.
3. Optional content-forensics enrichment.
4. Separate wireless and identity/security integrations.
5. Final risk fusion with modality-specific provenance and missingness handling.
