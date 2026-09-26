# Windows PowerShell execution guide

Run all commands from an extracted copy of the complete project export. Windows
access may still be blocked by local DNS, firewall, proxy, antivirus, or remote
site policy; the diagnostic is a gate, not a promise of connectivity.

## 1. Extract and verify

Extract the project ZIP, open PowerShell in its project root, and compare the ZIP
SHA-256 with the checksum reported alongside the download. The included
`EXPORT_MANIFEST.json` inventories every exported file and checksum, while
`SHA256SUMS` verifies its contents. Do not use a different or newly downloaded
ranking list.

## 2. Create the environment and run the diagnostic

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\windows\setup_and_diagnose.ps1
```

The script creates `.venv`, installs `requirements.txt`, verifies and extracts the
frozen Tranco snapshot, and runs only the fixed 10-domain diagnostic subset into:

```text
data\collection\windows_diagnostic\
```

The subset was chosen before connectivity results: it is the first ten ranked rows
after sorting the seed-20250926 1,200-domain sample. Do not substitute successful
domains for failures. Review `collection_manifest.json`, observations, and every
failure. At least five diagnostic domains must produce observations before the
full-run helper will proceed; this operational check is not the research
suitability gate.

## 3. Run the preserved full configuration

Only after reviewing acceptable connectivity:

```powershell
.\scripts\windows\run_full_collection.ps1
```

This uses seed 20250926, ranks 1,001–100,000, 1,200 candidates, cap 3, timeout 4
seconds, 20 workers, and a 0.25-second same-domain request delay. It writes a new
directory, `data\collection\windows_full_2026-09-26\`, and never overwrites the
Linux failed-pilot evidence. It then runs the existing audit into
`results\assignment02\windows_collection_audit_2026-09-26\`. Exit code 2 means
**unsuitable**; do not create Dataset v2 or run models in that case.

## 4. Package actual outputs for return

```powershell
.\scripts\windows\package_outputs.ps1
```

This creates `artifacts\assignment02_windows_collection_outputs.zip` and prints its
SHA-256. Upload that ZIP through the chat/file-upload interface. Inspect URLs before
sharing if local policies require further redaction. Do not upload `.venv`, browser
profiles, credentials, or unrelated files.
