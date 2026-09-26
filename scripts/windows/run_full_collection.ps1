$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) { throw "Run setup_and_diagnose.ps1 first." }
$DiagnosticCsv = Join-Path $Root "data\collection\windows_diagnostic\observed_legitimate_urls.csv"
if (-not (Test-Path $DiagnosticCsv)) { throw "Run the connectivity diagnostic first." }
$DiagnosticRows = @(Import-Csv $DiagnosticCsv)
$DiagnosticDomains = @($DiagnosticRows.candidate_domain | Sort-Object -Unique)
if ($DiagnosticDomains.Count -lt 5) {
    throw "Connectivity gate failed: only $($DiagnosticDomains.Count) of 10 diagnostic domains produced observations. Do not run the full collection."
}

$Output = Join-Path $Root "data\collection\windows_full_2026-09-26"
if (Test-Path $Output) { throw "Full output already exists: $Output. Preserve it; do not overwrite." }
$env:PYTHONPATH = Join-Path $Root "src"
& $VenvPython -m phishing_url.legitimate_collection `
    --tranco data/raw/tranco-top-1m-2026-09-26.csv `
    --output $Output `
    --seed 20250926 --rank-min 1001 --rank-max 100000 `
    --domains 1200 --per-domain-cap 3 --timeout 4 --workers 20 --request-delay 0.25
if ($LASTEXITCODE -ne 0) { throw "Full collection failed to execute." }

$Audit = Join-Path $Root "results\assignment02\windows_collection_audit_2026-09-26"
if (Test-Path $Audit) { throw "Audit output already exists: $Audit. Preserve it; do not overwrite." }
& $VenvPython -m phishing_url.collection_audit `
    --observations (Join-Path $Output "observed_legitimate_urls.csv") `
    --failures (Join-Path $Output "collection_failures.csv") `
    --output $Audit
$AuditExit = $LASTEXITCODE
if ($AuditExit -ne 0 -and $AuditExit -ne 2) { throw "Collection audit failed with exit code $AuditExit." }
if ($AuditExit -eq 2) { Write-Warning "Suitability gate returned UNSUITABLE. Do not build Dataset v2 or train models." }

Write-Host "Collection and audit finished. Inspect suitability_gate.json before any dataset integration."
