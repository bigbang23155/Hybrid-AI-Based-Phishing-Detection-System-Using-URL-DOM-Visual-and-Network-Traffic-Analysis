param(
    [string]$Python = "py"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    & $Python -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Unable to create the Python virtual environment." }
}
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
& $VenvPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }

$TrancoCsv = Join-Path $Root "data\raw\tranco-top-1m-2026-09-26.csv"
if (-not (Test-Path $TrancoCsv)) {
    $TrancoZip = Join-Path $Root "data\raw\tranco-top-1m-2026-09-26.csv.zip"
    if (-not (Test-Path $TrancoZip)) { throw "Missing frozen Tranco ZIP: $TrancoZip" }
    $Temp = Join-Path $env:TEMP "phishing-url-tranco"
    Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -Path $TrancoZip -DestinationPath $Temp
    New-Item (Split-Path $TrancoCsv) -ItemType Directory -Force | Out-Null
    Copy-Item (Join-Path $Temp "top-1m.csv") $TrancoCsv
}

$ActualHash = (Get-FileHash $TrancoCsv -Algorithm SHA256).Hash.ToLowerInvariant()
$ExpectedHash = "831476d0f554af0a5164d6977acc85c95b4cc176b47366be3caa3227f5e63f90"
if ($ActualHash -ne $ExpectedHash) { throw "Frozen Tranco CSV checksum mismatch: $ActualHash" }

$Diagnostic = Join-Path $Root "data\collection\windows_diagnostic"
if (Test-Path $Diagnostic) { throw "Diagnostic output already exists: $Diagnostic. Preserve or rename it before rerunning." }
$env:PYTHONPATH = Join-Path $Root "src"
& $VenvPython -m phishing_url.legitimate_collection `
    --tranco config/windows_connectivity_domains.csv `
    --output $Diagnostic `
    --seed 20250926 --rank-min 1001 --rank-max 100000 `
    --domains 10 --per-domain-cap 3 --timeout 4 --workers 4 --request-delay 0.25
if ($LASTEXITCODE -ne 0) { throw "Connectivity diagnostic failed to execute." }

$Rows = @(Import-Csv (Join-Path $Diagnostic "observed_legitimate_urls.csv"))
$Domains = @($Rows.candidate_domain | Sort-Object -Unique)
Write-Host "Diagnostic complete: $($Rows.Count) observed URLs from $($Domains.Count) candidate domains."
Write-Host "Review data\collection\windows_diagnostic\collection_manifest.json and collection_failures.csv."
Write-Host "Do not run the full collection unless public-site access is adequate. Diagnostic failures must not be replaced."
