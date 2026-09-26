$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root
$Paths = @(
    "data\collection\windows_diagnostic",
    "data\collection\windows_full_2026-09-26",
    "results\assignment02\windows_collection_audit_2026-09-26",
    "config\legitimate_collection_windows.json",
    "config\windows_connectivity_domains.csv"
) | Where-Object { Test-Path $_ }
if ($Paths.Count -eq 0) { throw "No Windows collection outputs were found." }
$Destination = Join-Path $Root "artifacts\assignment02_windows_collection_outputs.zip"
if (Test-Path $Destination) { throw "Output archive already exists: $Destination. Preserve or rename it before packaging." }
New-Item (Split-Path $Destination) -ItemType Directory -Force | Out-Null
Compress-Archive -Path $Paths -DestinationPath $Destination -CompressionLevel Optimal
$Hash = (Get-FileHash $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Created: $Destination"
Write-Host "SHA-256: $Hash"
