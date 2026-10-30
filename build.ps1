# Builds securdp.exe (stripped, no debug paths).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
go run ./tools/mkres   # icon, manifest and version info -> rsrc_windows_amd64.syso
if ($LASTEXITCODE -ne 0) { throw "resource generation failed" }
go test ./...
if ($LASTEXITCODE -ne 0) { throw "tests failed" }
go build -trimpath -ldflags "-s -w" -o securdp.exe .
if ($LASTEXITCODE -ne 0) { throw "build failed" }
Write-Host "Built $PSScriptRoot\securdp.exe"
