# Builds securdp.exe (stripped, no debug paths).
# Build the Android app first (android\gradlew.bat assembleRelease) so the exe
# bundles it: a hub then hands it to phones that log in (see internal/apk).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
go run ./tools/mkres   # icon, manifest and version info -> rsrc_windows_amd64.syso
if ($LASTEXITCODE -ne 0) { throw "resource generation failed" }

$out = "android\app\build\outputs\apk\release"
$bundle = "internal\apk\bundle"
Remove-Item "$bundle\SecuRDP.apk", "$bundle\version.txt" -ErrorAction SilentlyContinue
if (Test-Path "$out\app-release.apk") {
    $m = (Get-Content "$out\output-metadata.json" -Raw | ConvertFrom-Json).elements[0]
    Copy-Item "$out\app-release.apk" "$bundle\SecuRDP.apk"
    [IO.File]::WriteAllText("$PSScriptRoot\$bundle\version.txt", "$($m.versionCode) $($m.versionName)")
    Write-Host "Bundling Android app $($m.versionName) (code $($m.versionCode))"
} else {
    Write-Host "No release APK found - building without the Android app"
}

go test ./...
if ($LASTEXITCODE -ne 0) { throw "tests failed" }
go build -trimpath -ldflags "-s -w" -o securdp.exe .
if ($LASTEXITCODE -ne 0) { throw "build failed" }
Write-Host "Built $PSScriptRoot\securdp.exe"
