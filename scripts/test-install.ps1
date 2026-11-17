# Tests site/static/install.ps1 against a local fake release served over HTTP.
# Run from the repository root on Windows.
$ErrorActionPreference = 'Stop'

$root = (Get-Location).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("nw-test-" + [Guid]::NewGuid().ToString('N'))
$version = '9.9.9'
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$archive = "nw_${version}_windows_${arch}.zip"
$rel = Join-Path $tmp "rel\v$version"
$stage = Join-Path $tmp 'stage'
New-Item -ItemType Directory -Path $rel, $stage | Out-Null

go build -ldflags "-X github.com/hesamzakerirad/nwrk/internal/buildinfo.Version=$version" -o (Join-Path $stage 'nw.exe') ./cmd/nw
if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
Copy-Item LICENSE, README.md $stage
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath (Join-Path $rel $archive)
$hash = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $rel $archive)).Hash.ToLower()
"$hash  $archive" | Set-Content -Encoding ascii (Join-Path $rel 'checksums.txt')

$server = Start-Process python -ArgumentList '-m', 'http.server', '8099', '--bind', '127.0.0.1', '--directory', (Join-Path $tmp 'rel') -PassThru -WindowStyle Hidden
try {
    Start-Sleep -Seconds 2
    $env:NW_DOWNLOAD_BASE = 'http://127.0.0.1:8099'
    $env:NW_VERSION = $version

    Write-Host '== good archive'
    $env:NW_INSTALL_DIR = Join-Path $tmp 'good'
    & (Join-Path $root 'site\static\install.ps1')
    $out = & (Join-Path $tmp 'good\nw.exe') version --output json | Out-String
    if ($out -notmatch '"version": "9.9.9"') { throw "unexpected version output: $out" }

    Write-Host '== tampered archive is rejected'
    Add-Content -Path (Join-Path $rel $archive) -Value 'tampered' -Encoding ascii
    $env:NW_INSTALL_DIR = Join-Path $tmp 'bad'
    & (Join-Path $root 'site\static\install.ps1') 2>$null
    if (Test-Path (Join-Path $tmp 'bad\nw.exe')) { throw 'tampered archive was installed' }

    Write-Host 'install.ps1 tests passed'
} finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}
