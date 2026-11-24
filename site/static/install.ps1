# nw installer for Windows: https://nwrk.ir
#
#   irm https://nwrk.ir/install.ps1 | iex
#
# Downloads the nw release archive from GitHub Releases, verifies its SHA-256
# checksum against checksums.txt, and installs nw.exe for the current user.
# No administrator rights needed.
#
# Environment:
#   NW_VERSION        version to install, for example 0.1.0 (default: latest)
#   NW_INSTALL_DIR    install directory (default: %LOCALAPPDATA%\nwrk\bin)
#   NW_DOWNLOAD_BASE  release download base URL (default: GitHub Releases)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo = 'radestsam/nwrk'
$Releases = "https://github.com/$Repo/releases"
$Base = if ($env:NW_DOWNLOAD_BASE) { $env:NW_DOWNLOAD_BASE } else { "$Releases/download" }

function Get-File([string]$Url, [string]$Dest) {
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
            return
        } catch {
            if ($attempt -ge 3) { throw }
            Start-Sleep -Seconds 2
        }
    }
}

function Install-Nw {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw "unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
    }

    $version = if ($env:NW_VERSION) { $env:NW_VERSION.TrimStart('v') } else { '' }
    if (-not $version) {
        try {
            $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
            $version = $latest.tag_name.TrimStart('v')
        } catch {
            throw "could not find the latest release; see $Releases or set NW_VERSION"
        }
    }

    $archive = "nw_${version}_windows_${arch}.zip"
    $dir = if ($env:NW_INSTALL_DIR) { $env:NW_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'nwrk\bin' }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("nw-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null

    try {
        Write-Host "Installing nw $version (windows/$arch)"
        try {
            Get-File "$Base/v$version/$archive" (Join-Path $tmp $archive)
            Get-File "$Base/v$version/checksums.txt" (Join-Path $tmp 'checksums.txt')
        } catch {
            throw "download failed; download $archive and checksums.txt manually from $Releases/tag/v$version"
        }

        $line = Get-Content (Join-Path $tmp 'checksums.txt') |
            Where-Object { ($_ -split '\s+')[1] -eq $archive } |
            Select-Object -First 1
        if (-not $line) { throw "$archive is not listed in checksums.txt" }
        $want = ($line -split '\s+')[0].ToLower()
        $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $archive)).Hash.ToLower()
        if ($got -ne $want) {
            throw "checksum mismatch for $archive (expected $want, got $got); nothing was installed"
        }
        Write-Host 'Checksum verified'

        Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath (Join-Path $tmp 'x') -Force
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $target = Join-Path $dir 'nw.exe'
        Copy-Item -Path (Join-Path $tmp 'x\nw.exe') -Destination "$target.new" -Force
        Move-Item -Path "$target.new" -Destination $target -Force

        Write-Host "Installed $target"
        & $target version | Select-Object -First 1

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $entries = if ($userPath) { $userPath -split ';' } else { @() }
        if ($entries -notcontains $dir) {
            [Environment]::SetEnvironmentVariable('Path', (($entries + $dir) -join ';').TrimStart(';'), 'User')
            Write-Host "Added $dir to your user PATH. Open a new terminal to use nw."
        }
    } finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }
}

try {
    Install-Nw
} catch {
    [Console]::Error.WriteLine("install: $($_.Exception.Message)")
    # `irm | iex` runs in the caller's session, so return instead of exiting it.
    return
}
