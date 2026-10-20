param(
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-NormalizedFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
}

function Assert-ContainedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $normalizedPath = Get-NormalizedFullPath -Path $Path
    $normalizedParent = Get-NormalizedFullPath -Path $Parent
    $prefix = "$normalizedParent$([IO.Path]::DirectorySeparatorChar)"
    if (-not $normalizedPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description '$normalizedPath' must stay below '$normalizedParent'."
    }
}

function Assert-NoReparsePoints {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $normalizedPath = Get-NormalizedFullPath -Path $Path
    $normalizedRoot = Get-NormalizedFullPath -Path $Root
    Assert-ContainedPath -Path $normalizedPath -Parent $normalizedRoot -Description "Path"

    $rootItem = Get-Item -LiteralPath $normalizedRoot -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Workspace root '$normalizedRoot' must not be a reparse point."
    }

    $current = $normalizedRoot
    $relative = [IO.Path]::GetRelativePath($normalizedRoot, $normalizedPath)
    foreach ($segment in $relative.Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = Join-Path $current $segment
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Path '$current' must not be a reparse point."
            }
        }
    }
}

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {
    throw "Version '$Version' is not valid for a release archive."
}
if ($Label -notmatch '^(windows-x86_64|linux-(x86_64|aarch64)|macos-(x86_64|aarch64))$') {
    throw "Release label '$Label' is not one of the supported v0.1 targets."
}

$targetByLabel = @{
    "windows-x86_64" = "x86_64-pc-windows-msvc"
    "linux-x86_64"   = "x86_64-unknown-linux-gnu"
    "linux-aarch64"  = "aarch64-unknown-linux-gnu"
    "macos-x86_64"   = "x86_64-apple-darwin"
    "macos-aarch64"  = "aarch64-apple-darwin"
}
if ($Target -ne $targetByLabel[$Label]) {
    throw "Target '$Target' does not match release label '$Label'."
}

$workspaceCandidate = if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_WORKSPACE)) {
    [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
} else {
    [IO.Path]::GetFullPath((Get-Location).Path)
}
if ($workspaceCandidate -eq [IO.Path]::GetPathRoot($workspaceCandidate)) {
    throw "The workspace must not be a filesystem root."
}
$workspaceRoot = Get-NormalizedFullPath -Path $workspaceCandidate

$extension = if ($Label.StartsWith("windows-")) { ".exe" } else { "" }
$binaryPath = Get-NormalizedFullPath -Path (Join-Path "target/$Target/release" "bloxguard$extension")
Assert-ContainedPath -Path $binaryPath -Parent $workspaceRoot -Description "Release binary"
Assert-NoReparsePoints -Path $binaryPath -Root $workspaceRoot
if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
    throw "Release binary '$binaryPath' was not built."
}

$resolvedOutputDirectory = Get-NormalizedFullPath -Path $OutputDirectory
Assert-ContainedPath -Path $resolvedOutputDirectory -Parent $workspaceRoot -Description "Output directory"
Assert-NoReparsePoints -Path $resolvedOutputDirectory -Root $workspaceRoot

New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
$resolvedOutputDirectory = (Get-Item -LiteralPath $resolvedOutputDirectory -Force).FullName
Assert-ContainedPath -Path $resolvedOutputDirectory -Parent $workspaceRoot -Description "Output directory"
Assert-NoReparsePoints -Path $resolvedOutputDirectory -Root $workspaceRoot

$stagingDirectory = Join-Path $resolvedOutputDirectory "staging-$Label-$([Guid]::NewGuid().ToString('N'))"
Assert-ContainedPath -Path $stagingDirectory -Parent $resolvedOutputDirectory -Description "Staging directory"
New-Item -ItemType Directory -Path $stagingDirectory | Out-Null
$stagingDirectory = (Get-Item -LiteralPath $stagingDirectory -Force).FullName
Assert-NoReparsePoints -Path $stagingDirectory -Root $workspaceRoot

$archiveName = "bloxguard-$Version-$Label.zip"
$archivePath = Join-Path $resolvedOutputDirectory $archiveName
$checksumPath = "$archivePath.sha256"
Assert-ContainedPath -Path $archivePath -Parent $resolvedOutputDirectory -Description "Archive"
Assert-ContainedPath -Path $checksumPath -Parent $resolvedOutputDirectory -Description "Checksum"
$stagedBinary = Join-Path $stagingDirectory "bloxguard$extension"

try {
    Copy-Item -LiteralPath $binaryPath -Destination $stagedBinary

    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    if ($IsWindows) {
        Compress-Archive -LiteralPath $stagedBinary -DestinationPath $archivePath -CompressionLevel Optimal
    } else {
        & chmod 755 -- $stagedBinary
        if ($LASTEXITCODE -ne 0) {
            throw "Could not set executable permissions on the staged binary."
        }
        if ($null -eq (Get-Command zip -ErrorAction SilentlyContinue)) {
            throw "The zip command is required to preserve Unix executable permissions."
        }
        Push-Location $stagingDirectory
        try {
            & zip -q -9 -- $archivePath "bloxguard$extension"
            if ($LASTEXITCODE -ne 0) {
                throw "Could not create release archive '$archivePath'."
            }
        } finally {
            Pop-Location
        }
    }

    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath $checksumPath -Value "$hash  $archiveName" -Encoding utf8NoBOM
} finally {
    if (Test-Path -LiteralPath $stagingDirectory) {
        Assert-ContainedPath -Path $stagingDirectory -Parent $resolvedOutputDirectory -Description "Staging directory"
        Assert-NoReparsePoints -Path $stagingDirectory -Root $workspaceRoot
        if (Test-Path -LiteralPath $stagedBinary -PathType Leaf) {
            $stagedItem = Get-Item -LiteralPath $stagedBinary -Force
            if (($stagedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Staged binary '$stagedBinary' must not be a reparse point."
            }
            Remove-Item -LiteralPath $stagedBinary -Force
        }
        if (@(Get-ChildItem -LiteralPath $stagingDirectory -Force).Count -ne 0) {
            throw "Refusing to remove non-empty staging directory '$stagingDirectory'."
        }
        Remove-Item -LiteralPath $stagingDirectory -Force
    }
}

Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "archive=$archivePath" -Encoding utf8
Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "checksum=$checksumPath" -Encoding utf8
