$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-ActionOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "$Name=$Value" -Encoding utf8
}

$repository = $env:BLOXGUARD_REPOSITORY
if ($repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw "Could not determine the action repository. Set the version input on an action used from GitHub."
}

$requestedVersion = $env:BLOXGUARD_VERSION
if ([string]::IsNullOrWhiteSpace($requestedVersion)) {
    $requestedVersion = $env:BLOXGUARD_ACTION_REF
}
if ([string]::IsNullOrWhiteSpace($requestedVersion)) {
    throw "Set the version input when the action is not referenced by a version tag."
}

$tag = if ($requestedVersion.StartsWith("v", [System.StringComparison]::OrdinalIgnoreCase)) {
    $requestedVersion
} else {
    "v$requestedVersion"
}
$archiveVersion = $tag.Substring(1)
if ($archiveVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {
    throw "Release version '$requestedVersion' is not a supported version tag. Use a value such as v0.1.0."
}

$platform = switch ($env:RUNNER_OS) {
    "Windows" { "windows" }
    "Linux" { "linux" }
    "macOS" { "macos" }
    default { throw "Unsupported runner operating system '$($env:RUNNER_OS)'." }
}
$architecture = switch ($env:RUNNER_ARCH) {
    "X64" { "x86_64" }
    "ARM64" { "aarch64" }
    default { throw "Unsupported runner architecture '$($env:RUNNER_ARCH)'." }
}
if ($platform -eq "windows" -and $architecture -ne "x86_64") {
    throw "The v0.1 release does not provide a Windows $architecture binary."
}

$assetName = "bloxguard-$archiveVersion-$platform-$architecture.zip"
$downloadRoot = Join-Path $env:RUNNER_TEMP "bloxguard-action"
$extractRoot = Join-Path $downloadRoot "bin"
New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null
if (Test-Path -LiteralPath $extractRoot) {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $extractRoot | Out-Null

$releaseBase = "https://github.com/$repository/releases/download/$tag"
$assetPath = Join-Path $downloadRoot $assetName
$checksumsPath = Join-Path $downloadRoot "SHA256SUMS"
$headers = @{}
if (-not [string]::IsNullOrWhiteSpace($env:BLOXGUARD_GITHUB_TOKEN)) {
    $headers.Authorization = "Bearer $($env:BLOXGUARD_GITHUB_TOKEN)"
}

Invoke-WebRequest -Uri "$releaseBase/SHA256SUMS" -Headers $headers -OutFile $checksumsPath
Invoke-WebRequest -Uri "$releaseBase/$assetName" -Headers $headers -OutFile $assetPath

$escapedAssetName = [Regex]::Escape($assetName)
$expectedHash = $null
foreach ($line in Get-Content -LiteralPath $checksumsPath) {
    if ($line -match "^([0-9A-Fa-f]{64})\s+\*?$escapedAssetName$") {
        $expectedHash = $Matches[1].ToLowerInvariant()
        break
    }
}
if ($null -eq $expectedHash) {
    throw "SHA256SUMS does not contain an entry for $assetName."
}

$actualHash = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "SHA-256 verification failed for $assetName."
}

Expand-Archive -LiteralPath $assetPath -DestinationPath $extractRoot
$binaryName = if ($platform -eq "windows") { "bloxguard.exe" } else { "bloxguard" }
$binaries = @(Get-ChildItem -LiteralPath $extractRoot -Filter $binaryName -File -Recurse)
if ($binaries.Count -ne 1) {
    throw "Expected exactly one $binaryName in $assetName, found $($binaries.Count)."
}
if ($platform -ne "windows") {
    & chmod +x -- $binaries[0].FullName
    if ($LASTEXITCODE -ne 0) {
        throw "Could not mark the downloaded binary executable."
    }
}

Write-ActionOutput -Name "binary" -Value $binaries[0].FullName
