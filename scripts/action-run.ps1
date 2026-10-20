$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-ActionOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        # An empty sarif_file tells later steps that no SARIF file was written.
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "$Name=$Value" -Encoding utf8
}

# Print the human report in the job log and add it to the job summary. The
# caller has turned workflow commands off. GitHub limits a step's summary to
# 1 MiB, so a report over 512 KiB is cut in the summary and stays whole in
# the log.
function Write-ActionReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $utf8 = New-Object System.Text.UTF8Encoding $false
    $lineEnds = [char[]]@([char]13, [char]10)
    $report = [System.IO.File]::ReadAllText($Path, $utf8)
    Write-Output $report.TrimEnd($lineEnds)

    if ([string]::IsNullOrEmpty($env:GITHUB_STEP_SUMMARY)) {
        return
    }
    $maxReportBytes = 512KB
    if ($utf8.GetByteCount($report) -gt $maxReportBytes) {
        # Every character is at least one UTF-8 byte, so dropping as many
        # characters as there are excess bytes fits. The cut ends at a line.
        $report = $report.Substring(0, [Math]::Min($report.Length, $maxReportBytes))
        $excess = $utf8.GetByteCount($report) - $maxReportBytes
        if ($excess -gt 0) {
            $report = $report.Substring(0, $report.Length - $excess)
        }
        $lastLine = $report.LastIndexOf("`n")
        if ($lastLine -gt 0) {
            $report = $report.Substring(0, $lastLine + 1)
        }
        $report += "... the report was cut here; the job log has all of it`n"
    }
    # A fence longer than any run of backticks in the report keeps it literal.
    $longestRun = 0
    foreach ($match in [regex]::Matches($report, '`+')) {
        $longestRun = [Math]::Max($longestRun, $match.Length)
    }
    $fence = "``" * [Math]::Max(3, $longestRun + 1)
    $summary = "### bloxguard scan`n`n$($fence)text`n$($report.TrimEnd($lineEnds))`n$fence`n"
    [System.IO.File]::AppendAllText($env:GITHUB_STEP_SUMMARY, $summary, $utf8)
}

if (-not (Test-Path -LiteralPath $env:BLOXGUARD_BINARY -PathType Leaf)) {
    throw "The verified bloxguard binary is missing."
}

$paths = @(
    $env:BLOXGUARD_PATHS -split "`r?`n" |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_.Length -gt 0 }
)
if ($paths.Count -eq 0) {
    throw "The paths input must contain at least one path."
}

$resultRoot = Join-Path $env:RUNNER_TEMP "bloxguard-action-results"
New-Item -ItemType Directory -Path $resultRoot -Force | Out-Null
$sarifPath = Join-Path $resultRoot "bloxguard.sarif"
$reportPath = Join-Path $resultRoot "bloxguard-report.txt"

$scanOptions = @("--fail-on", $env:BLOXGUARD_FAIL_ON)
if (-not [string]::IsNullOrWhiteSpace($env:BLOXGUARD_CONFIG)) {
    $scanOptions += @("--config", $env:BLOXGUARD_CONFIG)
}
if (-not [string]::IsNullOrWhiteSpace($env:BLOXGUARD_BASELINE)) {
    $scanOptions += @("--baseline", $env:BLOXGUARD_BASELINE)
}
if ($env:BLOXGUARD_ALLOW_INCOMPLETE -eq "true") {
    $scanOptions += "--allow-incomplete"
} elseif ($env:BLOXGUARD_ALLOW_INCOMPLETE -ne "false") {
    throw "The allow-incomplete input must be 'true' or 'false'."
}
if ($env:BLOXGUARD_UPLOAD_SARIF -ne "true" -and $env:BLOXGUARD_UPLOAD_SARIF -ne "false") {
    throw "The upload-sarif input must be 'true' or 'false'."
}

$scanArguments = @("scan") + $paths + @(
    "--format", "sarif",
    "--output", $sarifPath
) + $scanOptions

# Everything bloxguard prints, the report and its errors alike, can quote the
# scanned repository: names, evidence, and configuration text in TOML or JSON
# errors. Workflow commands stay off from the first scan to the end of the
# report, with one token for this run.
$stopMarker = [guid]::NewGuid().ToString("N")
Write-Output "::stop-commands::$stopMarker"
try {
    # A SARIF file from an earlier run in this job must not stand in for this one.
    if (Test-Path -LiteralPath $sarifPath) { Remove-Item -LiteralPath $sarifPath -Force }
    & $env:BLOXGUARD_BINARY @scanArguments
    $scanExitCode = $LASTEXITCODE

    Write-ActionOutput -Name "exit_code" -Value ([string]$scanExitCode)
    if (Test-Path -LiteralPath $sarifPath -PathType Leaf) {
        Write-ActionOutput -Name "sarif_file" -Value $sarifPath
    } else {
        Write-ActionOutput -Name "sarif_file" -Value ""
    }

    # The same scan in human form for people reading the job. Its exit code is
    # not used. Exit code 3 means invalid usage or configuration, which the
    # first run already printed, so there is no report to show.
    if ($scanExitCode -ne 3) {
        try {
            if (Test-Path -LiteralPath $reportPath) {
                Remove-Item -LiteralPath $reportPath -Force
            }
            $reportArguments = @("scan") + $paths + @(
                "--format", "human",
                "--output", $reportPath
            ) + $scanOptions
            & $env:BLOXGUARD_BINARY @reportArguments
            if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
                Write-ActionReport -Path $reportPath
            }
        } catch {
            Write-Warning "The bloxguard report could not be shown: $_"
        }
    }
} finally {
    Write-Output "::$($stopMarker)::"
}

exit 0
