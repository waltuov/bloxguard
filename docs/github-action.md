# GitHub Actions

The bloxguard action scans your repository on every push or pull request. It downloads the release archive for the runner, checks its SHA-256 against the release's `SHA256SUMS`, runs a scan, prints the report in the job log and the job summary, and uploads SARIF so findings show up in GitHub code scanning. It runs on Windows x64, Linux x64 and arm64, and macOS x64 and Apple silicon runners. Its steps use PowerShell 7 (`pwsh`), which GitHub hosted runners include; a self hosted runner needs it installed.

## Example workflow

Save this as `.github/workflows/bloxguard.yml`:

```yaml
name: bloxguard

on:
  push:
  pull_request:

permissions:
  contents: read
  actions: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: waltuov/bloxguard@v0.1.0-rc.1
        with:
          paths: |
            MyPlace.rbxl
            src
          fail-on: high
```

A `permissions` block sets every permission it does not list to `none`, so the example lists `contents: read` for the checkout step. `security-events: write` lets the action upload SARIF, and a private repository also needs `actions: read` for that upload. On a private repository, code scanning needs GitHub Code Security. Without it, set `upload-sarif: false`: the scan still runs and sets the exit code, and the upload step is skipped.

To pin the action to a full commit SHA instead of a tag, name the release in `version`:

```yaml
      - uses: waltuov/bloxguard@<full commit SHA>
        with:
          version: v0.1.0-rc.1
```

## Inputs and outputs

| Input | Default | Meaning |
| --- | --- | --- |
| `paths` | `.` | Paths to scan, one per line. |
| `fail-on` | `high` | Lowest severity that fails the job. Use `medium` for third party models (see [Known limits](limits.md#medium-findings-pass-the-default-threshold)). |
| `config` | empty | Path to `bloxguard.toml`. Empty uses automatic discovery. |
| `baseline` | empty | Path to a baseline file. Empty reports every finding. |
| `allow-incomplete` | `false` | Let an incomplete scan use the findings exit code instead of exit code 2. |
| `upload-sarif` | `true` | Upload the SARIF file to code scanning. Set `false` where code scanning is not available. |
| `version` | the action ref | Release tag to download. Needed when the action is pinned to a commit SHA. |

The outputs are `exit-code`, the exit code bloxguard returned, and `sarif-file`, the absolute path of the SARIF file, which is empty when no file was written. The job fails when bloxguard returns a nonzero exit code (see [Exit codes](cli.md#exit-codes)).

## Report and SARIF

The action prints the human report in the job log and adds it to the job summary. A report above 512 KiB is cut in the summary and stays whole in the log.

In SARIF, a finding in a script inside a place or model file points at that file without a line, because the line belongs to the script. In a folder scan, that is the nested place, model, `.model.json` or metadata file the script came from. The message names the script's instance path and its line in the script, and `properties.scriptRegion` holds that region in the script: `startLine` and, when known, `startColumn`, `endLine` and `endColumn`. Names in the message are escaped, square brackets carry a backslash and braces are doubled, so scanned names cannot form a link or a placeholder.

## Rojo repositories

`paths` defaults to `.`, the repository root. On a typical Rojo repository that scan stays complete: every source file under the root is scanned and the project file becomes a note. Wally packages under `Packages` are scanned when they are present in the checkout. If your project file maps folders from outside the repository, sets inline properties that rules read, or depends on generated output, build the place with Rojo in an earlier step and list the built file in `paths` instead.

To report only new findings, commit a baseline created with the same paths the action scans (see [Configuration](configuration.md#baselines)), and protect `bloxguard.toml` and the baseline with CODEOWNERS review.
