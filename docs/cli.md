# Command line

bloxguard is one program with no installer. This page covers installing it, the commands, and what a report and its exit code mean. The [README](../README.md) shows the quickest way to check a game without typing commands.

## Install

### Download a release

The [releases page](https://github.com/waltuov/bloxguard/releases) has one archive per platform. Each holds only the `bloxguard` program (`bloxguard.exe` on Windows):

| Platform | Archive |
| --- | --- |
| Windows, x64 | `bloxguard-0.1.0-rc.2-windows-x86_64.zip` |
| macOS, Apple silicon | `bloxguard-0.1.0-rc.2-macos-aarch64.zip` |
| macOS, Intel | `bloxguard-0.1.0-rc.2-macos-x86_64.zip` |
| Linux, x64 | `bloxguard-0.1.0-rc.2-linux-x86_64.zip` |
| Linux, arm64 | `bloxguard-0.1.0-rc.2-linux-aarch64.zip` |

0.1.0-rc.2 is a pre-release. `SHA256SUMS` on the same page lists the SHA-256 of every archive. To check a download, run this in the download folder.

Windows PowerShell prints `True` when the archive matches:

```powershell
(Get-FileHash .\bloxguard-0.1.0-rc.2-windows-x86_64.zip).Hash -eq ((Select-String -Path .\SHA256SUMS -SimpleMatch 'bloxguard-0.1.0-rc.2-windows-x86_64.zip').Line -split '\s+')[0]
```

macOS:

```sh
shasum -a 256 -c --ignore-missing SHA256SUMS
```

Linux:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

The downloads are not signed yet. On Windows, the first start may show "Windows protected your PC": choose **More info**, then **Run anyway**. On macOS, remove the download mark once with `xattr -d com.apple.quarantine bloxguard`. If macOS or Linux says permission denied, run `chmod +x bloxguard`.

### Rokit

In a project with a `rokit.toml` (create one with `rokit init`):

```sh
rokit add waltuov/bloxguard@0.1.0-rc.2
```

Add `--global` to install it for every project. Write the version without a leading `v`. While only the pre-release exists, `rokit add waltuov/bloxguard` without a version finds no release, because it skips pre-releases.

### Cargo

With Rust 1.96 or newer:

```sh
cargo install --git https://github.com/waltuov/bloxguard --tag v0.1.0-rc.2 --locked bloxguard
```

### Build from a checkout

```sh
cargo build --locked --release
```

The program is then at `target/release/bloxguard` on Linux and macOS, and at `target\release\bloxguard.exe` on Windows. `cargo install --path crates/bloxguard --locked` installs it from the checkout instead.

## Scan

```sh
# In a Rojo project, scan the project folder
bloxguard scan .
# Or scan a place or model file
bloxguard scan MyPlace.rbxl
```

The examples call `bloxguard`. Use the full path to the program if it is not on your `PATH`.

Here is `bloxguard scan .` on a Rojo project with a free car kit in `src/workspace/FAKE_FreeCarKit`. Line 6 of its weld script is an `end` followed by 300 spaces and `getfenv()[string.reverse("eriuqer")](999000000004242)`. All names and IDs are fake. Captured on Windows:

```text
bloxguard 0.1.0-rc.2 scan: complete

. [complete]
  9 instances, 3 scripts
  info: Rojo project mapping in .\default.project.json was not applied; instance paths follow the folder layout. Run `rojo build` and scan the output for full fidelity
  [high, high confidence] BG001 module is loaded from a numeric asset ID
    /root/src/workspace/FAKE_FreeCarKit/Weld (.\src\workspace\FAKE_FreeCarKit\Weld.server.luau, line 6:305)
    evidence: getfenv()[string.reverse("eriuqer")](999000000004242) [resolved asset id: 999000000004242]
    fingerprint: aea4d5c5d53d23f244ece74a0cd7731070178abe722a51e71901a24e7c8bc45a
  [high, high confidence] BG004 script accesses or changes a runtime environment
    /root/src/workspace/FAKE_FreeCarKit/Weld (.\src\workspace\FAKE_FreeCarKit\Weld.server.luau, line 6:305)
    evidence: getfenv()
    fingerprint: 4c4a333eaa0273e576300b5931eacee6d92c132c0cad86330d07b5874b2cf5fb

2 findings: 0 critical, 2 high, 0 medium, 0 low
```

Each finding shows its severity and confidence, rule ID, message, instance path, location, short evidence, and stable fingerprint. The instance path follows the folder layout here, and `root` stands for the scanned folder `.`. `line 6:305` is line 6, column 305, so code pushed far to the right is easy to find. The `info` line is a note, not a finding. The exit code is 1 because both findings meet the default `high` threshold. Run `bloxguard explain BG001` for an explanation of a rule.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan is complete and no finding meets the failure threshold. |
| 1 | At least one finding meets the failure threshold. |
| 2 | Scan is incomplete. Something could not be read or checked, and the output lists why. |
| 3 | Command usage or configuration is invalid. |

The failure threshold is `high` unless you set `--fail-on` or `fail_on`. An incomplete scan without findings is not a clean result. `--allow-incomplete` allows an incomplete scan to use the finding threshold result. It does not change the completeness field in JSON or SARIF.

When you review a third party model, use `--fail-on medium`. Purchase prompts, teleports and package links in inserted content are medium findings, so the default threshold passes them with exit code 0 (see [Known limits](limits.md#medium-findings-pass-the-default-threshold)).

## More commands

```sh
# Scan one or more files or directories
bloxguard scan MyPlace.rbxl models/ src/
# Write deterministic JSON or SARIF
bloxguard scan MyPlace.rbxl --format json --output bloxguard.json
bloxguard scan MyPlace.rbxl --format sarif --output bloxguard.sarif
# Inventory every script before opening a file in Studio
bloxguard inventory commissioned-model.rbxm
# List rules or explain one finding
bloxguard rules
bloxguard explain BG002
# Create a baseline, then report only new findings
bloxguard baseline create MyPlace.rbxl --output bloxguard-baseline.json
bloxguard scan MyPlace.rbxl --baseline bloxguard-baseline.json
```

The JSON report is described in [JSON output](json-output.md), and settings, suppressions and baselines in [Configuration](configuration.md). The full scan command is:

```text
bloxguard scan <paths...> [--format human|json|sarif] [--output FILE] [--fail-on SEVERITY] [--config FILE] [--baseline FILE] [--allow-incomplete] [--as-of YYYY-MM-DD]
```

Supported input files are `.rbxl`, `.rbxlx`, `.rbxm`, `.rbxmx`, `.lua`, and `.luau`. A directory scan also finds `.lua`, `.luau`, nested Roblox model files, Rojo metadata, and Rojo model data. A folder scan does not apply a Rojo project file's mapping; for full fidelity, run `rojo build` and scan the output (see [Known limits](limits.md#rojo-projects-and-source-trees)).

## Drop a file onto bloxguard.exe

When every argument is an existing file or folder, bloxguard runs exactly what `bloxguard scan` runs with those paths: human output, `bloxguard.toml` from the working directory when present, and the same exit code. This is how Windows starts a program when you drag a place file or a project folder onto `bloxguard.exe`. After the report, a short note says what the result means. A subcommand name or an option as the first argument keeps its usual meaning, also when a file of that name exists, and a path that does not exist gives the usual usage error. On Windows, a window that opened just for bloxguard waits for Enter before it closes, so you can read the report, and started that way without arguments, bloxguard explains how to drop a file. Started from a terminal, a script or CI, it never waits.
