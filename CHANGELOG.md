# Changelog

All notable changes will be recorded here.

## Unreleased

## 0.1.0-rc.2 (2026-10-20)

### Fixed

- A folder with two place or model files that hold the same infected script at the same instance path reported it for only one file. Each file now keeps its own finding.
- The Windows binary needed the Visual C++ runtime and did not start on a PC without it. It now links the C runtime statically.

### Changed

- The note after a drop mode scan follows the most severe finding instead of the failure threshold: "Some findings are high or critical" or "No high or critical findings". An incomplete scan with a high finding gets both notes.
- The README is written for game developers who use Studio: save the game, download, drop the file onto `bloxguard.exe`, and what to do with each kind of finding.

## 0.1.0-rc.1 (2026-10-20)

First public pre-release.

### Added

- Offline scans of Roblox place and model files (`.rbxl`, `.rbxlx`, `.rbxm`, `.rbxmx`), Luau files (`.lua`, `.luau`) and Rojo source trees. Scripts and object data are parsed, never run.
- Twelve rules, BG001 to BG012: remote module requires, module IDs read from properties and attributes, runtime code construction, environment access, obfuscation, unusual script placement and deceptive names, runtime asset loading, HTTP exfiltration, conditional activation, purchase prompts and teleports, package links, and text that asks a developer to run commands.
- Human, JSON and SARIF 2.1.0 reports. The same files and settings give byte identical JSON and SARIF. A scan that could not read or check part of its input is marked incomplete and exits with code 2 unless `--allow-incomplete` is passed.
- `inventory`, `rules` and `explain` commands.
- Drop mode: with only paths of existing files or folders as arguments, such as a place file dropped onto `bloxguard.exe`, bloxguard runs `scan` on them and adds a short note on the result. On Windows, a window opened just for it waits for Enter before it closes ([command line](docs/cli.md)).
- `bloxguard.toml` configuration for rules, severities, the failure threshold, trusted asset IDs, suppressions with a reason and an optional expiry date, and resource limits. Baselines are scoped to their input paths.
- A read-only MCP server (`bloxguard mcp`) whose file tools stay inside the roots you pass, and a Studio snippet that exports a selected instance for its `scan_bundle` tool.
- A GitHub Action that downloads a release archive, checks its SHA-256, scans, shows the report in the job log and summary, and uploads SARIF to code scanning.
- Release archives for Windows x86_64, Linux x86_64 and aarch64, and macOS x86_64 and aarch64, with a `SHA256SUMS` file.
- Documented [known limits](docs/limits.md) and an [evaluation](docs/evaluation.md) on synthetic cases, 16 open source projects and three real games.
