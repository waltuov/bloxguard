# Evaluation

BloxGuard is evaluated with synthetic fixtures, a pinned clean corpus, and a generated large place. Results apply only to the named inputs and BloxGuard version shown with each run.

The evaluation does not prove intent. A finding in an open source project is a candidate false positive until a person reviews it. Do not use these results to accuse a project or its authors.

## Limits

BloxGuard reads files and source text offline. It cannot see code fetched later from the internet. It cannot prove that code is malicious or safe. The malicious fixtures are synthetic and defanged. They do not represent the full range of real attacks.

## Synthetic rule corpus

Each rule must have at least two defanged malicious fixtures and two clean look alike fixtures. Asset IDs use the fake range documented in [SECURITY.md](../SECURITY.md), `999000000000000` through `999999999999999`. Webhook fixtures use `https://discord.com/api/webhooks/000/FAKE`. No fixture makes a network call or executes Luau.

The v0.1 matrix contains at least two malicious and two clean look alike cases for each rule. Every case passes through `load_source`, `load_bundle`, or `load_bytes`, then through the full scan engine. File cases are `.rbxm` and `.rbxmx` models generated at test time with the same encoders the loaders decode. Every input must remain complete. The target rule must produce exactly one finding for each malicious case. A clean case passes only when the whole report contains no high or critical finding.

BG011 has two extra malicious file cases, a `PackageLink` in an `.rbxm` and one in an `.rbxmx` model, and two extra clean file cases: an unpublished `PackageLink` with an empty reference and a model without package data.

Measured on 2026-10-20 with BloxGuard 0.1.0-rc.2.

Command:

```text
cargo test --locked --package bloxguard-core --test evaluation -- --nocapture
```

Result: 1 passed, 0 failed. Every clean case had no high or critical finding anywhere in its report.

| Rule | Malicious detected | Malicious total | Clean high or critical | Clean total | Status |
| --- | ---: | ---: | ---: | ---: | --- |
| BG001 | 2 | 2 | 0 | 2 | Pass |
| BG002 | 2 | 2 | 0 | 2 | Pass |
| BG003 | 2 | 2 | 0 | 2 | Pass |
| BG004 | 2 | 2 | 0 | 2 | Pass |
| BG005 | 2 | 2 | 0 | 2 | Pass |
| BG006 | 2 | 2 | 0 | 2 | Pass |
| BG007 | 2 | 2 | 0 | 2 | Pass |
| BG008 | 2 | 2 | 0 | 2 | Pass |
| BG009 | 2 | 2 | 0 | 2 | Pass |
| BG010 | 2 | 2 | 0 | 2 | Pass |
| BG011 | 4 | 4 | 0 | 4 | Pass |
| BG012 | 2 | 2 | 0 | 2 | Pass |

A parse failure or incomplete scan fails the matrix. It is not counted as a true negative.

## Review round 1 corpus

[`review_round1.rs`](../crates/bloxguard-core/tests/review_round1.rs) contains 40 synthetic evasion cases named E01 through E40 and 14 legitimate look alike cases named L01 through L14. Every case must produce a complete report. Each E case must contain its expected rule. Each L case must contain no high or critical finding across the whole report, except for the documented L07 result.

Command:

```text
cargo test --locked --package bloxguard-core --test review_round1
```

Measured on 2026-10-20 with BloxGuard 0.1.0-rc.2.

Result: 54 passed, 0 failed in 0.35 seconds after compilation.

| Check | Passed | Total |
| --- | ---: | ---: |
| E cases detected with the expected rule | 40 | 40 |
| L cases with no high or critical finding | 13 | 14 |
| Documented L07 BG008 false positive allowed by the test | 1 | 1 |

L07 sends `player.UserId` to an analytics endpoint. BG008 reports it at high severity because user identifiers are treated as sensitive. The passing suite therefore includes one known false positive.

## Clean corpus

The corpus manifest is [`clean-corpus.json`](clean-corpus.json). It contains 16 Roblox projects at exact commits. GitHub repository metadata reported an MIT or Apache 2.0 license for every selected project on 2026-10-18.

The clean corpus runs only in GitHub Actions. The workflow checks out each exact commit without submodules or Git LFS content and with an empty hooks folder. It verifies the commit and moves Git metadata outside the scan root. It rejects symlinks.

It scans each project checkout as one directory tree, `bloxguard scan <checkout>`, the way users and the GitHub Action scan a project. The tree keeps the folders around each script, so a path such as `script.Parent.Parent.State.Value` resolves to the project's own ModuleScript. A scan of loose files would not see those folders and would report such paths as values from outside the content. The tree scan uses the scanner's own directory rules, including its excluded folders (see [configuration](configuration.md#source-trees-and-rojo)).

A checkout is one scan input, and `max_file_ms` is the time budget of one input, shared by loading, analysis and inventory. The default of 30 seconds is a safety limit for interactive use. A large project such as NevermoreEngine, with about 1,700 source files, on a shared runner can need longer, and a budget stop would make the result partial for a reason that says nothing about the code. So the measurement passes its own configuration with `max_file_ms = 300000` (five minutes) and records each project's scan time. The configuration is passed with `--config` from outside the checkout, so a `bloxguard.toml` in a project is never read. The job timeout still bounds the whole run.

The results file lists, for each project, the completeness, every incomplete reason, the informational notes (such as type declaration files), and every finding with its rule, severity, confidence, file, instance path, location and evidence. A partial project is reported with its reasons rather than stopping the run.

Every finding on this corpus is a candidate false positive: the projects are popular and reviewed, but a finding is only a false positive once a person has read the code and confirmed that it is ordinary. The counts are not confirmed false positives and not true positives, and they say nothing about intent.

The source corpus measures BG001, BG003, BG004, BG005, BG007, BG008, BG009, and BG012. BG002, BG006, BG010, and BG011 mostly need a place file: a value object, an attribute or an object's placement that source trees rarely hold. They are counted like any other candidate when they fire, and the report marks them as not measured when they have no findings instead of publishing zero counts. Their clean look alike behavior is measured by the complete synthetic matrix above.

Emulators, test runners and Studio plugins that build and run code on purpose, such as lemur's module loader and NevermoreEngine's plugin and CLI tools, get BG003 and BG004 at high severity on this corpus. Those findings are correct: the code does run generated code. Projects like these suppress the two rules by path for the files that do it.

The workflow does not run dependency installation, hooks, build scripts, tests, or project code. It runs only the locally built BloxGuard scanner.

### First run, 2026-10-19

The first run scanned loose files in batches, with a development version before the first public release. Its candidates on ordinary code led to four changes: a BG002 value the scan cannot see is medium instead of critical, an instance stored in a loop and required is a local module, a `getfenv().it` read of a test runner's global is BG004 low, and a luau-lsp type declaration file gets a note instead of making the project partial. The remaining NevermoreEngine partial reasons are template files with `{{placeholder}}` names, which are not Luau.

### Tree scan, 2026-10-19

The tree scan ran on a GitHub hosted Linux runner, with a development version before the first public release. It covered 16 projects with 2,833 source files and 3,022 scripts, in 6.2 seconds of scan time in total. Three more runs gave the same findings: one after changes to output, documentation and the Action, one after the real game fixes below, which change analysis and loading, and one on 0.1.0-rc.1.

| Result | Projects |
| --- | ---: |
| Complete, no candidate at medium or higher | 13 |
| Complete, with high candidates from code that runs generated code | 2 |
| Partial | 1 |

| Rule | Candidates | At high or critical |
| --- | ---: | ---: |
| BG001 | 42 | 0 |
| BG002 | 15 | 0 |
| BG003 | 8 | 8 |
| BG004 | 212 | 11 |
| BG006 | 10 | 0 |
| BG007 | 1 | 1 |

The two complete projects with high candidates are lemur, whose module loader runs module source with `loadstring` and `setfenv`, and Fusion, whose bundled TestEZ runner sets the environment of test callbacks. NevermoreEngine is partial only because of its `{{placeholder}}` template files. Its high candidates are its UI converter plugin and CLI tools, which run code with `loadstring` and `getfenv` or `setfenv`, its module loader in an integration test place, which reads its caller's environment with `getfenv(2)`, and `InsertService:LoadAsset` in its `InsertServiceUtils` module. These are the cases described above: the code does what the rule reports. The 201 other BG004 candidates are low, all in test files reading a test runner's globals such as `expect` and `it` through `getfenv()`. Every BG001 candidate is low: a `require` of a value the scan cannot resolve, such as a module from a list. Every BG002 candidate is medium: a value the scan cannot see.

## Real games, 2026-10-19

The project's author scanned three of their team's own games: a place saved by current Roblox Studio and two places built with Rojo that bundle Wally packages such as React and Jest, plus the Rojo project folder. The scans ran locally and only read the files. The games are private, so only counts are given. "Before" is the development version the scans first ran on, "after" is the version with the fixes these scans led to, which 0.1.0-rc.1 includes.

| Input | Before | After |
| --- | --- | --- |
| Studio place, 93 scripts | partial: a value type no decoder knows yet, on Terrain | complete: 1 high, 7 medium |
| The same place, saved a month earlier | complete, the same 8 findings | unchanged |
| Rojo built place, 572 scripts | 1 BG001 high, 6 BG004 high, 1 BG009 medium | 6 BG004 low |
| Rojo built place, 565 scripts | 6 BG004 high | 6 BG004 low |
| Rojo project folder, 2,402 scripts | partial: the luau-lsp definitions file | complete: 14 high |

No backdoor was found. The four changes were: a value type that no decoder knows is a note on a class that cannot hold code, a function that only requires local modules gets no BG001 summary finding, output capture of `print` and `warn` in package test specs is BG004 low, and a long definitions file gets the declaration note. The remaining highs are code that does what the rule reports: Jest's module loader (one BG001, one BG003 and seven BG004), the team's own test helper that runs module source (one BG003 and two BG004), and the team's analytics script, which posts player data to its own webhook (one BG008 in the place and two in the folder, which holds two copies), a known false positive. The 7 medium findings in the Studio place are the team's own purchase prompts in Workspace, a configuration ModuleScript in SoundService and links to packages a team member made.

## Performance

The performance input is generated by `cargo run --release --package bloxguard-core --example performance`. It contains exactly 500,000 serialized instances, including 20,000 harmless scripts. The generator uses `rbx_dom_weak` and `rbx_binary`. The repository does not contain a generated place or an opaque binary fixture.

Build the release binary first, then run the example:

```text
cargo build --locked --release --package bloxguard --bin bloxguard
cargo run --locked --release --package bloxguard-core --example performance
```

Measured on 2026-10-20 with BloxGuard 0.1.0-rc.1.

| Field | Result |
| --- | ---: |
| CPU | AMD Ryzen 7 9800X3D 8-Core Processor |
| Operating system | Windows 11 Pro 10.0.26200 x64 |
| Rust | rustc 1.96.0 `ac68faa20` |
| Serialized instances | 500,000 |
| Scripts | 20,000 |
| Place size | 2,729,387 bytes |
| Generation time | 0.175 seconds |
| Serialization time | 0.219 seconds |
| Scan time | 2.047 seconds |
| Completeness | complete |
| Findings | 0 |

Generation and serialization time are not part of scan time. The table shows the median of three warm runs, after one run to warm up. The scans took 2.022, 2.047 and 2.103 seconds. Other programs, including a game, were running on the machine at the same time. These are measurements on one machine, not a hardware-independent performance guarantee. Generated files were removed after each run.
