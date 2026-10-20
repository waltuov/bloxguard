# Configuration

bloxguard reads `bloxguard.toml` in the current working directory by default. Pass `--config FILE` to use another file. Unknown fields, unknown rule IDs, invalid values, and malformed suppressions are configuration errors. A suppression is malformed when it has no reason, has neither `path` nor `fingerprint`, or names an unknown rule, an invalid glob, an invalid fingerprint or an invalid date. A suppression that matches no finding, or has expired, is not an error.

This example shows every setting. It uses only synthetic IDs and names. The `baseline` line is commented out because the baseline file must exist: a baseline that cannot be read is a configuration error with exit code 3. Create the file with `bloxguard baseline create` first, then remove the `#`.

```toml
fail_on = "high"
trusted_asset_ids = [999000000000001]
# baseline = "bloxguard-baseline.json"

[rules.BG005]
enabled = true
severity = "high"

[rules.BG012]
enabled = false

[[suppressions]]
rule = "BG008"
path = "/FAKE_Analytics/**"
reason = "FAKE analytics client sends only approved test counters"
expires = "2026-12-31"

[[suppressions]]
rule = "BG006"
fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
reason = "FAKE generated path reviewed with its source"

[[suppressions]]
rule = "BG001"
path = "/FAKE_Admin/Loader"
fingerprint = "1111111111111111111111111111111111111111111111111111111111111111"
reason = "FAKE reviewed loader at this path and revision"

[limits]
max_file_bytes = 209715200
max_instances = 600000
max_script_bytes = 2097152
max_depth = 128
max_analysis_steps = 100000
max_file_ms = 30000
```

## Finding threshold

`fail_on` is the lowest severity that returns exit code 1. Valid values are `low`, `medium`, `high`, and `critical`. The default is `high`. The command line `--fail-on` value overrides the configuration for that scan.

## Trusted module IDs

`trusted_asset_ids` is empty by default. A trusted ID removes the BG001 or BG002 finding of a `require` whose argument is a constant: literals, and locals declared once from such values and never assigned again, read in the function that declares them. A trusted ID read any other way, such as from a table, a value object, an attribute, a global, a call result or a function parameter, is still reported at medium confidence with the evidence `trusted asset id, not a constant target`. Suppress such a reviewed loader by path. Add only IDs controlled and reviewed by your project. Do not copy a trust list from another project.

Trusting an ID does not copy its source into the scan. Review its ownership and update policy separately.

## Rule settings

Use `[rules.BGxxx]` to configure a known rule. `enabled = false` disables it. `severity` overrides its reported severity. Omitting a field keeps the rule default.

Disabling a rule removes its findings. Record why the project accepts that gap.

Require review for pull requests that change `bloxguard.toml`. A GitHub repository can use CODEOWNERS with branch protection so a rule, threshold, trust entry, or suppression cannot change without the selected review.

## Suppressions

Every `[[suppressions]]` entry requires a valid `rule` and a nonempty `reason`. It also needs `path`, `fingerprint`, or both.

`path` is a glob matched against the escaped instance path in a finding. `fingerprint` is the 64 character hexadecimal value of a finding: the `fingerprint:` line in human output, the `fingerprint` field in JSON, and `partialFingerprints` `bloxguard/v1` in SARIF. If an entry contains both fields, both must match the same finding.

`expires` uses `YYYY-MM-DD`. A suppression remains active on that UTC date and stops matching after it. By default, the scan uses the current UTC date. Use a fixed date for a reproducible review:

```sh
bloxguard scan game.rbxl --config bloxguard.toml --as-of 2026-10-18
```

An expired suppression is ignored. A malformed date, empty reason, unknown rule, invalid glob, or invalid fingerprint is a configuration error.

## Baselines

`baseline` selects a JSON baseline. A relative path is resolved from the directory that contains the configuration file. `--baseline FILE` overrides the configured path.

Create a reviewed baseline with the CLI:

```sh
bloxguard baseline create game.rbxl --config bloxguard.toml --output bloxguard-baseline.json
```

The command refuses to create a baseline from an incomplete scan. A generated version 1 baseline contains the fingerprint list and an input scope for each fingerprint:

```json
{
  "schema_version": 1,
  "fingerprints": [
    "2222222222222222222222222222222222222222222222222222222222222222"
  ],
  "input_scopes": {
    "2222222222222222222222222222222222222222222222222222222222222222": [
      "game.rbxl"
    ]
  }
}
```

A fingerprint hashes the rule ID, escaped instance path, and normalized AST evidence for source findings. Structural findings use their normalized rule evidence. Line numbers are not part of the fingerprint. The input path is part of it only through the instance path: a Luau file's name becomes the script name, and a scanned folder's name becomes the first path segment (`root` for `.`), while the name of a place or model file is not part of it. See [JSON output](json-output.md) for examples. Create the baseline with the same paths that CI scans.

`input_scopes` maps a fingerprint to the inputs where it was reviewed. Before matching, bloxguard removes a leading `./` and trailing separators, uses `/` as the separator, and makes an absolute input relative to the working directory when possible. When the mapping is present, both the fingerprint and normalized input must match. This prevents a reviewed finding in one file from hiding the same finding in another file.

The `input_scopes` field is optional for compatibility with manually written baselines. A baseline that omits it applies every listed fingerprint globally to all input paths. Use that form only when global suppression is deliberate.

Require review for pull requests that change baseline files. A baseline can hide existing findings, so protect it with the same CODEOWNERS review as `bloxguard.toml`.

## Limits

All limit values must be positive. Exceeding a limit makes the affected input partial instead of clean.

| Field | Default | Meaning |
| --- | ---: | --- |
| `max_file_bytes` | 209715200 | Maximum bytes read from one Roblox file or metadata file. This is 200 MiB. |
| `max_instances` | 600000 | Maximum normalized instances and the main directory entry safety scale. |
| `max_script_bytes` | 2097152 | Maximum bytes in one Luau source. This is 2 MiB. |
| `max_depth` | 128 | Maximum depth of value evaluation. Values above 256 are rejected. Reaching it makes the input partial only when a value cut off while the arguments of a call are evaluated reaches `require`, directly, through a wrapper such as `pcall(require, ...)`, through a function that calls `require`, or after a fold such as `tonumber`. It also bounds the `__index` tables searched past the first 8. |
| `max_analysis_steps` | 100000 | Analysis steps allowed for every 8,192 tokens of one source. |
| `max_file_ms` | 30000 | Cooperative time budget for one input, in milliseconds, shared by loading, analysis and inventory. |

The Luau front end checks source size, token count, expression complexity, and nesting before and during analysis. A parser limit produces a partial reason. It does not silently skip the source. A type declaration file is the one exception, see [type declaration files](#type-declaration-files). These caps are fixed: 1,024 nested brackets and blocks, 1,024 operators in one expression plus up to 8,192 `..` concatenations, and 128 nested interpolated strings. The token cap is half of `max_script_bytes`, at least 1,024 tokens.

`max_file_ms` is a soft cooperative limit with one clock per input. Loading the input, analyzing its scripts and listing them in the inventory all use the same budget, and time spent on other inputs does not count. Model files nested in a directory scan use the budget of that directory. bloxguard checks the clock between loading and analysis steps. It does not run each parser in a separate process and cannot stop inside one parser call. A call can finish after the configured time before bloxguard marks the input partial. Once the budget is used up, the remaining steps for that input are skipped, including its inventory entries, and the input is partial, unless it failed for another reason. A directory scan that the budget stops is partial with the reason `time budget of N ms exceeded`, also when it stopped before reading any script. It does not fail with the reason `source tree contains no supported scripts or Roblox model/place files`, which only a walk that did not stop early gives.

The budget counts wall clock time, so a slow disk or antivirus software can use it up. On Windows, the first scan of thousands of freshly written files can take many times longer than later scans while the files are checked: a folder of 20,000 small scripts took about 60 seconds on its first scan and under 3 seconds afterwards on the test machine. Raise `max_file_ms` for very large source trees if a first scan ends partial.

XML input has an additional fixed safe parser limit of 2,048 nested `Item` elements. The count includes the deepest `Item` and no other elements, so a script inside 2,047 folders is still read. All markup together may nest 2,064 elements deep, which leaves room for the `roblox` root, `Properties` and structured values such as `Font` around the deepest `Item`. These limits are not configurable. Exceeding either makes that input partial.

Output also has fixed limits. Each instance path can use up to 1 MiB. A scan returns at most 10,000 findings and 100,000 inventory entries. Finding paths and serialized inventory each have a 32 MiB budget. One script can return up to 256 source findings with an 8 MiB path budget. An input keeps at most 256 detailed incomplete reasons, each truncated to 512 characters, plus a notice about omitted reasons. Reaching any output limit marks the input partial.

The analyzer builds the full instance path of every script it examines. In a chain of nested scripts that work grows with the square of the depth, so the paths of the examined scripts in one input may add up to at most 1 GiB. A script whose path does not fit is skipped, a later script with a shorter path is still examined, and the input is partial with the reason `instance path work limit reached`. Ordinary places stay far below this budget. A chain of 20,000 nested ModuleScripts reaches it after about one second in a release build.

Binary preflight checks declared and actual decompressed sizes, header counts, instance records, property type tags, and common embedded string lengths. It cannot prove that every allocation inside a dependency parser is bounded. These checks reduce malformed input risk; they are not process isolation or an operating system memory limit.

Attributes (`AttributesSerialize`) in all four file formats are decoded by bloxguard itself, not by the file decoders. This includes classes the bundled reflection database does not know. Before decoding, it checks that every declared length and count in the attribute data fits in the bytes that follow and that every value type is known. Attribute data that fails this check or does not decode makes the input partial with a reason that starts with `unreadable attributes on`. The other properties and scripts of the file are still scanned.

Attributes also have fixed caps, which are not configurable:

| Cap | Value |
| --- | ---: |
| Attributes on one instance | 10,000 |
| Attributes in one input | 500,000 |
| Serialized attribute data decoded for one input | 32 MiB |

The attribute count and size are read from the attribute data before it is decoded. An instance whose attributes would pass a cap keeps none of them, and the input is partial with a reason that starts with `attribute limit reached on`. Skipped attributes do not use up any of the budget, so a later instance that still fits is read, and the other properties and scripts of the file are still scanned. A directory scan is one input: attributes from nested model files, `.model.json` and `.model.jsonc` files, and `.meta.json` and `.meta.jsonc` files share its caps. Attributes in an MCP bundle, a JSON model file or a metadata file count toward the first two caps.

## Unknown classes

Roblox files can contain classes newer than the bundled reflection database. An unknown non-script class is listed as an informational diagnostic when its properties remain readable, and the scan can remain complete. The scan is partial when the unknown class may hide source or a property used by a rule. An undecodable `Source`, an unreadable script property, an unreadable value object, or attribute data that does not decode also makes the scan partial.

Studio can also write a property value type that is newer than the file decoders, such as the type 0x23 that current Studio writes on `Terrain` in binary places. The decoders skip such a value. When the class is in the bundled reflection database, cannot hold code, and no rule reads the property, the skipped value is an informational diagnostic that names the class and the property, and the scan can remain complete. It makes the scan partial in every other case: on a script or any other class that can hold code, on `Source` or any property whose name contains `source`, on a property a rule reads (`Name`, `Value`, `Tags`, attributes, shown text such as `Text`, run settings such as `Disabled`, and package fields), on any property of a value object or a `PackageLink`, on a class the reflection database does not know, and in XML on a class or property name that cannot be read as plain text. The same rule applies to binary and XML files.

bloxguard analyzes the source of `Script`, `LocalScript`, and `ModuleScript`. Any other place that can carry code makes the input partial instead of letting it pass unread:

- a nonempty `ProtectedString` property in an XML file, on any class, unless it is the `Source` of one of those three script classes,
- a Rojo style typed `{"ProtectedString": ...}` value in a bundle or model JSON file,
- a string property of an unknown class whose text parses as at least one Luau statement. Shown text such as `Text` is judged as text, because a label like `Press "E"` can parse as a call.

Text that does not tokenize as Luau is not treated as code. The parser only builds a syntax tree. Nothing is executed.

The XML checks read each start tag's attributes in order and compare names without a namespace prefix, as the decoder does, so a `class="..."` written inside another attribute's value does not count. A `ProtectedString` whose `name`, or the `class` of its `Item`, cannot be read as plain text, such as one written with an entity or given twice, makes the input partial.

## Type declaration files

A source that does not parse makes the input partial, with one exception: a type declaration file for luau-lsp, such as the `testez.d.lua` that TestEZ projects keep for their editor. It is recognized by its syntax, not its name. The first parse error must be at the token right after a `declare` that starts a line, and that token must begin a declaration: `declare function name(...)`, `declare name: type`, `declare class Name`, or `declare extern type Name with`. Luau's parser accepts this syntax only with its `allowDeclarationSyntax` option, which is off by default and is meant for type definition files, so such a file does not compile as a script and none of it runs, also code after the declarations. The input stays complete and gets the informational note `type declaration file, not run by Roblox, not scanned` for that script. The file is not scanned.

Anything else that fails to parse stays partial: an error before the first declaration, `declare` after other code on its line, `declare` followed by anything that does not begin a declaration, a declaration that starts with an attribute such as `@checked`, and template files with placeholders such as `{{name}}`.

A method signature or a `declare function` line has no `end`, so the parser safety check counts each one as an open block, and a long declaration file such as the Roblox definitions that luau-lsp generates is over the cap of 1,024 nested blocks. When a whole file is over a parser cap or does not tokenize as Luau, such as a file with a character Luau does not know, like `$`, after its declarations, only the code before its first declaration is checked against every cap and parsed, and it must parse on its own. Then the file gets the same note. Nothing from the first declaration on is parsed, however deep it nests. The file stays partial when the code before the first declaration is over a cap or does not parse without the lines after it, when no `declare` that starts a line begins a declaration, and when the file is larger than `max_script_bytes`.

## Source trees and Rojo

Direct directory scans use Rojo file naming and selected metadata as an approximation. They scan every source file in the tree and do not apply a Rojo project mapping, so instance paths follow the folder layout. Each `*.project.json` or `*.project.jsonc` file is read and checked instead.

Rojo 7.7 accepts the `.jsonc` extension for every JSON file it reads, and direct scans read the same kinds with either extension: `*.model.json` and `*.model.jsonc` models, `<name>.meta.json` and `<name>.meta.jsonc` metadata next to a script file, `init.meta.json` and `init.meta.jsonc` metadata in a folder, and project files. Rojo reads all of them with one JSONC parser, so every one accepts `//` and `/* */` comments and trailing commas, also with comments between a trailing comma and the closing bracket. A `//` comment ends at a line feed, as in Rojo, so text after a lone carriage return stays in the comment. A file Rojo cannot read that way, such as one saved with CR line endings, is read with a carriage return also ending a comment. A block comment without its closing `*/` is not read as a comment to the end of the file. It makes the file unparsable, like a cut off string or a lone `/`. Unquoted keys, single quoted strings and hexadecimal numbers, which Rojo's parser also accepts, make the file unparsable too. A UTF-8 byte order mark at the start of any of these files is ignored, as many Windows editors write one. One anywhere else makes the file unparsable. A model or metadata file that cannot be read or parsed makes the input partial.

Metadata follows Rojo's order. `<name>.meta.json` is applied first and `<name>.meta.jsonc` second. A property the second file names replaces the value from the first, and a nonempty attribute list replaces the whole list. An init script also gets `<folder>/<folder name>.meta.json` and `.meta.jsonc` before `init.meta.json`, as in Rojo. Rojo applies metadata after it reads a script file, so a `Source` property in metadata replaces the file's text. That text is what is scanned, and a note names both files. Rojo before 7.7 reads no `.jsonc` file, so two cases depend on the Rojo version and make the input partial: a `.meta.jsonc` file next to a `.meta.json` file for the same instance, and a `.meta.jsonc` file that sets `Source` for a script file. A `.model.json` and a `.model.jsonc` file with the same name are two instances, as in Rojo.

Rojo also builds instances from data files: plain `.json` and `.jsonc` files and `.toml` and `.yaml` files become ModuleScripts that return the data, `.txt` files become StringValues and `.csv` files become LocalizationTables. Direct scans do not read data files. Metadata that Rojo applies to one of them makes the input partial when it sets a rule input, such as `Source`, `Value` or attributes, because it changes an instance the scan does not see.

A project file adds one informational note to the input. It makes the input partial when it pulls in something the direct scan cannot see:

- a `$path` that leaves the scanned folder, by `..`, an absolute path, or a link,
- a `$path` inside an excluded folder such as `node_modules` that exists in the checkout,
- inline `$properties` that rules read, such as `Source`, `Value`, `LinkedSource`, `RunContext`, package link fields, shown text, or `Attributes`,
- nonempty inline `$attributes`,
- a file that cannot be read, cannot be parsed, or has no `tree` object.

Ordinary inline properties such as `Ambient`, `FilteringEnabled`, or part sizes are not rule inputs and stay notes. A `$path` that does not exist in the checkout, such as `Packages` before `wally install`, is named in a note, because there is nothing there to scan. Run the step that creates it first if it holds code.

A roblox-ts project that maps `node_modules/@rbxts` stays partial after `npm install`. Passing `node_modules` as another input, as in `bloxguard scan . node_modules`, scans that code, but the project folder's input stays partial and the exit code is 2. Build with Rojo and scan the output, or pass `--allow-incomplete` once you have reviewed the reasons.

Directory scans exclude `.git`, `.hg`, `.svn`, `.cargo-home`, `target`, and `node_modules`. These are outside the default source scan scope. Pass an excluded directory explicitly if you need to inspect it. Symlinks and reparse points are refused and make the input incomplete.

For full Rojo fidelity, run `rojo build` in your own CI and scan the resulting `.rbxl`, `.rbxlx`, `.rbxm`, or `.rbxmx` file.
