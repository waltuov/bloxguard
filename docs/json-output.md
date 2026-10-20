# JSON output

An input can include an optional `diagnostics` array. Each informational diagnostic has `level: "info"`, a `message`, and an optional `instance_path`. For example, a harmless class newer than the bundled reflection data can be listed here while the input remains complete, and so can a type declaration file, with the message `type declaration file, not run by Roblox, not scanned` and the script's `instance_path`. Informational diagnostics do not count as security findings or change the exit code. Diagnostics that indicate unreadable code or rule-relevant data remain incomplete reasons.

`bloxguard scan --format json` writes one scan report. The format has a version so consumers can reject incompatible changes. Version 1 is described by [`json-output.schema.json`](json-output.schema.json).

The top level fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | The JSON contract version. Version 1 is the only value in bloxguard 0.1. |
| `tool` and `version` | The scanner name and release version. |
| `completeness` | `complete`, `partial`, or `failed`. A report with no findings is not a pass unless this is `complete`. |
| `inputs` | One status record for each requested input. Reasons explain every partial or failed input. |
| `inventory` | Every script found, without its source text. It includes the instance path, class, source size, and source hash when available. |
| `findings` | Findings with stable fingerprints and short evidence. |
| `suppressed_count` | Findings hidden by configured suppressions. |
| `baseline_count` | Findings hidden because their fingerprint and optional input scope matched the baseline. |

Each finding has a rule ID, severity, confidence, input, escaped instance path, location, message, truncated evidence, and fingerprint. Evidence keeps the spelling of the source, including quotes, backslashes, and printable non-ASCII text. Only control characters, bidirectional controls, line separators, and invisible format characters are escaped, as `\n`, `\t`, `\r`, or `\u{...}`. Evidence stops at 180 characters or 300 bytes and then ends with `...`. An escape is never cut in half. `source_file` names the script's own `.lua` or `.luau` file, whose lines `location` counts, or the label given to an MCP tool. A script inside a place, model, JSON model or metadata file has no `source_file`. In a folder scan, the optional `container_file` names the nested place, model, `.model.json` or `.meta.json` file (also in their `.jsonc` forms) that holds the finding's script or object, and the location's lines count lines of the script, not of that file. A place or model file scanned on its own is named by `input`. A source location can use line and column ranges. A property finding can use `property` or `attribute`. `related_locations` records where a resolved value came from.

The fingerprint hashes length-prefixed rule ID, instance path, and normalized evidence fields. Source findings use normalized evidence derived from the parsed Luau AST. Line numbers are not part of it, so moving unrelated lines does not change it. The input path is not hashed, but it can be part of the instance path:

- The name of a place or model file is not in the instance path, so renaming or moving the file keeps its fingerprints.
- A Luau file's name becomes the script name: `FAKE_loader.server.luau` is `/FAKE_loader`. Renaming the file changes its fingerprints. The folders above a file scanned on its own do not.
- A scanned folder's name becomes the first path segment: `bloxguard scan game` gives `/game/...` and `bloxguard scan .` gives `/root/...`. Scanning the same tree under another name, or scanning a subfolder, changes the fingerprints.

Path globs in suppressions match the instance path too. Scan with the same paths in CI as when you created a baseline or wrote a suppression.

Arrays are sorted before serialization. Object keys and whitespace are stable. Scanning the same inputs with the same configuration produces byte identical JSON. The report contains no timestamp.

Consumers should check both `schema_version` and `completeness`. They should not infer safety from an empty `findings` array when a scan is partial or failed.

Example:

```json
{
  "baseline_count": 0,
  "completeness": "complete",
  "findings": [],
  "inputs": [
    {
      "completeness": "complete",
      "input": "src",
      "instance_count": 3,
      "reasons": [],
      "script_count": 2
    }
  ],
  "inventory": [],
  "schema_version": 1,
  "suppressed_count": 0,
  "tool": "bloxguard",
  "version": "0.1.0-rc.1"
}
```

Source code is never included in the report. Evidence is a short escaped excerpt and can still contain project data. Treat reports according to the sensitivity of the scanned project.
