# MCP setup and workflow

bloxguard can run as a read-only MCP server over standard input and output. It does not make network requests. It never runs source passed to it.

The examples need the bloxguard binary. [Command line](cli.md#install) describes how to install it.

## Start the server

Give the server every directory that its file tools may read:

```sh
bloxguard mcp --root C:\path\to\project --root C:\path\to\review
```

`scan_path` and `inventory` require absolute paths and refuse paths outside those roots. They also reject a requested root, requested path, or traversed child that is a symbolic link, junction, or Windows reparse point. They do not resolve link targets.

The root check comes first and uses only the path text, so a path outside the roots gets the same answer whether or not it exists. `.` and `..` are resolved in the text before the check. Spell the path from the same root you passed to `--root`. Letter case does not matter on Windows, but a short 8.3 name for the root does not match it. On Windows, names that end with a dot or space and names that contain `:` are refused, because Windows would open a different name than the one checked. Inside a root, the server inspects each folder from the root down and stops at the first link or junction, so it never inspects a path through a link.

The `scan_source` and `scan_bundle` tools analyze request data without reading a file. Root limits still apply to the file tools.

## Tools

### `scan_path(path)`

Scans a supported Roblox file or a Luau source tree. The result uses the same JSON report as `bloxguard scan --format json`.

### `inventory(path)`

Lists every script with its instance path, class, run context, enabled state, byte size, SHA-256, and source file when known. Read the completeness field before trusting the inventory.

### `explain_rule(id)`

Returns metadata and review guidance for a rule such as `BG002`.

### `scan_source(source, path?, class?)`

Scans one Luau source string. `path` labels the input and `class` supplies script context. Neither value grants file access.

### `scan_bundle(bundle)`

Scans a JSON snapshot of an instance subtree. The snapshot can include scripts, attributes, tags, and value objects. This lets property resolution work on content copied from Studio. See [bundle format](bundle.md).

All scan results include a completeness state. `partial` or `failed` means some content was not analyzed.

The tools use the built-in defaults. They read no `bloxguard.toml`, neither from the scanned project nor from the server's working directory, and `bloxguard mcp` has no option to pass one. Every rule runs at its default severity, with no trusted IDs, suppressions or baseline, and with the default limits. A finding that your configuration suppresses in the CLI still appears here.

## Requests the server cannot read

The server reads one JSON-RPC message per line. A line it cannot decode gets an error reply, and the server keeps serving:

- `-32700 Parse error` when the line is not JSON. Examples are a cut off line, invalid UTF-8, a lone surrogate escape such as `\ud800`, or nesting deeper than the decoder allows (about 128 levels).
- `-32600 Invalid request` when the line is JSON but not a message, such as a known method with parameters of the wrong shape. A notification, which is an object with a string `method` and no `id`, gets no reply, because JSON-RPC never answers notifications.
- `-32600 Invalid request` without an `id` when the line has an `id` member that is not a string or an integer that fits in a signed 64 bit integer, or has two `id` members. Valid integers run from `-9223372036854775808` to `9223372036854775807`. Examples of refused ids are an object, an array, `true`, `null`, `1.5`, `1.0`, `1e2`, `9223372036854775808`, and `18446744073709551615`. `-0` is refused too, because the decoder reads it as a fraction; send `0` instead. A line with an `id` member is never treated as a notification.

The reply carries the request `id` when the server can read it from the top level of the line, so the client can fail that request at once. An `id` counts only when its value is complete and is followed by `,` or `}`. When there is no readable `id`, or more than one, the reply has no `id` member, as the MCP specification asks. The `data` member says what the decoder rejected.

Error replies do not repeat long request text. The message and a string `data` member of a JSON-RPC error, and the text of a tool error result, keep at most their first 256 bytes, followed by `... (cut from N bytes)`. This covers method names, rule IDs, paths, and argument names.

A request line may hold at most 64 MiB. A longer line gets one `-32600 Request too large` reply, and then the server closes the connection and exits. Tool arguments have smaller limits: source text up to 2 MiB and bundles up to 8 MiB once encoded.

## Claude Code

After installing the binary, add the server for your user with the Claude Code CLI. The user scope makes it available in all your projects and keeps your paths out of the repository. Replace the example paths with absolute paths on your machine. Everything after `--` is the server command. In PowerShell, write it as `'--'`, because a `claude` installed with npm runs through a PowerShell script that drops a bare `--`:

```powershell
claude mcp add --transport stdio --scope user bloxguard '--' 'C:\path\to\bloxguard.exe' mcp --root 'C:\path\to\project'
```

A `.mcp.json` file in the project root is the project scope instead. It is meant to be checked in, so everyone who uses the repository gets the same server, and its paths must work on each of their machines:

```json
{
  "mcpServers": {
    "bloxguard": {
      "command": "C:\\path\\to\\bloxguard.exe",
      "args": ["mcp", "--root", "C:\\path\\to\\project"]
    }
  }
}
```

Review `.mcp.json` before you commit it. Local paths can reveal usernames and folder layouts.

## Codex

Add a local server entry to your Codex configuration. Replace the example paths.

```toml
[mcp_servers.bloxguard]
command = 'C:\path\to\bloxguard.exe'
args = ['mcp', '--root', 'C:\path\to\project']
```

Restart the client after changing its MCP configuration.

## Cursor

Add `.cursor/mcp.json` to the project, or `~/.cursor/mcp.json` in your home directory for every project. Replace the example paths.

```json
{
  "mcpServers": {
    "bloxguard": {
      "type": "stdio",
      "command": "C:\\path\\to\\bloxguard.exe",
      "args": ["mcp", "--root", "C:\\path\\to\\project"]
    }
  }
}
```

## Agent instructions

Give an agent a clear review rule. One useful instruction is:

```text
Before keeping Roblox content, call bloxguard. Treat partial or failed analysis as unresolved. Show every finding to the user. Do not keep flagged inserted content unless the user reviews the finding and decides to keep it. Never execute source to test whether it is safe.
```

## Studio asset workflow

1. Insert the asset in Studio.
2. Select the inserted root instance.
3. Review [snapshot.luau](snapshot.luau), then run it through Studio's Luau execution tool.
4. Copy only the JSON printed by the snippet.
5. Pass the JSON object to `scan_bundle`.
6. Check the completeness state and findings.
7. Remove flagged content unless the user makes an informed decision to keep it.

The snippet reads the selected subtree. It does not call scripts, require modules, change instances, save the place, or make network requests. It has bounded instance and source limits. Exceeding a limit stops the export and reports an error instead of returning a shortened snapshot.

## Result handling

Do not reduce a report to a pass or fail label. Show the rule ID, severity, confidence, instance path, message, and completeness state. Use `explain_rule` when a finding is unfamiliar.

A complete report covers the data supplied to bloxguard. It does not cover content fetched later or source that Studio did not expose.
