# Security policy

## Supported version

Security fixes go into the latest release. Today that is the pre-release 0.1.0-rc.2.

## Report a scanner bypass privately

Do not publish a working bypass, payload, real asset ID, or creator allegation. Use **Report a vulnerability** on the repository's [**Security** tab](https://github.com/waltuov/bloxguard/security) to share details privately.

Include the bloxguard version, input format, expected rule, actual result, and the smallest defanged reproduction you can make. Replace real IDs with the fake range `999000000000000` through `999999999999999`. Replace webhook URLs with `https://discord.com/api/webhooks/000/FAKE`. Remove creator, account, game, and asset names.

Do not send live malicious files. A synthetic source fragment or a fixture generator is preferred.

## Report a malicious Roblox asset

Use Roblox's reporting process for suspected malicious assets. Do not accuse a creator publicly based only on a bloxguard finding. Findings identify patterns that need review. They do not prove intent.

## Scanner safety model

bloxguard parses files and text. It never runs scanned Luau. The MCP server is read-only, makes no network requests, and limits file access to roots supplied by the user. Its file tools reject symbolic links, junctions, and Windows reparse points. A partial or failed input cannot silently pass as complete.

Scan stable trees. Root validation is not an operating system sandbox and cannot eliminate a race with another process replacing files during a scan. Parser time limits are cooperative. See [resource limits](docs/configuration.md#limits) for the remaining dependency parser limitations.
