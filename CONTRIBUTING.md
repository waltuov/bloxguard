# Contributing

bloxguard is developed at [github.com/waltuov/bloxguard](https://github.com/waltuov/bloxguard). Open an issue for a bug or a false positive, and a pull request for a fix. Report a way past the scanner privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Safety rules

Never add real malware, Creator Store downloads, plugins, place files, creator names, account names, or real asset IDs. Fixtures must be synthetic and inert. Use names containing `FAKE`, asset IDs from `999000000000000` through `999999999999999`, and the webhook string `https://discord.com/api/webhooks/000/FAKE`.

Never execute scanned content. Tests may parse source and object data. They must not run Luau, emulate `loadstring`, call webhooks, or make network requests.

The clean corpus workflow may fetch pinned open source repositories only in GitHub Actions. Do not run it on a contributor workstation.

## Local setup

Use stable Rust 1.96 or newer. Dependencies come from crates.io and stay pinned in `Cargo.lock`.

```sh
cargo build --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo doc --workspace --no-deps --locked
```

Do not use scanned fixtures as build scripts, test programs, or shell input.

## Changes

Keep loading, analysis, and reporting deterministic. Unknown data and parser failures must produce a partial or failed result instead of a clean pass. Avoid recursive instance traversal because input nesting is attacker controlled.

Each rule change needs at least two synthetic matching fixtures and two clean look-alikes. Update the rule page, snapshots, and evaluation table. Explain false positives and show how to suppress the rule with a reason.

Run focused tests while working, then run the full commands above. In the pull request description, say what you changed, how you checked it, and anything that is still open.

## Public text

Use short, plain sentences. Do not use hype, em dashes, en dashes, real creator names, or allegations. Findings describe observable behavior and uncertainty.

## License

Unless stated otherwise, contributions are licensed under MIT OR Apache-2.0.
