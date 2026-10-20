#!/usr/bin/env python3
"""Fetch and scan the pinned clean corpus inside GitHub Actions only.

Each project checkout is scanned as one directory tree, `bloxguard scan <checkout>`,
the way users and the GitHub Action scan a project, so `script.Parent` paths
resolve inside the project. Every finding is a candidate false positive until a
person reviews it.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, NoReturn


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ALLOWED_LICENSES = {"Apache-2.0", "MIT"}
RULE_IDS = [f"BG{number:03d}" for number in range(1, 13)]
SOURCE_CORPUS_RULES = {
    "BG001",
    "BG003",
    "BG004",
    "BG005",
    "BG007",
    "BG008",
    "BG009",
    "BG012",
}
DOM_CONTEXT_RULES = set(RULE_IDS) - SOURCE_CORPUS_RULES
MAX_DETAILS = 500
# One checkout is one scan input, and `max_file_ms` is the time budget of one input,
# shared by loading, analysis and inventory. The default of 30 seconds is a safety
# limit for interactive use. A large monorepo on a shared runner can need longer, and
# a budget stop would make the result partial for a reason that says nothing about the
# code, so this measurement raises it. The workflow's job timeout still bounds the run.
MAX_FILE_MS = 300_000
CORPUS_CONFIG = f"""\
# Clean corpus measurement: each project checkout is one input.
[limits]
max_file_ms = {MAX_FILE_MS}
"""


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def run(command: list[str], *, cwd: pathlib.Path, env: dict[str, str]) -> None:
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=cwd, env=env, check=False)
    if completed.returncode != 0:
        fail(f"Command failed with exit code {completed.returncode}: {command[0]}")


def report_inputs(report: dict[str, Any]) -> list[dict[str, Any]]:
    inputs = report.get("inputs")
    return [item for item in inputs if isinstance(item, dict)] if isinstance(inputs, list) else []


def finding_detail(finding: dict[str, Any], tree_name: str) -> dict[str, Any]:
    """The fields needed to judge one candidate false positive. `input` is the file
    relative to the repository, or the repository itself for a finding without one."""
    keys = ("rule_id", "severity", "confidence", "instance_path", "location", "message")
    detail = {key: finding.get(key) for key in keys if key in finding}
    source_file = str(finding.get("source_file") or "").replace("\\", "/")
    prefix = f"{tree_name}/"
    if source_file.startswith(prefix):
        source_file = source_file[len(prefix) :]
    detail["input"] = source_file or "."
    detail["evidence"] = str(finding.get("evidence", ""))[:300]
    return detail


def note_detail(diagnostic: dict[str, Any]) -> str:
    """An informational note, such as a type declaration file, with its script."""
    message = str(diagnostic.get("message", ""))
    instance_path = diagnostic.get("instance_path")
    return (f"{message} ({instance_path})" if instance_path else message)[:500]


def check_checkout(checkout: pathlib.Path) -> int:
    """Refuse a checkout with symlinks anywhere, and count its Lua and Luau files."""
    sources = 0
    for root, directories, names in os.walk(checkout, followlinks=False):
        root_path = pathlib.Path(root)
        for name in directories + names:
            candidate = root_path / name
            if candidate.is_symlink():
                fail(f"Corpus checkout contains a symlink: {candidate.relative_to(checkout)}")
        sources += sum(1 for name in names if pathlib.Path(name).suffix.lower() in {".lua", ".luau"})
    return sources


def fetch_checkout(
    project: dict[str, Any],
    checkout: pathlib.Path,
    metadata_destination: pathlib.Path,
    empty_hooks: pathlib.Path,
    environment: dict[str, str],
) -> None:
    """Check out the pinned commit without hooks, submodules or LFS content, then move
    the Git metadata out of the scan root."""
    repository = project["repository"]
    run(["git", "init", "--quiet"], cwd=checkout, env=environment)
    run(["git", "remote", "add", "origin", project["url"]], cwd=checkout, env=environment)
    run(
        [
            "git",
            "-c",
            "protocol.version=2",
            "fetch",
            "--quiet",
            "--depth=1",
            "--no-tags",
            "origin",
            project["commit"],
        ],
        cwd=checkout,
        env=environment,
    )
    run(
        [
            "git",
            "-c",
            f"core.hooksPath={empty_hooks}",
            "checkout",
            "--quiet",
            "--detach",
            "FETCH_HEAD",
        ],
        cwd=checkout,
        env=environment,
    )
    actual_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=checkout, env=environment, text=True
    ).strip()
    if actual_commit != project["commit"]:
        fail(f"Checked out the wrong commit for {repository}.")
    git_metadata = checkout / ".git"
    if not git_metadata.is_dir():
        fail(f"Git metadata is missing for {repository}.")
    git_metadata.rename(metadata_destination)


def scan_checkout(
    scanner: pathlib.Path,
    config_path: pathlib.Path,
    checkout: pathlib.Path,
    report_path: pathlib.Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    """Scan one checkout as one directory tree, as users and the Action scan a
    project, and summarize the report."""
    tree_name = checkout.name
    source_file_count = check_checkout(checkout)
    if not source_file_count:
        fail(f"No Lua or Luau source files found in {tree_name}.")
    command = [
        str(scanner),
        "scan",
        tree_name,
        "--config",
        str(config_path),
        "--format",
        "json",
        "--output",
        str(report_path),
        "--fail-on",
        "critical",
    ]
    print("+ bloxguard scan", tree_name, flush=True)
    started = time.monotonic()
    # Scanning the relative tree name keeps `source_file` in findings repository relative.
    scan = subprocess.run(command, cwd=checkout.parent, env=environment, check=False)
    scan_seconds = round(time.monotonic() - started, 1)
    # Exit code 2 is an incomplete scan. It is recorded with its reasons, because a
    # partial result on ordinary code is itself something the evaluation has to show.
    if scan.returncode not in (0, 1, 2):
        fail(f"BloxGuard failed for {tree_name} with exit code {scan.returncode}.")
    if not report_path.is_file():
        fail(f"BloxGuard did not write JSON for {tree_name}.")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    inputs = report_inputs(report)
    reasons = [str(reason)[:500] for item in inputs for reason in item.get("reasons") or []]
    notes = [
        note_detail(diagnostic)
        for item in inputs
        for diagnostic in item.get("diagnostics") or []
        if isinstance(diagnostic, dict)
    ]
    findings = [finding for finding in report.get("findings") or [] if isinstance(finding, dict)]
    counts: collections.Counter[str] = collections.Counter()
    for finding in findings:
        rule_id = finding.get("rule_id")
        counts[rule_id if isinstance(rule_id, str) and rule_id else "UNKNOWN"] += 1
    return {
        "source_file_count": source_file_count,
        "script_count": sum(int(item.get("script_count") or 0) for item in inputs),
        "completeness": str(report.get("completeness", "unknown")),
        "scan_seconds": scan_seconds,
        "incomplete_reason_count": len(reasons),
        "incomplete_reasons": reasons[:MAX_DETAILS],
        "informational_notes": notes[:MAX_DETAILS],
        "finding_count": len(findings),
        "counts_by_rule": dict(sorted(counts.items())),
        "findings": [finding_detail(finding, tree_name) for finding in findings[:MAX_DETAILS]],
    }


def markdown_summary(result: dict[str, Any]) -> str:
    lines = [
        "# Clean corpus evaluation",
        "",
        "All findings are candidate false positives. This run does not prove intent and must not be used to accuse a project or its authors.",
        "",
        f"Each project checkout was scanned as one directory tree with `max_file_ms = {result['max_file_ms']}`.",
        "",
        f"BloxGuard commit: `{result['bloxguard_commit']}`",
        "",
        f"Corpus manifest SHA-256: `{result['manifest_sha256']}`",
        "",
        "## Counts by rule",
        "",
        "| Rule | Candidate findings | Corpus coverage |",
        "| --- | ---: | --- |",
    ]
    for rule in RULE_IDS:
        if rule in SOURCE_CORPUS_RULES:
            lines.append(
                f"| {rule} | {result['totals_by_rule'].get(rule, 0)} | Source trees |"
            )
        elif result["totals_by_rule"].get(rule):
            lines.append(
                f"| {rule} | {result['totals_by_rule'][rule]} | Source trees (rule mostly needs a place file) |"
            )
        else:
            lines.append(f"| {rule} | Not measured | Needs a place file |")
    unknown_count = sum(
        count
        for rule, count in result["totals_by_rule"].items()
        if rule not in RULE_IDS
    )
    if unknown_count:
        lines.append(f"| Other or unknown | {unknown_count} |")
    lines.extend(
        [
            "",
            "## Counts by repository",
            "",
            "| Repository | Commit | Lua and Luau files | Scripts scanned | Scan status "
            "| Seconds | Candidate findings |",
            "| --- | --- | ---: | ---: | --- | ---: | ---: |",
        ]
    )
    for project in result["projects"]:
        lines.append(
            f"| {project['repository']} | `{project['commit'][:12]}` | {project['source_file_count']} | "
            f"{project['script_count']} | {project['completeness']} | {project['scan_seconds']} | "
            f"{project['finding_count']} |"
        )
    partial = [project for project in result["projects"] if project["completeness"] != "complete"]
    if partial:
        lines.extend(["", "## Incomplete scans", ""])
        for project in partial:
            lines.append(
                f"- {project['repository']}: {project['incomplete_reason_count']} reasons, for example:"
            )
            for reason in project["incomplete_reasons"][:5]:
                lines.append(f"  - {reason.replace('|', '/').replace(chr(10), ' ')}")
    serious = [
        (project["repository"], finding)
        for project in result["projects"]
        for finding in project["findings"]
        if finding.get("severity") in ("critical", "high", "medium")
    ]
    if serious:
        lines.extend(
            [
                "",
                "## Medium, high and critical candidates",
                "",
                "| Repository | Rule | Severity | Confidence | File | Evidence |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for repository, finding in serious[:100]:
            evidence = str(finding.get("evidence", ""))[:120].replace("|", "/").replace("\n", " ")
            lines.append(
                f"| {repository} | {finding.get('rule_id')} | {finding.get('severity')} | "
                f"{finding.get('confidence')} | `{finding.get('input')}` | `{evidence}` |"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--scanner", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--summary", required=True, type=pathlib.Path)
    args = parser.parse_args()

    if os.environ.get("GITHUB_ACTIONS") != "true":
        fail("The clean corpus may run only in GitHub Actions.")
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        fail("RUNNER_TEMP is required.")
    if not args.scanner.is_file():
        fail(f"Scanner does not exist: {args.scanner}")

    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    projects = manifest.get("projects")
    if not isinstance(projects, list) or not 10 <= len(projects) <= 20:
        fail("The corpus must contain 10 to 20 projects.")

    seen: set[str] = set()
    for project in projects:
        repository = project.get("repository", "")
        if not REPOSITORY_RE.fullmatch(repository) or repository.split("/")[1] in {".", ".."}:
            fail(f"Invalid repository name: {repository!r}")
        if repository.lower() in seen:
            fail(f"Duplicate repository: {repository}")
        seen.add(repository.lower())
        if not COMMIT_RE.fullmatch(project.get("commit", "")):
            fail(f"Commit must be a full SHA for {repository}.")
        if project.get("license") not in ALLOWED_LICENSES:
            fail(f"License is not permitted for {repository}.")
        expected_url = f"https://github.com/{repository}"
        if project.get("url") != expected_url:
            fail(f"Repository URL does not match the repository name for {repository}.")

    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    totals: collections.Counter[str] = collections.Counter()
    project_results: list[dict[str, Any]] = []

    temp_parent = pathlib.Path(runner_temp).resolve()
    with tempfile.TemporaryDirectory(prefix="bloxguard-clean-corpus-", dir=temp_parent) as temp:
        temp_root = pathlib.Path(temp)
        empty_hooks = temp_root / "empty-hooks"
        empty_hooks.mkdir()
        # Outside every checkout, and passed explicitly, so a `bloxguard.toml` in a
        # project is never read.
        config_path = temp_root / "corpus-bloxguard.toml"
        config_path.write_text(CORPUS_CONFIG, encoding="utf-8")
        for index, project in enumerate(projects):
            repository = project["repository"]
            # The tree root is named after the repository, so instance paths read
            # `/Fusion/src/...`.
            checkout = temp_root / f"project-{index:02d}" / repository.split("/")[1]
            checkout.mkdir(parents=True)
            fetch_checkout(
                project,
                checkout,
                temp_root / f"git-metadata-{index:02d}",
                empty_hooks,
                environment,
            )
            scanned = scan_checkout(
                args.scanner.resolve(),
                config_path,
                checkout,
                temp_root / f"report-{index:02d}.json",
                environment,
            )
            # Rules that usually need a place file can still fire on source
            # (BG002 reads a `.Value` or attribute in code). They are counted
            # and listed like every other candidate instead of stopping the run.
            totals.update(scanned["counts_by_rule"])
            project_results.append(
                {
                    "repository": repository,
                    "commit": project["commit"],
                    "license": project["license"],
                    **scanned,
                }
            )

    result = {
        "schema_version": 2,
        "classification": "candidate_false_positives",
        "evaluation_scope": "project_checkouts_scanned_as_one_directory_tree",
        "max_file_ms": MAX_FILE_MS,
        "measured_rules": sorted(SOURCE_CORPUS_RULES),
        "not_measured_rules": sorted(DOM_CONTEXT_RULES),
        "warning": "These counts do not prove intent and must not be used to accuse a project or its authors.",
        "bloxguard_commit": os.environ.get("GITHUB_SHA", "unknown"),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "totals_by_rule": dict(sorted(totals.items())),
        "projects": project_results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = markdown_summary(result)
    args.summary.write_text(summary, encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
