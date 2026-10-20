//! Deterministic renderers for terminal, JSON and SARIF output.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::model::Completeness;
use crate::report::ScanReport;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// Serialize the public report format. Arrays whose order has no semantic meaning
/// are sorted here so callers do not have to prepare a report in a special order.
pub fn json(report: &ScanReport) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(report)?;
    normalize_report(&mut value);
    serde_json::to_string_pretty(&value)
}

/// Render a concise, stable terminal report. Color is deliberately a CLI concern
/// because this function is also used by tests, files and MCP clients.
pub fn human(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} {} scan: {}\n",
        terminal_text(&report.tool),
        terminal_text(&report.version),
        completeness(report.completeness)
    ));

    let mut inputs: Vec<_> = report.inputs.iter().collect();
    inputs.sort_by(|a, b| a.input.cmp(&b.input));
    for input in inputs {
        out.push_str(&format!(
            "\n{} [{}]\n  {} {}, {} {}\n",
            terminal_text(&input.input),
            completeness(input.completeness),
            input.instance_count,
            plural(input.instance_count, "instance", "instances"),
            input.script_count,
            plural(input.script_count, "script", "scripts")
        ));
        let mut reasons = input.reasons.clone();
        reasons.sort();
        reasons.dedup();
        for reason in reasons {
            out.push_str(&format!("  incomplete: {}\n", terminal_text(&reason)));
        }
        let mut diagnostics: Vec<_> = input.diagnostics.iter().collect();
        diagnostics
            .sort_by(|a, b| (&a.instance_path, &a.message).cmp(&(&b.instance_path, &b.message)));
        for diagnostic in diagnostics {
            out.push_str(&format!(
                "  info: {}{}\n",
                terminal_text(&diagnostic.message),
                diagnostic
                    .instance_path
                    .as_ref()
                    .map_or(String::new(), |path| format!(" ({})", terminal_path(path)))
            ));
        }

        let mut findings: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.input == input.input)
            .collect();
        findings.sort_by_key(|finding| finding_key(finding));
        for finding in findings {
            out.push_str(&format!(
                "  [{}, {} confidence] {} {}\n    {}{}\n    evidence: {}\n    fingerprint: {}\n",
                finding.severity,
                confidence(finding.confidence),
                terminal_text(&finding.rule_id),
                terminal_text(&finding.message),
                terminal_path(&finding.instance_path),
                display_location(finding),
                terminal_text(&finding.evidence),
                terminal_text(&finding.fingerprint)
            ));
        }
    }

    let counts = severity_counts(&report.findings);
    out.push_str(&format!(
        "\n{} {}: {} critical, {} high, {} medium, {} low",
        report.findings.len(),
        plural(report.findings.len(), "finding", "findings"),
        counts[3],
        counts[2],
        counts[1],
        counts[0]
    ));
    if report.suppressed_count > 0 || report.baseline_count > 0 {
        out.push_str(&format!(
            "; {} suppressed, {} in baseline",
            report.suppressed_count, report.baseline_count
        ));
    }
    out.push('\n');
    out
}

/// Render the script inventory without exposing source text.
pub fn inventory_human(report: &ScanReport) -> String {
    let mut rows: Vec<_> = report.inventory.iter().collect();
    rows.sort_by(|a, b| {
        (&a.input, &a.instance_path, &a.class, &a.source_file).cmp(&(
            &b.input,
            &b.instance_path,
            &b.class,
            &b.source_file,
        ))
    });

    let mut out = format!(
        "{} {}\n",
        rows.len(),
        plural(rows.len(), "script", "scripts")
    );
    for script in rows {
        let context = script
            .run_context
            .as_ref()
            .map(compact_value)
            .unwrap_or_else(|| "unknown".into());
        let enabled = script
            .enabled
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into());
        let hash = script.sha256.as_deref().unwrap_or("unavailable");
        out.push_str(&format!(
            "\n{}\n  input: {}\n  class: {}\n  run context: {}\n  enabled: {}\n  size: {} bytes\n  sha256: {}\n",
            terminal_path(&script.instance_path),
            terminal_text(&script.input),
            terminal_text(&script.class),
            terminal_text(&context),
            enabled,
            script.size_bytes,
            terminal_text(hash)
        ));
        if let Some(file) = &script.source_file {
            out.push_str(&format!("  source: {}\n", terminal_text(file)));
        }
    }
    for input in &report.inputs {
        for diagnostic in &input.diagnostics {
            out.push_str(&format!(
                "  info: {}: {}\n",
                terminal_text(&input.input),
                terminal_text(&diagnostic.message)
            ));
        }
    }
    out
}

/// Serialize SARIF 2.1.0. No timestamps or machine-specific execution data are
/// emitted, which keeps repeated scans byte identical.
pub fn sarif(report: &ScanReport) -> Result<String, serde_json::Error> {
    let mut rules: Vec<_> = crate::rules::all().iter().collect();
    rules.sort_by(|a, b| a.id.cmp(b.id));
    let rule_indices: BTreeMap<_, _> = rules
        .iter()
        .enumerate()
        .map(|(index, rule)| (rule.id, index))
        .collect();

    // GitHub filters results by the `security` tag. `security-severity` is
    // left out on purpose: GitHub reads it from the rule and shows it in place
    // of each result's level, so every result of a rule would show the rule's
    // default severity, such as a low BG001 or BG004 finding shown as high.
    let sarif_rules: Vec<_> = rules
        .into_iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "name": rule.name,
                "shortDescription": { "text": rule.description },
                "fullDescription": { "text": rule.description },
                "help": { "text": rule.help, "markdown": rule.help },
                "defaultConfiguration": { "level": sarif_level(rule.default_severity) },
                "properties": {
                    "defaultSeverity": rule.default_severity.to_string(),
                    "confidence": confidence(rule.confidence),
                    "documentation": rule.help_uri,
                    "tags": ["security"]
                }
            })
        })
        .collect();

    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by_key(|finding| finding_key(finding));
    let results: Vec<_> = findings
        .into_iter()
        .map(|finding| sarif_result(finding, rule_indices.get(finding.rule_id.as_str()).copied()))
        .collect();

    let mut notifications = Vec::new();
    let mut inputs: Vec<_> = report.inputs.iter().collect();
    inputs.sort_by(|a, b| a.input.cmp(&b.input));
    for input in inputs {
        let mut reasons = input.reasons.clone();
        reasons.sort();
        reasons.dedup();
        for reason in reasons {
            notifications.push(json!({
                "level": if input.completeness == Completeness::Failed { "error" } else { "warning" },
                "message": { "text": format!("{}: {}", input.input, reason) },
                "properties": {
                    "input": input.input,
                    "completeness": completeness(input.completeness)
                }
            }));
        }
    }

    for input in &report.inputs {
        let mut diagnostics: Vec<_> = input.diagnostics.iter().collect();
        diagnostics
            .sort_by(|a, b| (&a.instance_path, &a.message).cmp(&(&b.instance_path, &b.message)));
        for diagnostic in diagnostics {
            notifications.push(json!({"level":"note", "message":{"text":format!("{}: {}",input.input,diagnostic.message)}, "properties":{"input":input.input,"instancePath":diagnostic.instance_path}}));
        }
    }
    let mut invocation = Map::new();
    invocation.insert(
        "executionSuccessful".into(),
        Value::Bool(report.completeness == Completeness::Complete),
    );
    invocation.insert(
        "properties".into(),
        json!({
            "completeness": completeness(report.completeness),
            "suppressedCount": report.suppressed_count,
            "baselineCount": report.baseline_count
        }),
    );
    if !notifications.is_empty() {
        invocation.insert(
            "toolExecutionNotifications".into(),
            Value::Array(notifications),
        );
    }

    let value = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": report.tool,
                "semanticVersion": report.version,
                "rules": sarif_rules
            }},
            "invocations": [Value::Object(invocation)],
            "results": results
        }]
    });
    serde_json::to_string_pretty(&value)
}

fn sarif_result(finding: &Finding, rule_index: Option<usize>) -> Value {
    // A script without a source file of its own is embedded in a place or
    // model file, a JSON model or metadata: the scanned file, or in a folder
    // scan the nested file that holds it. Its line numbers count lines of the
    // script, not of that file, so the location has no region. The script's
    // position goes in the message and a property.
    let embedded = finding.source_file.is_none();
    let uri = path_uri(
        finding
            .source_file
            .as_deref()
            .or(finding.container_file.as_deref())
            .unwrap_or(&finding.input),
    );
    let mut physical = json!({ "artifactLocation": { "uri": uri } });
    let region = sarif_region(&finding.location);
    if let Some(region) = region.as_ref().filter(|_| !embedded) {
        physical
            .as_object_mut()
            .expect("physical location is an object")
            .insert("region".into(), region.clone());
    }
    let message = if embedded {
        format!("{} ({})", finding.message, embedded_position(finding))
    } else {
        finding.message.clone()
    };

    let mut result = json!({
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": { "text": message },
        "locations": [{
            "physicalLocation": physical,
            "logicalLocations": [{
                "fullyQualifiedName": finding.instance_path,
                "kind": "instance"
            }]
        }],
        "partialFingerprints": { "bloxguard/v1": finding.fingerprint },
        "properties": {
            "severity": finding.severity.to_string(),
            "confidence": confidence(finding.confidence),
            "evidence": finding.evidence,
            "instancePath": finding.instance_path
        }
    });
    let object = result.as_object_mut().expect("SARIF result is an object");
    if let Some(index) = rule_index {
        object.insert("ruleIndex".into(), json!(index));
    }
    add_location_properties(&mut object["properties"], &finding.location);
    if let Some(region) = region.filter(|_| embedded) {
        object["properties"]["scriptRegion"] = region;
    }

    if !finding.related_locations.is_empty() {
        let mut related = finding.related_locations.clone();
        related.sort_by(|a, b| (&a.instance_path, &a.message).cmp(&(&b.instance_path, &b.message)));
        object.insert(
            "relatedLocations".into(),
            Value::Array(
                related
                    .iter()
                    .enumerate()
                    .map(|(index, location)| {
                        let mut value = json!({
                            "id": index + 1,
                            "message": { "text": location.message },
                            "physicalLocation": { "artifactLocation": { "uri": path_uri(location.file.as_deref().unwrap_or(&finding.input)) } },
                            "logicalLocations": [{
                                "fullyQualifiedName": location.instance_path,
                                "kind": "instance"
                            }],
                            "properties": { "origin": related_origin(&location.location) }
                        });
                        add_location_properties(&mut value["properties"], &location.location);
                        if let Some(region) = sarif_region(&location.location) {
                            value["physicalLocation"]["region"] = region;
                        }
                        value
                    })
                    .collect(),
            ),
        );
    }
    result
}

fn sarif_region(location: &Location) -> Option<Value> {
    let line = location.line?;
    let mut region = json!({ "startLine": line.max(1) });
    if let Some(column) = location.column {
        region["startColumn"] = json!(column.max(1));
    }
    if let Some(end_line) = location.end_line {
        region["endLine"] = json!(end_line.max(line).max(1));
    }
    if let Some(end_column) = location.end_column {
        region["endColumn"] = json!(end_column.max(1));
    }
    Some(region)
}

/// Where an embedded script's finding is, for readers that see only the file:
/// the instance path and the line inside the script.
///
/// The names come from scanned content and go into SARIF message text.
/// Property and attribute names are escaped like instance path segments, so
/// no control, bidirectional or invisible character and no raw backslash
/// remains. Then the text is made literal for SARIF: square brackets get a
/// backslash, so names cannot form an embedded link (SARIF 2.1.0 §3.11.6),
/// and braces are doubled, as message strings require (§3.11.5).
fn embedded_position(finding: &Finding) -> String {
    let mut parts = vec![terminal_path(&finding.instance_path)];
    if let Some(line) = finding.location.line {
        let mut text = format!("script line {line}");
        if let Some(column) = finding.location.column {
            text.push_str(&format!(":{column}"));
        }
        parts.push(text);
    }
    if let Some(property) = &finding.location.property {
        parts.push(format!("property {}", crate::model::escape_name(property)));
    }
    if let Some(attribute) = &finding.location.attribute {
        parts.push(format!(
            "attribute {}",
            crate::model::escape_name(attribute)
        ));
    }
    sarif_literal_text(&parts.join(", "))
}

/// Plain text that a SARIF consumer shows as written: `[` and `]` are
/// backslash escaped and `{` and `}` are doubled.
fn sarif_literal_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '[' | ']' => {
                out.push('\\');
                out.push(character);
            }
            '{' => out.push_str("{{"),
            '}' => out.push_str("}}"),
            _ => out.push(character),
        }
    }
    out
}

fn add_location_properties(properties: &mut Value, location: &Location) {
    if let Some(property) = &location.property {
        properties["property"] = json!(property);
    }
    if let Some(attribute) = &location.attribute {
        properties["attribute"] = json!(attribute);
    }
}

fn related_origin(location: &Location) -> &'static str {
    if location.attribute.is_some() {
        "attribute"
    } else if location.property.is_some() {
        "property"
    } else {
        "source"
    }
}

fn normalize_report(value: &mut Value) {
    let Some(report) = value.as_object_mut() else {
        return;
    };
    sort_array_by(report.get_mut("inputs"), |item| string_field(item, "input"));
    sort_array_by(report.get_mut("inventory"), |item| {
        format!(
            "{}\0{}\0{}\0{}",
            string_field(item, "input"),
            string_field(item, "instance_path"),
            string_field(item, "class"),
            string_field(item, "source_file")
        )
    });
    sort_array_by(report.get_mut("findings"), finding_value_key);
    if let Some(inputs) = report.get_mut("inputs").and_then(Value::as_array_mut) {
        for input in inputs {
            sort_string_array(input.get_mut("reasons"));
            sort_array_by(input.get_mut("diagnostics"), |item| {
                format!(
                    "{}\0{}",
                    string_field(item, "instance_path"),
                    string_field(item, "message")
                )
            });
        }
    }
    if let Some(findings) = report.get_mut("findings").and_then(Value::as_array_mut) {
        for finding in findings {
            sort_array_by(finding.get_mut("related_locations"), |item| {
                format!(
                    "{}\0{}",
                    string_field(item, "instance_path"),
                    string_field(item, "message")
                )
            });
        }
    }
}

fn sort_array_by<F>(value: Option<&mut Value>, mut key: F)
where
    F: FnMut(&Value) -> String,
{
    if let Some(items) = value.and_then(Value::as_array_mut) {
        items.sort_by_cached_key(|item| key(item));
    }
}

fn sort_string_array(value: Option<&mut Value>) {
    if let Some(items) = value.and_then(Value::as_array_mut) {
        items.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        items.dedup();
    }
}

fn finding_value_key(value: &Value) -> String {
    format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}",
        string_field(value, "input"),
        severity_rank(string_field(value, "severity").as_str()),
        string_field(value, "rule_id"),
        string_field(value, "instance_path"),
        string_field(value, "source_file"),
        value["location"]["line"].as_u64().unwrap_or(0),
        string_field(value, "fingerprint")
    )
}

fn string_field(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn finding_key(finding: &Finding) -> (String, u8, String, String, String, usize, usize, String) {
    (
        finding.input.clone(),
        3 - severity_index(finding.severity),
        finding.rule_id.clone(),
        finding.instance_path.clone(),
        finding.source_file.clone().unwrap_or_default(),
        finding.location.line.unwrap_or(0),
        finding.location.column.unwrap_or(0),
        finding.fingerprint.clone(),
    )
}

fn display_location(finding: &Finding) -> String {
    let mut parts = Vec::new();
    if let Some(file) = finding
        .source_file
        .as_ref()
        .or(finding.container_file.as_ref())
    {
        parts.push(terminal_text(file));
    }
    if let Some(line) = finding.location.line {
        // Without a Luau file of its own, the line is one of the script, not
        // of the place, model or JSON file that holds it.
        let mut text = if finding.source_file.is_some() {
            format!("line {line}")
        } else {
            format!("script line {line}")
        };
        if let Some(column) = finding.location.column {
            text.push_str(&format!(":{column}"));
        }
        parts.push(text);
    }
    if let Some(property) = &finding.location.property {
        parts.push(format!("property {}", terminal_text(property)));
    }
    if let Some(attribute) = &finding.location.attribute {
        parts.push(format!("attribute {}", terminal_text(attribute)));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
}

fn compact_value(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "unknown".into())
}

fn completeness(value: Completeness) -> &'static str {
    match value {
        Completeness::Complete => "complete",
        Completeness::Partial => "partial",
        Completeness::Failed => "failed",
    }
}

fn confidence(value: Confidence) -> &'static str {
    match value {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn sarif_level(value: Severity) -> &'static str {
    match value {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn severity_index(value: Severity) -> u8 {
    match value {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn severity_counts(findings: &[Finding]) -> [usize; 4] {
    let mut counts = [0; 4];
    for finding in findings {
        counts[severity_index(finding.severity) as usize] += 1;
    }
    counts
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

/// Keep untrusted names and messages from changing terminal state, hiding text
/// or adding forged lines. Control characters and the invisible format
/// characters that evidence escapes are written as `\u{..}`. Readable text in
/// any script stays as written. Instance paths arrive already escaped, so
/// their visible `\u{...}` escapes remain unchanged.
fn terminal_text(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() || crate::finding::is_hidden_format(character) {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\u{{{:x}}}", character as u32);
        } else {
            out.push(character);
        }
    }
    out
}

/// Instance paths are shown in the escaped form that JSON, SARIF and
/// suppression globs use: every character other than printable ASCII and the
/// space is a `\u{..}` escape, so a path copied from the terminal matches.
fn terminal_path(path: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(path.len());
    for character in path.chars() {
        if character.is_ascii_graphic() || character == ' ' {
            out.push(character);
        } else {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\u{{{:x}}}", character as u32);
        }
    }
    out
}

/// Convert platform paths to URI references without depending on the current
/// machine. UTF-8 is percent encoded byte by byte. A relative path loses its
/// leading `./`, so `scan .` names files as GitHub expects, from the root.
fn path_uri(path: &str) -> String {
    let mut normalized = path.replace('\\', "/");
    while let Some(rest) = normalized.strip_prefix("./") {
        normalized = if rest.is_empty() {
            ".".to_owned()
        } else {
            rest.to_owned()
        };
    }
    let prefix = if normalized.starts_with("//") {
        "file:"
    } else if normalized.len() >= 3
        && normalized.as_bytes()[0].is_ascii_alphabetic()
        && normalized.as_bytes()[1] == b':'
        && normalized.as_bytes()[2] == b'/'
    {
        "file:///"
    } else if normalized.starts_with('/') {
        "file://"
    } else {
        ""
    };
    let mut encoded = String::new();
    for byte in normalized.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/' | b':') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("{prefix}{encoded}")
}

#[cfg(test)]
mod unit_tests {
    use super::path_uri;

    #[test]
    fn windows_and_unicode_paths_are_valid_uri_references() {
        assert_eq!(
            path_uri(r"C:\work dir\café.luau"),
            "file:///C:/work%20dir/caf%C3%A9.luau"
        );
        assert_eq!(path_uri("src/a b.luau"), "src/a%20b.luau");
    }

    #[test]
    fn relative_paths_lose_a_leading_dot_segment() {
        assert_eq!(path_uri("./src/a.luau"), "src/a.luau");
        assert_eq!(path_uri(r".\src\a.luau"), "src/a.luau");
        assert_eq!(path_uri("././a.rbxmx"), "a.rbxmx");
        assert_eq!(path_uri("./"), ".");
        assert_eq!(path_uri("."), ".");
        assert_eq!(path_uri("../a.rbxl"), "../a.rbxl");
    }
}
