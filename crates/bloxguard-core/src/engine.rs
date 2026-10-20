//! Deterministic orchestration and policy application.
use crate::{
    config::Config,
    finding::Severity,
    model::{
        Completeness, Document, DomIndex, InputClock, MAX_ANALYZED_PATH_BYTES,
        MAX_INSTANCE_PATH_BYTES, MAX_REPORT_FINDINGS, MAX_REPORT_PATH_BYTES,
    },
    report::{InputDiagnostic, InputReport, ScanReport, ScriptInventory},
};
use globset::Glob;
use std::path::PathBuf;

pub fn scan_paths(paths: &[PathBuf], config: &Config) -> ScanReport {
    let documents = paths
        .iter()
        .flat_map(|p| crate::loading::load_path(p, &config.limits))
        .collect();
    scan_documents(documents, config)
}

pub fn scan_documents(documents: Vec<Document>, config: &Config) -> ScanReport {
    scan_documents_with_path_budget(documents, config, MAX_ANALYZED_PATH_BYTES)
}
fn scan_documents_with_path_budget(
    documents: Vec<Document>,
    config: &Config,
    path_budget: usize,
) -> ScanReport {
    crate::parsing::on_large_stack(|| scan_documents_on_worker(documents, config, path_budget))
        .unwrap_or_else(|reason| {
            inventory_documents(vec![Document {
                input: "<parser-worker>".into(),
                completeness: Completeness::Failed,
                reasons: vec![reason],
                ..Document::default()
            }])
        })
}
fn scan_documents_on_worker(
    mut documents: Vec<Document>,
    config: &Config,
    path_budget: usize,
) -> ScanReport {
    if let Err(error) = config.validate() {
        documents.push(Document {
            input: "<configuration>".into(),
            completeness: Completeness::Failed,
            reasons: vec![format!("invalid scan configuration: {error}")],
            instances: vec![],
            ..Document::default()
        });
        return inventory_documents_with_limits(documents, &config.limits);
    }
    let mut findings = Vec::new();
    for doc in &mut documents {
        // Analysis continues the time budget that loading this input started.
        let clock = InputClock::resume(&config.limits, doc.time_spent);
        let index = DomIndex::new(doc);
        if index.has_oversized_paths() {
            doc.partial("instance paths exceed the 1 MiB path output limit");
        }
        let mut finding_path_bytes = 0usize;
        let mut analyzed_path_bytes = 0usize;
        let mut path_budget_reached = false;
        for id in 0..doc.instances.len() {
            if !doc.instances[id].is_script() {
                continue;
            }
            if index.path_bytes(id) > MAX_INSTANCE_PATH_BYTES {
                continue;
            }
            if findings.len() >= MAX_REPORT_FINDINGS || finding_path_bytes >= MAX_REPORT_PATH_BYTES
            {
                doc.partial("finding output limit reached; remaining scripts unexamined");
                break;
            }
            if clock.exceeded() {
                doc.partial("analysis time budget exceeded; remaining scripts unexamined");
                break;
            }
            if doc.instances[id]
                .source
                .as_ref()
                .is_some_and(|s| s.len() > config.limits.max_script_bytes)
            {
                doc.partial(format!("script size limit exceeded: {}", doc.path(id)));
                continue;
            }
            // Checked from the index before the analyzer builds the path. A script
            // that does not fit is skipped; a later one with a short path still runs.
            let script_path_bytes = index.path_bytes(id);
            if analyzed_path_bytes.saturating_add(script_path_bytes) > path_budget {
                if !path_budget_reached {
                    path_budget_reached = true;
                    doc.partial(
                        "instance path work limit reached; deeply nested scripts unexamined",
                    );
                }
                continue;
            }
            analyzed_path_bytes += script_path_bytes;
            // The analyzer times each script with its own clock, so it gets what
            // this input has left as its `max_file_ms` and stops at the same time.
            let limits = clock.remaining_limits(&config.limits);
            let result = crate::analysis::analyze_indexed(
                doc,
                id,
                &limits,
                &config.trusted_asset_ids,
                &index,
            );
            for finding in result.findings {
                finding_path_bytes = finding_path_bytes.saturating_add(finding.instance_path.len());
                if findings.len() >= MAX_REPORT_FINDINGS
                    || finding_path_bytes > MAX_REPORT_PATH_BYTES
                {
                    doc.partial("finding output limit reached; additional findings omitted");
                    break;
                }
                findings.push(finding);
            }
            for reason in result.reasons {
                doc.partial(reason);
            }
            for note in result.notes {
                doc.informational(note, Some(id));
            }
        }
        if !clock.exceeded() {
            doc.time_spent = clock.spent();
            let result = crate::heuristics::analyze(doc, &config.limits);
            for finding in result.findings {
                finding_path_bytes = finding_path_bytes.saturating_add(finding.instance_path.len());
                if findings.len() >= MAX_REPORT_FINDINGS
                    || finding_path_bytes > MAX_REPORT_PATH_BYTES
                {
                    doc.partial("finding output limit reached; additional heuristics omitted");
                    break;
                }
                findings.push(finding);
            }
            for reason in result.reasons {
                doc.partial(reason);
            }
        } else {
            doc.partial("analysis time budget exceeded; structural heuristics incomplete");
        }
        if clock.exceeded() {
            doc.partial("analysis exceeded file time budget");
        }
        doc.time_spent = clock.spent();
    }
    // Correlate by script, never by an unrelated script in the same place.
    let risky: std::collections::BTreeSet<_> = findings
        .iter()
        .filter(|f| {
            f.severity >= Severity::High
                && matches!(f.rule_id.as_str(), "BG001" | "BG002" | "BG003" | "BG004")
        })
        .map(|f| (f.input.clone(), f.instance_path.clone()))
        .collect();
    for f in &mut findings {
        if f.rule_id == "BG005" && risky.contains(&(f.input.clone(), f.instance_path.clone())) {
            f.severity = Severity::High;
        }
    }
    let mut report = inventory_documents_with_limits(documents, &config.limits);
    let suppressions: Vec<_> = config
        .suppressions
        .iter()
        .filter(|s| {
            s.expires
                .as_ref()
                .is_none_or(|date| date >= &config.current_date)
        })
        .map(|s| {
            (
                s,
                s.path
                    .as_ref()
                    .and_then(|p| Glob::new(p).ok())
                    .map(|g| g.compile_matcher()),
            )
        })
        .collect();
    for mut finding in findings {
        if let Some(policy) = config.rules.get(&finding.rule_id) {
            if policy.enabled == Some(false) {
                continue;
            }
            if let Some(severity) = policy.severity {
                finding.severity = severity;
            }
        }
        if suppressions.iter().any(|(s, matcher)| {
            s.rule == finding.rule_id
                && matcher
                    .as_ref()
                    .is_none_or(|m| m.is_match(&finding.instance_path))
                && s.fingerprint
                    .as_ref()
                    .is_none_or(|fp| fp == &finding.fingerprint)
        }) {
            report.suppressed_count += 1;
            continue;
        }
        if config.baseline_fingerprints.contains(&finding.fingerprint)
            && config.baseline_scopes.as_ref().is_none_or(|scopes| {
                scopes.get(&finding.fingerprint).is_some_and(|inputs| {
                    inputs.iter().any(|input| {
                        crate::config::normalize_input_scope(input)
                            == crate::config::normalize_input_scope(&finding.input)
                    })
                })
            })
        {
            report.baseline_count += 1;
            continue;
        }
        report.findings.push(finding);
    }
    report.findings.sort_by(|a, b| {
        (
            &a.input,
            std::cmp::Reverse(a.severity),
            &a.instance_path,
            &a.rule_id,
            a.location.line,
            a.location.column,
            &a.fingerprint,
            &a.container_file,
        )
            .cmp(&(
                &b.input,
                std::cmp::Reverse(b.severity),
                &b.instance_path,
                &b.rule_id,
                b.location.line,
                b.location.column,
                &b.fingerprint,
                &b.container_file,
            ))
    });
    // Two place or model files in one scanned folder can hold the same script at
    // the same instance path, so the file that holds it is part of the key.
    report.findings.dedup_by(|a, b| {
        a.input == b.input
            && a.source_file == b.source_file
            && a.container_file == b.container_file
            && a.fingerprint == b.fingerprint
            && a.location == b.location
    });
    report
}

pub fn inventory_documents(documents: Vec<Document>) -> ScanReport {
    inventory_documents_with_limits(documents, &crate::model::Limits::default())
}
pub fn inventory_documents_with_limits(
    mut documents: Vec<Document>,
    limits: &crate::model::Limits,
) -> ScanReport {
    let mut report = ScanReport::default();
    let mut inventory_bytes = 0usize;
    if documents.is_empty() {
        documents.push(Document {
            input: "<no-input>".into(),
            completeness: Completeness::Failed,
            reasons: vec!["nothing to scan".into()],
            instances: vec![],
            ..Document::default()
        });
    }
    for mut doc in documents {
        let clock = InputClock::resume(limits, doc.time_spent);
        let mut path_bytes = 0usize;
        doc.reasons.sort();
        doc.reasons.dedup();
        let script_count = doc.instances.iter().filter(|n| n.is_script()).count();
        for (id, node) in doc.instances.iter().enumerate() {
            if !node.is_script() {
                continue;
            }
            if clock.exceeded() {
                doc.partial("inventory time budget exceeded");
                break;
            }
            if report.inventory.len() >= crate::model::MAX_INVENTORY_ENTRIES {
                doc.partial("inventory entry limit exceeded; remaining entries omitted");
                break;
            }
            let instance_path = doc.path(id);
            path_bytes = path_bytes.saturating_add(instance_path.len());
            if instance_path.starts_with("/<path-limit>/") || path_bytes > MAX_REPORT_PATH_BYTES {
                doc.partial("inventory path output limit exceeded; remaining entries omitted");
                break;
            }
            let enabled = node
                .properties
                .get("Enabled")
                .and_then(|v| v.as_bool())
                .or_else(|| {
                    node.properties
                        .get("Disabled")
                        .and_then(|v| v.as_bool())
                        .map(|v| !v)
                });
            if doc
                .input
                .len()
                .saturating_add(node.class.len())
                .saturating_add(node.source_file.as_ref().map_or(0, String::len))
                > MAX_REPORT_PATH_BYTES
            {
                doc.partial("inventory label output limit exceeded");
                break;
            }
            let entry = ScriptInventory {
                input: doc.input.clone(),
                instance_path,
                class: node.class.clone(),
                run_context: node.properties.get("RunContext").cloned(),
                enabled,
                size_bytes: node.source.as_ref().map_or(0, String::len),
                sha256: node.source_hash(),
                source_file: node.source_file.clone(),
            };
            let encoded_bytes =
                serde_json::to_vec(&entry).map_or(MAX_REPORT_PATH_BYTES + 1, |bytes| bytes.len());
            inventory_bytes = inventory_bytes.saturating_add(encoded_bytes);
            if inventory_bytes > MAX_REPORT_PATH_BYTES {
                doc.partial(
                    "inventory serialized output limit exceeded; remaining entries omitted",
                );
                break;
            }
            report.inventory.push(entry);
        }
        doc.reasons.sort();
        doc.reasons.dedup();
        report.completeness = report.completeness.max(doc.completeness);
        let mut diagnostics: Vec<_> = doc
            .diagnostics
            .iter()
            .map(|diagnostic| InputDiagnostic {
                level: "info".into(),
                message: diagnostic.message.clone(),
                instance_path: diagnostic.instance.map(|id| doc.path(id)),
            })
            .collect();
        diagnostics
            .sort_by(|a, b| (&a.instance_path, &a.message).cmp(&(&b.instance_path, &b.message)));
        report.inputs.push(InputReport {
            input: doc.input,
            completeness: doc.completeness,
            reasons: doc.reasons,
            diagnostics,
            instance_count: doc.instances.len(),
            script_count,
        });
    }
    report.inputs.sort_by(|a, b| a.input.cmp(&b.input));
    report.inventory.sort_by(|a, b| {
        (&a.input, &a.instance_path, &a.class, &a.sha256).cmp(&(
            &b.input,
            &b.instance_path,
            &b.class,
            &b.sha256,
        ))
    });
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Instance;

    const PATH_WORK_REASON: &str =
        "instance path work limit reached; deeply nested scripts unexamined";

    /// A model with a chain of nested ModuleScripts. The deepest one and one
    /// script directly under the root require an ID.
    fn chain(levels: usize) -> Document {
        let mut instances = vec![Instance {
            name: "FAKE_Root".into(),
            class: "Model".into(),
            ..Instance::default()
        }];
        for level in 0..levels {
            let source = if level + 1 == levels {
                "require(999000000004343)"
            } else {
                "return 1"
            };
            instances.push(Instance {
                name: format!("M{level}"),
                class: "ModuleScript".into(),
                parent: Some(instances.len() - 1),
                source: Some(source.into()),
                ..Instance::default()
            });
        }
        instances.push(Instance {
            name: "FAKE_Shallow".into(),
            class: "Script".into(),
            parent: Some(0),
            source: Some("require(999000000004242)".into()),
            ..Instance::default()
        });
        Document {
            input: "FAKE_chain.rbxm".into(),
            instances,
            ..Document::default()
        }
    }

    fn required_ids(report: &ScanReport) -> Vec<&str> {
        let mut ids: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "BG001")
            .filter_map(|finding| {
                ["999000000004343", "999000000004242"]
                    .into_iter()
                    .find(|id| finding.evidence.contains(id))
            })
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Analysis and inventory continue the time loading already used: an input
    /// whose loading used the whole budget is neither analyzed nor listed.
    #[test]
    fn analysis_and_inventory_continue_the_time_loading_used() {
        let mut config = Config::default();
        config.limits.max_file_ms = 60_000;
        let document = Document {
            input: "FAKE_clock.rbxm".into(),
            instances: vec![Instance {
                name: "FAKE_Loader".into(),
                class: "Script".into(),
                source: Some("require(999000000006102)".into()),
                ..Instance::default()
            }],
            ..Document::default()
        };

        let fresh = scan_documents(vec![document.clone()], &config);
        assert_eq!(fresh.completeness, Completeness::Complete);
        assert_eq!(fresh.inventory.len(), 1);
        assert!(fresh.findings.iter().any(|f| f.rule_id == "BG001"));

        let loaded = Document {
            time_spent: std::time::Duration::from_millis(60_001),
            ..document
        };
        let used = scan_documents(vec![loaded], &config);
        assert_eq!(used.completeness, Completeness::Partial);
        assert!(used.findings.is_empty(), "{:?}", used.findings);
        assert!(used.inventory.is_empty());
        assert_eq!(
            used.inputs[0].reasons,
            [
                "analysis exceeded file time budget",
                "analysis time budget exceeded; remaining scripts unexamined",
                "analysis time budget exceeded; structural heuristics incomplete",
                "inventory time budget exceeded",
            ]
        );
    }

    /// The analyzer times each script itself, so it must get only what the
    /// input has left: here 20 ms, far less than one slow script needs.
    #[test]
    fn the_analyzer_gets_only_the_time_the_input_has_left() {
        let mut config = Config::default();
        config.limits.max_file_ms = 60_000;
        let slow: String = (0..20_000)
            .map(|index| format!("local FAKE_v{index} = {{{index}, \"FAKE\"}}\n"))
            .collect();
        let document = Document {
            input: "FAKE_clock.rbxm".into(),
            instances: vec![Instance {
                name: "FAKE_Slow".into(),
                class: "ModuleScript".into(),
                source: Some(slow),
                ..Instance::default()
            }],
            time_spent: std::time::Duration::from_millis(59_980),
            ..Document::default()
        };
        let report = scan_documents(vec![document], &config);
        assert!(
            report.inputs[0].reasons.iter().any(|reason| reason
                == "analysis time budget reached in /FAKE_Slow; some values are unresolved"),
            "{:?}",
            report.inputs[0].reasons
        );
    }

    /// The structural heuristics continue the same budget.
    #[test]
    fn heuristics_continue_the_time_the_input_used() {
        let limits = crate::model::Limits {
            max_file_ms: 60_000,
            ..crate::model::Limits::default()
        };
        let document = Document {
            input: "FAKE_clock.rbxm".into(),
            instances: vec![Instance {
                name: "FAKE_Script".into(),
                class: "Script".into(),
                source: Some("return 1".into()),
                ..Instance::default()
            }],
            time_spent: std::time::Duration::from_millis(60_001),
            ..Document::default()
        };
        let result = crate::heuristics::analyze(&document, &limits);
        assert_eq!(
            result.reasons,
            [
                "heuristic time budget exceeded in FAKE_clock.rbxm; remaining instances were not examined"
            ]
        );
    }

    #[test]
    fn path_work_budget_skips_deep_scripts_and_still_scans_short_paths() {
        let document = chain(200);
        let index = DomIndex::new(&document);
        let total: usize = (0..document.instances.len())
            .filter(|&id| document.instances[id].is_script())
            .map(|id| index.path_bytes(id))
            .sum();
        for id in 0..document.instances.len() {
            assert_eq!(index.path_bytes(id), document.path(id).len());
        }

        let unlimited =
            scan_documents_with_path_budget(vec![document.clone()], &Config::default(), total);
        assert_eq!(
            required_ids(&unlimited),
            ["999000000004242", "999000000004343"]
        );
        assert!(
            !unlimited.inputs[0]
                .reasons
                .iter()
                .any(|reason| reason == PATH_WORK_REASON),
            "{:?}",
            unlimited.inputs[0].reasons
        );

        // Room for everything except the deepest path: that script is skipped,
        // and the shallow script after it still fits.
        let deepest = document.instances.len() - 2;
        assert!(index.path_bytes(deepest) > index.path_bytes(deepest + 1));
        let budget = total - index.path_bytes(deepest);
        let limited = scan_documents_with_path_budget(vec![document], &Config::default(), budget);
        assert_eq!(limited.completeness, Completeness::Partial);
        assert_eq!(
            limited.inputs[0]
                .reasons
                .iter()
                .filter(|reason| *reason == PATH_WORK_REASON)
                .count(),
            1
        );
        assert_eq!(required_ids(&limited), ["999000000004242"]);
    }
}
