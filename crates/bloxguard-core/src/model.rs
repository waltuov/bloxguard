//! Flat instance graph shared by files, source trees and MCP snapshots.
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const MAX_INSTANCE_PATH_BYTES: usize = 1024 * 1024;
pub const MAX_REPORT_PATH_BYTES: usize = 32 * 1024 * 1024;
/// The analyzer builds the full instance path of every script it examines, so a
/// chain of nested scripts costs the square of its depth in path bytes. This
/// caps the sum of those paths per document (about one second of work in a
/// release build). Ordinary places use a few megabytes.
pub const MAX_ANALYZED_PATH_BYTES: usize = 1024 * 1024 * 1024;
pub const MAX_REPORT_FINDINGS: usize = 10_000;
pub const MAX_INVENTORY_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildLookup {
    Found(usize),
    Missing,
    Ambiguous,
}

/// Instance properties and attributes that some script of a document writes, found by
/// one pass over the tokens of every script. A read of a written one may not give the
/// stored value.
#[derive(Debug, Clone, Default)]
pub struct InstanceWrites {
    pub properties: HashSet<String>,
    pub attributes: HashSet<String>,
    /// A property is written under a name the pass cannot read, such as `x[key] = v`.
    pub any_property: bool,
    /// An attribute is set under a name the pass cannot read.
    pub any_attribute: bool,
}

impl InstanceWrites {
    pub fn property(&self, name: &str) -> bool {
        self.any_property || self.properties.contains(name)
    }

    pub fn attribute(&self, name: &str) -> bool {
        self.any_attribute || self.attributes.contains(name)
    }
}

/// Built once per document so repeated property reads do not rescan the tree.
pub struct DomIndex {
    children: HashMap<usize, HashMap<String, ChildLookup>>,
    path_bytes: Vec<usize>,
    data_model: Option<usize>,
    workspace: Option<usize>,
    /// Computed the first time a script reads a property or an attribute.
    instance_writes: OnceLock<InstanceWrites>,
    /// For each instance, whether it or an object below it stores an asset ID shaped
    /// value. Computed the first time an analysis asks.
    stored_ids: OnceLock<Vec<bool>>,
}
impl DomIndex {
    pub fn new(doc: &Document) -> Self {
        let mut children: HashMap<usize, HashMap<String, ChildLookup>> = HashMap::new();
        let mut path_bytes: Vec<usize> = Vec::with_capacity(doc.instances.len());
        let mut data_model = None;
        let mut workspace = None;
        for (id, node) in doc.instances.iter().enumerate() {
            if node.class == "DataModel" && data_model.is_none() {
                data_model = Some(id);
            }
            if node.class == "Workspace" && workspace.is_none() {
                workspace = Some(id);
            }
            if let Some(parent) = node.parent {
                children
                    .entry(parent)
                    .or_default()
                    .entry(node.name.clone())
                    .and_modify(|entry| *entry = ChildLookup::Ambiguous)
                    .or_insert(ChildLookup::Found(id));
            }
            let parent_size = node.parent.map_or(0, |parent| {
                path_bytes
                    .get(parent)
                    .copied()
                    .unwrap_or(MAX_INSTANCE_PATH_BYTES)
            });
            let name_size = escaped_name_len(&node.name);
            path_bytes.push(parent_size.saturating_add(name_size).saturating_add(1));
        }
        Self {
            children,
            path_bytes,
            data_model,
            workspace,
            instance_writes: OnceLock::new(),
            stored_ids: OnceLock::new(),
        }
    }
    /// The instance writes of the document this index was built from. `compute` runs
    /// at most once per index, so the pass costs one scan per document.
    pub fn instance_writes(&self, compute: impl FnOnce() -> InstanceWrites) -> &InstanceWrites {
        self.instance_writes.get_or_init(compute)
    }
    /// Which instances store an asset ID shaped value at or below them, computed once
    /// per index like [`DomIndex::instance_writes`].
    pub fn stored_ids(&self, compute: impl FnOnce() -> Vec<bool>) -> &[bool] {
        self.stored_ids.get_or_init(compute)
    }
    pub fn child(&self, parent: usize, name: &str) -> ChildLookup {
        self.children
            .get(&parent)
            .and_then(|names| names.get(name))
            .copied()
            .unwrap_or(ChildLookup::Missing)
    }
    pub fn data_model(&self) -> Option<usize> {
        self.data_model
    }
    pub fn workspace(&self) -> Option<usize> {
        self.workspace
    }
    pub fn path_bytes(&self, id: usize) -> usize {
        self.path_bytes
            .get(id)
            .copied()
            .unwrap_or(MAX_INSTANCE_PATH_BYTES + 1)
    }
    pub fn has_oversized_paths(&self) -> bool {
        self.path_bytes.iter().any(|n| *n > MAX_INSTANCE_PATH_BYTES)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Completeness {
    #[default]
    Complete,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub max_instances: usize,
    pub max_script_bytes: usize,
    pub max_depth: usize,
    pub max_analysis_steps: usize,
    pub max_file_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 200 * 1024 * 1024,
            max_instances: 600_000,
            max_script_bytes: 2 * 1024 * 1024,
            max_depth: 128,
            max_analysis_steps: 100_000,
            max_file_ms: 30_000,
        }
    }
}

/// The cooperative time budget of one input: `max_file_ms`, shared by its
/// loading, analysis and inventory. Each phase resumes the clock with the time
/// the earlier phases of the same input used (`Document::time_spent`), so time
/// spent on other inputs never counts. The budget is checked between steps, so
/// one parser call can still run past it.
#[derive(Debug, Clone, Copy)]
pub struct InputClock {
    resumed: Instant,
    spent_before: Duration,
    budget: Duration,
}

impl InputClock {
    /// A clock for an input that has used no time yet.
    pub fn start(limits: &Limits) -> Self {
        Self::resume(limits, Duration::ZERO)
    }

    /// Continue the budget of an input that has already used `spent_before`.
    pub fn resume(limits: &Limits, spent_before: Duration) -> Self {
        Self {
            resumed: Instant::now(),
            spent_before,
            budget: Duration::from_millis(limits.max_file_ms),
        }
    }

    /// The time this input has used in every phase so far.
    pub fn spent(&self) -> Duration {
        self.spent_before.saturating_add(self.resumed.elapsed())
    }

    pub fn exceeded(&self) -> bool {
        self.spent() > self.budget
    }

    /// `limits` with `max_file_ms` cut to what this input has left, for code
    /// that starts its own timer, so that timer ends when this budget does.
    pub fn remaining_limits(&self, limits: &Limits) -> Limits {
        let left = self.budget.saturating_sub(self.spent());
        Limits {
            max_file_ms: u64::try_from(left.as_millis()).unwrap_or(u64::MAX),
            ..limits.clone()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    pub name: String,
    pub class: String,
    #[serde(default)]
    pub parent: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_map_or_empty_array")]
    pub properties: BTreeMap<String, serde_json::Value>,
    #[serde(default, deserialize_with = "deserialize_map_or_empty_array")]
    pub attributes: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_file: Option<String>,
    /// The place, model, JSON model or metadata file inside a scanned folder
    /// that holds this instance, or the text of its script, when the instance
    /// has no source file of its own. Reports name it so a reader can find the
    /// script. It is provenance only: no rule, limit or fingerprint reads it,
    /// and a bundle cannot set it.
    #[serde(skip)]
    pub container_file: Option<std::sync::Arc<str>>,
}

fn deserialize_map_or_empty_array<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Object(values) => Ok(values.into_iter().collect()),
        serde_json::Value::Array(values) if values.is_empty() => Ok(BTreeMap::new()),
        serde_json::Value::Array(_) => Err(de::Error::custom(
            "expected an object or an empty array for an empty map",
        )),
        _ => Err(de::Error::custom(
            "expected an object or an empty array for an empty map",
        )),
    }
}
impl Instance {
    pub fn is_script(&self) -> bool {
        matches!(
            self.class.as_str(),
            "Script" | "LocalScript" | "ModuleScript"
        )
    }
    pub fn source_hash(&self) -> Option<String> {
        self.source.as_ref().map(|s| sha256(s.as_bytes()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Document {
    pub input: String,
    pub instances: Vec<Instance>,
    pub completeness: Completeness,
    pub reasons: Vec<String>,
    pub diagnostics: Vec<DocumentDiagnostic>,
    /// Time this input has used so far, counted against `max_file_ms` by the
    /// next phase (see `InputClock`).
    pub time_spent: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLevel {
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentDiagnostic {
    pub level: DiagnosticLevel,
    pub message: String,
    pub instance: Option<usize>,
}
impl Document {
    pub fn partial(&mut self, reason: impl Into<String>) {
        self.completeness = self.completeness.max(Completeness::Partial);
        self.add_reason(reason.into());
    }
    pub fn failed(&mut self, reason: impl Into<String>) {
        self.completeness = Completeness::Failed;
        self.add_reason(reason.into());
    }
    fn add_reason(&mut self, reason: String) {
        if self.reasons.len() == 256 {
            self.reasons
                .push("additional incomplete reasons omitted at report limit".into());
        } else if self.reasons.len() < 256 {
            self.reasons.push(reason.chars().take(512).collect());
        }
    }
    pub fn informational(&mut self, message: impl Into<String>, instance: Option<usize>) {
        let diagnostic = DocumentDiagnostic {
            level: DiagnosticLevel::Info,
            message: message.into().chars().take(512).collect(),
            instance,
        };
        if self.diagnostics.len() < 256 {
            self.diagnostics.push(diagnostic);
        } else if self
            .diagnostics
            .last()
            .is_some_and(|item| item.message != "additional diagnostics omitted at report limit")
        {
            self.diagnostics[255] = DocumentDiagnostic {
                level: DiagnosticLevel::Info,
                message: "additional diagnostics omitted at report limit".into(),
                instance: None,
            };
        }
    }
    /// Iterative, cycle-safe path construction. Names cannot impersonate separators.
    ///
    /// The cost is linear in the length of the returned path: one walk up the
    /// parents measures it, and the text is then written into one buffer. Callers
    /// that build a path per script still pay for every byte, so deep chains rely
    /// on the per-path and per-report budgets.
    pub fn path(&self, id: usize) -> String {
        // (name, name needs escapes), from the instance up to the root.
        let mut segments: Vec<(&str, bool)> = Vec::new();
        let mut current = Some(id);
        let mut path_bytes = 0usize;
        let mut invalid_parent = false;
        for _ in 0..=self.instances.len() {
            let Some(index) = current else { break };
            let Some(node) = self.instances.get(index) else {
                invalid_parent = true;
                break;
            };
            if node.name.len().saturating_add(path_bytes) > MAX_INSTANCE_PATH_BYTES {
                return format!("/<path-limit>/instance-{id}");
            }
            let plain = is_plain_name(&node.name);
            let escaped = if plain {
                node.name.len()
            } else {
                escaped_name_len(&node.name)
            };
            path_bytes = path_bytes.saturating_add(escaped).saturating_add(1);
            if path_bytes > MAX_INSTANCE_PATH_BYTES {
                return format!("/<path-limit>/instance-{id}");
            }
            segments.push((&node.name, !plain));
            current = node.parent;
        }
        let mut path = String::with_capacity(path_bytes.saturating_add(32));
        if current.is_some() {
            path.push_str("/<cycle>");
        }
        if invalid_parent {
            path.push_str("/<invalid-parent>");
        }
        for (name, needs_escapes) in segments.iter().rev() {
            path.push('/');
            if *needs_escapes {
                push_escaped_chars(&mut path, name);
            } else {
                path.push_str(name);
            }
        }
        path
    }
    pub fn child(&self, parent: usize, name: &str) -> Option<usize> {
        let mut matching = self
            .instances
            .iter()
            .enumerate()
            .filter(|(_, n)| n.parent == Some(parent) && n.name == name);
        let first = matching.next()?.0;
        if matching.next().is_some() {
            None
        } else {
            Some(first)
        }
    }
}

/// Flat, ordered nodes keep snapshots safe at arbitrary instance nesting depths.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema_version: u32,
    pub instances: Vec<Instance>,
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
/// A character kept as it is in an instance path segment. Every other
/// character is written as a `\u{..}` escape, so a name cannot fake a separator.
fn is_plain_path_char(c: char) -> bool {
    c.is_ascii_graphic() && c != '/' && c != '\\'
}

/// True when `escape_name` returns the name unchanged.
fn is_plain_name(name: &str) -> bool {
    name.bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b'\\')
}

/// Byte length of `\u{..}` for one character, without formatting it.
fn escaped_char_len(c: char) -> usize {
    let code = c as u32;
    let hex_digits = if code == 0 {
        1
    } else {
        (32 - code.leading_zeros() as usize).div_ceil(4)
    };
    // `\u{` + digits + `}`
    4 + hex_digits
}

/// Byte length of `escape_name(name)`, without building it.
pub fn escaped_name_len(name: &str) -> usize {
    if is_plain_name(name) {
        return name.len();
    }
    name.chars()
        .map(|c| {
            if is_plain_path_char(c) {
                1
            } else {
                escaped_char_len(c)
            }
        })
        .sum()
}

fn push_escaped_chars(out: &mut String, name: &str) {
    use std::fmt::Write as _;
    for c in name.chars() {
        if is_plain_path_char(c) {
            out.push(c);
        } else {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        }
    }
}

pub fn escape_name(name: &str) -> String {
    if is_plain_name(name) {
        return name.to_owned();
    }
    let mut escaped = String::with_capacity(escaped_name_len(name));
    push_escaped_chars(&mut escaped, name);
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_clock_continues_the_time_earlier_phases_used() {
        let limits = Limits {
            max_file_ms: 10_000,
            ..Limits::default()
        };
        let fresh = InputClock::start(&limits);
        assert!(!fresh.exceeded());
        assert!(fresh.remaining_limits(&limits).max_file_ms <= 10_000);

        let most = InputClock::resume(&limits, Duration::from_millis(6_000));
        assert!(!most.exceeded());
        assert!(most.spent() >= Duration::from_millis(6_000));
        let rest = most.remaining_limits(&limits);
        assert!(rest.max_file_ms <= 4_000, "{}", rest.max_file_ms);
        assert!(rest.max_file_ms > 3_000, "{}", rest.max_file_ms);
        assert_eq!(rest.max_depth, limits.max_depth);
        assert_eq!(rest.max_analysis_steps, limits.max_analysis_steps);

        let used = InputClock::resume(&limits, Duration::from_millis(10_001));
        assert!(used.exceeded());
        assert_eq!(used.remaining_limits(&limits).max_file_ms, 0);
    }
}
