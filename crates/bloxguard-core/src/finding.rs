use crate::model::sha256;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    #[default]
    High,
    Critical,
}
impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Low => "low",
                Self::Medium => "medium",
                Self::High => "high",
                Self::Critical => "critical",
            }
        )
    }
}
impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!("unknown severity: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedLocation {
    pub instance_path: String,
    pub location: Location,
    pub message: String,
    /// The file that holds the related instance, picked the way SARIF picks
    /// a finding's file: its own Luau file, else the place, model, JSON model
    /// or metadata file inside a scanned folder. SARIF points the related
    /// location at it, and at the input when there is none. Provenance only:
    /// JSON reports leave it out, so their format is unchanged.
    #[serde(skip)]
    pub file: Option<String>,
}
impl RelatedLocation {
    /// The file a reader opens to find `instance`, as described on `file`.
    pub fn file_of(instance: &crate::model::Instance) -> Option<String> {
        instance
            .source_file
            .clone()
            .or_else(|| instance.container_file.as_deref().map(str::to_owned))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub input: String,
    pub instance_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    pub location: Location,
    pub message: String,
    pub evidence: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<RelatedLocation>,
    /// The place, model, JSON model or metadata file inside a scanned folder
    /// that holds the finding's script or object, from
    /// [`crate::model::Instance::container_file`]. `source_file` stays the
    /// script's own Luau file, whose lines the location counts. JSON reports
    /// carry both fields; human and SARIF output name this file when there is
    /// no `source_file`. Provenance only: it is not part of the fingerprint
    /// and does not decide which findings are kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_file: Option<String>,
}
impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: &str,
        severity: Severity,
        confidence: Confidence,
        input: &str,
        path: &str,
        location: Location,
        message: &str,
        evidence: &str,
    ) -> Self {
        let normalized = evidence.split_whitespace().collect::<Vec<_>>().join(" ");
        // Length-prefix each component so untrusted NULs cannot collide across fields.
        let mut identity = Vec::new();
        for component in [rule_id, path, &normalized] {
            identity.extend_from_slice(&(component.len() as u64).to_le_bytes());
            identity.extend_from_slice(component.as_bytes());
        }
        let fingerprint = sha256(&identity);
        let short = short_evidence(evidence);
        Self {
            rule_id: rule_id.into(),
            severity,
            confidence,
            input: input.into(),
            instance_path: path.into(),
            source_file: None,
            location,
            message: message.into(),
            evidence: short,
            fingerprint,
            related_locations: Vec::new(),
            container_file: None,
        }
    }

    /// Copy the files an instance's script or data came from onto this finding.
    pub fn set_files_from(&mut self, instance: &crate::model::Instance) {
        self.source_file.clone_from(&instance.source_file);
        self.container_file = instance.container_file.as_deref().map(str::to_owned);
    }
}

const MAX_EVIDENCE_CHARS: usize = 180;
const MAX_EVIDENCE_BYTES: usize = 300;

/// Shorten evidence so it reads like the source it came from.
///
/// Only characters that can change a terminal or hide text are escaped: control
/// characters, bidirectional controls, line and paragraph separators and other
/// invisible format characters. Quotes, backslashes and printable non-ASCII text
/// stay as written. An escape is never split, and a cut adds `...`.
fn short_evidence(evidence: &str) -> String {
    let mut short = String::new();
    let mut piece = String::new();
    let mut truncated = false;
    for (count, character) in evidence.chars().enumerate() {
        if count == MAX_EVIDENCE_CHARS {
            truncated = true;
            break;
        }
        piece.clear();
        escape_evidence_char(character, &mut piece);
        if short.len() + piece.len() > MAX_EVIDENCE_BYTES {
            truncated = true;
            break;
        }
        short.push_str(&piece);
    }
    if truncated {
        short.push_str("...");
    }
    short
}

fn escape_evidence_char(character: char, out: &mut String) {
    match character {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        _ if character.is_control() || is_hidden_format(character) => {
            out.push_str(&format!("\\u{{{:x}}}", character as u32));
        }
        _ => out.push(character),
    }
}

/// Bidirectional controls, separators that break lines, and zero-width or
/// otherwise invisible format characters. Human output escapes the same set.
pub(crate) fn is_hidden_format(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
    )
}
