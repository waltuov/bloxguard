use crate::{finding::Finding, model::Completeness};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDiagnostic {
    pub level: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputReport {
    pub input: String,
    pub completeness: Completeness,
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<InputDiagnostic>,
    pub instance_count: usize,
    pub script_count: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptInventory {
    pub input: String,
    pub instance_path: String,
    pub class: String,
    pub run_context: Option<serde_json::Value>,
    pub enabled: Option<bool>,
    pub size_bytes: usize,
    pub sha256: Option<String>,
    pub source_file: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub tool: String,
    pub version: String,
    pub completeness: Completeness,
    pub inputs: Vec<InputReport>,
    pub inventory: Vec<ScriptInventory>,
    pub findings: Vec<Finding>,
    pub suppressed_count: usize,
    pub baseline_count: usize,
}
impl Default for ScanReport {
    fn default() -> Self {
        Self {
            schema_version: 1,
            tool: crate::PRODUCT_NAME.into(),
            version: crate::VERSION.into(),
            completeness: Completeness::Complete,
            inputs: vec![],
            inventory: vec![],
            findings: vec![],
            suppressed_count: 0,
            baseline_count: 0,
        }
    }
}
impl ScanReport {
    pub fn exit_code(&self, fail_on: crate::finding::Severity, allow_incomplete: bool) -> u8 {
        if self.completeness != Completeness::Complete && !allow_incomplete {
            2
        } else if self.findings.iter().any(|f| f.severity >= fail_on) {
            1
        } else {
            0
        }
    }
}
