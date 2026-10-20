//! Strict configuration. Unknown fields, unknown rule IDs, invalid values and
//! malformed suppressions are errors. A suppression that matches no finding,
//! or has expired, is not.
use crate::{finding::Severity, model::Limits, rules};
use globset::Glob;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub severity: Option<Severity>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    pub rule: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub expires: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub fail_on: Severity,
    pub trusted_asset_ids: Vec<u64>,
    pub rules: BTreeMap<String, RuleConfig>,
    pub suppressions: Vec<Suppression>,
    pub baseline: Option<PathBuf>,
    pub limits: Limits,
    /// Explicit UTC date makes expiry behavior reproducible; CLI supplies today.
    #[serde(skip, default = "today_utc")]
    pub current_date: String,
    #[serde(skip)]
    pub baseline_fingerprints: BTreeSet<String>,
    #[serde(skip)]
    pub baseline_scopes: Option<BTreeMap<String, BTreeSet<String>>>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            fail_on: Severity::High,
            trusted_asset_ids: vec![],
            rules: BTreeMap::new(),
            suppressions: vec![],
            baseline: None,
            limits: Limits::default(),
            current_date: today_utc(),
            baseline_fingerprints: BTreeSet::new(),
            baseline_scopes: None,
        }
    }
}
impl Config {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        let mut config: Self = toml::from_str(&text).map_err(|e| format!("invalid config: {e}"))?;
        config.validate()?;
        if let Some(baseline) = &config.baseline
            && baseline.is_relative()
        {
            config.baseline = Some(path.parent().unwrap_or(Path::new(".")).join(baseline));
        }
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), String> {
        validate_date(&self.current_date)?;
        for id in self.rules.keys() {
            if rules::rule(id).is_none() {
                return Err(format!("unknown rule: {id}"));
            }
        }
        for suppression in &self.suppressions {
            if rules::rule(&suppression.rule).is_none() {
                return Err(format!("unknown suppression rule: {}", suppression.rule));
            }
            if suppression.reason.trim().is_empty() {
                return Err("suppression reason is required".into());
            }
            if suppression.path.is_none() && suppression.fingerprint.is_none() {
                return Err("suppression needs a path glob or fingerprint".into());
            }
            if let Some(path) = &suppression.path {
                if path.trim().is_empty() {
                    return Err("empty suppression path".into());
                }
                Glob::new(path).map_err(|e| format!("invalid suppression path glob: {e}"))?;
            }
            if let Some(fp) = &suppression.fingerprint {
                validate_fingerprint(fp)?;
            }
            if let Some(date) = &suppression.expires {
                validate_date(date)?;
            }
        }
        let l = &self.limits;
        if l.max_file_bytes == 0
            || l.max_instances == 0
            || l.max_script_bytes == 0
            || l.max_depth == 0
            || l.max_analysis_steps == 0
            || l.max_file_ms == 0
        {
            return Err("all limits must be positive".into());
        }
        if l.max_depth > 256 {
            return Err("max_depth cannot exceed the parser safety ceiling of 256".into());
        }
        Ok(())
    }
    pub fn load_baseline(&mut self, override_path: Option<&Path>) -> Result<(), String> {
        if let Some(path) = override_path.or(self.baseline.as_deref()) {
            let baseline = Baseline::read(path)?;
            self.baseline_fingerprints = baseline.fingerprints;
            self.baseline_scopes = baseline.input_scopes.map(|scopes| {
                scopes
                    .into_iter()
                    .map(|(fingerprint, inputs)| {
                        (
                            fingerprint,
                            inputs
                                .into_iter()
                                .map(|input| normalize_input_scope(&input))
                                .collect(),
                        )
                    })
                    .collect()
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub schema_version: u32,
    pub fingerprints: BTreeSet<String>,
    /// New CLI baselines bind review to the scanned input as well as its finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_scopes: Option<BTreeMap<String, BTreeSet<String>>>,
}
impl Baseline {
    pub fn read(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("cannot read baseline {}: {e}", path.display()))?;
        let baseline: Self =
            serde_json::from_slice(&data).map_err(|e| format!("invalid baseline: {e}"))?;
        if baseline.schema_version != 1 {
            return Err("unsupported baseline schema_version".into());
        }
        for fp in &baseline.fingerprints {
            validate_fingerprint(fp)?;
        }
        if let Some(scopes) = &baseline.input_scopes {
            for (fp, inputs) in scopes {
                validate_fingerprint(fp)?;
                if !baseline.fingerprints.contains(fp) || inputs.is_empty() {
                    return Err("baseline input scopes must reference known fingerprints and nonempty inputs".into());
                }
            }
        }
        Ok(baseline)
    }
}
fn validate_fingerprint(fp: &str) -> Result<(), String> {
    if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
        Err("fingerprint must be 64 hexadecimal characters".into())
    } else {
        Ok(())
    }
}
pub fn check_date(date: &str) -> Result<(), String> {
    validate_date(date).map_err(|error| error.replacen("expires", "--as-of", 1))
}

/// Normalize review identity without touching the filesystem or following links.
pub fn normalize_input_scope(input: &str) -> String {
    use std::path::Component;
    fn clean(path: &Path) -> PathBuf {
        let mut result = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if matches!(result.components().next_back(), Some(Component::Normal(_))) {
                        result.pop();
                    }
                }
                #[cfg(windows)]
                Component::Prefix(prefix) => {
                    use std::path::Prefix;
                    match prefix.kind() {
                        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                            result.push(format!("{}:", char::from(letter.to_ascii_uppercase())))
                        }
                        _ => result.push(component.as_os_str()),
                    }
                }
                _ => result.push(component.as_os_str()),
            }
        }
        result
    }
    let cwd = clean(&std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let portable = input.replace('\\', "/");
    let path = Path::new(&portable);
    let absolute = clean(&if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    });
    absolute
        .strip_prefix(&cwd)
        .map(|relative| {
            if relative.as_os_str().is_empty() {
                ".".into()
            } else {
                relative.to_string_lossy().replace('\\', "/")
            }
        })
        .unwrap_or_else(|_| absolute.to_string_lossy().replace('\\', "/"))
}
fn validate_date(date: &str) -> Result<(), String> {
    let bytes = date.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, b)| i != 4 && i != 7 && !b.is_ascii_digit())
    {
        return Err("expires must be YYYY-MM-DD".into());
    }
    let year = date[..4].parse::<u32>().unwrap_or(0);
    let month = date[5..7].parse::<u32>().unwrap_or(0);
    let day = date[8..].parse::<u32>().unwrap_or(0);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > max {
        Err("expires is not a valid calendar date".into())
    } else {
        Ok(())
    }
}
/// Gregorian conversion from Unix days, without locale or timezone dependencies.
pub fn today_utc() -> String {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86400;
    let z = days as i64 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(m <= 2);
    format!("{year:04}-{m:02}-{d:02}")
}
