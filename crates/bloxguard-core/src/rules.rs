use crate::finding::{Confidence, Severity};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub default_severity: Severity,
    pub confidence: Confidence,
    pub help: &'static str,
    pub help_uri: &'static str,
}
macro_rules! rule {
    ($id:literal, $name:literal, $severity:ident, $confidence:ident, $desc:literal, $help:literal) => {
        Rule {
            id: $id,
            name: $name,
            default_severity: Severity::$severity,
            confidence: Confidence::$confidence,
            description: $desc,
            help: $help,
            help_uri: concat!(
                "https://github.com/waltuov/bloxguard/blob/master/docs/rules/",
                $id,
                ".md"
            ),
        }
    };
}
static RULES: &[Rule] = &[
    rule!(
        "BG001",
        "Remote module require",
        High,
        High,
        "Numeric or unresolved external module loading.",
        "Review external module loading. Prefer code stored in your repository. Trust specific IDs only after review."
    ),
    rule!(
        "BG002",
        "Property-backed remote loader",
        Critical,
        High,
        "Remote module IDs read from instance properties or attributes.",
        "Review the script and the related property location. Hidden configuration can change the module that runs."
    ),
    rule!(
        "BG003",
        "Runtime code compilation",
        High,
        High,
        "loadstring or an alias builds executable code at runtime.",
        "Inspect the code origin. This scanner never executes or fetches generated code."
    ),
    rule!(
        "BG004",
        "Environment manipulation",
        High,
        High,
        "Environment access can hide calls or replace globals.",
        "Review getfenv, setfenv and indirect environment access. Legacy libraries may use them legitimately."
    ),
    rule!(
        "BG005",
        "Obfuscation signals",
        Medium,
        Medium,
        "Encoded strings, character chains or dispatch shapes obscure behavior.",
        "Review source that conceals intent. Minification and embedded data may be harmless. Correlated loaders raise severity."
    ),
    rule!(
        "BG006",
        "Unusual script placement",
        Medium,
        Medium,
        "Script placement, names or run context deserve review.",
        "Inspect the instance path and run context. Unusual placement alone does not establish malicious intent."
    ),
    rule!(
        "BG007",
        "Runtime asset loading",
        High,
        High,
        "Code imports assets or objects at runtime.",
        "Review the destination and inserted content. Offline analysis cannot inspect content fetched later."
    ),
    rule!(
        "BG008",
        "Possible HTTP exfiltration",
        High,
        Medium,
        "Outbound calls use suspicious endpoints or player and game data.",
        "Review what is sent and who controls the endpoint. Approved analytics can resemble exfiltration."
    ),
    rule!(
        "BG009",
        "Conditional activation",
        Medium,
        Medium,
        "Studio, identity or time checks control risky actions.",
        "Review hidden activation paths and long delays. Ordinary debug checks can be legitimate."
    ),
    rule!(
        "BG010",
        "Prompts and redirects",
        Medium,
        Medium,
        "Purchase prompts or external teleport destinations need review.",
        "Confirm the destination belongs to your experience or intended shop. Offline files do not prove ownership."
    ),
    rule!(
        "BG011",
        "Externally linked content",
        Medium,
        Medium,
        "Package links or linked source can change independently.",
        "Review package ownership, permissions and automatic updates. Your own packages can trigger this rule."
    ),
    rule!(
        "BG012",
        "Developer command instruction",
        High,
        Medium,
        "Text asks a developer to run or paste commands.",
        "Do not paste commands from untrusted content. Tutorials may contain legitimate instructions."
    ),
];
pub fn all() -> &'static [Rule] {
    RULES
}
pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}
