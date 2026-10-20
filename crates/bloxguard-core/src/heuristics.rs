//! Parse-only heuristics for rules that combine Luau shape and instance metadata.
//!
//! This module never evaluates Luau. Source checks run only after `full_moon`
//! has parsed the script, and comments are excluded by walking AST tokens.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::model::{
    Document, InputClock, Instance, Limits, MAX_REPORT_FINDINGS, MAX_REPORT_PATH_BYTES,
};
use full_moon::tokenizer::{Lexer, LexerResult, Token, TokenType};
use std::collections::{BTreeMap, BTreeSet};

const CORE_NAMES: &[&str] = &[
    "coregui",
    "game",
    "lighting",
    "players",
    "replicatedfirst",
    "replicatedstorage",
    "serverscriptservice",
    "serverstorage",
    "startergui",
    "starterpack",
    "starterplayer",
    "workspace",
];

const ODD_SCRIPT_CONTAINERS: &[&str] = &[
    "AnalyticsService",
    "CoreGui",
    "HttpService",
    "InsertService",
    "Lighting",
    "LocalizationService",
    "MaterialService",
    "SoundService",
    "TeleportService",
    "TextChatService",
];

#[derive(Debug)]
struct CodeToken {
    text: String,
    literal: Option<String>,
    is_number: bool,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
}

impl CodeToken {
    fn from_token(token: &Token) -> Self {
        let literal = match token.token_type() {
            TokenType::StringLiteral { literal, .. }
            | TokenType::InterpolatedString { literal, .. } => Some(literal.to_string()),
            TokenType::SingleLineComment { comment }
            | TokenType::MultiLineComment { comment, .. } => Some(comment.to_string()),
            _ => None,
        };
        let start = token.start_position();
        let end = token.end_position();
        Self {
            text: token.to_string(),
            literal,
            is_number: matches!(token.token_type(), TokenType::Number { .. }),
            line: start.line(),
            column: start.character(),
            end_line: end.line(),
            end_column: end.character(),
        }
    }

    fn location(&self) -> Location {
        Location {
            line: Some(self.line),
            column: Some(self.column),
            end_line: Some(self.end_line),
            end_column: Some(self.end_column),
            ..Location::default()
        }
    }
}

#[derive(Debug)]
struct LexedTokens {
    code: Vec<CodeToken>,
    comments: Vec<CodeToken>,
}

/// Analyze the metadata rules and the source-shape rules in this module.
///
/// Work is bounded by `Limits`. Oversized scripts and scripts that do not parse
/// are left to the loader/completeness layer rather than being scanned as text.
/// The time budget continues from `document.time_spent`.
pub fn analyze(document: &Document, limits: &Limits) -> crate::analysis::AnalysisResult {
    crate::parsing::on_large_stack(|| analyze_on_worker(document, limits)).unwrap_or_else(
        |reason| crate::analysis::AnalysisResult {
            reasons: vec![reason],
            ..crate::analysis::AnalysisResult::default()
        },
    )
}
fn analyze_on_worker(document: &Document, limits: &Limits) -> crate::analysis::AnalysisResult {
    let mut findings = Vec::new();
    let mut reasons = Vec::new();
    let mut accounted_findings = 0usize;
    let mut finding_path_bytes = 0usize;
    let clock = InputClock::resume(limits, document.time_spent);
    let placements = placements(document);

    if document.instances.len() > limits.max_instances {
        reasons.push(format!(
            "heuristic instance limit reached in {} ({} > {})",
            document.input,
            document.instances.len(),
            limits.max_instances
        ));
    }

    for (index, instance) in document
        .instances
        .iter()
        .enumerate()
        .take(limits.max_instances)
    {
        if findings.len() >= MAX_REPORT_FINDINGS || finding_path_bytes >= MAX_REPORT_PATH_BYTES {
            reasons.push(
                "heuristic finding output limit reached; remaining instances were not examined"
                    .into(),
            );
            break;
        }
        if clock.exceeded() {
            reasons.push(format!(
                "heuristic time budget exceeded in {}; remaining instances were not examined",
                document.input
            ));
            break;
        }

        check_package_link(document, index, instance, &mut findings);
        check_social_string_value(document, index, instance, &mut findings);
        if !account_new_findings(
            &mut findings,
            &mut accounted_findings,
            &mut finding_path_bytes,
        ) {
            reasons
                .push("heuristic finding output limit reached; additional findings omitted".into());
            break;
        }

        if !instance.is_script() {
            continue;
        }

        check_unusual_placement(document, index, instance, &placements[index], &mut findings);
        if !account_new_findings(
            &mut findings,
            &mut accounted_findings,
            &mut finding_path_bytes,
        ) {
            reasons
                .push("heuristic finding output limit reached; additional findings omitted".into());
            break;
        }

        let Some(source) = instance.source.as_deref() else {
            continue;
        };
        let source = crate::parsing::source_without_bom(source);
        if let Err(reason) = crate::analysis::parser_budget(source, limits) {
            // A declaration file is not code that runs: the analysis adds the note.
            if !crate::parsing::is_declaration_file_over_budget(source, limits) {
                reasons.push(format!(
                    "cannot safely parse {} for heuristic rules: {reason}",
                    document.path(index)
                ));
            }
            continue;
        }
        let ast = match full_moon::parse(source) {
            Ok(ast) => ast,
            // Not code that runs: the analysis adds the note for it.
            Err(errors) if crate::parsing::is_declaration_file(source, &errors) => continue,
            Err(errors) => {
                let summary = errors
                    .first()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown parse error".into());
                reasons.push(format!(
                    "could not parse {} for heuristic rules: {summary}",
                    document.path(index)
                ));
                continue;
            }
        };
        let dispatch_loop = vm_dispatch_loop(&ast);
        drop(ast);

        let tokens = match lex_code_tokens(source, crate::analysis::max_lexical_tokens(limits)) {
            Ok(tokens) => tokens,
            Err(reason) => {
                reasons.push(format!(
                    "cannot tokenize {} for heuristic rules: {reason}",
                    document.path(index)
                ));
                continue;
            }
        };
        if clock.exceeded() {
            reasons.push(format!(
                "heuristic time budget exceeded while parsing {}; source rules were not run",
                document.path(index)
            ));
            break;
        }

        check_obfuscation(
            document,
            index,
            instance,
            &tokens.code,
            dispatch_loop,
            &mut findings,
        );
        check_social_engineering(
            document,
            index,
            instance,
            &tokens.code,
            &tokens.comments,
            &mut findings,
        );
        if !account_new_findings(
            &mut findings,
            &mut accounted_findings,
            &mut finding_path_bytes,
        ) {
            reasons
                .push("heuristic finding output limit reached; additional findings omitted".into());
            break;
        }
    }

    findings.sort_by(|left, right| {
        (
            &left.rule_id,
            &left.instance_path,
            left.location.line,
            left.location.column,
            &left.evidence,
        )
            .cmp(&(
                &right.rule_id,
                &right.instance_path,
                right.location.line,
                right.location.column,
                &right.evidence,
            ))
    });
    crate::analysis::AnalysisResult {
        findings,
        reasons,
        notes: Vec::new(),
    }
}

fn account_new_findings(
    findings: &mut Vec<Finding>,
    accounted: &mut usize,
    path_bytes: &mut usize,
) -> bool {
    while *accounted < findings.len() {
        if *accounted >= MAX_REPORT_FINDINGS {
            findings.truncate(*accounted);
            return false;
        }
        let next_path_bytes = findings[*accounted].instance_path.len();
        if path_bytes.saturating_add(next_path_bytes) > MAX_REPORT_PATH_BYTES {
            findings.truncate(*accounted);
            return false;
        }
        *path_bytes += next_path_bytes;
        *accounted += 1;
    }
    true
}

fn lex_code_tokens(source: &str, limit: usize) -> Result<LexedTokens, String> {
    let mut lexer = Lexer::new(source, full_moon::LuaVersion::luau());
    let mut code = Vec::new();
    let mut comments = Vec::new();
    let mut token_count = 0usize;
    while let Some(item) = lexer.consume() {
        let reference = match item {
            LexerResult::Ok(reference) | LexerResult::Recovered(reference, _) => reference,
            LexerResult::Fatal(errors) => {
                return Err(format!("Luau tokenization failed: {errors:?}"));
            }
        };

        for trivia in reference.leading_trivia() {
            if matches!(
                trivia.token_type(),
                TokenType::SingleLineComment { .. } | TokenType::MultiLineComment { .. }
            ) {
                push_bounded_token(&mut comments, trivia, &mut token_count, limit)?;
            }
        }
        push_bounded_token(&mut code, reference.token(), &mut token_count, limit)?;
        for trivia in reference.trailing_trivia() {
            if matches!(
                trivia.token_type(),
                TokenType::SingleLineComment { .. } | TokenType::MultiLineComment { .. }
            ) {
                push_bounded_token(&mut comments, trivia, &mut token_count, limit)?;
            }
        }
    }
    Ok(LexedTokens { code, comments })
}

fn push_bounded_token(
    tokens: &mut Vec<CodeToken>,
    token: &Token,
    token_count: &mut usize,
    limit: usize,
) -> Result<(), String> {
    if *token_count >= limit {
        return Err(format!("token budget exceeded (more than {limit} tokens)"));
    }
    *token_count += 1;
    tokens.push(CodeToken::from_token(token));
    Ok(())
}

fn check_obfuscation(
    document: &Document,
    index: usize,
    instance: &Instance,
    tokens: &[CodeToken],
    dispatch_loop: Option<Location>,
    findings: &mut Vec<Finding>,
) {
    let mut signal: Option<(Location, String)> = None;

    for token in tokens {
        let Some(literal) = token.literal.as_deref() else {
            continue;
        };
        if is_high_entropy_blob(literal) {
            let content_hash = &crate::model::sha256(literal.as_bytes())[..12];
            signal = Some((
                token.location(),
                format!(
                    "long high-entropy string literal ({} characters; content_sha256={content_hash})",
                    literal.chars().count(),
                ),
            ));
            break;
        }
        let escapes = escape_profile(literal);
        if escapes.is_dense(literal.len()) {
            let content_hash = &crate::model::sha256(literal.as_bytes())[..12];
            signal = Some((
                token.location(),
                format!(
                    "dense escaped string literal ({} encoded characters; content_sha256={content_hash})",
                    escapes.encoded
                ),
            ));
            break;
        }
    }

    if signal.is_none()
        && let Some((token, arguments, content_hash)) = long_string_char_call(tokens)
    {
        signal = Some((
            token.location(),
            format!(
                "string.char builds data from {arguments} numeric arguments; content_sha256={content_hash}"
            ),
        ));
    }

    if signal.is_none() {
        let byte_calls: Vec<_> = (0..tokens.len())
            .filter(|&position| member_call_at(tokens, position, "string", "byte"))
            .collect();
        if byte_calls.len() >= 6 {
            let call_arguments = byte_calls.iter().flat_map(|&position| {
                let end = member_call_end(tokens, position).unwrap_or(position + 4);
                tokens[position + 4..end].iter()
            });
            let content_hash = short_literal_token_hash(call_arguments);
            signal = Some((
                tokens[byte_calls[0]].location(),
                format!(
                    "dense string.byte chain ({} calls); content_sha256={content_hash}",
                    byte_calls.len()
                ),
            ));
        }
    }

    if signal.is_none()
        && let Some(location) = dispatch_loop
        && vm_dispatch_shape(tokens)
    {
        signal = Some((
            location,
            format!(
                "VM-like loop dispatches over indexed junk data; content_sha256={}",
                short_literal_token_hash(tokens)
            ),
        ));
    }

    if let Some((location, evidence)) = signal {
        push_source_finding(
            findings,
            document,
            index,
            instance,
            "BG005",
            Severity::Medium,
            Confidence::High,
            location,
            "Obfuscation-like source shape needs review",
            &evidence,
        );
    }
}

fn check_unusual_placement(
    document: &Document,
    index: usize,
    instance: &Instance,
    placement: &Placement,
    findings: &mut Vec<Finding>,
) {
    let depth = placement.depth;
    let mut reason = None;
    let mut location = Location::default();

    if contains_invisible(&instance.name) {
        reason = Some("script name contains an invisible Unicode control".to_owned());
    } else if is_core_camouflage(&instance.name) {
        reason = Some(format!(
            "script name resembles a Roblox core object: {}",
            crate::model::escape_name(&instance.name)
        ));
    } else if depth >= 8 && placement.inside_model_or_part {
        reason = Some(format!(
            "script is hidden {depth} levels inside models or parts"
        ));
    } else if let Some(container) = placement
        .odd_container
        .and_then(|ancestor| document.instances.get(ancestor))
    {
        reason = Some(format!(
            "script is inside unusual service {}",
            container.class
        ));
    } else if let Some(run_context) = instance
        .properties
        .get("RunContext")
        .and_then(serde_json::Value::as_str)
        && ((run_context.eq_ignore_ascii_case("client")
            && (placement.server_container || placement.workspace_container))
            || (run_context.eq_ignore_ascii_case("server") && placement.client_container))
    {
        location.property = Some("RunContext".into());
        reason = Some(format!(
            "RunContext {run_context} conflicts with the containing hierarchy"
        ));
    }

    if let Some(reason) = reason {
        let path = document.path(index);
        let mut finding = Finding::new(
            "BG006",
            Severity::Medium,
            Confidence::High,
            &document.input,
            &path,
            location,
            "Script uses an unusual name or placement",
            &reason,
        );
        finding.set_files_from(instance);
        findings.push(finding);
    }
}

fn check_package_link(
    document: &Document,
    index: usize,
    instance: &Instance,
    findings: &mut Vec<Finding>,
) {
    // Every package property spelling is checked in a fixed order, so a file that
    // carries both the migrated `PackageContent` and a raw `PackageIdSerialize`
    // yields one stable finding.
    let candidate = if instance.class == "PackageLink" {
        crate::loading::PACKAGE_LINK_PROPERTIES
            .iter()
            .find_map(|name| {
                instance
                    .properties
                    .get(*name)
                    .filter(|value| is_external_reference(value))
                    .map(|value| ((*name).to_owned(), value))
            })
    } else {
        instance
            .properties
            .get("LinkedSource")
            .filter(|value| is_external_reference(value))
            .map(|value| ("LinkedSource".to_owned(), value))
    };

    let Some((property, value)) = candidate else {
        return;
    };
    let path = document.path(index);
    let evidence = format!("{property}={}", short_value(value));
    let mut finding = Finding::new(
        "BG011",
        Severity::Medium,
        Confidence::Medium,
        &document.input,
        &path,
        Location {
            property: Some(property),
            ..Location::default()
        },
        "Instance can receive externally controlled package content",
        &evidence,
    );
    finding.set_files_from(instance);
    findings.push(finding);
}

/// Properties that hold text shown to a developer or player: `Text` and every
/// `*Text` property (TextLabel, TextButton, TextBox, ProximityPrompt and others),
/// tool tips and dialog lines.
pub(crate) fn is_text_property(name: &str) -> bool {
    name.ends_with("Text")
        || matches!(
            name,
            "ToolTip" | "InitialPrompt" | "UserDialog" | "ResponseDialog" | "GoodbyeDialog"
        )
}

/// BG012 over instance data: a `StringValue` value, text properties, the
/// instance name and string attributes. One finding per instance, in that order.
fn check_social_string_value(
    document: &Document,
    index: usize,
    instance: &Instance,
    findings: &mut Vec<Finding>,
) {
    let string_value = (instance.class == "StringValue")
        .then(|| instance.properties.get("Value"))
        .flatten()
        .and_then(serde_json::Value::as_str)
        .map(|value| {
            (
                Location {
                    property: Some("Value".into()),
                    ..Location::default()
                },
                "StringValue instructs a developer to run code in Studio",
                value,
            )
        });
    let text_property = || {
        instance
            .properties
            .iter()
            .filter(|(name, _)| is_text_property(name))
            .find_map(|(name, value)| {
                value
                    .as_str()
                    .filter(|text| looks_like_social_instruction(text))
                    .map(|text| {
                        (
                            Location {
                                property: Some(name.clone()),
                                ..Location::default()
                            },
                            "Text property instructs a developer to run code in Studio",
                            text,
                        )
                    })
            })
    };
    let name = || {
        looks_like_social_instruction(&instance.name).then(|| {
            (
                Location {
                    property: Some("Name".into()),
                    ..Location::default()
                },
                "Instance name instructs a developer to run code in Studio",
                instance.name.as_str(),
            )
        })
    };
    let attribute = || {
        instance.attributes.iter().find_map(|(name, value)| {
            value
                .as_str()
                .filter(|text| looks_like_social_instruction(text))
                .map(|text| {
                    (
                        Location {
                            attribute: Some(name.clone()),
                            ..Location::default()
                        },
                        "Attribute instructs a developer to run code in Studio",
                        text,
                    )
                })
        })
    };
    let Some((location, message, evidence)) = string_value
        .filter(|(_, _, value)| looks_like_social_instruction(value))
        .or_else(text_property)
        .or_else(name)
        .or_else(attribute)
    else {
        return;
    };

    let path = document.path(index);
    let mut finding = Finding::new(
        "BG012",
        Severity::High,
        Confidence::High,
        &document.input,
        &path,
        location,
        message,
        evidence,
    );
    finding.set_files_from(instance);
    findings.push(finding);
}

fn check_social_engineering(
    document: &Document,
    index: usize,
    instance: &Instance,
    tokens: &[CodeToken],
    comments: &[CodeToken],
    findings: &mut Vec<Finding>,
) {
    if let Some(token) = tokens.iter().find(|token| {
        token
            .literal
            .as_deref()
            .is_some_and(looks_like_social_instruction)
    }) {
        let literal = token.literal.as_deref().unwrap_or_default();
        push_source_finding(
            findings,
            document,
            index,
            instance,
            "BG012",
            Severity::High,
            Confidence::High,
            token.location(),
            "String instructs a developer to run code in Studio",
            literal,
        );
    }

    if let Some(comment) = comments.iter().find(|comment| {
        comment
            .literal
            .as_deref()
            .is_some_and(looks_like_social_instruction)
    }) {
        let literal = comment.literal.as_deref().unwrap_or_default();
        push_source_finding(
            findings,
            document,
            index,
            instance,
            "BG012",
            Severity::High,
            Confidence::Medium,
            comment.location(),
            "Comment instructs a developer to run code in Studio",
            literal,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_source_finding(
    findings: &mut Vec<Finding>,
    document: &Document,
    index: usize,
    instance: &Instance,
    rule: &str,
    severity: Severity,
    confidence: Confidence,
    location: Location,
    message: &str,
    evidence: &str,
) {
    let path = document.path(index);
    let mut finding = Finding::new(
        rule,
        severity,
        confidence,
        &document.input,
        &path,
        location,
        message,
        evidence,
    );
    finding.set_files_from(instance);
    findings.push(finding);
}

fn is_high_entropy_blob(value: &str) -> bool {
    let characters: Vec<_> = value.chars().collect();
    if characters.len() < 256 {
        return false;
    }
    let non_whitespace = characters
        .iter()
        .filter(|character| !character.is_whitespace())
        .count();
    if non_whitespace * 100 < characters.len() * 96 {
        return false;
    }
    let mut counts = std::collections::BTreeMap::new();
    for character in &characters {
        *counts.entry(*character).or_insert(0usize) += 1;
    }
    if counts.len() < 24 {
        return false;
    }
    let length = characters.len() as f64;
    let entropy = counts.values().fold(0.0, |total, &count| {
        let probability = count as f64 / length;
        total - probability * probability.log2()
    });
    entropy >= 4.5
}

/// Numeric escapes in the raw text of a string literal: `\ddd` (one to three
/// digits), `\xHH` and `\u{...}`, each measured by the bytes it really uses.
/// A `\z` escape only skips the whitespace after it, so those bytes are kept
/// apart. Other escapes such as `\n` or `\\` count as ordinary text.
#[derive(Debug, Default, PartialEq, Eq)]
struct EscapeProfile {
    /// Number of numeric escapes.
    encoded: usize,
    /// Source bytes used by those escapes.
    encoded_bytes: usize,
    /// Bytes of `\z` escapes and the whitespace they skip.
    skipped_bytes: usize,
}

impl EscapeProfile {
    /// Dense means at least 12 numeric escapes and either at most five source
    /// bytes per escape on average (the rule from before `\u{...}` escapes were
    /// measured) or at most one byte of other text per escape on average.
    fn is_dense(&self, literal_bytes: usize) -> bool {
        if self.encoded < 12 {
            return false;
        }
        let other_bytes = literal_bytes.saturating_sub(self.encoded_bytes + self.skipped_bytes);
        self.encoded * 5 >= literal_bytes.max(1) || other_bytes <= self.encoded
    }
}

fn escape_profile(value: &str) -> EscapeProfile {
    let bytes = value.as_bytes();
    let mut profile = EscapeProfile::default();
    let mut position = 0;
    while position < bytes.len() {
        if bytes[position] != b'\\' || position + 1 == bytes.len() {
            position += 1;
            continue;
        }
        let start = position;
        position += 2;
        match bytes[start + 1] {
            b'0'..=b'9' => {
                while position < start + 4 && bytes.get(position).is_some_and(u8::is_ascii_digit) {
                    position += 1;
                }
            }
            b'x' | b'X' => {
                while position < start + 4 && bytes.get(position).is_some_and(u8::is_ascii_hexdigit)
                {
                    position += 1;
                }
            }
            b'u' | b'U' => {
                if bytes.get(position) == Some(&b'{') {
                    let mut end = position + 1;
                    while bytes.get(end).is_some_and(u8::is_ascii_hexdigit) {
                        end += 1;
                    }
                    position = if bytes.get(end) == Some(&b'}') {
                        end + 1
                    } else {
                        end
                    };
                }
            }
            b'z' => {
                while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
                    position += 1;
                }
                profile.skipped_bytes += position - start;
                continue;
            }
            _ => continue,
        }
        profile.encoded += 1;
        profile.encoded_bytes += position - start;
    }
    profile
}

/// Location of the first loop shaped like the dispatch loop of a bytecode VM.
/// In the loop body, not counting nested functions, `if` and `elseif`
/// conditions compare one value with at least three different numbers, in one
/// chain or in nested `if` statements. The value is read from indexed data:
/// it is indexed itself (`inst[1]`), or a name assigned from an index read
/// (`local op = ops[pc]`). Table lookups such as `handlers[id](...)` and
/// comparisons with names or strings do not count.
fn vm_dispatch_loop(ast: &full_moon::ast::Ast) -> Option<Location> {
    use full_moon::visitors::Visitor;

    let mut finder = DispatchFinder {
        functions: vec![Vec::new()],
        ..DispatchFinder::default()
    };
    finder.visit_ast(ast);
    let indexed_names = &finder.indexed_names;
    finder
        .closed
        .into_iter()
        .filter(|candidate| {
            candidate.comparisons.iter().any(|(subject, constants)| {
                constants.len() >= 3 && (subject.indexed || indexed_names.contains(&subject.base))
            })
        })
        .map(|candidate| candidate.location)
        .min_by_key(|location| (location.line, location.column))
}

#[derive(Default)]
struct DispatchFinder {
    /// Open loops of each enclosing function body; the last entry is the
    /// function being visited, the first one the script's main chunk.
    functions: Vec<Vec<DispatchLoop>>,
    closed: Vec<DispatchLoop>,
    /// Names assigned from an index read anywhere in the script.
    indexed_names: BTreeSet<String>,
}

struct DispatchLoop {
    location: Location,
    /// Numeric constants each subject is compared with.
    comparisons: BTreeMap<DispatchSubject, BTreeSet<String>>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DispatchSubject {
    base: String,
    text: String,
    indexed: bool,
}

impl DispatchFinder {
    fn open(&mut self, keyword: &full_moon::tokenizer::TokenReference) {
        let start = keyword.token().start_position();
        let end = keyword.token().end_position();
        if let Some(loops) = self.functions.last_mut() {
            loops.push(DispatchLoop {
                location: Location {
                    line: Some(start.line()),
                    column: Some(start.character()),
                    end_line: Some(end.line()),
                    end_column: Some(end.character()),
                    ..Location::default()
                },
                comparisons: BTreeMap::new(),
            });
        }
    }

    fn close(&mut self) {
        if let Some(open) = self.functions.last_mut().and_then(Vec::pop) {
            self.closed.push(open);
        }
    }

    fn record(&mut self, condition: &full_moon::ast::Expression) {
        use full_moon::ast::{BinOp, Expression};

        let Some(open) = self.functions.last_mut().and_then(|loops| loops.last_mut()) else {
            return;
        };
        let mut pending = vec![condition];
        while let Some(expression) = pending.pop() {
            match expression {
                Expression::Parentheses { expression, .. } => pending.push(expression),
                Expression::BinaryOperator { lhs, binop, rhs } => match binop {
                    BinOp::And(_) | BinOp::Or(_) => {
                        pending.push(rhs);
                        pending.push(lhs);
                    }
                    BinOp::TwoEqual(_)
                    | BinOp::TildeEqual(_)
                    | BinOp::LessThan(_)
                    | BinOp::LessThanEqual(_)
                    | BinOp::GreaterThan(_)
                    | BinOp::GreaterThanEqual(_) => {
                        let pair = match (dispatch_subject(lhs), number_text(rhs)) {
                            (Some(subject), Some(number)) => Some((subject, number)),
                            _ => dispatch_subject(rhs).zip(number_text(lhs)),
                        };
                        if let Some((subject, number)) = pair {
                            open.comparisons.entry(subject).or_default().insert(number);
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
}

impl full_moon::visitors::Visitor for DispatchFinder {
    fn visit_function_body(&mut self, _node: &full_moon::ast::FunctionBody) {
        self.functions.push(Vec::new());
    }
    fn visit_function_body_end(&mut self, _node: &full_moon::ast::FunctionBody) {
        if let Some(open) = self.functions.pop() {
            self.closed.extend(open);
        }
    }
    fn visit_while(&mut self, node: &full_moon::ast::While) {
        self.open(node.while_token());
    }
    fn visit_while_end(&mut self, _node: &full_moon::ast::While) {
        self.close();
    }
    fn visit_repeat(&mut self, node: &full_moon::ast::Repeat) {
        self.open(node.repeat_token());
    }
    fn visit_repeat_end(&mut self, _node: &full_moon::ast::Repeat) {
        self.close();
    }
    fn visit_numeric_for(&mut self, node: &full_moon::ast::NumericFor) {
        self.open(node.for_token());
    }
    fn visit_numeric_for_end(&mut self, _node: &full_moon::ast::NumericFor) {
        self.close();
    }
    fn visit_generic_for(&mut self, node: &full_moon::ast::GenericFor) {
        self.open(node.for_token());
    }
    fn visit_generic_for_end(&mut self, _node: &full_moon::ast::GenericFor) {
        self.close();
    }
    fn visit_if(&mut self, node: &full_moon::ast::If) {
        self.record(node.condition());
        for branch in node.else_if().into_iter().flatten() {
            self.record(branch.condition());
        }
    }
    fn visit_local_assignment(&mut self, node: &full_moon::ast::LocalAssignment) {
        for (name, value) in node.names().iter().zip(node.expressions().iter()) {
            if is_index_read(value) {
                self.indexed_names.insert(name.token().to_string());
            }
        }
    }
    fn visit_assignment(&mut self, node: &full_moon::ast::Assignment) {
        for (variable, value) in node.variables().iter().zip(node.expressions().iter()) {
            if let full_moon::ast::Var::Name(name) = variable
                && is_index_read(value)
            {
                self.indexed_names.insert(name.token().to_string());
            }
        }
    }
}

fn without_parentheses(mut expression: &full_moon::ast::Expression) -> &full_moon::ast::Expression {
    use full_moon::ast::Expression;
    loop {
        match expression {
            Expression::Parentheses {
                expression: inner, ..
            }
            | Expression::TypeAssertion {
                expression: inner, ..
            } => expression = inner,
            _ => return expression,
        }
    }
}

/// `name` or `name` followed only by `.field` and `[key]` indexes.
fn dispatch_subject(expression: &full_moon::ast::Expression) -> Option<DispatchSubject> {
    use full_moon::ast::{Expression, Index, Prefix, Suffix, Var};

    match without_parentheses(expression) {
        Expression::Var(Var::Name(name)) => {
            let name = name.token().to_string();
            Some(DispatchSubject {
                base: name.clone(),
                text: name,
                indexed: false,
            })
        }
        Expression::Var(Var::Expression(var)) => {
            let Prefix::Name(base) = var.prefix() else {
                return None;
            };
            let base = base.token().to_string();
            let mut text = base.clone();
            let mut indexed = false;
            for suffix in var.suffixes() {
                match suffix {
                    Suffix::Index(Index::Brackets { expression, .. }) => {
                        indexed = true;
                        text.push('[');
                        text.push_str(expression.to_string().trim());
                        text.push(']');
                    }
                    Suffix::Index(Index::Dot { name, .. }) => {
                        text.push('.');
                        text.push_str(&name.token().to_string());
                    }
                    _ => return None,
                }
            }
            Some(DispatchSubject {
                base,
                text,
                indexed,
            })
        }
        _ => None,
    }
}

fn number_text(expression: &full_moon::ast::Expression) -> Option<String> {
    match without_parentheses(expression) {
        full_moon::ast::Expression::Number(number) => Some(number.token().to_string()),
        _ => None,
    }
}

/// A read such as `ops[pc]` or `code[pc][1]`: indexes that include a `[key]`
/// and end in an index, not a call.
fn is_index_read(expression: &full_moon::ast::Expression) -> bool {
    use full_moon::ast::{Expression, Index, Suffix, Var};

    let Expression::Var(Var::Expression(var)) = without_parentheses(expression) else {
        return false;
    };
    let suffixes: Vec<_> = var.suffixes().collect();
    suffixes
        .last()
        .is_some_and(|last| matches!(last, Suffix::Index(_)))
        && suffixes
            .iter()
            .any(|suffix| matches!(suffix, Suffix::Index(Index::Brackets { .. })))
}

fn long_string_char_call(tokens: &[CodeToken]) -> Option<(&CodeToken, usize, String)> {
    for position in 0..tokens.len() {
        if !member_call_at(tokens, position, "string", "char") {
            continue;
        }
        let mut depth = 0usize;
        let mut numbers = 0usize;
        let mut argument_end = None;
        for (offset, token) in tokens.iter().enumerate().skip(position + 3) {
            match token.text.as_str() {
                "(" => depth += 1,
                ")" if depth == 1 => {
                    argument_end = Some(offset);
                    break;
                }
                ")" => depth = depth.saturating_sub(1),
                _ if depth == 1 && token.is_number => numbers += 1,
                _ => {}
            }
        }
        if numbers >= 10
            && let Some(argument_end) = argument_end
        {
            let content_hash = short_literal_token_hash(tokens[position + 4..argument_end].iter());
            return Some((&tokens[position], numbers, content_hash));
        }
    }
    None
}

fn member_call_end(tokens: &[CodeToken], position: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, token) in tokens.iter().enumerate().skip(position + 3) {
        match token.text.as_str() {
            "(" => depth += 1,
            ")" if depth == 1 => return Some(offset),
            ")" => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn short_literal_token_hash<'a>(tokens: impl IntoIterator<Item = &'a CodeToken>) -> String {
    let mut canonical = Vec::new();
    for token in tokens {
        let Some(content) = token
            .literal
            .as_deref()
            .or_else(|| token.is_number.then_some(token.text.as_str()))
        else {
            continue;
        };
        canonical.extend_from_slice(&(content.len() as u64).to_le_bytes());
        canonical.extend_from_slice(content.as_bytes());
    }
    crate::model::sha256(&canonical)[..12].to_owned()
}

fn member_call_at(tokens: &[CodeToken], position: usize, receiver: &str, member: &str) -> bool {
    tokens
        .get(position)
        .is_some_and(|token| token.text == receiver)
        && tokens
            .get(position + 1)
            .is_some_and(|token| token.text == ".")
        && tokens
            .get(position + 2)
            .is_some_and(|token| token.text == member)
        && tokens
            .get(position + 3)
            .is_some_and(|token| token.text == "(")
}

/// The data around a dispatch loop: enough code, indexing and numbers. The loop
/// and its branches are checked on the syntax tree by `vm_dispatch_loop`.
fn vm_dispatch_shape(tokens: &[CodeToken]) -> bool {
    if tokens.len() < 60 {
        return false;
    }
    let indexes = tokens.iter().filter(|token| token.text == "[").count();
    let numbers = tokens
        .iter()
        .filter(|token| token.text.parse::<f64>().is_ok())
        .count();
    indexes >= 3 && numbers >= 8
}

/// What the ancestors of one instance contain, for the BG006 placement checks.
#[derive(Debug, Clone, Copy, Default)]
struct Placement {
    depth: usize,
    inside_model_or_part: bool,
    /// Nearest ancestor whose class is in `ODD_SCRIPT_CONTAINERS`.
    odd_container: Option<usize>,
    server_container: bool,
    client_container: bool,
    workspace_container: bool,
}

impl Placement {
    fn child_of(self, parent_index: usize, parent: &Instance) -> Self {
        let class = parent.class.as_str();
        Self {
            depth: self.depth.saturating_add(1),
            inside_model_or_part: self.inside_model_or_part
                || matches!(
                    class,
                    "Model"
                        | "Part"
                        | "MeshPart"
                        | "UnionOperation"
                        | "WedgePart"
                        | "TrussPart"
                        | "Seat"
                        | "VehicleSeat"
                ),
            odd_container: if ODD_SCRIPT_CONTAINERS.contains(&class) {
                Some(parent_index)
            } else {
                self.odd_container
            },
            server_container: self.server_container
                || matches!(class, "ServerScriptService" | "ServerStorage"),
            client_container: self.client_container
                || matches!(
                    class,
                    "ReplicatedStorage"
                        | "ReplicatedFirst"
                        | "StarterGui"
                        | "StarterPlayer"
                        | "StarterPlayerScripts"
                        | "StarterCharacterScripts"
                ),
            workspace_container: self.workspace_container || class == "Workspace",
        }
    }
}

/// Placement of every instance in one pass over the whole ancestor chain, so a
/// deep tree costs linear time and no ancestor is out of sight. A parent cycle
/// stops at the first instance seen twice.
fn placements(document: &Document) -> Vec<Placement> {
    let count = document.instances.len();
    let mut placements = vec![Placement::default(); count];
    let mut seen = vec![false; count];
    let mut chain = Vec::new();
    for start in 0..count {
        let mut current = Some(start);
        while let Some(index) = current.filter(|&index| index < count && !seen[index]) {
            seen[index] = true;
            chain.push(index);
            current = document.instances[index].parent;
        }
        // Nearest the root first, so each parent is filled in before its children.
        while let Some(index) = chain.pop() {
            if let Some(parent) = document.instances[index].parent.filter(|&p| p < count) {
                placements[index] =
                    placements[parent].child_of(parent, &document.instances[parent]);
            }
        }
    }
    placements
}

fn contains_invisible(value: &str) -> bool {
    value.chars().any(is_invisible)
}

fn is_invisible(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'
            | '\u{1160}'
            | '\u{17b4}'
            | '\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{e0000}'..='\u{e007f}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}

/// Combining marks from the blocks that decorate Latin, Greek and Cyrillic
/// letters. A mark on an ASCII letter keeps the letter's look.
fn is_combining_mark(character: char) -> bool {
    matches!(
        character,
        '\u{0300}'..='\u{036f}'
            | '\u{0483}'..='\u{0489}'
            | '\u{1ab0}'..='\u{1aff}'
            | '\u{1dc0}'..='\u{1dff}'
            | '\u{20d0}'..='\u{20ff}'
            | '\u{fe20}'..='\u{fe2f}'
    )
}

fn is_unicode_space(character: char) -> bool {
    matches!(
        character,
        '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// Text folded for comparison: lowercase ASCII where every changed character
/// had an obvious ASCII reading.
struct FoldedText {
    text: String,
    /// A character was removed or replaced by more than ASCII lowercasing.
    changed: bool,
    /// A non-ASCII character had no ASCII reading and was kept as it is.
    unmapped: bool,
}

/// Fold names and messages before matching. Invisible characters and combining
/// marks are removed, fullwidth and mathematical letters become ASCII, accented
/// Latin letters lose their accent, and known look-alike letters become the
/// letter they imitate. Nothing here is locale specific, so output is stable.
fn fold_text(value: &str) -> FoldedText {
    let mut folded = FoldedText {
        text: String::with_capacity(value.len()),
        changed: false,
        unmapped: false,
    };
    for character in value.chars() {
        if character.is_ascii() {
            folded.text.push(character.to_ascii_lowercase());
            continue;
        }
        folded.changed = true;
        if is_invisible(character) || is_combining_mark(character) {
            continue;
        }
        if is_unicode_space(character) {
            folded.text.push(' ');
        } else if let Some(ascii) = ascii_reading(character) {
            folded.text.push(ascii.to_ascii_lowercase());
        } else {
            folded.unmapped = true;
            folded.text.extend(character.to_lowercase());
        }
    }
    folded
}

fn ascii_reading(character: char) -> Option<char> {
    let code = character as u32;
    match code {
        // Fullwidth ASCII forms.
        0xff01..=0xff5e => char::from_u32(code - 0xfee0),
        // Mathematical alphanumeric letters: styled A to Z and a to z blocks.
        0x1d400..=0x1d6a3 => char::from_u32(u32::from(b'a') + (code - 0x1d400) % 52 % 26),
        // Mathematical digits.
        0x1d7ce..=0x1d7ff => char::from_u32(u32::from(b'0') + (code - 0x1d7ce) % 10),
        _ => latin_base_letter(character).or_else(|| confusable_ascii(character)),
    }
}

/// Base letter of a precomposed Latin letter, as Unicode decomposition gives it.
fn latin_base_letter(character: char) -> Option<char> {
    Some(match character {
        'À'..='Å' | 'à'..='å' | 'Ā'..='ą' | 'Ǎ' | 'ǎ' | 'Ạ' | 'ạ' => 'a',
        'Ç' | 'ç' | 'Ć'..='č' => 'c',
        'Ď'..='đ' => 'd',
        'È'..='Ë' | 'è'..='ë' | 'Ē'..='ě' | 'Ẹ' | 'ẹ' => 'e',
        'Ĝ'..='ģ' => 'g',
        'Ĥ'..='ħ' => 'h',
        'Ì'..='Ï' | 'ì'..='ï' | 'Ĩ'..='ı' | 'Ǐ' | 'ǐ' | 'Ị' | 'ị' => 'i',
        'Ĵ' | 'ĵ' => 'j',
        'Ķ' | 'ķ' => 'k',
        'Ĺ'..='ł' => 'l',
        'Ñ' | 'ñ' | 'Ń'..='ň' => 'n',
        'Ò'..='Ö' | 'Ø' | 'ò'..='ö' | 'ø' | 'Ō'..='ő' | 'Ǒ' | 'ǒ' | 'Ọ' | 'ọ' => 'o',
        'Ŕ'..='ř' => 'r',
        'Ś'..='š' => 's',
        'Ţ'..='ŧ' => 't',
        'Ù'..='Ü' | 'ù'..='ü' | 'Ũ'..='ų' | 'Ǔ' | 'ǔ' | 'Ụ' | 'ụ' => 'u',
        'Ŵ' | 'ŵ' => 'w',
        'Ý' | 'ý' | 'ÿ' | 'Ŷ'..='Ÿ' => 'y',
        'Ź'..='ž' => 'z',
        _ => return None,
    })
}

/// Collapse ASCII letters and digits that look alike in Studio's Explorer font,
/// in the spirit of Unicode TR39 skeletons, after `fold_text`.
fn ascii_skeleton(folded: &str) -> String {
    folded
        .trim()
        .replace("rn", "m")
        .replace("vv", "w")
        .chars()
        .map(|character| match character {
            '0' => 'o',
            '1' | 'i' | '|' => 'l',
            other => other,
        })
        .collect()
}

fn is_core_camouflage(name: &str) -> bool {
    let folded = fold_text(name);
    if folded.unmapped {
        return false;
    }
    let skeleton = ascii_skeleton(&folded.text);
    CORE_NAMES
        .iter()
        .any(|core| ascii_skeleton(core) == skeleton)
}

fn confusable_ascii(character: char) -> Option<char> {
    Some(match character {
        'А' | 'а' | 'Α' | 'α' => 'a',
        'В' | 'в' | 'Β' | 'β' => 'b',
        'С' | 'с' => 'c',
        'Е' | 'е' | 'Ε' | 'ε' => 'e',
        'Н' | 'н' => 'h',
        'І' | 'і' | 'Ι' | 'ι' => 'i',
        'Ј' | 'ј' => 'j',
        'К' | 'к' | 'Κ' | 'κ' => 'k',
        'М' | 'м' | 'Μ' | 'μ' => 'm',
        'Ν' | 'ν' => 'n',
        'О' | 'о' | 'Ο' | 'ο' => 'o',
        'Р' | 'р' | 'Ρ' | 'ρ' => 'p',
        'Ѕ' | 'ѕ' => 's',
        'Т' | 'т' | 'Τ' | 'τ' => 't',
        'Х' | 'х' | 'Χ' | 'χ' => 'x',
        'Ү' | 'ү' | 'Υ' | 'υ' => 'y',
        'ԁ' => 'd',
        'һ' => 'h',
        'Ӏ' | 'ӏ' => 'l',
        'ԛ' => 'q',
        'Ԝ' | 'ԝ' => 'w',
        // Letterlike symbols, Roman numerals and IPA letters with a Latin look.
        'ɑ' => 'a',
        'ⅆ' => 'd',
        'ℯ' | 'ⅇ' => 'e',
        'ℊ' | 'ɡ' => 'g',
        'ℎ' => 'h',
        'ℹ' | 'ⅈ' | 'ɩ' | 'Ⅰ' | 'ⅰ' => 'i',
        'ℓ' | 'Ⅼ' | 'ⅼ' => 'l',
        'ℴ' => 'o',
        'Ⅽ' | 'ⅽ' => 'c',
        'Ⅾ' | 'ⅾ' => 'd',
        'Ⅿ' | 'ⅿ' => 'm',
        'Ⅴ' | 'ⅴ' => 'v',
        'Ⅹ' | 'ⅹ' => 'x',
        _ => return None,
    })
}

fn is_external_reference(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(enabled) => *enabled,
        serde_json::Value::Number(number) => number.as_u64().unwrap_or(1) != 0,
        serde_json::Value::String(text) => {
            let text = text.trim();
            let lower = text.to_ascii_lowercase();
            // `rbxassetid://0` and a bare scheme are the empty forms Studio writes.
            let asset = lower.strip_prefix("rbxassetid://").unwrap_or(&lower);
            !text.is_empty()
                && !asset.is_empty()
                && !asset.bytes().all(|byte| byte == b'0')
                && lower != "null"
                && !lower.starts_with("rbxasset://")
                && !lower.starts_with("rbxgameasset://")
        }
        serde_json::Value::Array(values) => !values.is_empty(),
        serde_json::Value::Object(values) => !values.is_empty(),
    }
}

fn short_value(value: &serde_json::Value) -> String {
    let rendered = value.to_string();
    rendered.chars().take(80).collect()
}

/// Names of the privileged places where pasted Luau runs. Matched as whole
/// words after folding, so `Command-Bar`, `cmd bar` and look-alike letters match.
const COMMAND_SURFACES: &[&str] = &[
    "command bar",
    "commandbar",
    "cmd bar",
    "cmdbar",
    "developer console",
    "dev console",
    "devconsole",
];

const DIRECT_INSTRUCTIONS: &[&str] = &[
    "paste this",
    "paste the following",
    "paste the code",
    "paste the script",
    "paste it",
    "copy and paste",
    "copy paste",
    "copy this",
    "run this",
    "run the following",
    "run the code",
    "run the script",
    "execute this",
    "execute the following",
    "execute the code",
    "type this",
    "enter this",
    "put this",
    "insert this",
];

/// Verbs that need a code fragment nearby before the text counts as an instruction.
const INSTRUCTION_ACTIONS: &[&str] = &[
    "paste",
    "pastes",
    "pasting",
    "run",
    "runs",
    "running",
    "execute",
    "executes",
    "executing",
    "exec",
    "type",
    "typing",
    "enter",
    "entering",
    "copy",
    "copying",
    "put",
    "insert",
    "inserting",
];

fn looks_like_social_instruction(value: &str) -> bool {
    // Cheap exit for the common ASCII case: every surface spells cmd, command
    // or console.
    if value.is_ascii()
        && !["cmd", "command", "console"]
            .iter()
            .any(|needle| ascii_contains_ignore_case(value, needle))
    {
        return false;
    }
    let folded = fold_text(value).text;
    let mut words = String::with_capacity(folded.len() + 2);
    words.push(' ');
    for character in folded.chars() {
        if character.is_ascii_alphanumeric() {
            words.push(character);
        } else if !words.ends_with(' ') {
            words.push(' ');
        }
    }
    if !words.ends_with(' ') {
        words.push(' ');
    }
    let has_words = |phrase: &str| words.contains(&format!(" {phrase} "));
    if !COMMAND_SURFACES.iter().any(|surface| has_words(surface)) {
        return false;
    }
    DIRECT_INSTRUCTIONS.iter().any(|phrase| has_words(phrase))
        || (INSTRUCTION_ACTIONS.iter().any(|action| has_words(action))
            && contains_code_fragment(&folded))
}

fn ascii_contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Luau that a reader is told to run: a call to a loader or environment function,
/// or an index into `game`, `workspace`, `script`, `shared` or `_G`.
fn contains_code_fragment(folded: &str) -> bool {
    let bytes = folded.as_bytes();
    let starts_identifier = |start: usize| {
        start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_')
    };
    for name in ["require", "loadstring", "getfenv", "setfenv"] {
        for (start, _) in folded.match_indices(name) {
            if !starts_identifier(start) {
                continue;
            }
            let after = folded[start + name.len()..].trim_start();
            if after.starts_with(['(', '"', '\'', '[', '{']) {
                return true;
            }
        }
    }
    for name in ["game", "workspace", "script", "shared", "_g"] {
        for (start, _) in folded.match_indices(name) {
            if !starts_identifier(start) {
                continue;
            }
            let after = &bytes[start + name.len()..];
            if after.len() >= 2 && matches!(after[0], b'.' | b':') && after[1].is_ascii_alphabetic()
            {
                return true;
            }
        }
    }
    false
}
