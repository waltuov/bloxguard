//! Bounded, parse-only Luau analysis.
//!
//! This module never evaluates scanned source. `full_moon` supplies the AST and the
//! small evaluator below only folds literals and follows the normalized instance graph.
//! Every set of candidate values, replayed function body and folded string is bounded.

use crate::finding::{Confidence, Finding, Location, RelatedLocation, Severity};
use crate::model::{ChildLookup, Document, DomIndex, InstanceWrites, Limits, sha256};
use full_moon::ast::luau::{ConstAssignment, ConstFunction, IfExpression, InterpolatedString};
use full_moon::ast::punctuated::Punctuated;
use full_moon::ast::{
    Assignment, BinOp, Block, Call, CompoundAssignment, CompoundOp, ElseIf, Expression, Field,
    FunctionArgs, FunctionBody, FunctionCall, FunctionDeclaration, GenericFor, If, Index, LastStmt,
    LocalAssignment, LocalFunction, MethodCall, NumericFor, Parameter, Prefix, Repeat, Return,
    Stmt, Suffix, TableConstructor, UnOp, Var, VarExpression, While,
};
use full_moon::node::Node;
use full_moon::tokenizer::{
    InterpolatedStringKind, Lexer, LexerResult, Position, StringLiteralQuoteType, Symbol,
    TokenReference, TokenType,
};
use full_moon::visitors::{Visit, Visitor};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub reasons: Vec<String>,
    /// Informational notes about the script, such as a type declaration file that was
    /// not scanned. They do not make the input partial.
    pub notes: Vec<String>,
}

/// Fixed cap on lexical nesting (brackets, blocks and function bodies) before parsing.
///
/// Luau's own parser stops near 1,000 levels, so code that Roblox accepts stays below
/// this cap. It is independent of the configurable `max_depth`.
pub const MAX_LEXICAL_NESTING: usize = 1_024;

/// Fixed cap on operators (binary, unary, casts and if-expressions) that can nest in one
/// expression. The count is cumulative along open brackets and restarts per statement.
/// Concatenation is counted separately, see [`MAX_CONCAT_OPERATORS`].
pub const MAX_EXPRESSION_OPERATORS: usize = 1_024;

/// Fixed cap on `..` operators in one expression, counted like
/// [`MAX_EXPRESSION_OPERATORS`]. Long concatenations of text are common. Measured on
/// the parser worker's stack with 880 brackets, 1,000 operators and 120 nested
/// interpolations around the chain, a debug build still finished 32,768 levels and a
/// release build 131,072, so this cap keeps a margin of four in debug and sixteen in
/// release. A plain chain overflowed at 65,536 levels in debug and 262,144 in release.
pub const MAX_CONCAT_OPERATORS: usize = 8_192;

/// Fixed cap on nested interpolated strings, which cost more parser stack per level.
pub const MAX_INTERPOLATION_NESTING: usize = 128;

/// Number of Luau tokens that buy one `max_analysis_steps` allowance.
pub const TOKENS_PER_STEP_ALLOWANCE: usize = 8_192;

/// Token cap derived from the script size limit: one token per two bytes.
pub fn max_lexical_tokens(limits: &Limits) -> usize {
    (limits.max_script_bytes / 2).max(1_024)
}

/// Propagation steps allowed for a script with this many tokens.
pub fn analysis_step_budget(limits: &Limits, tokens: usize) -> usize {
    limits
        .max_analysis_steps
        .saturating_mul(1 + tokens / TOKENS_PER_STEP_ALLOWANCE)
}

/// What the lexical budget learned about a script that passed it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LexicalSummary {
    /// Number of code tokens, comments and whitespace excluded.
    pub tokens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Root,
    Paren,
    Bracket,
    Brace,
    Interpolation,
    Block,
    LoopHeader,
    Repeat,
}

#[derive(Debug, Clone, Copy)]
struct LexicalFrame {
    kind: FrameKind,
    /// Operator count when the frame opened. Statements inside restart from it.
    base: usize,
    /// Concatenation count when the frame opened.
    concat_base: usize,
    /// If-expressions at this level that have not reached their `else` yet.
    open_if_expressions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Previous {
    /// Start of input or a statement boundary.
    Statement,
    /// A token that can end an operand, such as a name, a literal or a closing bracket.
    Operand,
    /// A token after which an expression must follow.
    Expression,
}

struct LexicalBudget {
    frames: Vec<LexicalFrame>,
    interpolations: usize,
    operators: usize,
    concats: usize,
    previous: Previous,
}

impl LexicalBudget {
    fn new() -> Self {
        Self {
            frames: vec![LexicalFrame {
                kind: FrameKind::Root,
                base: 0,
                concat_base: 0,
                open_if_expressions: 0,
            }],
            interpolations: 0,
            operators: 0,
            concats: 0,
            previous: Previous::Statement,
        }
    }

    fn base(&self) -> usize {
        self.frames.last().map_or(0, |frame| frame.base)
    }

    fn concat_base(&self) -> usize {
        self.frames.last().map_or(0, |frame| frame.concat_base)
    }

    fn statement_boundary(&mut self) {
        self.operators = self.base();
        self.concats = self.concat_base();
        if let Some(frame) = self.frames.last_mut() {
            frame.open_if_expressions = 0;
        }
    }

    fn open(&mut self, kind: FrameKind) -> Result<(), String> {
        self.frames.push(LexicalFrame {
            kind,
            base: self.operators,
            concat_base: self.concats,
            open_if_expressions: 0,
        });
        if kind == FrameKind::Interpolation {
            self.interpolations += 1;
            if self.interpolations > MAX_INTERPOLATION_NESTING {
                return Err(format!(
                    "Luau interpolated string nesting exceeds the parser safety cap ({} > {MAX_INTERPOLATION_NESTING})",
                    self.interpolations
                ));
            }
        }
        let depth = self.frames.len() - 1;
        if depth > MAX_LEXICAL_NESTING {
            return Err(format!(
                "Luau nesting depth exceeds the parser safety cap ({depth} > {MAX_LEXICAL_NESTING})"
            ));
        }
        Ok(())
    }

    /// Close the innermost frame when it is one of `kinds`. A closer that does not match
    /// leaves the frames open: over-counting malformed input is harmless because it does
    /// not parse, while popping unrelated frames could under-count real nesting.
    fn close(&mut self, kinds: &[FrameKind]) {
        if !self
            .frames
            .last()
            .is_some_and(|frame| kinds.contains(&frame.kind))
        {
            return;
        }
        if let Some(frame) = self.frames.pop() {
            if frame.kind == FrameKind::Interpolation {
                self.interpolations = self.interpolations.saturating_sub(1);
            }
            self.operators = frame.base;
            self.concats = frame.concat_base;
        }
    }

    fn operator(&mut self) -> Result<(), String> {
        self.operators += 1;
        if self.operators > MAX_EXPRESSION_OPERATORS {
            return Err(format!(
                "Luau expression complexity exceeds the parser safety cap ({} > {MAX_EXPRESSION_OPERATORS})",
                self.operators
            ));
        }
        Ok(())
    }

    fn concat(&mut self) -> Result<(), String> {
        self.concats += 1;
        if self.concats > MAX_CONCAT_OPERATORS {
            return Err(format!(
                "Luau expression complexity exceeds the parser safety cap ({} > {MAX_CONCAT_OPERATORS} concatenations)",
                self.concats
            ));
        }
        Ok(())
    }

    fn token(&mut self, token_type: &TokenType) -> Result<(), String> {
        match token_type {
            TokenType::Identifier { .. } => {
                // Two operands never touch inside one expression, so a name right after
                // an operand starts a new statement.
                if self.previous == Previous::Operand {
                    self.statement_boundary();
                }
                self.previous = Previous::Operand;
            }
            TokenType::Number { .. } | TokenType::StringLiteral { .. } => {
                self.previous = Previous::Operand;
            }
            TokenType::InterpolatedString { kind, .. } => match kind {
                InterpolatedStringKind::Begin => {
                    self.open(FrameKind::Interpolation)?;
                    self.previous = Previous::Expression;
                }
                InterpolatedStringKind::Middle => {
                    self.operators = self.base();
                    self.concats = self.concat_base();
                    self.previous = Previous::Expression;
                }
                InterpolatedStringKind::End => {
                    self.close(&[FrameKind::Interpolation]);
                    self.previous = Previous::Operand;
                }
                InterpolatedStringKind::Simple => self.previous = Previous::Operand,
            },
            TokenType::Symbol { symbol } => self.symbol(*symbol)?,
            _ => {}
        }
        Ok(())
    }

    fn symbol(&mut self, symbol: Symbol) -> Result<(), String> {
        let previous = self.previous;
        self.previous = Previous::Expression;
        match symbol {
            Symbol::LeftParen => self.open(FrameKind::Paren)?,
            Symbol::LeftBracket => self.open(FrameKind::Bracket)?,
            Symbol::LeftBrace => self.open(FrameKind::Brace)?,
            Symbol::RightParen => {
                self.close(&[FrameKind::Paren]);
                self.previous = Previous::Operand;
            }
            Symbol::RightBracket => {
                self.close(&[FrameKind::Bracket]);
                self.previous = Previous::Operand;
            }
            Symbol::RightBrace => {
                self.close(&[FrameKind::Brace]);
                self.previous = Previous::Operand;
            }
            Symbol::Function => self.open(FrameKind::Block)?,
            Symbol::If => {
                if previous == Previous::Expression {
                    // An if-expression has no `end`; it nests like an operator.
                    self.operator()?;
                    if let Some(frame) = self.frames.last_mut() {
                        frame.open_if_expressions += 1;
                    }
                } else {
                    self.statement_boundary();
                    self.open(FrameKind::Block)?;
                }
            }
            Symbol::Then | Symbol::ElseIf => {
                if self
                    .frames
                    .last()
                    .is_none_or(|frame| frame.open_if_expressions == 0)
                {
                    self.statement_boundary();
                    // A statement follows `then`; a condition follows `elseif`.
                    if symbol == Symbol::Then {
                        self.previous = Previous::Statement;
                    }
                }
            }
            Symbol::Else => {
                if let Some(frame) = self
                    .frames
                    .last_mut()
                    .filter(|frame| frame.open_if_expressions > 0)
                {
                    frame.open_if_expressions -= 1;
                } else {
                    self.statement_boundary();
                    self.previous = Previous::Statement;
                }
            }
            Symbol::While | Symbol::For => {
                self.statement_boundary();
                self.open(FrameKind::LoopHeader)?;
            }
            Symbol::Do => {
                if self
                    .frames
                    .last()
                    .is_some_and(|frame| frame.kind == FrameKind::LoopHeader)
                {
                    if let Some(frame) = self.frames.last_mut() {
                        frame.kind = FrameKind::Block;
                    }
                    self.statement_boundary();
                } else {
                    self.statement_boundary();
                    self.open(FrameKind::Block)?;
                }
                self.previous = Previous::Statement;
            }
            Symbol::Repeat => {
                self.statement_boundary();
                self.open(FrameKind::Repeat)?;
                self.previous = Previous::Statement;
            }
            Symbol::End => {
                self.close(&[FrameKind::Block, FrameKind::LoopHeader]);
                self.previous = Previous::Operand;
            }
            Symbol::Until => {
                self.close(&[FrameKind::Repeat]);
                self.statement_boundary();
            }
            Symbol::Semicolon | Symbol::Break => {
                self.statement_boundary();
                self.previous = Previous::Statement;
            }
            Symbol::Local
            | Symbol::Return
            | Symbol::Equal
            | Symbol::Comma
            | Symbol::In
            | Symbol::PlusEqual
            | Symbol::MinusEqual
            | Symbol::StarEqual
            | Symbol::SlashEqual
            | Symbol::DoubleSlashEqual
            | Symbol::PercentEqual
            | Symbol::CaretEqual
            | Symbol::TwoDotsEqual => self.statement_boundary(),
            Symbol::True | Symbol::False | Symbol::Nil | Symbol::Ellipsis => {
                self.previous = Previous::Operand;
            }
            Symbol::QuestionMark => {
                self.operator()?;
                self.previous = Previous::Operand;
            }
            Symbol::Plus
            | Symbol::Minus
            | Symbol::Star
            | Symbol::Slash
            | Symbol::DoubleSlash
            | Symbol::Percent
            | Symbol::Caret
            | Symbol::TwoEqual
            | Symbol::TildeEqual
            | Symbol::LessThan
            | Symbol::LessThanEqual
            | Symbol::GreaterThan
            | Symbol::GreaterThanEqual
            | Symbol::And
            | Symbol::Or
            | Symbol::Not
            | Symbol::Hash
            | Symbol::Pipe
            | Symbol::Ampersand
            | Symbol::ThinArrow
            | Symbol::TwoColons => self.operator()?,
            Symbol::TwoDots => self.concat()?,
            _ => {}
        }
        Ok(())
    }
}

/// Reject source shapes that can make a recursive parser exhaust the native stack.
///
/// Tokenization is streaming and does not build an AST. The same budget is shared by
/// every rule module before it calls `full_moon::parse`. Nesting caps are fixed and do
/// not depend on `max_depth`; the token cap follows `max_script_bytes`.
pub fn parser_budget(source: &str, limits: &Limits) -> Result<(), String> {
    lexical_summary(source, limits).map(|_| ())
}

/// Same check as [`parser_budget`], returning what the lexer counted.
pub fn lexical_summary(source: &str, limits: &Limits) -> Result<LexicalSummary, String> {
    let source = crate::parsing::source_without_bom(source);
    if source.len() > limits.max_script_bytes {
        return Err(format!(
            "script exceeds max_script_bytes ({} > {})",
            source.len(),
            limits.max_script_bytes
        ));
    }
    let token_cap = max_lexical_tokens(limits);
    let mut lexer = Lexer::new(source, full_moon::LuaVersion::luau());
    let mut budget = LexicalBudget::new();
    let mut tokens = 0usize;
    while let Some(item) = lexer.consume() {
        let token = match item {
            LexerResult::Ok(token) => token,
            LexerResult::Recovered(token, _) => token,
            LexerResult::Fatal(_) => return Err("Luau tokenization failed".into()),
        };
        if matches!(token.token_type(), TokenType::Eof) {
            continue;
        }
        tokens = tokens.saturating_add(1);
        if tokens > token_cap {
            return Err(format!(
                "Luau token budget exceeded ({tokens} tokens > {token_cap})"
            ));
        }
        budget.token(token.token_type())?;
    }
    Ok(LexicalSummary { tokens })
}

/// Instance properties and attributes that the scripts of a document write: `x.P = v`,
/// `x.P += v`, `x["P"] = v` and ``x[`P`] = v`` in assignments, including assignments with
/// several targets, fields of the table passed to a `Create` call such as
/// `TweenService:Create(o, info, {P = v})` or `TweenService.Create(TweenService, o, info,
/// {P = v})`, and `:SetAttribute("A", v)`. Every name the pass cannot read counts as
/// every name: a computed key, a property argument of `Create` that is not a table
/// constructor, `Create` or `SetAttribute` taken as a value, `SetAttribute` called with a
/// dot, and a script the lexer rejects. The pass reads tokens only, so it costs one lex
/// of every script per document.
pub fn instance_writes(doc: &Document, limits: &Limits) -> InstanceWrites {
    let mut writes = InstanceWrites::default();
    for node in &doc.instances {
        if !node.is_script() {
            continue;
        }
        let Some(source) = node.source.as_deref() else {
            continue;
        };
        let source = crate::parsing::source_without_bom(source);
        if source.len() > limits.max_script_bytes {
            writes.any_property = true;
            writes.any_attribute = true;
            continue;
        }
        let mut scan = WriteScan::default();
        let mut lexer = Lexer::new(source, full_moon::LuaVersion::luau());
        while let Some(item) = lexer.consume() {
            let token = match item {
                LexerResult::Ok(token) | LexerResult::Recovered(token, _) => token,
                LexerResult::Fatal(_) => {
                    writes.any_property = true;
                    writes.any_attribute = true;
                    break;
                }
            };
            scan.token(token.token_type(), &mut writes);
            if writes.any_property && writes.any_attribute {
                return writes;
            }
        }
        scan.finish(&mut writes);
    }
    writes
}

/// A token as the instance write pass sees it.
#[derive(Debug, Clone, PartialEq, Default)]
enum WriteToken {
    Name(String),
    Text(String),
    Number,
    Symbol(Symbol),
    /// The end of an interpolated string, which ends an operand.
    InterpolationEnd,
    #[default]
    Other,
}

impl WriteToken {
    /// A token that can end an operand, so a name after it starts a new statement and a
    /// `[` after it indexes a value.
    fn ends_operand(&self) -> bool {
        match self {
            WriteToken::Name(_)
            | WriteToken::Text(_)
            | WriteToken::Number
            | WriteToken::InterpolationEnd => true,
            WriteToken::Symbol(symbol) => matches!(
                symbol,
                Symbol::RightParen
                    | Symbol::RightBracket
                    | Symbol::RightBrace
                    | Symbol::End
                    | Symbol::True
                    | Symbol::False
                    | Symbol::Nil
                    | Symbol::Ellipsis
            ),
            WriteToken::Other => false,
        }
    }
}

/// What an index or a field being written names.
#[derive(Debug, Clone, PartialEq)]
enum WriteTarget {
    Name(String),
    /// A number: not an instance property.
    Index,
    /// A length with arithmetic: a number unless a `__len` metamethod returns something
    /// else.
    Length,
    /// A name the pass cannot read.
    Computed,
}

/// Contents of an open `[`, read directly inside it.
#[derive(Debug, Clone, PartialEq)]
enum BracketContent {
    Empty,
    Text(String),
    Number,
    /// `#t + 1` and the like: a length with arithmetic, always a number.
    Length,
    Other,
}

#[derive(Debug, Clone, PartialEq)]
enum Opener {
    Paren,
    Brace,
    Interpolation,
    /// `[`, with whether it indexes a value (or opens a constructor key) and what is
    /// directly inside so far.
    Bracket(bool, BracketContent),
}

/// Where a `SetAttribute` call is in its arguments.
#[derive(Debug, Clone, PartialEq, Default)]
enum SetAttribute {
    #[default]
    Idle,
    /// After the name; `true` for a method call with `:`.
    Name(bool),
    /// After `(`.
    Open,
    /// After the name argument.
    Key(String),
}

/// A `Create` call being read, such as `TweenService:Create(object, info, properties)`.
#[derive(Debug, Clone, PartialEq)]
struct CreateCall {
    /// Number of open brackets directly inside the call's parentheses.
    depth: usize,
    /// Position of the first argument that sets properties: 2 for `x:Create(...)`, 3 for
    /// `x.Create(x, ...)` and `x["Create"](x, ...)`, which pass the receiver first.
    properties: usize,
    /// Position of the argument being read.
    argument: usize,
    /// The argument being read has tokens, and so far they are one table constructor.
    started: bool,
    constructor: bool,
}

impl CreateCall {
    /// End of an argument: properties the pass cannot list count as every name.
    fn finish_argument(&mut self, writes: &mut InstanceWrites) {
        if self.started && self.argument >= self.properties && !self.constructor {
            writes.any_property = true;
        }
        self.argument += 1;
        self.started = false;
        self.constructor = false;
    }
}

/// Whether a write target is a member named `Create`, such as `x.Create` or
/// `x["Create"]`.
fn names_create(target: &Option<(usize, WriteTarget)>) -> bool {
    matches!(target, Some((_, WriteTarget::Name(name))) if name == "Create")
}

#[derive(Default)]
struct WriteScan {
    previous: [WriteToken; 2],
    openers: Vec<Opener>,
    /// Targets seen before a `,` that an `=` at the same depth would write, with that
    /// depth.
    pending: Vec<(usize, WriteTarget)>,
    /// The field or index that the previous token completed, with its depth.
    last_target: Option<(usize, WriteTarget)>,
    /// `Create(` argument lists being read, innermost last.
    creates: Vec<CreateCall>,
    /// After `function` and before its parameter list, so `function M.Create(` is a
    /// definition, not a call.
    function_name: bool,
    set_attribute: SetAttribute,
    /// A write under a length key, and whether the script names `__len`.
    length_write: bool,
    len_metamethod: bool,
}

impl WriteScan {
    fn token(&mut self, token_type: &TokenType, writes: &mut InstanceWrites) {
        let token = match token_type {
            TokenType::Identifier { identifier } => WriteToken::Name(identifier.to_string()),
            TokenType::StringLiteral { .. } => {
                WriteToken::Text(token_literal(token_type).unwrap_or_default())
            }
            TokenType::Number { .. } => WriteToken::Number,
            TokenType::Symbol { symbol } => WriteToken::Symbol(*symbol),
            TokenType::InterpolatedString { kind, .. } => match kind {
                // A string with expressions: as a key or an argument it is unknown.
                InterpolatedStringKind::Begin => {
                    self.observe(&WriteToken::Other, writes);
                    self.openers.push(Opener::Interpolation);
                    self.advance(WriteToken::Other);
                    return;
                }
                InterpolatedStringKind::Middle => WriteToken::Other,
                InterpolatedStringKind::End => {
                    if self.openers.last() == Some(&Opener::Interpolation) {
                        self.openers.pop();
                    }
                    WriteToken::InterpolationEnd
                }
                // A string without expressions is its text, like a quoted string.
                InterpolatedStringKind::Simple => {
                    WriteToken::Text(token_literal(token_type).unwrap_or_default())
                }
            },
            TokenType::Whitespace { .. }
            | TokenType::SingleLineComment { .. }
            | TokenType::MultiLineComment { .. }
            | TokenType::Shebang { .. }
            | TokenType::Eof => return,
            _ => WriteToken::Other,
        };
        self.observe(&token, writes);
        let depth = self.openers.len();
        let mut completed = None;
        if matches!(&token, WriteToken::Name(name) | WriteToken::Text(name) if name == "__len") {
            self.len_metamethod = true;
        }
        match &token {
            WriteToken::Name(name) => {
                if self.previous[1] == WriteToken::Symbol(Symbol::Dot) {
                    completed = Some((depth, WriteTarget::Name(name.clone())));
                } else if self.previous[1].ends_operand() {
                    // A name right after an operand starts a new statement.
                    self.pending.retain(|(at, _)| *at < depth);
                }
            }
            WriteToken::Text(text) if text == "SetAttribute" => writes.any_attribute = true,
            WriteToken::Symbol(symbol) => match symbol {
                Symbol::LeftParen => {
                    let method = self.previous[1] == WriteToken::Name("Create".into())
                        && self.previous[0] == WriteToken::Symbol(Symbol::Colon);
                    // `x.Create(` and `x["Create"](`, with the receiver passed first.
                    let member = names_create(&self.last_target);
                    let definition = std::mem::take(&mut self.function_name);
                    self.openers.push(Opener::Paren);
                    if (method || member) && !definition {
                        self.creates.push(CreateCall {
                            depth: self.openers.len(),
                            properties: if method { 2 } else { 3 },
                            argument: 0,
                            started: false,
                            constructor: false,
                        });
                    }
                }
                Symbol::LeftBrace => self.openers.push(Opener::Brace),
                Symbol::LeftBracket => {
                    let index = self.previous[1].ends_operand();
                    self.openers
                        .push(Opener::Bracket(index, BracketContent::Empty));
                }
                Symbol::RightParen | Symbol::RightBrace => {
                    let expected = if *symbol == Symbol::RightParen {
                        Opener::Paren
                    } else {
                        Opener::Brace
                    };
                    if self.openers.last() == Some(&expected) {
                        if expected == Opener::Paren
                            && self
                                .creates
                                .last()
                                .is_some_and(|call| call.depth == self.openers.len())
                            && let Some(mut call) = self.creates.pop()
                        {
                            call.finish_argument(writes);
                        }
                        self.openers.pop();
                        self.pending.retain(|(at, _)| *at < self.openers.len() + 1);
                    }
                }
                Symbol::RightBracket => {
                    if let Some(Opener::Bracket(index, content)) = self.openers.last().cloned() {
                        self.openers.pop();
                        let target = match content {
                            BracketContent::Text(name) => WriteTarget::Name(name),
                            BracketContent::Number => WriteTarget::Index,
                            BracketContent::Length => WriteTarget::Length,
                            _ => WriteTarget::Computed,
                        };
                        if index {
                            completed = Some((self.openers.len(), target));
                        } else if self.in_create() {
                            // `["P"] = v` in a table passed to `Create`.
                            completed = Some((self.openers.len(), target));
                        }
                    }
                }
                Symbol::Comma => {
                    if let Some((at, target)) = self.last_target.take()
                        && at == depth
                    {
                        self.pending.push((at, target));
                    }
                }
                Symbol::Equal
                | Symbol::PlusEqual
                | Symbol::MinusEqual
                | Symbol::StarEqual
                | Symbol::SlashEqual
                | Symbol::DoubleSlashEqual
                | Symbol::PercentEqual
                | Symbol::CaretEqual
                | Symbol::TwoDotsEqual => {
                    if let Some((at, target)) = self.last_target.take()
                        && at == depth
                    {
                        self.record(target, writes);
                    } else if *symbol == Symbol::Equal
                        && self.in_create()
                        && matches!(self.openers.last(), Some(Opener::Brace))
                        && let WriteToken::Name(name) = &self.previous[1]
                        && matches!(
                            self.previous[0],
                            WriteToken::Symbol(
                                Symbol::LeftBrace | Symbol::Comma | Symbol::Semicolon
                            )
                        )
                    {
                        // `{ P = v }` in a table passed to `Create`.
                        writes.properties.insert(name.clone());
                    }
                    let pending = std::mem::take(&mut self.pending);
                    for (at, target) in pending {
                        if at == depth {
                            self.record(target, writes);
                        } else {
                            self.pending.push((at, target));
                        }
                    }
                }
                Symbol::Semicolon
                | Symbol::Local
                | Symbol::Return
                | Symbol::If
                | Symbol::Then
                | Symbol::Else
                | Symbol::ElseIf
                | Symbol::While
                | Symbol::Do
                | Symbol::For
                | Symbol::In
                | Symbol::Function
                | Symbol::Repeat
                | Symbol::Until
                | Symbol::End
                | Symbol::Break => {
                    self.function_name |= *symbol == Symbol::Function;
                    self.pending.retain(|(at, _)| *at < depth);
                }
                _ => {}
            },
            _ => {}
        }
        self.last_target = completed;
        self.advance(token);
    }

    /// What every token says before it changes the open brackets: the contents of an
    /// open `[`, the argument of a `Create` call being read, a `SetAttribute` call, and
    /// a `Create` member used other than by a call or as an assignment target.
    fn observe(&mut self, token: &WriteToken, writes: &mut InstanceWrites) {
        self.set_attribute(token, writes);
        if names_create(&self.last_target)
            && !matches!(
                token,
                WriteToken::Symbol(
                    Symbol::LeftParen
                        | Symbol::Equal
                        | Symbol::PlusEqual
                        | Symbol::MinusEqual
                        | Symbol::StarEqual
                        | Symbol::SlashEqual
                        | Symbol::DoubleSlashEqual
                        | Symbol::PercentEqual
                        | Symbol::CaretEqual
                        | Symbol::TwoDotsEqual
                )
            )
        {
            writes.any_property = true;
        }
        let depth = self.openers.len();
        if let Some(call) = self.creates.last_mut()
            && call.depth == depth
        {
            match token {
                WriteToken::Symbol(Symbol::Comma) => call.finish_argument(writes),
                WriteToken::Symbol(Symbol::RightParen) => {}
                WriteToken::Symbol(Symbol::LeftBrace) if !call.started => {
                    call.started = true;
                    call.constructor = true;
                }
                _ => {
                    call.started = true;
                    call.constructor = false;
                }
            }
        }
        // What is directly inside an open `[`.
        if let Some(Opener::Bracket(_, content)) = self.openers.last_mut()
            && *token != WriteToken::Symbol(Symbol::RightBracket)
        {
            *content = match (&*content, token) {
                (BracketContent::Empty, WriteToken::Text(text)) => {
                    BracketContent::Text(text.clone())
                }
                (BracketContent::Empty, WriteToken::Number) => BracketContent::Number,
                (BracketContent::Empty, WriteToken::Symbol(Symbol::Hash)) => BracketContent::Length,
                (
                    BracketContent::Length,
                    WriteToken::Name(_)
                    | WriteToken::Number
                    | WriteToken::Symbol(Symbol::Dot | Symbol::Plus | Symbol::Minus | Symbol::Star),
                ) => BracketContent::Length,
                _ => BracketContent::Other,
            };
        }
    }

    fn advance(&mut self, token: WriteToken) {
        self.previous = [std::mem::take(&mut self.previous[1]), token];
    }

    fn in_create(&self) -> bool {
        self.creates
            .last()
            .is_some_and(|call| self.openers.len() > call.depth)
    }

    fn record(&mut self, target: WriteTarget, writes: &mut InstanceWrites) {
        match target {
            WriteTarget::Name(name) => {
                writes.properties.insert(name);
            }
            WriteTarget::Index => {}
            WriteTarget::Length => self.length_write = true,
            WriteTarget::Computed => writes.any_property = true,
        }
    }

    /// End of a script: a length key counts as a number only without `__len`. A `Create`
    /// member as the last token, or a `Create` call still open, counts as every name.
    fn finish(&self, writes: &mut InstanceWrites) {
        if (self.length_write && self.len_metamethod)
            || names_create(&self.last_target)
            || !self.creates.is_empty()
        {
            writes.any_property = true;
        }
    }

    /// `x:SetAttribute("A", v)` sets `A`; any other use of `SetAttribute` may set any
    /// attribute.
    fn set_attribute(&mut self, token: &WriteToken, writes: &mut InstanceWrites) {
        self.set_attribute = match (std::mem::take(&mut self.set_attribute), token) {
            (_, WriteToken::Name(name)) if name == "SetAttribute" => {
                SetAttribute::Name(self.previous[1] == WriteToken::Symbol(Symbol::Colon))
            }
            (SetAttribute::Idle, _) => SetAttribute::Idle,
            (SetAttribute::Name(true), WriteToken::Symbol(Symbol::LeftParen)) => SetAttribute::Open,
            (SetAttribute::Open, WriteToken::Text(name)) => SetAttribute::Key(name.clone()),
            (SetAttribute::Key(name), WriteToken::Symbol(Symbol::Comma | Symbol::RightParen)) => {
                writes.attributes.insert(name);
                SetAttribute::Idle
            }
            _ => {
                writes.any_attribute = true;
                SetAttribute::Idle
            }
        };
    }
}

pub fn analyze(
    doc: &Document,
    id: usize,
    limits: &Limits,
    trusted_asset_ids: &[u64],
) -> AnalysisResult {
    let dom_index = DomIndex::new(doc);
    analyze_indexed(doc, id, limits, trusted_asset_ids, &dom_index)
}

pub fn analyze_indexed(
    doc: &Document,
    id: usize,
    limits: &Limits,
    trusted_asset_ids: &[u64],
    dom_index: &DomIndex,
) -> AnalysisResult {
    crate::parsing::on_large_stack(|| {
        analyze_on_worker(doc, id, limits, trusted_asset_ids, dom_index)
    })
    .unwrap_or_else(|reason| AnalysisResult {
        reasons: vec![reason],
        ..AnalysisResult::default()
    })
}

fn analyze_on_worker(
    doc: &Document,
    id: usize,
    limits: &Limits,
    trusted_asset_ids: &[u64],
    dom_index: &DomIndex,
) -> AnalysisResult {
    let Some(instance) = doc.instances.get(id) else {
        return AnalysisResult {
            reasons: vec![format!("cannot analyze missing instance {id}")],
            ..AnalysisResult::default()
        };
    };
    let Some(source) = instance.source.as_deref() else {
        return AnalysisResult {
            reasons: if instance.is_script() {
                vec![format!("{} has no readable Source property", doc.path(id))]
            } else {
                Vec::new()
            },
            ..AnalysisResult::default()
        };
    };
    let source = crate::parsing::source_without_bom(source);
    let declaration_file = || AnalysisResult {
        notes: vec![crate::parsing::DECLARATION_FILE_NOTE.into()],
        ..AnalysisResult::default()
    };
    let summary = match lexical_summary(source, limits) {
        Ok(summary) => summary,
        Err(_) if crate::parsing::is_declaration_file_over_budget(source, limits) => {
            return declaration_file();
        }
        Err(reason) => {
            return AnalysisResult {
                reasons: vec![format!("cannot safely parse {}: {reason}", doc.path(id))],
                ..AnalysisResult::default()
            };
        }
    };
    let ast = match full_moon::parse(source) {
        Ok(ast) => ast,
        Err(errors) if crate::parsing::is_declaration_file(source, &errors) => {
            return declaration_file();
        }
        Err(errors) => {
            let summary = errors
                .first()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown parse error".into());
            return AnalysisResult {
                reasons: vec![format!(
                    "could not parse {}: {}",
                    doc.path(id),
                    short_reason(&summary)
                )],
                ..AnalysisResult::default()
            };
        }
    };

    let mut analyzer = Analyzer::new(doc, id, limits, trusted_asset_ids, dom_index, source);
    analyzer.step_budget = analysis_step_budget(limits, summary.tokens);
    let bindings = Bindings::run(&ast);
    analyzer.loop_targets = LoopScan::run(&ast, &bindings);
    analyzer.facts = ScriptScan::run(&ast, &bindings);
    analyzer.environment_reads = EnvironmentReads::run(&ast, &bindings);
    analyzer.bindings = bindings;
    analyzer.visit_ast(&ast);
    analyzer.finish()
}

/// Largest number of candidate values kept for one expression.
const MAX_CANDIDATES: usize = 8;
/// Entries stored per constant table; later entries are evaluated but not stored.
const MAX_TABLE_ENTRIES: usize = 65_536;
/// Constant tables per script.
const MAX_TABLES: usize = 262_144;
/// Arguments evaluated per call.
const MAX_CALL_ARGUMENTS: usize = 256;
/// Nested replays of local function bodies at call sites.
const MAX_REPLAY_DEPTH: usize = 3;
/// Distinct argument shapes replayed per function.
const MAX_REPLAYS_PER_FUNCTION: usize = 16;
/// Replays per script.
const MAX_REPLAYS_PER_SCRIPT: usize = 128;
/// Tables of an `__index` chain followed exactly. Past them a found value is a
/// candidate next to an unknown value.
const MAX_INDEX_CHAIN: usize = 8;
/// Function bodies larger than this are summarized instead of replayed.
const MAX_REPLAY_BODY_BYTES: usize = 256 * 1024;
/// Functions without sinks are replayed for their return value only when this small.
const MAX_VALUE_REPLAY_BODY_BYTES: usize = 16 * 1024;
/// Source bytes rendered into one finding's evidence.
const MAX_EVIDENCE_SOURCE_BYTES: usize = 4 * 1024;
/// Source bytes scanned for ID-shaped literals and outbound data per call.
const MAX_LITERAL_SCAN_BYTES: usize = 64 * 1024;
/// Findings kept per script.
const MAX_FINDINGS_PER_SCRIPT: usize = 256;
/// Instance path bytes kept in findings per script.
const MAX_PATH_BYTES_PER_SCRIPT: usize = 8 * 1024 * 1024;
/// Distinct webhook-shaped constants remembered per script.
const MAX_WEBHOOK_CONSTANTS: usize = 16;
/// Bytes of new strings that constant folding may create per script.
const MAX_FOLDED_BYTES: usize = 64 * 1024 * 1024;
/// Smallest integer treated as an asset ID when it cannot be fully resolved.
const ASSET_ID_MIN: f64 = 1_000_000.0;
/// Shortest digit run in a string treated as an asset ID.
const ASSET_ID_DIGITS: usize = 7;

const SINK_REQUIRE: u8 = 1;
const SINK_CODE: u8 = 2;
const SINK_HTTP: u8 = 4;
const SINK_OTHER: u8 = 8;
/// A `require` whose target may be something other than a local module, so a value
/// the function receives may reach it. Always set together with [`SINK_REQUIRE`].
const SINK_REQUIRE_INPUT: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    instance: usize,
    property: Option<String>,
    attribute: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct ConstantTable {
    fields: BTreeMap<String, Value>,
    items: Vec<Value>,
    numbered: BTreeMap<i64, Value>,
    /// Values written under keys the scanner could not resolve.
    loose: Vec<Value>,
    sensitive: bool,
    /// What answers a missing key when there is no known metatable: an unknown value
    /// for an unknown metatable, or unresolved instance data for an attribute table.
    fallback: Option<Box<Value>>,
    /// Metatable. `__index`, `__call`, `__newindex` and the operator metamethods are
    /// read from it when they are used, so a later change to it is seen.
    metatable: Option<usize>,
    /// Code the scanner cannot see may have changed the contents, for example an
    /// unknown function that received the table. Reads keep the stored value and the
    /// ID shaped values of the table as candidates and add an unknown value.
    escaped: bool,
    /// Serial of the scope that created the table. A write from a branch, a loop or a
    /// function body below that scope may not run, so it is joined with the old value.
    home: usize,
    /// Stored under a variable or key that a write the scanner could not place went
    /// through (see [`Analyzer::unpinned_write`]), so sensitive data written that way
    /// counts as its content.
    stray: bool,
    /// Byte offset of the table constructor that made the table, which tells which
    /// later writes of the script may reach it (see [`TableKey`]).
    constructor: Option<usize>,
}

impl ConstantTable {
    fn entries(&self) -> usize {
        self.fields.len() + self.items.len() + self.numbered.len() + self.loose.len()
    }

    fn number(&self, key: i64) -> Option<&Value> {
        if key >= 1 && (key as u64) <= self.items.len() as u64 {
            self.items.get((key - 1) as usize)
        } else {
            self.numbered.get(&key)
        }
    }

    fn set_number(&mut self, key: i64, value: Value) {
        if key >= 1 && (key as u64) <= self.items.len() as u64 {
            self.items[(key - 1) as usize] = value;
        } else if key >= 1 && key as u64 == self.items.len() as u64 + 1 {
            self.items.push(value);
        } else {
            self.numbered.insert(key, value);
        }
    }

    fn values(&self) -> impl Iterator<Item = &Value> {
        self.fields
            .values()
            .chain(self.items.iter())
            .chain(self.numbered.values())
            .chain(self.loose.iter())
    }

    /// Stored value for a resolved key, without metatables.
    fn raw(&self, key: &Value) -> Option<&Value> {
        match key {
            Value::String(key, _) => self.fields.get(&key[..]),
            Value::Number(number, _) => integer(*number).and_then(|key| self.number(key)),
            _ => None,
        }
    }
}

/// Shared string payload, so copying a value that holds a large string is cheap. The
/// digest used in replay keys is computed once per payload.
#[derive(Clone)]
struct Text(Rc<TextInner>);

struct TextInner {
    text: Box<str>,
    digest: std::cell::OnceCell<String>,
}

impl Text {
    fn digest(&self) -> &str {
        self.0.digest.get_or_init(|| sha256(self.0.text.as_bytes()))
    }
}

impl PartialEq for Text {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0) || self.0.text == other.0.text
    }
}

impl std::ops::Deref for Text {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0.text
    }
}

impl From<String> for Text {
    fn from(text: String) -> Self {
        Self(Rc::new(TextInner {
            text: text.into_boxed_str(),
            digest: std::cell::OnceCell::new(),
        }))
    }
}

impl From<&str> for Text {
    fn from(text: &str) -> Self {
        Self::from(text.to_string())
    }
}

impl std::fmt::Display for Text {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0.text)
    }
}

impl std::fmt::Debug for Text {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&*self.0.text, formatter)
    }
}

#[derive(Debug, Clone)]
enum Value {
    Nil,
    Bool(bool),
    Number(f64, Option<Origin>),
    String(Text, Option<Origin>),
    Dom(usize),
    Namespace(String),
    Callable(String),
    Function(usize),
    Table(usize),
    Sensitive,
    /// An instance path that leaves the scanned content, or names an object that is
    /// not in it.
    ExternalDom,
    /// Data read from such an instance.
    ExternalData,
    /// An object inside the scanned content that the scanner could not pin down, such
    /// as an element of `GetChildren()`. The number is the closest known instance.
    ModelDom(usize),
    /// Data read from such an object, such as its `.Value` or an attribute.
    ModelData(usize),
    /// A list of instances, such as the result of `GetChildren()`, with its element.
    InstanceList(Box<Value>),
    /// An engine object of a known kind that is not stored in the content: a service
    /// such as `HttpService`, or an object a service returns, such as a `DataStore`.
    Object(String),
    /// The iterator `gmatch` returns: the values of each iteration, as tuples.
    Matches(Vec<Value>),
    /// A number between two bounds, such as `math.random(600, 1200)`.
    Range(f64, f64),
    UnresolvedOrigin(Origin),
    /// Unresolved value derived from an asset-ID-shaped literal.
    IdLike(String),
    /// A global read through a key the analyzer could not resolve.
    ComputedGlobal,
    /// Unknown because the evaluation depth limit was reached.
    Truncated,
    /// Data downloaded at runtime, such as an HTTP response.
    Remote,
    /// A string whose start is known, such as a URL prefix joined to unknown text.
    Partial(String),
    /// Bounded set of possible values.
    Union(Vec<Value>),
    /// Multiple results of a call or `...`.
    Tuple(Vec<Value>),
    Unknown,
    /// Marks a candidate set that lost members at the size cap, so it never counts
    /// as fully resolved.
    Overflow,
}

impl Value {
    fn single(self) -> Value {
        match self {
            Value::Tuple(values) => values
                .into_iter()
                .next()
                .map(Value::single)
                .unwrap_or(Value::Nil),
            other => other,
        }
    }

    fn candidates(&self) -> Vec<&Value> {
        match self {
            Value::Union(values) => values.iter().collect(),
            other => vec![other],
        }
    }

    fn truthy(&self) -> Option<bool> {
        match self {
            Value::Nil => Some(false),
            Value::Bool(value) => Some(*value),
            Value::Number(..)
            | Value::String(..)
            | Value::Dom(_)
            | Value::Namespace(_)
            | Value::Callable(_)
            | Value::Function(_)
            | Value::Table(_)
            | Value::InstanceList(_)
            | Value::Object(_)
            | Value::Matches(_)
            | Value::Range(..) => Some(true),
            Value::Union(values) => {
                let first = values.first()?.truthy()?;
                values
                    .iter()
                    .all(|value| value.truthy() == Some(first))
                    .then_some(first)
            }
            _ => None,
        }
    }

    fn same(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Nil, Value::Nil)
            | (Value::Sensitive, Value::Sensitive)
            | (Value::ExternalDom, Value::ExternalDom)
            | (Value::ExternalData, Value::ExternalData)
            | (Value::ComputedGlobal, Value::ComputedGlobal)
            | (Value::Truncated, Value::Truncated)
            | (Value::Remote, Value::Remote)
            | (Value::Unknown, Value::Unknown)
            | (Value::Overflow, Value::Overflow) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a, ao), Value::Number(b, bo)) => a.to_bits() == b.to_bits() && ao == bo,
            (Value::String(a, ao), Value::String(b, bo)) => a == b && ao == bo,
            (Value::Dom(a), Value::Dom(b))
            | (Value::Function(a), Value::Function(b))
            | (Value::Table(a), Value::Table(b))
            | (Value::ModelDom(a), Value::ModelDom(b))
            | (Value::ModelData(a), Value::ModelData(b)) => a == b,
            (Value::InstanceList(a), Value::InstanceList(b)) => a.same(b),
            (Value::Range(a, b), Value::Range(c, d)) => {
                a.to_bits() == c.to_bits() && b.to_bits() == d.to_bits()
            }
            (Value::Namespace(a), Value::Namespace(b))
            | (Value::Object(a), Value::Object(b))
            | (Value::Callable(a), Value::Callable(b))
            | (Value::IdLike(a), Value::IdLike(b))
            | (Value::Partial(a), Value::Partial(b)) => a == b,
            (Value::UnresolvedOrigin(a), Value::UnresolvedOrigin(b)) => a == b,
            _ => false,
        }
    }

    fn origin(&self) -> Option<&Origin> {
        match self {
            Value::Number(_, origin) | Value::String(_, origin) => origin.as_ref(),
            _ => None,
        }
    }

    /// Ranking used when a candidate set overflows: risky candidates are kept first.
    fn interest(&self) -> u8 {
        match self {
            Value::Overflow => 4,
            Value::Number(number, origin) => {
                if origin.is_some() || is_asset_number(*number) {
                    3
                } else {
                    2
                }
            }
            Value::String(text, origin) => {
                if origin.is_some()
                    || digit_run(text, ASSET_ID_DIGITS).is_some()
                    || starts_with_http(text)
                {
                    3
                } else {
                    2
                }
            }
            Value::Callable(name) if is_dangerous_callable(name) => 3,
            Value::Partial(text) => {
                if digit_run(text, ASSET_ID_DIGITS).is_some() || starts_with_http(text) {
                    3
                } else {
                    2
                }
            }
            Value::IdLike(_)
            | Value::ExternalData
            | Value::ModelData(_)
            | Value::UnresolvedOrigin(_)
            | Value::Sensitive
            | Value::ComputedGlobal
            | Value::Truncated
            | Value::Remote => 3,
            Value::Function(_) | Value::Table(_) | Value::Matches(_) | Value::Range(..) => 2,
            Value::Dom(_)
            | Value::ExternalDom
            | Value::ModelDom(_)
            | Value::InstanceList(_)
            | Value::Object(_)
            | Value::Namespace(_)
            | Value::Callable(_) => 1,
            _ => 0,
        }
    }
}

/// Combine possible values into one bounded candidate set.
fn join(values: impl IntoIterator<Item = Value>) -> Value {
    let mut out: Vec<Value> = Vec::new();
    for value in values {
        match value.single() {
            Value::Union(inner) => {
                for candidate in inner {
                    push_candidate(&mut out, candidate);
                }
            }
            candidate => push_candidate(&mut out, candidate),
        }
    }
    if out.len() > MAX_CANDIDATES {
        out.sort_by_key(|value| std::cmp::Reverse(value.interest()));
        // Dropping instances, nil or booleans loses nothing a sink cares about. Any
        // other dropped member could be an ID, so the marker keeps the set unresolved.
        let lossy = out[MAX_CANDIDATES..].iter().any(|value| {
            !matches!(
                value,
                Value::Dom(_)
                    | Value::ExternalDom
                    | Value::ModelDom(_)
                    | Value::Object(_)
                    | Value::Nil
                    | Value::Bool(_)
            )
        });
        if lossy {
            out.retain(|value| !matches!(value, Value::Overflow));
            out.truncate(MAX_CANDIDATES - 1);
            out.push(Value::Overflow);
        } else {
            out.truncate(MAX_CANDIDATES);
        }
    }
    match out.len() {
        0 => Value::Unknown,
        1 => out.pop().unwrap_or(Value::Unknown),
        _ => Value::Union(out),
    }
}

/// What a value can be when it is `false` or `nil`. A candidate of unknown truth
/// contributes `nil`, because a false value is never an ID, a URL or data.
fn falsy_part(value: &Value) -> Value {
    let mut out = Vec::new();
    for candidate in value.candidates() {
        match candidate.truthy() {
            Some(true) => {}
            Some(false) => out.push(candidate.clone()),
            None => out.push(Value::Nil),
        }
    }
    join(out)
}

/// What a value can be when it is true: every candidate that is not known to be false.
fn truthy_part(value: &Value) -> Value {
    join(
        value
            .candidates()
            .into_iter()
            .filter(|candidate| candidate.truthy() != Some(false))
            .cloned(),
    )
}

fn push_candidate(out: &mut Vec<Value>, value: Value) {
    if !out.iter().any(|existing| existing.same(&value)) {
        out.push(value);
    }
}

/// Source range of a node, built from its first and last tokens.
#[derive(Debug, Clone, Copy, Default)]
struct Site {
    start: Option<Position>,
    end: Option<Position>,
}

impl Site {
    fn between(first: Option<&TokenReference>, last: Option<&TokenReference>) -> Self {
        Self {
            start: first.map(|token| token.token().start_position()),
            end: last.map(|token| token.token().end_position()),
        }
    }

    fn token(token: &TokenReference) -> Self {
        Self::between(Some(token), Some(token))
    }

    fn expression(expression: &Expression) -> Self {
        Self::between(
            first_token_of_expression(expression),
            last_token_of_expression(expression),
        )
    }

    fn location(self) -> Location {
        Location {
            line: self.start.map(|position| position.line()),
            column: self.start.map(|position| position.character()),
            end_line: self.end.map(|position| position.line()),
            end_column: self.end.map(|position| position.character()),
            ..Location::default()
        }
    }
}

struct Scope {
    vars: BTreeMap<Slot, Value>,
    /// Code in this scope may run zero or more times: a branch, a loop body, or a
    /// function body seen where it is defined.
    conditional: bool,
    /// A function body seen where it is defined. It may run later, any number of
    /// times, with arguments the scanner does not know.
    deferred: bool,
    /// A loop body, which runs any number of times.
    repeats: bool,
    serial: usize,
    /// Gate that controls code in this scope from here on (BG009).
    gate: Option<Site>,
}

/// An if statement being visited, so its branches learn the gate of the conditions
/// before them. Branches are visited in order, so `next` finds the coming one.
struct IfGate {
    /// Addresses of the then block, each elseif block, and the else block.
    blocks: Vec<usize>,
    has_else: bool,
    next: usize,
    /// Gate of the conditions seen so far.
    gate: Option<Site>,
    /// Gate of the `elseif` condition being visited.
    else_if_gate: Option<Site>,
}

struct PendingBlock {
    block: usize,
    conditional: bool,
    repeats: bool,
    bindings: Vec<(Slot, Value)>,
}

#[derive(Default)]
struct FunctionInfo {
    body: Option<Rc<FunctionBody>>,
    body_bytes: usize,
    sinks: u8,
    returns: Option<Value>,
    method: bool,
    memo: BTreeMap<String, Value>,
    /// The body has been visited, so `sinks` and `returns` are known.
    visited: bool,
    /// Calls seen before the body was visited, such as an immediately invoked function.
    pending: Vec<(Vec<Value>, Site)>,
    /// Connected to an event, such as `PlayerAdded` or `ChildAdded`: what the event
    /// passes as the first parameter.
    first_parameter: Option<Value>,
    /// Runs behind a long `task.delay`, so its body is gated (BG009).
    gate: Option<Site>,
    /// The body checks a gate, such as `IsStudio`, so a call in a condition is one.
    checks_gate: bool,
    /// The function is a value other code can call: an anonymous function, a function
    /// stored in a table or a global, or a local function used other than by a call.
    /// A table it returns where it is defined may end up with code the scanner cannot see.
    escapes: bool,
    /// The body reads a variable of an enclosing scope that the script assigns again, or
    /// a table from outside, so what it does depends on when it runs. Every call replays
    /// it, and replays are not memoized.
    reads_captures: bool,
    /// Replays run so far, for the per function limit.
    replay_count: usize,
    /// The body holds a risky action (see [`is_risky_action`]), so a call under a gate
    /// is a gated action (BG009).
    risky: bool,
}

struct FunctionFrame {
    id: usize,
    returns: Option<Value>,
    root: bool,
    /// Position of the function body's scope on the scope stack.
    scope: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Other,
}

fn binop_kind(op: &BinOp) -> Op {
    match op {
        BinOp::Plus(_) => Op::Add,
        BinOp::Minus(_) => Op::Sub,
        BinOp::Star(_) => Op::Mul,
        BinOp::Slash(_) => Op::Div,
        BinOp::DoubleSlash(_) => Op::FloorDiv,
        BinOp::Percent(_) => Op::Mod,
        BinOp::Caret(_) => Op::Pow,
        BinOp::TwoDots(_) => Op::Concat,
        BinOp::TwoEqual(_) => Op::Eq,
        BinOp::TildeEqual(_) => Op::Ne,
        BinOp::LessThan(_) => Op::Lt,
        BinOp::LessThanEqual(_) => Op::Le,
        BinOp::GreaterThan(_) => Op::Gt,
        BinOp::GreaterThanEqual(_) => Op::Ge,
        BinOp::And(_) => Op::And,
        BinOp::Or(_) => Op::Or,
        _ => Op::Other,
    }
}

fn compound_kind(op: &CompoundOp) -> Op {
    match op {
        CompoundOp::PlusEqual(_) => Op::Add,
        CompoundOp::MinusEqual(_) => Op::Sub,
        CompoundOp::StarEqual(_) => Op::Mul,
        CompoundOp::SlashEqual(_) => Op::Div,
        CompoundOp::DoubleSlashEqual(_) => Op::FloorDiv,
        CompoundOp::PercentEqual(_) => Op::Mod,
        CompoundOp::CaretEqual(_) => Op::Pow,
        CompoundOp::TwoDotsEqual(_) => Op::Concat,
        _ => Op::Other,
    }
}

fn precedence(op: Op) -> u8 {
    match op {
        Op::Or => 1,
        Op::And => 2,
        Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge => 3,
        Op::Concat => 8,
        Op::Add | Op::Sub => 9,
        Op::Mul | Op::Div | Op::FloorDiv | Op::Mod => 10,
        Op::Pow => 12,
        Op::Other => 0,
    }
}

enum Dependence<'e> {
    Expressions(Vec<&'e Expression>),
    Always,
}

#[derive(Debug, Clone)]
enum RequireVerdict {
    Numeric(u64, Option<Origin>),
    External,
    /// Read from an object inside the content that could not be resolved.
    Model(usize),
    Property(Origin),
    IdShaped(String),
    Remote,
    Placeholder,
    Opaque,
    Truncated,
}

/// Asset IDs of a `require` target, each with the instance value it was read from.
type AssetIds = Vec<(u64, Option<Origin>)>;

/// Evidence label for a trusted ID whose `require` argument is not a constant.
const TRUST_NOT_APPLIED: &str = "trusted asset id, not a constant target";

/// Severity of a BG002 finding whose value the scan cannot see (low confidence): the
/// object cannot be pinned down, the content stores no value for it, or the path
/// leaves the scanned content. Like an unresolved BG001 target, it asks for review but
/// does not claim a remote load. A value the content stores keeps the rule's critical
/// severity, also when the scan cannot fold it into an ID, and so does a value read
/// from an unresolved object when an object at or below the closest known one stores
/// an ID shaped value or a reference into the content.
const UNRESOLVED_ORIGIN_SEVERITY: Severity = Severity::Medium;

/// What the arguments of the call being evaluated say about a `require` it reaches.
#[derive(Debug, Clone, Copy, Default)]
struct RequireContext {
    /// The target expression is a constant: literals and locals assigned once from
    /// literals. Only then can a trusted ID remove a finding.
    constant: bool,
    /// The evaluation depth limit cut a value while the arguments were evaluated.
    cut: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    Webhook,
    Paste,
    IpHost,
}

struct Analyzer<'a> {
    doc: &'a Document,
    script_id: usize,
    limits: &'a Limits,
    trusted: &'a [u64],
    dom_index: &'a DomIndex,
    source: &'a str,
    script_path: String,
    scopes: Vec<Scope>,
    tables: Vec<ConstantTable>,
    findings: Vec<Finding>,
    reasons: Vec<String>,
    steps: usize,
    step_budget: usize,
    exhausted: bool,
    capped: bool,
    started: Instant,
    finding_path_bytes: usize,
    output_capped: bool,
    /// Gate seen while the current condition was visited: an `IsStudio` call, or a
    /// creator, place, server, player count or clock check.
    gate_signal: Option<Site>,
    /// Gate for code that runs inside a call right now, such as `task.delay(..., require, id)`.
    call_gate: Option<Site>,
    /// The first gate that controls a risky action, reported as BG009.
    gated_action: Option<Site>,
    /// If statements being visited, innermost last.
    if_gates: Vec<IfGate>,
    /// While loops being visited, with the gate of their condition.
    while_gates: Vec<(usize, Option<Site>)>,
    /// Repeat loop bodies being visited.
    repeat_blocks: Vec<usize>,
    /// Variables assigned from a gate check, such as `local studio = rs:IsStudio()`.
    gate_names: HashMap<Slot, Site>,
    functions: Vec<FunctionInfo>,
    function_ids: HashMap<usize, usize>,
    function_stack: Vec<FunctionFrame>,
    pending_params: Option<Vec<Value>>,
    pending_blocks: Vec<PendingBlock>,
    replay_site: Option<Site>,
    replay_depth: usize,
    replays: usize,
    replay_returns: Option<Value>,
    /// Findings outside replays by rule, location and evidence label, so a replay does
    /// not repeat a claim already made at the same place.
    normal_findings: HashMap<(String, Option<usize>, Option<usize>, String), Severity>,
    summarized_sites: HashSet<(usize, Option<usize>, Option<usize>)>,
    webhook_constants: BTreeMap<String, Site>,
    folded_bytes: usize,
    next_scope: usize,
    escape_work: usize,
    /// What each loop body may change, keyed by the byte offset of its first token.
    loop_targets: HashMap<usize, Rc<LoopInfo>>,
    /// What the whole script assigns, from one pass before the analysis.
    facts: ScriptFacts,
    /// The variable each name refers to, from one pass before the analysis.
    bindings: Bindings,
    /// Context of the call whose arguments were evaluated last, for `require`.
    require_context: Option<RequireContext>,
    /// Values cut by the evaluation depth limit so far.
    truncations: usize,
    /// Variables and field keys that read as "anything assigned later" somewhere, for a
    /// loop body or for a function body that runs later.
    widened_names: HashSet<Slot>,
    widened_keys: HashSet<String>,
    /// A loop changes too much to list, so every variable is widened.
    widened_everything: bool,
    /// Widened variables and keys that a write went through. A table assigned to them
    /// may be the one the write changed, so it is treated as changed.
    stray_roots: HashSet<Slot>,
    stray_keys: HashSet<String>,
    stray_everything: bool,
    /// Values such writes stored, kept as candidates of the tables they may have reached.
    stray_values: Vec<Value>,
    stray_sensitive: bool,
    /// Above zero while a function body runs only for its value, without findings.
    silent: usize,
    /// Values this script writes to properties and attributes of objects in the
    /// content, so a later read lists them as candidates.
    dom_writes: HashMap<(usize, String), Vec<Value>>,
    attribute_writes: HashMap<(usize, String), Vec<Value>>,
    /// Counts table changes, so a replay memo keyed by table arguments is not reused
    /// after a table changed below the depth the key describes.
    mutation_epoch: usize,
    /// `_G` and `shared` as tables of this script, made when first written.
    global_tables: HashMap<String, usize>,
    /// Expressions being visited whose gate controls the calls inside them, with the
    /// call gate from before.
    expression_gates: Vec<(usize, Option<Site>)>,
    /// A global was written through `getfenv()` under a name the scanner cannot read.
    environment_changed: bool,
    /// Calls whose environment use gives a low BG004, such as a read of a name that is
    /// not a builtin, from one pass before the analysis (see [`EnvironmentReads`]).
    environment_reads: HashMap<usize, EnvironmentUse>,
}

impl<'a> Analyzer<'a> {
    fn new(
        doc: &'a Document,
        script_id: usize,
        limits: &'a Limits,
        trusted: &'a [u64],
        dom_index: &'a DomIndex,
        source: &'a str,
    ) -> Self {
        Self {
            doc,
            script_id,
            limits,
            trusted,
            dom_index,
            source,
            script_path: doc.path(script_id),
            scopes: Vec::new(),
            tables: Vec::new(),
            findings: Vec::new(),
            reasons: Vec::new(),
            steps: 0,
            step_budget: limits.max_analysis_steps,
            exhausted: false,
            capped: false,
            started: Instant::now(),
            finding_path_bytes: 0,
            output_capped: false,
            gate_signal: None,
            call_gate: None,
            gated_action: None,
            if_gates: Vec::new(),
            while_gates: Vec::new(),
            repeat_blocks: Vec::new(),
            gate_names: HashMap::new(),
            functions: Vec::new(),
            function_ids: HashMap::new(),
            function_stack: Vec::new(),
            pending_params: None,
            pending_blocks: Vec::new(),
            replay_site: None,
            replay_depth: 0,
            replays: 0,
            replay_returns: None,
            normal_findings: HashMap::new(),
            summarized_sites: HashSet::new(),
            webhook_constants: BTreeMap::new(),
            folded_bytes: 0,
            next_scope: 0,
            escape_work: 0,
            loop_targets: HashMap::new(),
            facts: ScriptFacts::default(),
            bindings: Bindings::default(),
            require_context: None,
            truncations: 0,
            widened_names: HashSet::new(),
            widened_keys: HashSet::new(),
            widened_everything: false,
            stray_roots: HashSet::new(),
            stray_keys: HashSet::new(),
            stray_everything: false,
            stray_values: Vec::new(),
            stray_sensitive: false,
            silent: 0,
            dom_writes: HashMap::new(),
            attribute_writes: HashMap::new(),
            mutation_epoch: 0,
            global_tables: HashMap::new(),
            expression_gates: Vec::new(),
            environment_changed: false,
            environment_reads: HashMap::new(),
        }
    }

    fn finish(mut self) -> AnalysisResult {
        let traced_exfiltration = self
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG008" && finding.severity >= Severity::High);
        if !traced_exfiltration {
            for site in std::mem::take(&mut self.webhook_constants).into_values() {
                self.push(
                    "BG008",
                    Severity::Medium,
                    Confidence::Medium,
                    site,
                    "script contains a webhook URL that can receive exfiltrated data",
                    "",
                );
            }
        }
        if let Some(site) = self.gated_action.take() {
            self.push(
                "BG009",
                Severity::Medium,
                Confidence::Medium,
                site,
                "risky behavior is gated by a Studio, experience, creator, time, or delay check",
                "",
            );
        }
        self.findings.sort_by(|a, b| {
            (
                a.location.line,
                a.location.column,
                &a.rule_id,
                &a.fingerprint,
            )
                .cmp(&(
                    b.location.line,
                    b.location.column,
                    &b.rule_id,
                    &b.fingerprint,
                ))
        });
        AnalysisResult {
            findings: self.findings,
            reasons: self.reasons,
            notes: Vec::new(),
        }
    }

    fn spend(&mut self) -> bool {
        if self.exhausted {
            return false;
        }
        self.steps = self.steps.saturating_add(1);
        if self.steps.is_multiple_of(256)
            && self.started.elapsed().as_millis() > u128::from(self.limits.max_file_ms)
        {
            self.exhausted = true;
            if !self.capped {
                self.capped = true;
                self.reasons.push(format!(
                    "analysis time budget reached in {}; some values are unresolved",
                    self.doc.path(self.script_id)
                ));
            }
            return false;
        }
        if self.steps <= self.step_budget {
            true
        } else {
            self.exhausted = true;
            if !self.capped {
                self.capped = true;
                self.reasons.push(format!(
                    "analysis propagation limit reached in {}; some values are unresolved",
                    self.doc.path(self.script_id)
                ));
            }
            false
        }
    }

    /// Account for a string created by folding. Past the per-script budget, folding
    /// stops and the scan is marked partial.
    fn charge(&mut self, bytes: usize) -> bool {
        self.folded_bytes = self.folded_bytes.saturating_add(bytes);
        if self.folded_bytes > MAX_FOLDED_BYTES {
            self.mark_resolution_limit("constant folding output limit reached");
            false
        } else {
            true
        }
    }

    fn mark_resolution_limit(&mut self, reason: &str) {
        if !self.capped {
            self.capped = true;
            self.reasons.push(format!(
                "{reason} in {}; some values are unresolved",
                self.doc.path(self.script_id)
            ));
        }
    }

    // ----- scopes -------------------------------------------------------------------

    /// The variable a name token declares or refers to.
    fn slot(&self, token: &TokenReference) -> Slot {
        self.bindings.slot(token)
    }

    /// Position on the scope stack of the scope that holds a variable. A local of a
    /// scope that is not open, such as a variable of a closure called after its scope
    /// ended, has none.
    fn slot_scope(&self, slot: &Slot) -> Option<usize> {
        self.scopes
            .iter()
            .rposition(|scope| scope.vars.contains_key(slot))
    }

    fn lookup(&self, slot: &Slot) -> Option<Value> {
        self.slot_scope(slot)
            .and_then(|index| self.scopes[index].vars.get(slot).cloned())
    }

    fn define(&mut self, slot: Slot, value: Value) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.vars.insert(slot, value);
        }
    }

    /// Whether code between scope `defining` and the current scope may not run, so a
    /// write there keeps the old value as a candidate.
    fn conditional_since(&self, defining: usize) -> bool {
        self.scopes
            .get(defining + 1..)
            .is_some_and(|scopes| scopes.iter().any(|scope| scope.conditional))
    }

    /// Whether code between scope `defining` and the current scope is a function body
    /// seen where it is defined, which may run later with other values.
    fn deferred_since(&self, defining: usize) -> bool {
        self.scopes
            .get(defining + 1..)
            .is_some_and(|scopes| scopes.iter().any(|scope| scope.deferred))
    }

    /// Whether a loop body lies between scope `defining` and the current scope.
    fn repeats_since(&self, defining: usize) -> bool {
        self.scopes
            .get(defining + 1..)
            .is_some_and(|scopes| scopes.iter().any(|scope| scope.repeats))
    }

    fn push_scope(
        &mut self,
        vars: BTreeMap<Slot, Value>,
        conditional: bool,
        deferred: bool,
        repeats: bool,
    ) {
        self.next_scope += 1;
        self.scopes.push(Scope {
            vars,
            conditional,
            deferred,
            repeats,
            serial: self.next_scope,
            gate: None,
        });
    }

    fn current_serial(&self) -> usize {
        self.scopes.last().map_or(0, |scope| scope.serial)
    }

    /// What a value computed in a deferred function body still says once it is stored:
    /// its taint (player data, downloaded data, an instance origin), the kind of object
    /// it is (see [`deferred_instance`]), or nothing.
    fn deferred_value(&self, value: &Value) -> Value {
        if self.is_sensitive(value) {
            return Value::Sensitive;
        }
        // `t.m = script:WaitForChild(t.name)` in a loop stores an instance, not data
        // read from one, so `require(t.m)` requires an instance, not an asset ID.
        if let Some(instance) = deferred_instance(value) {
            return instance;
        }
        match derived_from(std::slice::from_ref(value)) {
            taint @ (Value::ExternalData
            | Value::ModelData(_)
            | Value::Remote
            | Value::UnresolvedOrigin(_)) => taint,
            _ => Value::Unknown,
        }
    }

    /// Assign to a name. Straight-line code replaces the value. An assignment in a
    /// branch, a loop or a function body keeps every candidate, because that code may
    /// not run. A value that depends on locals and is assigned in a function body seen
    /// where it is defined keeps only its taint, because the function may run later,
    /// and so does a value in a loop that is computed from the variable itself, because
    /// it changes on every iteration.
    fn assign(&mut self, slot: Slot, value: Value, dependence: &Dependence<'_>) {
        if self.scopes.is_empty() {
            return;
        }
        let found = self.slot_scope(&slot);
        let (index, old) = match (found, &slot) {
            (Some(index), _) => (
                index,
                self.scopes[index]
                    .vars
                    .get(&slot)
                    .cloned()
                    .unwrap_or(Value::Unknown),
            ),
            // A global this script never assigned is nil.
            (None, Slot::Global(name)) => (0, self.global_default(name)),
            // A local of a scope that is not open: the variable of a closure that runs
            // after its scope ended. Only that closure reads it, and the scanner does
            // not follow it there, so each call replays and a table stored there
            // counts as changed by unknown code.
            (None, _) => {
                self.mark_captures(|_| true);
                self.escape(&value);
                return;
            }
        };
        let value = if (self.deferred_since(index) && self.depends_on_locals(dependence))
            || (self.repeats_since(index) && self.references(dependence, &slot))
        {
            self.deferred_value(&value)
        } else {
            value
        };
        let value = if self.conditional_since(index) {
            join([old, value])
        } else {
            value
        };
        // A function that assigns a variable of an enclosing scope changes it when it is
        // called, so each call replays it.
        self.mark_captures(|frame_scope| index < frame_scope);
        if holds_table(&value) {
            if matches!(slot, Slot::Global(_)) {
                // Code the scanner cannot see reads globals through the environment.
                self.escape(&value);
            } else if self.stray_everything || self.stray_roots.contains(&slot) {
                self.escape_stray(&value);
            }
        }
        self.scopes[index].vars.insert(slot, value);
    }

    /// The variables an assigned value reads, or `None` when they cannot be listed.
    fn dependence_slots(&self, dependence: &Dependence<'_>) -> Option<Vec<Slot>> {
        dependence_names(dependence).map(|names| {
            names
                .iter()
                .map(|(offset, name)| self.bindings.slot_at(*offset, name))
                .collect()
        })
    }

    fn depends_on_locals(&self, dependence: &Dependence<'_>) -> bool {
        match self.dependence_slots(dependence) {
            None => true,
            Some(slots) => slots.iter().any(|slot| self.slot_scope(slot).is_some()),
        }
    }

    /// Whether an assigned value is computed from the variable `slot`.
    fn references(&self, dependence: &Dependence<'_>, slot: &Slot) -> bool {
        self.dependence_slots(dependence)
            .is_none_or(|slots| slots.contains(slot))
    }

    // ----- tables -------------------------------------------------------------------

    fn new_table(&mut self, mut table: ConstantTable) -> Value {
        if self.tables.len() >= MAX_TABLES {
            return if table.sensitive {
                Value::Sensitive
            } else {
                Value::Unknown
            };
        }
        table.home = self.current_serial();
        self.tables.push(table);
        Value::Table(self.tables.len() - 1)
    }

    fn table(&self, id: usize) -> Option<&ConstantTable> {
        self.tables.get(id)
    }

    /// Current value of a metatable field, such as `__index` or `__call`.
    fn meta_field(&self, id: usize, name: &str) -> Option<Value> {
        let meta = self.table(id)?.metatable?;
        self.table(meta)?.fields.get(name).cloned()
    }

    /// The `__call` function of a table.
    fn call_handler(&self, id: usize) -> Option<usize> {
        match self.meta_field(id, "__call") {
            Some(Value::Function(handler)) => Some(handler),
            _ => None,
        }
    }

    /// The `__index` function of a table.
    fn index_function(&self, id: usize) -> Option<usize> {
        match self.meta_field(id, "__index") {
            Some(Value::Function(handler)) => Some(handler),
            _ => None,
        }
    }

    /// What a missing key falls back to, other than an `__index` function: the
    /// metatable's `__index` table or value, or the table's own fallback.
    fn index_fallback(&self, id: usize) -> Option<Value> {
        let table = self.table(id)?;
        if table.metatable.is_some() {
            return match self.meta_field(id, "__index") {
                Some(Value::Function(_) | Value::Nil) | None => None,
                Some(other) => Some(other),
            };
        }
        table.fallback.as_deref().cloned()
    }

    /// Mark every table reachable from `value` as changed by unknown code. Each table
    /// is marked once, so the work per script is bounded by the table count.
    fn escape(&mut self, value: &Value) {
        let mut stack = vec![value.clone()];
        while let Some(value) = stack.pop() {
            self.escape_work += 1;
            if self.escape_work > 4 * MAX_TABLES {
                self.mark_resolution_limit("table tracking limit reached");
                return;
            }
            match value {
                Value::Table(id) => {
                    let Some(table) = self.tables.get_mut(id) else {
                        continue;
                    };
                    if table.escaped {
                        continue;
                    }
                    table.escaped = true;
                    self.mutation_epoch += 1;
                    // Unknown code can reach the metatable through `getmetatable`.
                    let fallback = table.fallback.as_deref().cloned();
                    let metatable = table.metatable.map(Value::Table);
                    let nested: Vec<Value> = table
                        .values()
                        .filter(|value| holds_table(value))
                        .cloned()
                        .chain(fallback.filter(holds_table))
                        .chain(metatable)
                        .collect();
                    stack.extend(nested);
                }
                Value::Union(values) | Value::Tuple(values) => stack.extend(values),
                _ => {}
            }
        }
    }

    fn escape_all(&mut self, values: &[Value]) {
        for value in values {
            if holds_table(value) {
                self.escape(value);
            }
        }
    }

    /// Treat the tables of `value` as changed by a write that the scanner could not
    /// place, so the values of such writes are candidates of their fields.
    fn escape_stray(&mut self, value: &Value) {
        self.escape(value);
        for id in tables_in(value) {
            if let Some(table) = self.tables.get_mut(id) {
                table.stray = true;
            }
        }
    }

    /// Every table any visible variable holds may have been changed.
    fn escape_visible(&mut self) {
        let tables: Vec<Value> = self
            .scopes
            .iter()
            .flat_map(|scope| scope.vars.values())
            .filter(|value| holds_table(value))
            .cloned()
            .collect();
        for value in tables {
            self.escape_stray(&value);
        }
    }

    /// Remember the value of a write that may have reached a table the scanner did not
    /// pin down: a changed table lists it as a candidate. It is stored out of the
    /// scanner's sight, so its own tables escape too.
    fn record_stray(&mut self, value: &Value) {
        self.stray_sensitive |= self.is_sensitive(value);
        for candidate in value.candidates() {
            if self.stray_values.len() < MAX_CANDIDATES
                && self.interesting(candidate, 1)
                && !self.stray_values.iter().any(|old| old.same(candidate))
            {
                self.stray_values.push(candidate.clone());
            }
        }
        self.escape(value);
    }

    /// A write into `container` that may also have reached a table the scanner did not
    /// pin down. Code the scanner cannot see only holds tables that already escaped, and
    /// those are read as changed. Two cases are left. A value cut by the depth limit, or
    /// a candidate set that lost members, may be any table in sight. A variable or a
    /// field read as "anything assigned later" may be a table that is stored there
    /// later, so the variable or key is remembered and such a table is treated as
    /// changed when it is stored.
    fn unpinned_write(
        &mut self,
        container: &Value,
        root: Option<&Slot>,
        path: &[&Suffix],
        value: &Value,
    ) {
        let candidates = container.candidates();
        if candidates
            .iter()
            .any(|candidate| matches!(candidate, Value::Truncated | Value::Overflow))
        {
            self.record_stray(value);
            self.stray_everything = true;
            self.escape_visible();
            return;
        }
        if !candidates
            .iter()
            .any(|candidate| matches!(candidate, Value::Unknown))
        {
            return;
        }
        self.record_stray(value);
        if let Some(root) = root
            && (self.widened_everything || self.widened_names.contains(root))
        {
            self.stray_everything |= self.widened_everything;
            self.stray_roots.insert(root.clone());
        }
        for suffix in path {
            let key = match suffix {
                Suffix::Index(Index::Dot { name, .. }) => Some(format!("s:{}", token_text(name))),
                Suffix::Index(Index::Brackets { expression, .. }) => {
                    literal_value(expression).and_then(|key| field_key(&key))
                }
                _ => None,
            };
            if let Some(key) = key
                && self.widened_keys.contains(&key)
            {
                self.stray_keys.insert(key);
            }
        }
    }

    /// Read from a table that unknown code may have changed: the stored value, the ID
    /// shaped values of the table, and an unknown value, so the result never counts as
    /// fully resolved.
    fn escaped_read(&self, id: usize, stored: Option<Value>) -> Value {
        let mut values = vec![stored.unwrap_or(Value::Nil)];
        if let Some(table) = self.table(id) {
            values.extend(
                table
                    .values()
                    .take(256)
                    .filter(|value| self.interesting(value, 1))
                    .take(MAX_CANDIDATES)
                    .cloned(),
            );
        }
        values.extend(self.stray_values.iter().cloned());
        values.push(Value::Unknown);
        join(values)
    }

    /// Position on the scope stack of the scope that created a table, if it is still
    /// open.
    fn home_index(&self, id: usize) -> Option<usize> {
        let home = self.table(id)?.home;
        self.scopes.iter().rposition(|scope| scope.serial == home)
    }

    /// Whether a change to a table here may not happen, and whether it happens in a
    /// deferred function body.
    fn table_write_context(&self, id: usize, fallback: Option<usize>) -> (bool, bool) {
        let reference = self.table_reference(id, fallback);
        (
            self.conditional_since(reference),
            self.deferred_since(reference),
        )
    }

    fn table_reference(&self, id: usize, fallback: Option<usize>) -> usize {
        self.home_index(id).or(fallback).unwrap_or(0)
    }

    /// Store `value` under `key`. A write that may not run keeps the old value as a
    /// candidate. A key the scanner cannot resolve leaves the table changed by unknown
    /// code, with the value kept as a loose candidate.
    fn write_table(&mut self, id: usize, key: &Value, value: Value, conditional: bool) {
        self.mutation_epoch += 1;
        self.note_table_change(id);
        let sensitive = self.is_sensitive(&value);
        let escaped = self.table(id).is_some_and(|table| table.escaped);
        if escaped {
            self.escape(&value);
        } else if holds_table(&value)
            && (self.stray_everything
                || field_key(key).is_some_and(|key| self.stray_keys.contains(&key)))
        {
            self.escape_stray(&value);
        }
        if holds_table(key) {
            // A table used as a key is found again by a loop over the keys.
            self.escape(key);
        }
        if let Value::Union(keys) = key {
            for key in keys.clone() {
                self.write_table(id, &key, value.clone(), true);
            }
            return;
        }
        let resolved_key = match key {
            Value::String(..) => true,
            Value::Number(number, _) => integer(*number).is_some(),
            _ => false,
        };
        if resolved_key {
            let old = self
                .table(id)
                .and_then(|table| table.raw(key).cloned())
                .unwrap_or(Value::Nil);
            let value = if conditional {
                join([old, value])
            } else {
                value
            };
            if let Some(table) = self.tables.get_mut(id) {
                table.sensitive |= sensitive;
                let room = table.entries() < MAX_TABLE_ENTRIES || table.raw(key).is_some();
                match key {
                    Value::String(key, _) if room => {
                        table.fields.insert(key.to_string(), value);
                    }
                    Value::Number(number, _) if room => {
                        if let Some(key) = integer(*number) {
                            table.set_number(key, value);
                        }
                    }
                    _ => {}
                }
            }
            return;
        }
        if let Some(table) = self.tables.get_mut(id) {
            table.sensitive |= sensitive;
            if table.loose.len() < MAX_CANDIDATES {
                table.loose.push(value);
            }
        }
        self.escape(&Value::Table(id));
    }

    fn is_sensitive(&self, value: &Value) -> bool {
        self.is_sensitive_at(value, 0)
    }

    fn is_sensitive_at(&self, value: &Value, depth: usize) -> bool {
        if depth > 4 {
            return false;
        }
        match value {
            Value::Sensitive => true,
            Value::Table(id) => self.table(*id).is_some_and(|table| {
                table.sensitive
                    || (table.stray && self.stray_sensitive)
                    || table
                        .values()
                        .take(256)
                        .any(|value| self.is_sensitive_at(value, depth + 1))
            }),
            Value::Union(values) | Value::Tuple(values) => values
                .iter()
                .any(|value| self.is_sensitive_at(value, depth + 1)),
            _ => false,
        }
    }

    // ----- evaluation ---------------------------------------------------------------

    fn eval(&mut self, expression: &Expression, depth: usize) -> Value {
        self.eval_raw(expression, depth).single()
    }

    /// Evaluate an expression that may produce several values (a call or `...`).
    fn eval_raw(&mut self, expression: &Expression, depth: usize) -> Value {
        if depth > self.limits.max_depth {
            self.truncations += 1;
            return Value::Truncated;
        }
        if !self.spend() {
            return Value::Unknown;
        }
        match expression {
            Expression::Number(token) => parse_number(&token_text(token))
                .map(|n| Value::Number(n, None))
                .unwrap_or(Value::Unknown),
            Expression::String(token) => Value::String(Text::from(string_value(token)), None),
            Expression::Symbol(token) => match token_text(token).as_str() {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                "nil" => Value::Nil,
                "..." => self.lookup(&Slot::Vararg).unwrap_or(Value::Unknown),
                _ => Value::Unknown,
            },
            Expression::TableConstructor(table) => self.eval_table(table, depth),
            Expression::Parentheses { expression, .. } => self.eval(expression, depth + 1),
            Expression::UnaryOperator {
                unop,
                expression: operand,
            } => {
                let value = self.eval(operand, depth + 1);
                // `-t` and `#t` run `__unm` and `__len` on a table with those metamethods.
                let handler = match (&value, unop) {
                    (Value::Table(id), UnOp::Minus(_)) => self.meta_field(*id, "__unm"),
                    (Value::Table(id), UnOp::Hash(_)) => self.meta_field(*id, "__len"),
                    _ => None,
                };
                match handler {
                    Some(Value::Function(handler)) => {
                        let site = Site::expression(expression);
                        self.call_function(handler, vec![value.clone(), value], true, site)
                    }
                    _ => self.unary(unop, value),
                }
            }
            Expression::BinaryOperator { .. } => self.eval_binary(expression, depth),
            Expression::Var(var) => self.eval_var(var, depth),
            Expression::FunctionCall(call) => self.eval_call(call, depth, false),
            Expression::Function(function) => {
                Value::Function(self.anonymous_function(function.body()))
            }
            Expression::IfExpression(expression) => self.eval_if(expression, depth),
            Expression::TypeAssertion { expression, .. } => self.eval(expression, depth + 1),
            Expression::InterpolatedString(string) => self.eval_interpolated(string, depth),
            _ => Value::Unknown,
        }
    }

    /// Fold a chain of same-precedence operators iteratively, so long ordinary chains do
    /// not consume evaluation depth per operator.
    fn eval_binary(&mut self, expression: &Expression, depth: usize) -> Value {
        let Expression::BinaryOperator { lhs, binop, rhs } = expression else {
            return Value::Unknown;
        };
        let op = binop_kind(binop);
        if matches!(op, Op::And | Op::Or) {
            let mut operands = vec![&**rhs];
            let mut current = &**lhs;
            while let Expression::BinaryOperator { lhs, binop, rhs } = current {
                if binop_kind(binop) != op {
                    break;
                }
                operands.push(&**rhs);
                current = &**lhs;
            }
            operands.push(current);
            operands.reverse();
            return self.eval_logical(op, &operands, depth);
        }
        if matches!(op, Op::Concat | Op::Pow) {
            let mut operands = vec![&**lhs];
            let mut current = &**rhs;
            while let Expression::BinaryOperator { lhs, binop, rhs } = current {
                if binop_kind(binop) != op {
                    break;
                }
                operands.push(&**lhs);
                current = &**rhs;
            }
            operands.push(current);
            let values: Vec<Value> = operands
                .iter()
                .map(|operand| self.eval(operand, depth + 1))
                .collect();
            let site = Site::expression(expression);
            return if op == Op::Concat {
                self.concat_chain(values, site)
            } else {
                let mut values = values.into_iter().rev();
                let last = values.next().unwrap_or(Value::Unknown);
                values.fold(last, |acc, value| self.binary_at(Op::Pow, value, acc, site))
            };
        }
        let mut pairs = vec![(op, &**rhs)];
        let mut current = &**lhs;
        while let Expression::BinaryOperator { lhs, binop, rhs } = current {
            let inner = binop_kind(binop);
            if precedence(inner) != precedence(op) || matches!(inner, Op::Concat | Op::Pow) {
                break;
            }
            pairs.push((inner, &**rhs));
            current = &**lhs;
        }
        let site = Site::expression(expression);
        let mut acc = self.eval(current, depth + 1);
        for (op, operand) in pairs.into_iter().rev() {
            let value = self.eval(operand, depth + 1);
            acc = self.binary_at(op, acc, value, site);
        }
        acc
    }

    /// Fold `a .. b .. c ...` in one pass. Runs of known strings and numbers are joined
    /// into one buffer, so a long chain costs its final length and not the sum of every
    /// intermediate string. Any other operand goes through [`Analyzer::binary_at`].
    fn concat_chain(&mut self, values: Vec<Value>, site: Site) -> Value {
        let mut values = values.into_iter();
        let mut acc = values.next().unwrap_or(Value::Unknown);
        // Text joined so far that has not been turned into a value yet.
        let mut buffer: Option<(String, Option<Origin>)> = None;
        for value in values {
            let plain_acc =
                buffer.is_some() || matches!(acc, Value::String(..) | Value::Number(..));
            match (plain_acc, value_as_string(&value)) {
                (true, Some((text, origin))) => {
                    let (mut joined, joined_origin) = match buffer.take() {
                        Some(buffer) => buffer,
                        None => value_as_string(&acc).unwrap_or_default(),
                    };
                    if joined.len().saturating_add(text.len()) > self.limits.max_script_bytes {
                        self.mark_resolution_limit("constant folding output limit reached");
                        return Value::Unknown;
                    }
                    joined.push_str(&text);
                    buffer = Some((joined, joined_origin.or(origin)));
                }
                _ => {
                    if let Some((text, origin)) = buffer.take() {
                        if !self.charge(text.len()) {
                            return Value::Unknown;
                        }
                        acc = Value::String(Text::from(text), origin);
                    }
                    acc = self.binary_at(Op::Concat, acc, value, site);
                }
            }
        }
        match buffer {
            Some((text, origin)) => {
                if !self.charge(text.len()) {
                    return Value::Unknown;
                }
                Value::String(Text::from(text), origin)
            }
            None => acc,
        }
    }

    /// A binary operation that first looks for an operator metamethod, such as
    /// `__add` or `__concat`, on a table operand, so a wrapper hidden in one is checked
    /// where the operator is used.
    fn binary_at(&mut self, op: Op, left: Value, right: Value, site: Site) -> Value {
        let (name, swapped) = match op {
            Op::Add => ("__add", false),
            Op::Sub => ("__sub", false),
            Op::Mul => ("__mul", false),
            Op::Div => ("__div", false),
            Op::FloorDiv => ("__idiv", false),
            Op::Mod => ("__mod", false),
            Op::Pow => ("__pow", false),
            Op::Concat => ("__concat", false),
            Op::Eq | Op::Ne => ("__eq", false),
            Op::Lt => ("__lt", false),
            Op::Le => ("__le", false),
            Op::Gt => ("__lt", true),
            Op::Ge => ("__le", true),
            _ => return self.binary(op, left, right),
        };
        let handler = [&left, &right].into_iter().find_map(|operand| {
            let Value::Table(id) = operand else {
                return None;
            };
            let meta = self.table(self.table(*id)?.metatable?)?;
            match meta.fields.get(name) {
                Some(Value::Function(handler)) => Some(*handler),
                _ => None,
            }
        });
        let Some(handler) = handler else {
            return self.binary(op, left, right);
        };
        let args = if swapped {
            vec![right, left]
        } else {
            vec![left, right]
        };
        let result = self.call_function(handler, args, true, site);
        match op {
            Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge => Value::Unknown,
            _ => result,
        }
    }

    fn eval_logical(&mut self, op: Op, operands: &[&Expression], depth: usize) -> Value {
        let mut results = Vec::new();
        for (index, operand) in operands.iter().enumerate() {
            let value = self.eval(operand, depth + 1);
            if index + 1 == operands.len() {
                results.push(value);
                break;
            }
            match (op, value.truthy()) {
                (Op::Or, Some(true)) | (Op::And, Some(false)) => {
                    results.push(value);
                    break;
                }
                (Op::Or, Some(false)) | (Op::And, Some(true)) => {}
                // An undecided operand is the result only when it is false or nil for
                // `and`, and only when it is true for `or`.
                (Op::And, None) => results.push(falsy_part(&value)),
                _ => results.push(truthy_part(&value)),
            }
        }
        join(results)
    }

    fn eval_if(&mut self, expression: &IfExpression, depth: usize) -> Value {
        let mut results = Vec::new();
        let condition = self.eval(expression.condition(), depth + 1);
        match condition.truthy() {
            Some(true) => return self.eval(expression.if_expression(), depth + 1),
            Some(false) => {}
            None => results.push(self.eval(expression.if_expression(), depth + 1)),
        }
        if let Some(branches) = expression.else_if_expressions() {
            for branch in branches {
                let condition = self.eval(branch.condition(), depth + 1);
                match condition.truthy() {
                    Some(true) => {
                        results.push(self.eval(branch.expression(), depth + 1));
                        return join(results);
                    }
                    Some(false) => {}
                    None => results.push(self.eval(branch.expression(), depth + 1)),
                }
            }
        }
        results.push(self.eval(expression.else_expression(), depth + 1));
        join(results)
    }

    fn eval_interpolated(&mut self, string: &InterpolatedString, depth: usize) -> Value {
        let mut output = String::new();
        let mut origin = None;
        let mut pieces = Vec::new();
        for segment in string.segments() {
            output.push_str(&interpolated_literal(&segment.literal));
            let value = self.eval(&segment.expression, depth + 1);
            match value_as_string(&value) {
                Some((text, value_origin)) => {
                    output.push_str(&text);
                    origin = origin.or(value_origin);
                }
                None => {
                    pieces.push(value);
                }
            }
            if output.len() > self.limits.max_script_bytes {
                self.mark_resolution_limit("constant folding output limit reached");
                return Value::Unknown;
            }
        }
        output.push_str(&interpolated_literal(string.last_string()));
        if pieces.is_empty() {
            if !self.charge(output.len()) {
                return Value::Unknown;
            }
            return Value::String(Text::from(output), origin);
        }
        if pieces.iter().any(|value| self.is_sensitive(value)) {
            return Value::Sensitive;
        }
        pieces.push(Value::String(Text::from(output), origin));
        derived_from(&pieces)
    }

    fn eval_table(&mut self, table: &TableConstructor, depth: usize) -> Value {
        if depth > self.limits.max_depth {
            self.truncations += 1;
            return Value::Truncated;
        }
        let mut constant = ConstantTable {
            constructor: Some(constructor_offset(table)),
            ..ConstantTable::default()
        };
        let count = table.fields().len();
        for (position, field) in table.fields().iter().enumerate() {
            if !self.spend() {
                return Value::Unknown;
            }
            let store = constant.entries() < MAX_TABLE_ENTRIES;
            match field {
                Field::NameKey { key, value, .. } => {
                    let value = self.eval(value, depth + 1);
                    constant.sensitive |= self.is_sensitive(&value);
                    if store {
                        constant.fields.insert(token_text(key), value);
                    }
                }
                Field::ExpressionKey { key, value, .. } => {
                    let key = self.eval(key, depth + 1);
                    let value = self.eval(value, depth + 1);
                    if holds_table(&key) {
                        self.escape(&key);
                    }
                    constant.sensitive |= self.is_sensitive(&value);
                    if store {
                        match key {
                            Value::String(key, _) => {
                                constant.fields.insert(key.to_string(), value);
                            }
                            Value::Number(number, _) if integer(number).is_some() => {
                                constant.set_number(integer(number).unwrap_or_default(), value);
                            }
                            _ => {}
                        }
                    }
                }
                Field::NoKey(value) => {
                    let values = if position + 1 == count {
                        match self.eval_raw(value, depth + 1) {
                            Value::Tuple(values) => values,
                            value => vec![value],
                        }
                    } else {
                        vec![self.eval(value, depth + 1)]
                    };
                    for value in values {
                        constant.sensitive |= self.is_sensitive(&value);
                        if constant.entries() < MAX_TABLE_ENTRIES {
                            constant.items.push(value.single());
                        }
                    }
                }
                _ => {}
            }
        }
        self.new_table(constant)
    }

    fn eval_var(&mut self, var: &Var, depth: usize) -> Value {
        match var {
            Var::Name(name) => self.eval_name(name),
            Var::Expression(expression) => {
                let value = self.eval_prefix(expression.prefix(), depth);
                self.apply_suffixes(
                    value,
                    expression.suffixes(),
                    depth,
                    false,
                    first_token_of_prefix(expression.prefix()),
                )
            }
            _ => Value::Unknown,
        }
    }

    fn eval_name(&mut self, name: &TokenReference) -> Value {
        let slot = self.slot(name);
        self.read_slot(slot)
    }

    /// The value of a variable here. Each name reads the variable it refers to in the
    /// source, also in a replay, where an unrelated variable of the caller may have the
    /// same name.
    fn read_slot(&mut self, slot: Slot) -> Value {
        let Some(index) = self.slot_scope(&slot) else {
            return match &slot {
                Slot::Global(name) => {
                    // A global the script assigns later, read in a function that may
                    // run later.
                    if !self.function_stack.is_empty() && self.facts.reassigned.contains_key(&slot)
                    {
                        let value = self.global_default(name);
                        self.captured_read(&slot, 0, value)
                    } else {
                        match self.builtin(name) {
                            // A write through `getfenv()` under an unreadable name may
                            // have set it.
                            Value::Unknown if self.environment_changed => self.stray_read(),
                            builtin => builtin,
                        }
                    }
                }
                // A local of a scope that is not open: the variable of a closure that
                // runs after its scope ended.
                _ => Value::Unknown,
            };
        };
        let value = self.scopes[index]
            .vars
            .get(&slot)
            .cloned()
            .unwrap_or(Value::Unknown);
        // A global after a write through `getfenv()` under an unreadable name: the
        // values of such writes are candidates.
        let value = if self.environment_changed && matches!(slot, Slot::Global(_)) {
            join([value, self.stray_read()])
        } else {
            value
        };
        self.captured_read(&slot, index, value)
    }

    /// What a write to a place the scanner could not pin down may have stored: the
    /// values of such writes and an unknown value.
    fn stray_read(&self) -> Value {
        join(std::iter::once(Value::Unknown).chain(self.stray_values.iter().cloned()))
    }

    /// What a global holds before the script assigns it: a library value, or nil.
    fn global_default(&self, name: &str) -> Value {
        match self.builtin(name) {
            Value::Unknown => Value::Nil,
            builtin => builtin,
        }
    }

    /// A variable read inside a function from an enclosing scope. When the function
    /// body is visited where it is defined, it may run later, after the script assigned
    /// the variable again, so the read is the current value and every value the script
    /// assigns to that variable. Reading such a variable, or a table from outside, makes
    /// every call of the function replay it.
    fn captured_read(&mut self, slot: &Slot, index: usize, value: Value) -> Value {
        if self
            .function_stack
            .last()
            .is_none_or(|frame| index >= frame.scope)
        {
            return value;
        }
        let mut later: Vec<Value> = self
            .facts
            .reassigned
            .get(slot)
            .map(|assigned| assigned.values().collect())
            .unwrap_or_default();
        // A global may also be written through `getfenv()` under an unreadable name.
        if self.facts.environment_write && matches!(slot, Slot::Global(_)) {
            later.push(Value::Unknown);
        }
        if !later.is_empty() || holds_table(&value) {
            self.mark_captures(|frame_scope| index < frame_scope);
        }
        if !later.is_empty() && self.deferred_since(index) {
            self.widened_names.insert(slot.clone());
            return join(std::iter::once(value).chain(later));
        }
        value
    }

    /// A table from outside a function body changed inside it: each call replays the
    /// function, so the change happens where it is called.
    fn note_table_change(&mut self, id: usize) {
        if self.function_stack.is_empty() {
            return;
        }
        let Some(home) = self.table(id).map(|table| table.home) else {
            return;
        };
        let scopes: Vec<usize> = self.scopes.iter().map(|scope| scope.serial).collect();
        self.mark_captures(|frame_scope| scopes.get(frame_scope).is_some_and(|s| *s > home));
    }

    /// Mark the functions being visited whose body scope (by position on the scope
    /// stack) passes `captures` as reading captured state.
    fn mark_captures(&mut self, captures: impl Fn(usize) -> bool) {
        for index in 0..self.function_stack.len() {
            let frame = &self.function_stack[index];
            if captures(frame.scope)
                && let Some(function) = self.functions.get_mut(frame.id)
            {
                function.reads_captures = true;
            }
        }
    }

    /// Serial of the body scope of the innermost function visited where it is defined,
    /// which may run later.
    fn deferred_serial(&self) -> Option<usize> {
        self.function_stack
            .iter()
            .rev()
            .find(|frame| !frame.root)
            .and_then(|frame| self.scopes.get(frame.scope))
            .map(|scope| scope.serial)
    }

    /// A field of a table from outside a function body that is visited where it is
    /// defined: the body may run after the script wrote that field again, so the read is
    /// the stored value and every value the script writes to that key of a table it may
    /// reach (see [`TableKey`]). `tables` are the tables the read looked in: the table
    /// indexed and, for a key it lacks, each table of its `__index` chain up to the one
    /// that answered, since a later write to any of them changes the result. `key` is
    /// the canonical key of [`field_key`], or `None` for a key the scanner cannot fold.
    fn captured_field(&mut self, tables: &[usize], key: Option<String>, value: Value) -> Value {
        let Some(serial) = self.deferred_serial() else {
            return value;
        };
        // The write keys of every table made outside the body, and the oldest home. A
        // cyclic chain lists a table more than once.
        let mut written: Vec<TableKey> = Vec::new();
        let mut oldest: Option<usize> = None;
        let mut metatable = false;
        for &id in tables {
            let Some((home, constructor)) = self
                .table(id)
                .map(|table| (table.home, table.constructor))
                .filter(|(home, _)| *home < serial)
            else {
                continue;
            };
            oldest = Some(oldest.map_or(home, |oldest| oldest.min(home)));
            self.facts.extend_tables(constructor, &mut written);
            metatable |= self.facts.metatable_may_change(constructor);
        }
        let Some(oldest) = oldest else {
            return value;
        };
        let scopes: Vec<usize> = self.scopes.iter().map(|scope| scope.serial).collect();
        self.mark_captures(|frame_scope| scopes.get(frame_scope).is_some_and(|s| *s > oldest));
        written.sort_unstable();
        written.dedup();
        let mut later = self.facts.later_field_values(&written, key.as_deref());
        if matches!(value, Value::Nil) && metatable {
            later.push(Value::Unknown);
        }
        if later.is_empty() {
            return value;
        }
        if let Some(key) = key {
            self.widened_keys.insert(key);
        }
        join(std::iter::once(value).chain(later))
    }

    /// Whether a table from outside a function body visited where it is defined may be
    /// changed later by the script, for reads that take many of its values at once.
    fn captured_table_changes(&self, id: usize) -> bool {
        let Some(table) = self.table(id) else {
            return false;
        };
        let mut written = Vec::new();
        self.facts.extend_tables(table.constructor, &mut written);
        self.deferred_serial()
            .is_some_and(|serial| table.home < serial)
            && (self.facts.metatable_may_change(table.constructor)
                || self.facts.table_written(&written))
    }

    fn builtin(&self, name: &str) -> Value {
        match name {
            "require" | "loadstring" | "getfenv" | "setfenv" | "rawget" | "rawset" | "tonumber"
            | "tostring" | "pcall" | "xpcall" | "spawn" | "delay" | "select" | "setmetatable"
            | "print" | "warn" | "type" | "typeof" | "assert" | "error" | "pairs" | "ipairs"
            | "next" | "rawequal" | "rawlen" | "getmetatable" | "tick" | "time" => {
                Value::Callable(name.into())
            }
            "unpack" => Value::Callable("table.unpack".into()),
            "wait" => Value::Callable("task.wait".into()),
            "script" => Value::Dom(self.script_id),
            "game" | "Game" => self
                .dom_index
                .data_model()
                .map(Value::Dom)
                .unwrap_or(Value::ExternalDom),
            "workspace" | "Workspace" => self
                .dom_index
                .workspace()
                .map(Value::Dom)
                .unwrap_or(Value::ExternalDom),
            "string" | "table" | "task" | "coroutine" | "math" | "utf8" | "bit32" | "os" | "_G"
            | "shared" | "player" | "Player" | "Players" => Value::Namespace(name.into()),
            _ => Value::Unknown,
        }
    }

    fn eval_prefix(&mut self, prefix: &Prefix, depth: usize) -> Value {
        match prefix {
            Prefix::Name(name) => self.eval_name(name),
            Prefix::Expression(expression) => self.eval(expression, depth + 1),
            _ => Value::Unknown,
        }
    }

    fn eval_call(&mut self, call: &FunctionCall, depth: usize, report: bool) -> Value {
        // A function chosen by a gated expression, such as
        // `local f = if game.CreatorId == id then require else print`, runs gated.
        let outer = self.call_gate;
        if self.call_gate.is_none()
            && let Prefix::Name(name) = call.prefix()
        {
            self.call_gate = self.gate_names.get(&self.slot(name)).copied();
        }
        let value = self.eval_prefix(call.prefix(), depth);
        let result = self.apply_suffixes(
            value,
            call.suffixes(),
            depth,
            report,
            first_token_of_prefix(call.prefix()),
        );
        self.call_gate = outer;
        result
    }

    fn eval_list(&mut self, expressions: &Punctuated<Expression>, depth: usize) -> Vec<Value> {
        let count = expressions.len();
        let mut values = Vec::with_capacity(count.min(MAX_CALL_ARGUMENTS));
        for (index, expression) in expressions.iter().enumerate() {
            if index + 1 == count {
                match self.eval_raw(expression, depth + 1) {
                    Value::Tuple(tuple) => values.extend(tuple.into_iter().map(Value::single)),
                    value => values.push(value),
                }
            } else {
                values.push(self.eval(expression, depth + 1));
            }
            if values.len() >= MAX_CALL_ARGUMENTS {
                values.truncate(MAX_CALL_ARGUMENTS);
                break;
            }
        }
        values
    }

    fn eval_args(&mut self, args: &FunctionArgs, depth: usize) -> Vec<Value> {
        match args {
            FunctionArgs::Parentheses { arguments, .. } => self.eval_list(arguments, depth),
            FunctionArgs::String(token) => {
                vec![Value::String(Text::from(string_value(token)), None)]
            }
            FunctionArgs::TableConstructor(table) => vec![self.eval_table(table, depth + 1)],
            _ => Vec::new(),
        }
    }

    fn apply_suffixes<'b>(
        &mut self,
        mut value: Value,
        suffixes: impl Iterator<Item = &'b Suffix>,
        depth: usize,
        report: bool,
        start: Option<&TokenReference>,
    ) -> Value {
        // Name of the member indexed just before a method call, such as `PlayerAdded`,
        // and the value it was read from.
        let mut member: Option<(String, Value)> = None;
        for suffix in suffixes {
            if depth > self.limits.max_depth {
                self.truncations += 1;
                return Value::Truncated;
            }
            // A call in the middle of a chain gives its first result to the next suffix.
            if matches!(value, Value::Tuple(_)) {
                value = value.single();
            }
            let within_budget = self.spend();
            let site = Site::between(start, last_token_of_suffix(suffix));
            match suffix {
                Suffix::Index(index) => {
                    if !within_budget {
                        return Value::Unknown;
                    }
                    member = match index {
                        Index::Dot { name, .. } => Some((token_text(name), value.clone())),
                        _ => None,
                    };
                    value = self.index_suffix(value, index, depth, site);
                }
                Suffix::Call(Call::AnonymousCall(args)) => {
                    member = None;
                    // Calls still run without budget so sinks stay visible as unresolved.
                    value = self.invoke(value, args, depth, report, site);
                    if !within_budget {
                        return Value::Unknown;
                    }
                }
                Suffix::Call(Call::MethodCall(method)) => {
                    let parameter = member
                        .take()
                        .and_then(|(member, owner)| self.event_parameter(&member, &owner));
                    value = self.invoke_method(
                        value,
                        method.name(),
                        method.args(),
                        depth,
                        report,
                        site,
                    );
                    if let Some(parameter) = parameter {
                        value = self.event_callback(method, value, parameter, site);
                    }
                    if !within_budget {
                        return Value::Unknown;
                    }
                }
                _ => {}
            }
        }
        value
    }

    /// What an event of `owner` passes as the first parameter of a connected function:
    /// a player for `PlayerAdded`, an object of the content for `ChildAdded`, the new
    /// value for the `Changed` event of a value object.
    fn event_parameter(&self, member: &str, owner: &Value) -> Option<Value> {
        match member {
            "PlayerAdded" | "PlayerRemoving" => Some(Value::Namespace("player".into())),
            "ChildAdded" | "DescendantAdded" | "ChildRemoved" | "DescendantRemoving" => {
                Some(match owner {
                    Value::Dom(anchor) | Value::ModelDom(anchor) => Value::ModelDom(*anchor),
                    _ => Value::ExternalDom,
                })
            }
            "CharacterAdded" | "CharacterAppearanceLoaded" | "CharacterRemoving" => {
                Some(Value::ExternalDom)
            }
            "Changed" => match owner {
                Value::Dom(instance) => {
                    let class = self.doc.instances.get(*instance)?.class.as_str();
                    if class == "ObjectValue" {
                        Some(Value::ModelDom(*instance))
                    } else if class.ends_with("Value") {
                        Some(Value::UnresolvedOrigin(Origin {
                            instance: *instance,
                            property: Some("Value".into()),
                            attribute: None,
                        }))
                    } else {
                        None
                    }
                }
                Value::ModelDom(anchor) => Some(Value::ModelData(*anchor)),
                _ => None,
            },
            _ => None,
        }
    }

    /// `event:Connect(fn)`: the callback's first parameter is what the event passes,
    /// whatever it is called. `:Wait()` returns it.
    fn event_callback(
        &mut self,
        method: &MethodCall,
        result: Value,
        parameter: Value,
        site: Site,
    ) -> Value {
        match token_text(method.name()).as_str() {
            "Connect" | "Once" | "ConnectParallel" => {
                if let FunctionArgs::Parentheses { arguments, .. } = method.args() {
                    for argument in arguments.iter() {
                        if let Expression::Function(function) = argument {
                            // Not visited yet: its parameter is bound when it is.
                            let id = self.function_id(function.body());
                            self.functions[id]
                                .first_parameter
                                .get_or_insert(parameter.clone());
                        } else if let Some(Value::Function(id)) = match argument {
                            Expression::Var(Var::Name(name)) => self.lookup(&self.slot(name)),
                            _ => None,
                        } && self.functions[id].first_parameter.is_none()
                        {
                            // Already visited where it was defined: run it with the value.
                            self.functions[id].first_parameter = Some(parameter.clone());
                            self.replay(id, vec![parameter.clone()], site);
                        }
                    }
                }
                result
            }
            "Wait" => parameter,
            _ => result,
        }
    }

    fn index_suffix(&mut self, value: Value, index: &Index, depth: usize, site: Site) -> Value {
        let key = match index {
            Index::Dot { name, .. } => Value::String(Text::from(token_text(name)), None),
            Index::Brackets { expression, .. } => self.eval(expression, depth + 1),
            _ => return Value::Unknown,
        };
        // A missing key on a table with an `__index` function calls that function. An
        // ID shaped key replays it; any other key gets what the function returns where
        // it is defined, such as a constant.
        if let Value::Table(id) = value
            && let Some(function) = self.index_function(id)
        {
            let present = match &key {
                Value::String(text, _) => self
                    .table(id)
                    .is_some_and(|table| table.fields.contains_key(&text[..])),
                Value::Number(number, _) => integer(*number).is_some_and(|n| {
                    self.table(id)
                        .is_some_and(|table| table.number(n).is_some())
                }),
                _ => false,
            };
            if !present {
                // A function not visited yet has no result to reuse, so it runs now, and
                // so does one whose result depends on captured state.
                let reuse = self
                    .functions
                    .get(function)
                    .is_some_and(|function| function.visited && !function.reads_captures);
                if !reuse || self.interesting(&key, 0) {
                    return self.call_function(function, vec![Value::Table(id), key], true, site);
                }
                return self
                    .functions
                    .get(function)
                    .and_then(|function| function.returns.clone())
                    .unwrap_or(Value::Unknown);
            }
        }
        match index {
            Index::Dot { name, .. } => self.index(value, &token_text(name)),
            _ => self.index_by_value(value, key),
        }
    }

    fn index_by_value(&mut self, value: Value, key: Value) -> Value {
        match key {
            Value::String(key, _) => self.index(value, &key),
            Value::Number(number, _) if integer(number).is_some() => {
                self.index_number(value, integer(number).unwrap_or_default())
            }
            Value::Union(keys) => {
                let results: Vec<Value> = keys
                    .into_iter()
                    .map(|key| self.index_by_value(value.clone(), key))
                    .collect();
                join(results)
            }
            _ => self.index_unknown(value),
        }
    }

    fn index_unknown(&mut self, value: Value) -> Value {
        match value {
            Value::Remote => Value::Remote,
            Value::Namespace(namespace) if is_global_table(&namespace) => Value::ComputedGlobal,
            Value::Table(id) => {
                let Some(table) = self.table(id) else {
                    return Value::Unknown;
                };
                let mut values: Vec<Value> =
                    table.values().take(4 * MAX_CANDIDATES).cloned().collect();
                if values.is_empty() && !table.escaped {
                    return Value::Unknown;
                }
                values.push(Value::Nil);
                if table.entries() > 4 * MAX_CANDIDATES {
                    values.push(Value::Overflow);
                }
                let escaped = table.escaped;
                match self.index_fallback(id) {
                    Some(data @ (Value::ModelData(_) | Value::ExternalData)) => values.push(data),
                    Some(_) => values.push(Value::Unknown),
                    None => {}
                }
                if escaped || self.index_function(id).is_some() {
                    values.push(Value::Unknown);
                }
                let value = join(values);
                self.captured_field(&[id], None, value)
            }
            // A child chosen by a computed name is inside the content, unresolved.
            Value::Dom(instance) | Value::ModelDom(instance) => Value::ModelDom(instance),
            Value::ExternalDom | Value::Object(_) => Value::ExternalDom,
            Value::InstanceList(element) => *element,
            data @ (Value::ExternalData | Value::ModelData(_)) => data,
            Value::Union(values) => {
                let results: Vec<Value> = values
                    .into_iter()
                    .map(|value| self.index_unknown(value))
                    .collect();
                join(results)
            }
            _ => Value::Unknown,
        }
    }

    fn index_number(&mut self, value: Value, key: i64) -> Value {
        match value {
            Value::Remote => Value::Remote,
            Value::Table(id) => self.table_index(id, &Value::Number(key as f64, None)),
            Value::Dom(instance) | Value::ModelDom(instance) => Value::ModelDom(instance),
            Value::ExternalDom | Value::Object(_) => Value::ExternalDom,
            // `GetChildren()[1]`, `kids[#kids]`: some element of the list.
            Value::InstanceList(element) => *element,
            data @ (Value::ExternalData | Value::ModelData(_)) => data,
            Value::Namespace(namespace) if is_global_table(&namespace) => self
                .global_field(&namespace, &Value::Number(key as f64, None))
                .unwrap_or(Value::Unknown),
            Value::Union(values) => {
                let results: Vec<Value> = values
                    .into_iter()
                    .map(|value| self.index_number(value, key))
                    .collect();
                join(results)
            }
            _ => Value::Unknown,
        }
    }

    fn index(&mut self, value: Value, key: &str) -> Value {
        match value {
            Value::Union(values) => {
                let results: Vec<Value> = values
                    .into_iter()
                    .map(|value| self.index(value, key))
                    .collect();
                join(results)
            }
            Value::Namespace(namespace) if is_global_table(&namespace) => {
                if let Some(value) =
                    self.global_field(&namespace, &Value::String(Text::from(key), None))
                {
                    return value;
                }
                let library = match key {
                    "require" | "loadstring" | "getfenv" | "setfenv" => Value::Callable(key.into()),
                    "_G" | "shared" => Value::Namespace(key.into()),
                    _ => match self.builtin(key) {
                        value @ (Value::Callable(_) | Value::Namespace(_)) => value,
                        _ => Value::Unknown,
                    },
                };
                // A write through `getfenv()` under an unreadable name may have set it.
                if namespace == ENVIRONMENT && self.environment_changed {
                    join([library, self.stray_read()])
                } else {
                    library
                }
            }
            Value::Namespace(namespace) if namespace == "string" => {
                if is_string_method(key) || key == "char" {
                    Value::Callable(format!("string.{key}"))
                } else {
                    Value::Unknown
                }
            }
            Value::Namespace(namespace) if namespace == "table" => match key {
                "concat" | "unpack" | "insert" | "pack" | "remove" | "sort" | "move" | "clear"
                | "freeze" | "clone" | "find" | "isfrozen" | "maxn" | "create" => {
                    Value::Callable(format!("table.{key}"))
                }
                _ => Value::Unknown,
            },
            Value::Namespace(namespace) if namespace == "math" => match key {
                "huge" => Value::Number(f64::INFINITY, None),
                "pi" => Value::Number(std::f64::consts::PI, None),
                "floor" | "ceil" | "abs" | "max" | "min" | "fmod" | "round" | "clamp" | "sign"
                | "sqrt" | "pow" | "modf" | "random" => Value::Callable(format!("math.{key}")),
                _ => Value::Unknown,
            },
            Value::Namespace(namespace) if namespace == "utf8" => match key {
                "char" => Value::Callable("utf8.char".into()),
                _ => Value::Unknown,
            },
            Value::Namespace(namespace) if namespace == "bit32" => match key {
                "band" | "bor" | "bxor" | "bnot" | "lshift" | "rshift" | "arshift" | "extract"
                | "lrotate" | "rrotate" | "replace" => Value::Callable(format!("bit32.{key}")),
                _ => Value::Unknown,
            },
            Value::Namespace(namespace) if namespace == "task" => match key {
                "wait" | "spawn" | "defer" | "delay" => Value::Callable(format!("task.{key}")),
                _ => Value::Unknown,
            },
            Value::Namespace(namespace) if namespace == "coroutine" => match key {
                "wrap" | "create" | "resume" => Value::Callable(format!("coroutine.{key}")),
                _ => Value::Unknown,
            },
            Value::Namespace(namespace) if namespace == "os" => Value::Unknown,
            Value::Namespace(namespace) if is_sensitive_member(&namespace, key) => Value::Sensitive,
            Value::Namespace(_) if is_security_method(key) => {
                Value::Callable(format!("method.{key}"))
            }
            Value::String(..) if is_string_method(key) => Value::Callable(format!("string.{key}")),
            Value::Remote => Value::Remote,
            Value::ExternalDom if key == "Value" => Value::ExternalData,
            Value::ExternalDom if key == "LocalPlayer" => {
                Value::Namespace("player.LocalPlayer".into())
            }
            Value::ExternalDom if is_sensitive_member("external", key) => Value::Sensitive,
            // A method taken as a value keeps its name, so a later call with an explicit
            // receiver, such as `get(obj, "id")`, is the same method call.
            Value::ExternalDom if is_security_method(key) || is_instance_method(key) => {
                Value::Callable(format!("method.{key}"))
            }
            // `game.HttpService`: a service the content does not store.
            Value::ExternalDom if is_service_name(key) => Value::Object(key.into()),
            Value::ExternalDom => Value::ExternalDom,
            Value::Object(_) if is_security_method(key) || is_instance_method(key) => {
                Value::Callable(format!("method.{key}"))
            }
            Value::Object(_) => self.index(Value::ExternalDom, key),
            // Data read from outside or from an unresolved object stays that data, and so
            // does a component of an instance value such as `Vector3Value.Value.X`.
            data @ (Value::ExternalData | Value::ModelData(_) | Value::UnresolvedOrigin(_)) => data,
            Value::ModelDom(anchor) => match key {
                "Value" | "Name" | "ClassName" => Value::ModelData(anchor),
                _ if is_sensitive_member("external", key) => Value::Sensitive,
                _ if is_security_method(key) || is_instance_method(key) => {
                    Value::Callable(format!("method.{key}"))
                }
                _ => Value::ModelDom(anchor),
            },
            Value::Dom(instance) if key == "Parent" => self
                .doc
                .instances
                .get(instance)
                .and_then(|node| node.parent)
                .map(Value::Dom)
                .unwrap_or(Value::ExternalDom),
            Value::Dom(instance) => match self.dom_index.child(instance, key) {
                ChildLookup::Found(child) => Value::Dom(child),
                // Several children share the name: one of them, inside the content.
                ChildLookup::Ambiguous => Value::ModelDom(instance),
                ChildLookup::Missing if key == "Value" => self.read_value(instance),
                ChildLookup::Missing if key == "LocalPlayer" => {
                    Value::Namespace("player.LocalPlayer".into())
                }
                ChildLookup::Missing if key == "Name" || key == "ClassName" => {
                    match self.doc.instances.get(instance) {
                        Some(node) => {
                            let origin = Origin {
                                instance,
                                property: Some(key.into()),
                                attribute: None,
                            };
                            let stored = Value::String(
                                if key == "Name" {
                                    Text::from(node.name.clone())
                                } else {
                                    Text::from(node.class.clone())
                                },
                                Some(origin.clone()),
                            );
                            // `ClassName` cannot be written.
                            let written = key == "Name" && self.instance_writes().property(key);
                            self.written_read(
                                stored,
                                origin,
                                written,
                                self.dom_writes.get(&(instance, key.to_string())),
                            )
                        }
                        None => Value::Unknown,
                    }
                }
                ChildLookup::Missing => match self.read_property(instance, key) {
                    Value::Unknown if is_sensitive_member("instance", key) => Value::Sensitive,
                    Value::Unknown if is_security_method(key) || is_instance_method(key) => {
                        Value::Callable(format!("method.{key}"))
                    }
                    Value::Unknown if is_service_name(key) => Value::Object(key.into()),
                    Value::Unknown => Value::ExternalDom,
                    value => value,
                },
            },
            Value::Table(id) => self.table_index(id, &Value::String(Text::from(key), None)),
            Value::Namespace(namespace) => Value::Namespace(format!("{namespace}.{key}")),
            Value::Unknown if is_sensitive_identifier(key) => Value::Sensitive,
            _ => Value::Unknown,
        }
    }

    /// A key of a table, a string or an integer: the table's own value, or what its
    /// `__index` chain gives for a missing key. String and integer keys take this one
    /// path, so they follow `__index` tables and values alike.
    fn table_index(&mut self, id: usize, key: &Value) -> Value {
        let mut current = id;
        // Tables on the `__index` chain that unknown code may have changed.
        let mut escaped = Vec::new();
        // Every table the walk looked in: a later write to the key of any of them
        // changes what a deferred read gives.
        let mut visited = Vec::new();
        let mut found = Value::Unknown;
        // The first tables of the chain are followed exactly. Past that cap the chain is
        // still searched up to `max_depth` tables, and what is found there is a
        // candidate next to an unknown value.
        let limit = self.limits.max_depth.max(MAX_INDEX_CHAIN);
        let mut walked = 0;
        while walked < limit {
            walked += 1;
            let Some(table) = self.table(current) else {
                break;
            };
            visited.push(current);
            if let Some(value) = table.raw(key) {
                found = value.clone();
                if table.escaped {
                    escaped.push(current);
                }
                break;
            }
            if table.escaped {
                escaped.push(current);
            }
            if let Some(handler) = self.index_function(current) {
                // An `__index` function answers with what it returns.
                found = self
                    .functions
                    .get(handler)
                    .and_then(|function| function.returns.clone())
                    .unwrap_or(Value::Unknown);
                break;
            }
            match self.index_fallback(current) {
                Some(Value::Table(next)) => current = next,
                Some(other) => {
                    found = self.index_by_value(other, key.clone());
                    break;
                }
                None => {
                    found = Value::Nil;
                    break;
                }
            }
        }
        let mut result = if walked > MAX_INDEX_CHAIN {
            join([found, Value::Unknown])
        } else {
            found
        };
        for id in escaped {
            result = join([result.clone(), self.escaped_read(id, None)]);
        }
        self.captured_field(&visited, field_key(key), result)
    }

    /// A field of `_G` or `shared` that this script stored, or a value of the script
    /// environment read through `getfenv()`: a global for a name, a field of the
    /// environment table for any other key. String and integer keys are read alike.
    /// Other scripts may change all of them: that is a known limit.
    fn global_field(&mut self, namespace: &str, key: &Value) -> Option<Value> {
        let in_function = !self.function_stack.is_empty();
        // A write to the environment under a key the scanner cannot read may be this one.
        let changed = namespace == ENVIRONMENT && self.environment_changed;
        if namespace == ENVIRONMENT
            && let Value::String(name, _) = key
        {
            let slot = Slot::Global(name.to_string());
            let value = match self.scopes.first()?.vars.get(&slot) {
                Some(value) => value.clone(),
                // A function body may run after the script assigns the global.
                _ if in_function && self.facts.reassigned.contains_key(&slot) => Value::Nil,
                _ => return None,
            };
            return Some(self.captured_read(&slot, 0, value));
        }
        let id = self.global_table(namespace)?;
        let table = self.table(id)?;
        let stored = table.raw(key).cloned();
        let value = match (table.escaped, stored) {
            (true, stored) => self.escaped_read(id, stored),
            (false, Some(stored)) => stored,
            // Not stored yet: other scripts may set it, and a function body may run
            // after this script does.
            (false, None) if in_function || changed => Value::Unknown,
            (false, None) => return None,
        };
        let value = if changed {
            join([value, self.stray_read()])
        } else {
            value
        };
        Some(self.captured_field(&[id], field_key(key), value))
    }

    /// The table of `_G`, `shared`, or the keys of the script environment that are not
    /// names, in this script, made when it is first used.
    fn global_table(&mut self, namespace: &str) -> Option<usize> {
        if let Some(id) = self.global_tables.get(namespace) {
            return Some(*id);
        }
        let Value::Table(id) = self.new_table(ConstantTable::default()) else {
            return None;
        };
        // It belongs to the whole script, so a write in a branch or a function body
        // keeps the old value as a candidate.
        if let (Some(table), Some(scope)) = (self.tables.get_mut(id), self.scopes.first()) {
            table.home = scope.serial;
        }
        self.global_tables.insert(namespace.to_string(), id);
        Some(id)
    }

    /// A write into `_G`, `shared` or the script environment: the tables it reaches, and
    /// for the environment a global assignment. Other scripts can read globals, so the
    /// value escapes.
    fn global_store(
        &mut self,
        container: &Value,
        key: &Value,
        value: &Value,
        dependence: &Dependence<'_>,
    ) -> Vec<usize> {
        let namespaces: Vec<String> = container
            .candidates()
            .into_iter()
            .filter_map(|candidate| match candidate {
                Value::Namespace(namespace) if is_global_table(namespace) => {
                    Some(namespace.clone())
                }
                _ => None,
            })
            .collect();
        let mut tables = Vec::new();
        for namespace in &namespaces {
            if namespace == ENVIRONMENT {
                match key {
                    Value::String(name, _) => {
                        self.assign(Slot::Global(name.to_string()), value.clone(), dependence)
                    }
                    // An integer key is not a name: a field of the environment table.
                    Value::Number(number, _) if integer(*number).is_some() => {
                        if let Some(id) = self.global_table(namespace) {
                            tables.push(id);
                        }
                    }
                    _ => {
                        // Some global changed under a name the scanner cannot read.
                        self.environment_changed = true;
                        self.record_stray(value);
                    }
                }
            } else if let Some(id) = self.global_table(namespace) {
                tables.push(id);
            }
        }
        if !namespaces.is_empty() {
            self.escape(value);
        }
        tables
    }

    /// `GetAttributes()` of an object in the content: a table of its stored
    /// attributes, each with its origin. A missing key reads as an unresolved value of
    /// that object, because attributes can be set at runtime.
    fn attribute_table(&mut self, instance: usize) -> Value {
        const MAX_ATTRIBUTES_COPIED: usize = 4_096;
        let mut table = ConstantTable::default();
        if let Some(node) = self.doc.instances.get(instance) {
            // Past the cap the table holds only some of them, so it reads as changed.
            table.escaped = node.attributes.len() > MAX_ATTRIBUTES_COPIED;
            let writes = self.instance_writes();
            for (name, value) in node.attributes.iter().take(MAX_ATTRIBUTES_COPIED) {
                let origin = Origin {
                    instance,
                    property: None,
                    attribute: Some(name.clone()),
                };
                let value = self.written_read(
                    json_value(value, origin.clone()),
                    origin,
                    writes.attribute(name),
                    self.attribute_writes.get(&(instance, name.clone())),
                );
                table.fields.insert(name.clone(), value);
            }
        }
        table.fallback = Some(Box::new(Value::ModelData(instance)));
        self.new_table(table)
    }

    /// Closest ancestor of `instance` that matches.
    fn ancestor(
        &self,
        instance: usize,
        matches: impl Fn(&crate::model::Instance) -> bool,
    ) -> Option<usize> {
        let mut current = self.doc.instances.get(instance)?.parent;
        let mut guard = 0usize;
        while let Some(id) = current {
            guard += 1;
            if guard > self.doc.instances.len() {
                break;
            }
            let node = self.doc.instances.get(id)?;
            if matches(node) {
                return Some(id);
            }
            current = node.parent;
        }
        None
    }

    /// `.Value` of an object that has no child named `Value`. An `ObjectValue` points
    /// at another object in the content; any other object's value is an instance
    /// origin, unresolved when the property was not stored.
    fn read_value(&self, instance: usize) -> Value {
        if self
            .doc
            .instances
            .get(instance)
            .is_some_and(|node| node.class == "ObjectValue")
        {
            return Value::ModelDom(instance);
        }
        match self.read_property(instance, "Value") {
            Value::Unknown => {
                let origin = Origin {
                    instance,
                    property: Some("Value".into()),
                    attribute: None,
                };
                let written = self.dom_writes.get(&(instance, "Value".to_string()));
                join(
                    written
                        .into_iter()
                        .flatten()
                        .cloned()
                        .chain([Value::UnresolvedOrigin(origin)]),
                )
            }
            value => value,
        }
    }

    fn read_property(&self, instance: usize, key: &str) -> Value {
        let Some(node) = self.doc.instances.get(instance) else {
            return Value::Unknown;
        };
        let Some(value) = node.properties.get(key) else {
            return Value::Unknown;
        };
        let origin = Origin {
            instance,
            property: Some(key.into()),
            attribute: None,
        };
        let stored = json_value(value, origin.clone());
        self.written_read(
            stored,
            origin,
            self.instance_writes().property(key),
            self.dom_writes.get(&(instance, key.to_string())),
        )
    }

    /// Property and attribute writes of every script of the document, computed once.
    fn instance_writes(&self) -> &'a InstanceWrites {
        let (doc, limits) = (self.doc, self.limits);
        self.dom_index
            .instance_writes(|| instance_writes(doc, limits))
    }

    /// A stored property or attribute value that some script may change: the stored
    /// value, what this script wrote, and the value of an unresolved read of it.
    fn written_read(
        &self,
        stored: Value,
        origin: Origin,
        written: bool,
        values: Option<&Vec<Value>>,
    ) -> Value {
        if !written && values.is_none() {
            return stored;
        }
        join(
            std::iter::once(stored)
                .chain(values.into_iter().flatten().cloned())
                .chain([Value::UnresolvedOrigin(origin)]),
        )
    }

    // ----- operators ----------------------------------------------------------------

    fn unary(&mut self, op: &UnOp, value: Value) -> Value {
        if let Value::Union(values) = value {
            let results: Vec<Value> = values
                .into_iter()
                .map(|value| self.unary(op, value))
                .collect();
            return join(results);
        }
        match op {
            UnOp::Minus(_) => match coerce_number(&value) {
                Some((number, origin)) => Value::Number(-number, origin),
                None if self.is_sensitive(&value) => Value::Sensitive,
                None => derived_from(&[value]),
            },
            UnOp::Not(_) => match value.truthy() {
                Some(truth) => Value::Bool(!truth),
                None => Value::Unknown,
            },
            UnOp::Hash(_) => match &value {
                Value::String(text, origin) => Value::Number(text.len() as f64, origin.clone()),
                Value::Table(id) => match self.table(*id) {
                    Some(table)
                        if !table.escaped
                            && table.loose.is_empty()
                            && !self.captured_table_changes(*id) =>
                    {
                        Value::Number(table.items.len() as f64, None)
                    }
                    _ => Value::Unknown,
                },
                _ => Value::Unknown,
            },
            _ => Value::Unknown,
        }
    }

    fn binary(&mut self, op: Op, left: Value, right: Value) -> Value {
        if matches!(left, Value::Union(_)) || matches!(right, Value::Union(_)) {
            let lefts: Vec<Value> = match left {
                Value::Union(values) => values,
                value => vec![value],
            };
            let rights: Vec<Value> = match right {
                Value::Union(values) => values,
                value => vec![value],
            };
            let mut results = Vec::new();
            for left in &lefts {
                for right in &rights {
                    results.push(self.binary(op, left.clone(), right.clone()));
                    if results.len() >= MAX_CANDIDATES * MAX_CANDIDATES {
                        break;
                    }
                }
            }
            return join(results);
        }
        match op {
            Op::Concat => {
                if self.is_sensitive(&left) || self.is_sensitive(&right) {
                    return Value::Sensitive;
                }
                // Joining nil or a boolean raises an error, so the expression gives no
                // value; nil is the closest stand-in for that in a candidate set.
                if matches!(left, Value::Nil | Value::Bool(_))
                    || matches!(right, Value::Nil | Value::Bool(_))
                {
                    return Value::Nil;
                }
                match (value_as_string(&left), value_as_string(&right)) {
                    (Some((mut a, ao)), Some((b, bo))) => {
                        if a.len().saturating_add(b.len()) > self.limits.max_script_bytes
                            || !self.charge(a.len().saturating_add(b.len()))
                        {
                            self.mark_resolution_limit("constant folding output limit reached");
                            return Value::Unknown;
                        }
                        a.push_str(&b);
                        Value::String(Text::from(a), ao.or(bo))
                    }
                    (left_text, _) => {
                        let derived = derived_from(&[left.clone(), right]);
                        match (derived, left_text, left) {
                            (
                                derived @ (Value::ExternalData
                                | Value::ModelData(_)
                                | Value::UnresolvedOrigin(_)
                                | Value::Sensitive),
                                _,
                                _,
                            ) => derived,
                            (_, Some((prefix, None)), _) | (_, _, Value::Partial(prefix)) => {
                                Value::Partial(prefix.chars().take(4096).collect())
                            }
                            (derived, _, _) => derived,
                        }
                    }
                }
            }
            Op::Add | Op::Sub | Op::Mul | Op::Div | Op::FloorDiv | Op::Mod | Op::Pow => {
                if self.is_sensitive(&left) || self.is_sensitive(&right) {
                    return Value::Sensitive;
                }
                match (coerce_number(&left), coerce_number(&right)) {
                    (Some((a, ao)), Some((b, bo))) => match arithmetic(op, a, b) {
                        Some(number) => Value::Number(number, ao.or(bo)),
                        None => Value::Unknown,
                    },
                    // Scaling or shifting a range keeps its bounds, so a delay such as
                    // `60 * math.random(10, 20)` still has a lower bound.
                    _ => match (&left, &right, coerce_number(&left), coerce_number(&right)) {
                        (Value::Range(low, high), _, _, Some((n, _)))
                        | (_, Value::Range(low, high), Some((n, _)), _)
                            if matches!(op, Op::Add | Op::Mul) && n >= 0.0 =>
                        {
                            match (arithmetic(op, *low, n), arithmetic(op, *high, n)) {
                                (Some(low), Some(high)) => Value::Range(low, high),
                                _ => Value::Unknown,
                            }
                        }
                        _ => derived_from(&[left, right]),
                    },
                }
            }
            Op::Eq | Op::Ne => {
                let equal = match (&left, &right) {
                    (Value::Number(a, _), Value::Number(b, _)) => Some(a == b),
                    (Value::String(a, _), Value::String(b, _)) => Some(a == b),
                    (Value::Bool(a), Value::Bool(b)) => Some(a == b),
                    (Value::Nil, Value::Nil) => Some(true),
                    (Value::Nil, Value::Number(..) | Value::String(..) | Value::Bool(_))
                    | (Value::Number(..) | Value::String(..) | Value::Bool(_), Value::Nil) => {
                        Some(false)
                    }
                    _ => None,
                };
                match equal {
                    Some(equal) => Value::Bool(if op == Op::Eq { equal } else { !equal }),
                    None => Value::Unknown,
                }
            }
            Op::Lt | Op::Le | Op::Gt | Op::Ge => {
                let ordering = match (&left, &right) {
                    (Value::Number(a, _), Value::Number(b, _)) => a.partial_cmp(b),
                    (Value::String(a, _), Value::String(b, _)) => Some(a.cmp(b)),
                    _ => None,
                };
                match ordering {
                    Some(ordering) => Value::Bool(match op {
                        Op::Lt => ordering.is_lt(),
                        Op::Le => ordering.is_le(),
                        Op::Gt => ordering.is_gt(),
                        _ => ordering.is_ge(),
                    }),
                    None => Value::Unknown,
                }
            }
            _ => Value::Unknown,
        }
    }

    // ----- functions ----------------------------------------------------------------

    fn function_id(&mut self, body: &FunctionBody) -> usize {
        let key = body
            .parameters_parentheses()
            .tokens()
            .0
            .token()
            .start_position()
            .bytes();
        if let Some(id) = self.function_ids.get(&key) {
            return *id;
        }
        let id = self.functions.len();
        self.functions.push(FunctionInfo::default());
        self.function_ids.insert(key, id);
        id
    }

    /// An anonymous function where it is evaluated. Other code may call it. Its body is
    /// kept right away when it is small, so a call before the body is visited, such as
    /// an immediately invoked function or a `pcall` callback, can compute its result.
    fn anonymous_function(&mut self, body: &FunctionBody) -> usize {
        let id = self.function_id(body);
        let escapes = !self.facts.contained_functions.contains(&body_key(body));
        let function = &mut self.functions[id];
        function.escapes = escapes;
        if function.body.is_none() && !function.visited {
            let bytes = body_bytes(body);
            if bytes <= MAX_VALUE_REPLAY_BODY_BYTES {
                function.body_bytes = bytes;
                function.body = Some(Rc::new(body.clone()));
            }
        }
        id
    }

    fn mark_sink(&mut self, kind: u8) {
        for index in 0..self.function_stack.len() {
            let id = self.function_stack[index].id;
            if let Some(function) = self.functions.get_mut(id) {
                function.sinks |= kind;
            }
        }
    }

    fn call_function(&mut self, id: usize, args: Vec<Value>, report: bool, site: Site) -> Value {
        let Some((sinks, risky)) = self
            .functions
            .get(id)
            .map(|function| (function.sinks, function.risky))
        else {
            return Value::Unknown;
        };
        if report && sinks != 0 {
            // A function that calls a wrapper is itself a wrapper.
            self.mark_sink(sinks);
        }
        // A function with a risky action called under a gate, such as a wrapper without
        // arguments called only in `if game.PlaceId == id then`.
        if report
            && risky
            && self.gated_action.is_none()
            && let Some(gate) = self.current_gate()
        {
            self.gated_action = Some(gate);
        }
        // A value cut by the depth limit goes into a function that calls `require`.
        if sinks & SINK_REQUIRE != 0 && self.require_context.is_some_and(|context| context.cut) {
            self.mark_resolution_limit("analysis depth limit reached for a require target");
        }
        let Some(function) = self.functions.get(id) else {
            return Value::Unknown;
        };
        // Replays also run when only the value is needed, such as a constructor result
        // assigned to a local; the memo keeps findings from repeating. A table argument
        // is replayed for what the body does to it, such as `self.id = v`.
        let passes_table = args.iter().any(holds_table);
        // A body that reads captured state is judged where it is called.
        let replay_worthy = passes_table
            || function.reads_captures
            || args.iter().any(|value| self.interesting(value, 0));
        if !function.visited {
            // Called before its body was visited, such as an immediately invoked function
            // or a `pcall` callback: the body runs now, without findings, for what it
            // returns and changes, and a call that needs findings replays it once the
            // body was visited.
            let has_body = function.body.is_some();
            if replay_worthy
                && self.replay_site.is_none()
                && function.pending.len() < MAX_REPLAYS_PER_FUNCTION
            {
                self.functions[id].pending.push((args.clone(), site));
            }
            if has_body {
                self.silent += 1;
                let result = self.replay(id, args, site);
                self.silent -= 1;
                return result;
            }
            if passes_table {
                self.escape_all(&args);
            }
            return Value::Unknown;
        }
        if replay_worthy && (function.sinks != 0 || function.body.is_some()) {
            return self.replay(id, args, site);
        }
        if passes_table {
            // The body cannot be replayed, so it may have changed the tables.
            self.escape_all(&args);
        }
        let Some(function) = self.functions.get(id) else {
            return Value::Unknown;
        };
        if let Some(previous) = function.memo.get(&self.replay_key(&args)) {
            return previous.clone();
        }
        function.returns.clone().unwrap_or(Value::Unknown)
    }

    /// Re-run a local function body with the call-site arguments bound to its
    /// parameters, so a wrapper around `require` or an HTTP call is judged by what it
    /// receives. Findings are reported at the outermost call site.
    fn replay(&mut self, id: usize, args: Vec<Value>, site: Site) -> Value {
        let key = self.replay_key(&args);
        // A silent run neither uses nor fills the memo, so the replay with findings
        // still runs. A body that reads captured state may give something else each time.
        let memoized =
            |analyzer: &Self| analyzer.silent == 0 && !analyzer.functions[id].reads_captures;
        if memoized(self)
            && let Some(previous) = self.functions[id].memo.get(&key)
        {
            return previous.clone();
        }
        let body = self.functions[id].body.clone();
        let over_limit = self.replay_depth >= MAX_REPLAY_DEPTH
            || self.functions[id].replay_count >= MAX_REPLAYS_PER_FUNCTION
            || self.replays >= MAX_REPLAYS_PER_SCRIPT
            || self.functions[id].body_bytes > MAX_REPLAY_BODY_BYTES;
        let Some(body) = body.filter(|_| !over_limit) else {
            let location = site.location();
            if self.silent == 0
                && self
                    .summarized_sites
                    .insert((id, location.line, location.column))
            {
                self.summarized_call(id, &args, site);
            }
            self.escape_all(&args);
            return self.functions[id].returns.clone().unwrap_or(Value::Unknown);
        };
        self.replays += 1;
        self.functions[id].replay_count += 1;
        let outer_site = self.replay_site;
        if outer_site.is_none() {
            self.replay_site = Some(site);
        }
        self.replay_depth += 1;
        self.pending_params = Some(args);
        let scopes = self.scopes.len();
        let frames = self.function_stack.len();
        Visit::visit(&*body, self);
        self.scopes.truncate(scopes);
        self.function_stack.truncate(frames);
        self.pending_params = None;
        self.replay_depth -= 1;
        self.replay_site = outer_site;
        let result = self.replay_returns.take().unwrap_or(Value::Unknown);
        if memoized(self) {
            self.functions[id].memo.insert(key, result.clone());
        }
        result
    }

    /// Conservative check used when a call cannot be replayed within the limits.
    fn summarized_call(&mut self, id: usize, args: &[Value], site: Site) {
        let sinks = self.functions[id].sinks;
        // Only a `require` that may load something other than a local module can
        // receive the value; `require(script.Parent.Util)` in a callback cannot.
        if sinks & SINK_REQUIRE_INPUT != 0
            && let Some(literal) = args
                .iter()
                .find_map(|value| self.asset_shaped_within(value, 0))
        {
            self.push(
                "BG001",
                Severity::High,
                Confidence::Medium,
                site,
                "an asset ID is passed to a function that calls require",
                &format!(" [asset id literal: {literal}]"),
            );
        }
        if sinks & SINK_HTTP != 0
            && args.iter().any(|value| {
                value.candidates().into_iter().any(|candidate| {
                    matches!(candidate, Value::String(url, _) if classify_url(url) == Some(Endpoint::Webhook))
                })
            })
        {
            self.push(
                "BG008",
                Severity::High,
                Confidence::Medium,
                site,
                "a webhook URL is passed to a function that sends HTTP requests",
                "",
            );
        }
    }

    /// An asset-ID-shaped value, also inside a table argument: three levels deep and 64
    /// values per table.
    fn asset_shaped_within(&self, value: &Value, depth: usize) -> Option<String> {
        if let Some(literal) = asset_shaped(value) {
            return Some(literal);
        }
        if depth >= 3 {
            return None;
        }
        tables_in(value).into_iter().find_map(|id| {
            self.table(id)?
                .values()
                .take(64)
                .find_map(|value| self.asset_shaped_within(value, depth + 1))
        })
    }

    fn replay_key(&self, args: &[Value]) -> String {
        let mut key = String::new();
        for value in args.iter().take(16) {
            self.describe(value, 0, &mut key);
            key.push('|');
            if key.len() > 1024 {
                break;
            }
        }
        // The description stops at a small depth, so a table argument changed further
        // down would look the same: any table change since makes a new key.
        if args.iter().any(holds_table) {
            key.push_str(&format!("#{}", self.mutation_epoch));
        }
        key
    }

    fn describe(&self, value: &Value, depth: usize, out: &mut String) {
        if out.len() > 1024 || depth > 2 {
            out.push('~');
            return;
        }
        match value {
            Value::Nil => out.push_str("nil"),
            Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Value::Number(number, origin) => {
                out.push_str(&format_number(*number));
                if let Some(origin) = origin {
                    out.push_str(&format!("@{}", origin.instance));
                }
            }
            Value::String(text, origin) => {
                if text.len() > 96 {
                    out.push_str(text.digest());
                } else {
                    out.push_str(&format!("{text:?}"));
                }
                if let Some(origin) = origin {
                    out.push_str(&format!("@{}", origin.instance));
                }
            }
            Value::Table(id) => {
                out.push_str(&format!("t{id}{{"));
                if let Some(table) = self.table(*id) {
                    if table.sensitive {
                        out.push('!');
                    }
                    if table.escaped {
                        out.push('?');
                    }
                    for value in table.values().take(8) {
                        self.describe(value, depth + 1, out);
                        out.push(',');
                    }
                }
                out.push('}');
            }
            Value::Union(values) | Value::Tuple(values) => {
                out.push('(');
                for value in values {
                    self.describe(value, depth + 1, out);
                    out.push(',');
                }
                out.push(')');
            }
            other => out.push_str(&format!("{other:?}").chars().take(64).collect::<String>()),
        }
    }

    /// Arguments that make a replay worthwhile: asset-ID-shaped values, URLs, sensitive
    /// data, values read from the DOM and dangerous functions.
    fn interesting(&self, value: &Value, depth: usize) -> bool {
        if depth > 2 {
            return false;
        }
        match value {
            Value::Number(number, origin) => origin.is_some() || is_asset_number(*number),
            Value::String(text, origin) => {
                origin.is_some()
                    || digit_run(text, ASSET_ID_DIGITS).is_some()
                    || starts_with_http(text)
            }
            Value::IdLike(_)
            | Value::ExternalData
            | Value::ModelData(_)
            | Value::UnresolvedOrigin(_)
            | Value::Sensitive
            | Value::Remote
            | Value::ComputedGlobal => true,
            Value::Partial(text) => {
                digit_run(text, ASSET_ID_DIGITS).is_some() || starts_with_http(text)
            }
            Value::Callable(name) => is_dangerous_callable(name) || name.starts_with("method."),
            // Instances and services: a helper that reads `.Value`, an attribute or a
            // service method from its parameter is judged with them.
            Value::Dom(_)
            | Value::ModelDom(_)
            | Value::ExternalDom
            | Value::Object(_)
            | Value::InstanceList(_) => true,
            Value::Namespace(namespace) => {
                is_instance_namespace(namespace) || is_player_namespace(namespace)
            }
            Value::Table(id) => self.table(*id).is_some_and(|table| {
                table.sensitive
                    || self.call_handler(*id).is_some()
                    || table
                        .values()
                        .take(32)
                        .any(|value| self.interesting(value, depth + 1))
            }),
            Value::Union(values) | Value::Tuple(values) => values
                .iter()
                .any(|value| self.interesting(value, depth + 1)),
            _ => false,
        }
    }

    // ----- calls --------------------------------------------------------------------

    fn invoke(
        &mut self,
        callable: Value,
        args: &FunctionArgs,
        depth: usize,
        report: bool,
        site: Site,
    ) -> Value {
        let cuts = self.truncations;
        let values = self.eval_args(args, depth);
        if report {
            for value in &values {
                self.note_value(value, site);
            }
        }
        let cut = self.truncations > cuts;
        let context = self.require_context_for(&callable, &values, args, cut);
        let outer = std::mem::replace(&mut self.require_context, context);
        let result = match callable {
            Value::Union(callables) => {
                let results: Vec<Value> = callables
                    .into_iter()
                    .map(|callable| {
                        self.invoke_value(callable, values.clone(), Some(args), report, site)
                    })
                    .collect();
                join(results)
            }
            callable => self.invoke_value(callable, values, Some(args), report, site),
        };
        self.require_context = outer;
        result
    }

    /// Context for a `require` that this call reaches: called directly, or through a
    /// wrapper such as `pcall(require, id)`. A cut found here also holds for code the
    /// call replays.
    fn require_context_for(
        &self,
        callable: &Value,
        values: &[Value],
        args: &FunctionArgs,
        cut: bool,
    ) -> Option<RequireContext> {
        let cut = cut || self.require_context.is_some_and(|context| context.cut);
        let target = match callable {
            Value::Callable(name) if name == "require" => Some(0),
            Value::Callable(name) if is_dangerous_wrapper(name) => {
                let (callback, forwarded) = wrapper_positions(name, values.len());
                matches!(values.get(callback), Some(Value::Callable(name)) if name == "require")
                    .then_some(forwarded)
            }
            _ => None,
        };
        let constant = target.is_some_and(|index| match args {
            FunctionArgs::String(_) => index == 0,
            FunctionArgs::Parentheses { arguments, .. } => arguments
                .iter()
                .nth(index)
                .is_some_and(|expression| self.constant_target(expression)),
            _ => false,
        });
        (target.is_some() || cut).then_some(RequireContext { constant, cut })
    }

    /// Whether a `require` target is built only from literals and from locals that are
    /// assigned once, from such expressions. Nothing else can make a trusted ID go away.
    /// Each name is the one local it refers to, so another variable with the same name
    /// changes nothing. A variable read inside a function from an enclosing scope is
    /// captured and never counts, because the function may run later.
    fn constant_target(&self, expression: &Expression) -> bool {
        let body = self.function_stack.last().map_or(0, |frame| frame.scope);
        constant_structure(expression).is_some_and(|names| {
            names.iter().all(|name| {
                let slot = self.slot(name);
                self.facts.constant_slots.contains(&slot)
                    && self.slot_scope(&slot).is_some_and(|index| index >= body)
            })
        })
    }

    fn invoke_value(
        &mut self,
        callable: Value,
        values: Vec<Value>,
        args: Option<&FunctionArgs>,
        report: bool,
        site: Site,
    ) -> Value {
        match callable {
            Value::Callable(name) => self.call_builtin(&name, values, args, report, site),
            Value::Function(id) => {
                if report {
                    self.report_escaped_values(&values, site);
                }
                self.call_function(id, values, report, site)
            }
            Value::Table(id) if self.call_handler(id).is_some() => {
                let function = self.call_handler(id).unwrap_or(0);
                if report {
                    self.report_escaped_values(&values, site);
                }
                let mut arguments = vec![Value::Table(id)];
                arguments.extend(values);
                self.call_function(function, arguments, report, site)
            }
            // Calling a `gmatch` iterator directly returns the first match.
            Value::Matches(items) => items.into_iter().next().unwrap_or(Value::Nil),
            Value::ComputedGlobal => {
                if report {
                    self.report_computed_global(&values, site);
                    self.report_escaped_values(&values, site);
                }
                self.escape_all(&values);
                Value::Unknown
            }
            _ => {
                if report {
                    self.report_escaped_values(&values, site);
                }
                // An unknown function may change any table it receives.
                self.escape_all(&values);
                values
                    .iter()
                    .find_map(asset_shaped)
                    .map(Value::IdLike)
                    .unwrap_or(Value::Unknown)
            }
        }
    }

    fn call_builtin(
        &mut self,
        name: &str,
        values: Vec<Value>,
        args: Option<&FunctionArgs>,
        report: bool,
        site: Site,
    ) -> Value {
        if let Some(result) = self.invoke_dangerous(name, &values, args, report, site) {
            return result;
        }
        if is_dangerous_wrapper(name) {
            let (callback_index, forwarded_index) = wrapper_positions(name, values.len());
            let returns_callable = matches!(name, "coroutine.wrap" | "coroutine.create");
            let callback = values.get(callback_index).cloned().unwrap_or(Value::Nil);
            if returns_callable {
                if report {
                    self.report_callable_escape(&callback, site);
                }
                return callback;
            }
            let forwarded: Vec<Value> = values.get(forwarded_index..).unwrap_or_default().to_vec();
            let mut handled = false;
            let callbacks: Vec<Value> = callback.candidates().into_iter().cloned().collect();
            // A long delay gates the callback, whether it runs now or is visited later.
            let delayed = (report && matches!(name, "delay" | "task.delay"))
                .then(|| values.first().and_then(delay_seconds))
                .flatten()
                .is_some_and(|seconds| seconds >= 60.0);
            let outer_gate = self.call_gate;
            if delayed {
                self.call_gate = Some(site);
                for candidate in &callbacks {
                    if let Value::Function(id) = candidate
                        && let Some(function) = self.functions.get_mut(*id)
                    {
                        function.gate.get_or_insert(site);
                    }
                }
            }
            let mut results = Vec::new();
            // What a failed call gives instead: an error message from a library function,
            // anything `error` received from a function of the script, and for `xpcall`
            // whatever the handler returns.
            let mut failures = Vec::new();
            for candidate in callbacks {
                failures.push(match &candidate {
                    Value::Callable(_) if name != "xpcall" => {
                        Value::String("FAKE error".into(), None)
                    }
                    _ => Value::Unknown,
                });
                match candidate {
                    Value::Callable(dangerous) if is_dangerous_callable(&dangerous) => {
                        handled = true;
                        let result =
                            self.invoke_dangerous(&dangerous, &forwarded, args, report, site);
                        results.push(result.unwrap_or(Value::Unknown));
                    }
                    Value::Callable(other) if !is_dangerous_wrapper(&other) => {
                        handled = true;
                        let result =
                            self.call_builtin(&other, forwarded.clone(), args, report, site);
                        results.push(result.single());
                    }
                    callable @ (Value::Function(_) | Value::Table(_)) => {
                        handled = true;
                        let result =
                            self.invoke_value(callable, forwarded.clone(), args, report, site);
                        results.push(result.single());
                    }
                    _ => results.push(Value::Unknown),
                }
            }
            self.call_gate = outer_gate;
            if !handled {
                if report {
                    self.report_escaped_values(&values, site);
                }
                self.escape_all(&forwarded);
            }
            return match name {
                // A status, then what the callback returned, or an error value when it
                // failed.
                "pcall" | "xpcall" | "coroutine.resume" => {
                    results.push(if failures.is_empty() {
                        Value::Unknown
                    } else {
                        join(failures)
                    });
                    Value::Tuple(vec![
                        join([Value::Bool(true), Value::Bool(false)]),
                        join(results),
                    ])
                }
                _ => Value::Unknown,
            };
        }
        if report {
            self.report_escaped_values(&values, site);
        }
        if let Some(method) = name.strip_prefix("method.") {
            // A method taken as a value and called with its receiver first, such as
            // `obj.FindFirstChild(obj, "x")`, is the method call on that receiver.
            return match values.split_first() {
                Some((receiver, rest)) if is_receiver_shaped(receiver) => match receiver.clone() {
                    Value::Union(receivers) => {
                        let results: Vec<Value> = receivers
                            .into_iter()
                            .map(|receiver| {
                                self.method_call(receiver, method, rest, args, report, site)
                            })
                            .collect();
                        join(results)
                    }
                    receiver => self.method_call(receiver, method, rest, args, report, site),
                },
                _ => self.member_call(None, method, &values, args, report, site),
            };
        }
        if let Some(method) = name.strip_prefix("string.") {
            return match method {
                "char" => self.string_char(&values),
                _ => self.string_method(method, &values, args, report, site),
            };
        }
        if let Some(function) = name.strip_prefix("math.") {
            return self.math_call(function, &values);
        }
        if let Some(function) = name.strip_prefix("bit32.") {
            return bit32_call(function, &values);
        }
        let first = values.first().cloned().unwrap_or(Value::Nil);
        match name {
            "rawget" => {
                let key = values.get(1).cloned().unwrap_or(Value::Nil);
                match first {
                    Value::Namespace(namespace) if is_global_table(&namespace) => {
                        self.index_by_value(Value::Namespace(namespace), key)
                    }
                    Value::Table(id) => self.index_by_value(Value::Table(id), key),
                    _ => Value::Unknown,
                }
            }
            "tonumber" => {
                let base = values.get(1).and_then(|value| match value {
                    Value::Number(number, _) => integer(*number).map(|n| n as u32),
                    _ => None,
                });
                self.fold_tonumber(first, base)
            }
            "tostring" => match &first {
                // `__tostring` runs when the table is converted.
                Value::Table(id) => match self.meta_field(*id, "__tostring") {
                    Some(Value::Function(handler)) => {
                        self.call_function(handler, vec![first.clone()], true, site)
                    }
                    _ => self.fold_tostring(first),
                },
                _ => self.fold_tostring(first),
            },
            "select" => match first {
                Value::String(text, _) if &*text == "#" => {
                    Value::Number((values.len() - 1) as f64, None)
                }
                Value::Number(number, _) => match integer(number) {
                    Some(n) if n >= 1 => {
                        Value::Tuple(values.get(n as usize..).unwrap_or_default().to_vec())
                    }
                    Some(n) if n < 0 => {
                        let rest = values.len() as i64 - 1;
                        let start = (rest + n).max(0) as usize + 1;
                        Value::Tuple(values.get(start..).unwrap_or_default().to_vec())
                    }
                    Some(_) => Value::Unknown,
                    None => join(values.iter().skip(1).cloned()),
                },
                // A position the scanner cannot fold: one of the arguments.
                _ => join(values.iter().skip(1).cloned()),
            },
            "table.unpack" => {
                if let Value::InstanceList(element) = first {
                    return Value::Tuple(vec![*element]);
                }
                let Value::Table(id) = first else {
                    return Value::Unknown;
                };
                let Some(table) = self.table(id) else {
                    return Value::Unknown;
                };
                let bound = |index: usize, default: i64| match values.get(index) {
                    None | Some(Value::Nil) => Some(default),
                    Some(value) => integer_value(value),
                };
                let (Some(start), Some(end)) = (bound(1, 1), bound(2, table.items.len() as i64))
                else {
                    // A range the scanner cannot fold: some of the items.
                    return self.index_unknown(Value::Table(id));
                };
                let start = start.max(1);
                if end.saturating_sub(start) > MAX_CALL_ARGUMENTS as i64 {
                    return self.index_unknown(Value::Table(id));
                }
                let escaped =
                    table.escaped || !table.loose.is_empty() || self.captured_table_changes(id);
                let items: Vec<Value> = (start..=end)
                    .map(|key| table.number(key).cloned().unwrap_or(Value::Nil))
                    .collect();
                if escaped {
                    Value::Tuple(
                        items
                            .into_iter()
                            .map(|value| self.escaped_read(id, Some(value)))
                            .collect(),
                    )
                } else {
                    Value::Tuple(items)
                }
            }
            "table.pack" => {
                let mut table = ConstantTable::default();
                let count = values.len();
                for value in values.into_iter().take(MAX_TABLE_ENTRIES) {
                    table.sensitive |= self.is_sensitive(&value);
                    table.items.push(value);
                }
                table
                    .fields
                    .insert("n".into(), Value::Number(count as f64, None));
                self.new_table(table)
            }
            "table.concat" => self.table_concat(&values),
            "table.insert" => {
                self.table_insert(&values);
                Value::Nil
            }
            "table.remove" => self.table_remove(&values),
            "table.clear" => {
                self.mutation_epoch += 1;
                for id in tables_in(&first) {
                    self.note_table_change(id);
                    let (conditional, _) = self.table_write_context(id, None);
                    if conditional {
                        self.escape(&Value::Table(id));
                    } else if let Some(table) = self.tables.get_mut(id) {
                        table.fields.clear();
                        table.items.clear();
                        table.numbered.clear();
                        table.loose.clear();
                    }
                }
                Value::Nil
            }
            // Reordering and moving cannot be followed, so the contents become unknown
            // while their values stay candidates.
            "table.sort" => {
                self.escape(&first);
                Value::Nil
            }
            "table.move" => self.table_move(&values),
            "table.freeze" => first,
            "table.clone" => match first {
                Value::Table(id) => match self.table(id).cloned() {
                    Some(table) => self.new_table(table),
                    None => Value::Unknown,
                },
                _ => Value::Unknown,
            },
            "rawset" => {
                let key = values.get(1).cloned().unwrap_or(Value::Nil);
                let value = values.get(2).cloned().unwrap_or(Value::Nil);
                let several = first.candidates().len() > 1;
                let mut targets = tables_in(&first);
                for id in self.global_store(&first, &key, &value, &Dependence::Always) {
                    if !targets.contains(&id) {
                        targets.push(id);
                    }
                }
                for id in targets {
                    let (conditional, deferred) = self.table_write_context(id, None);
                    let value = if deferred {
                        self.deferred_value(&value)
                    } else {
                        value.clone()
                    };
                    self.write_table(id, &key, value, conditional || several);
                }
                if may_hold_unknown_table(&first) {
                    self.record_stray(&value);
                } else if tables_in(&first).is_empty() {
                    self.escape(&value);
                }
                first
            }
            "assert" => Value::Tuple(values),
            // `next(t)` gives some key and value of `t`.
            "next" => match first {
                Value::InstanceList(element) => Value::Tuple(vec![Value::Unknown, *element]),
                Value::Table(id) => {
                    let value = self.index_unknown(Value::Table(id));
                    Value::Tuple(vec![Value::Unknown, value])
                }
                _ => Value::Unknown,
            },
            // Pure globals: they read their arguments and change no table. `error` is not
            // one: `pcall` hands the error value to the caller.
            "print" | "warn" | "type" | "typeof" | "pairs" | "ipairs" | "rawequal" | "rawlen"
            | "tick" | "time" | "table.find" | "table.isfrozen" | "table.maxn" => Value::Unknown,
            "table.create" => self.table_create(&values),
            "utf8.char" => {
                let mut output = String::new();
                for value in &values {
                    let Some(code) = integer_value(value)
                        .and_then(|n| u32::try_from(n).ok())
                        .and_then(char::from_u32)
                    else {
                        return derived_from(&values);
                    };
                    output.push(code);
                }
                Value::String(Text::from(output), None)
            }
            "setmetatable" => {
                // A metatable on `_G` or `shared` changes what every global lookup
                // returns, like `setfenv`.
                if report
                    && matches!(&first, Value::Namespace(namespace) if is_global_table(namespace))
                {
                    self.mark_sink(SINK_CODE);
                    self.push(
                        "BG004",
                        Severity::High,
                        Confidence::High,
                        site,
                        "script changes the metatable of a global environment",
                        "",
                    );
                    return first;
                }
                let result = match first {
                    Value::Table(id) => Value::Table(id),
                    _ => self.new_table(ConstantTable::default()),
                };
                let Value::Table(id) = result else {
                    return result;
                };
                let (metatable, fallback, redirects_writes) = match values.get(1) {
                    Some(Value::Table(meta_id)) => match self.table(*meta_id) {
                        Some(meta) => (
                            Some(*meta_id),
                            None,
                            // A `__newindex` table sends writes somewhere the scanner
                            // does not follow; a function is called at each write.
                            meta.escaped
                                || meta
                                    .fields
                                    .get("__newindex")
                                    .is_some_and(|handler| !matches!(handler, Value::Function(_))),
                        ),
                        None => (None, Some(Box::new(Value::Unknown)), true),
                    },
                    Some(Value::Nil) | None => (None, None, false),
                    // An unknown metatable answers missing keys with unknown values, and
                    // its metamethods receive the table, so they may change it.
                    Some(_) => (None, Some(Box::new(Value::Unknown)), true),
                };
                self.mutation_epoch += 1;
                self.note_table_change(id);
                if let Some(table) = self.tables.get_mut(id) {
                    table.metatable = metatable;
                    table.fallback = fallback;
                }
                if redirects_writes {
                    self.escape(&result);
                }
                result
            }
            "getmetatable" => match first {
                Value::Table(id) => match self.table(id).and_then(|table| table.metatable) {
                    Some(meta) => self
                        .table(meta)
                        .and_then(|table| table.fields.get("__metatable").cloned())
                        .unwrap_or(Value::Table(meta)),
                    None if self.table(id).is_some_and(|table| table.fallback.is_some()) => {
                        Value::Unknown
                    }
                    None => Value::Nil,
                },
                // The string metatable: its `__index` is the string library.
                Value::String(..) => {
                    let mut table = ConstantTable::default();
                    table
                        .fields
                        .insert("__index".into(), Value::Namespace("string".into()));
                    self.new_table(table)
                }
                _ => Value::Unknown,
            },
            "task.wait" => {
                if report {
                    self.delay_gate(Some(&first), site);
                }
                Value::Unknown
            }
            _ => {
                // A library function the scanner does not model may change a table.
                self.escape_all(&values);
                Value::Unknown
            }
        }
    }

    /// `table.create(n, v)`: `n` copies of `v`, stored up to [`MAX_CALL_ARGUMENTS`]. A
    /// longer or uncounted table reads as changed, with `v` as a candidate, so its fill
    /// value and taint are never lost.
    fn table_create(&mut self, values: &[Value]) -> Value {
        let mut table = ConstantTable::default();
        let fill = values.get(1).cloned().unwrap_or(Value::Nil);
        if !matches!(fill, Value::Nil) {
            table.sensitive = self.is_sensitive(&fill);
            let count = values.first().and_then(integer_value);
            let stored = count.map_or(0, |count| count.clamp(0, MAX_CALL_ARGUMENTS as i64));
            for _ in 0..stored {
                table.items.push(fill.clone());
            }
            if count.is_none_or(|count| count > stored) {
                table.loose.push(fill.clone());
                table.escaped = true;
            }
        }
        self.new_table(table)
    }

    /// `table.move(a1, f, e, t, a2)`: a known range of a known table copied into a known
    /// table is followed exactly. Anything else leaves the destination changed, with the
    /// values of the source as candidates and its taint.
    fn table_move(&mut self, values: &[Value]) -> Value {
        self.mutation_epoch += 1;
        let source = values.first().cloned().unwrap_or(Value::Nil);
        let target = values.get(4).cloned().unwrap_or_else(|| source.clone());
        let numbers: Vec<Option<i64>> = (1..4)
            .map(|index| values.get(index).and_then(integer_value))
            .collect();
        let sources = tables_in(&source);
        let targets = tables_in(&target);
        if let ([from], [to], [Some(first), Some(last), Some(at)]) =
            (sources.as_slice(), targets.as_slice(), numbers.as_slice())
            && source.candidates().len() == 1
            && target.candidates().len() == 1
            && last.saturating_sub(*first) < MAX_CALL_ARGUMENTS as i64
        {
            // Read the whole range first, so an overlapping move copies the old values.
            let moved: Vec<Value> = (*first..=*last)
                .map(|key| self.index_number(Value::Table(*from), key))
                .collect();
            let (conditional, _) = self.table_write_context(*to, None);
            for (offset, value) in moved.into_iter().enumerate() {
                let key = Value::Number((*at + offset as i64) as f64, None);
                self.write_table(*to, &key, value, conditional);
            }
            return target;
        }
        let carried: Vec<Value> = sources
            .iter()
            .filter_map(|id| self.table(*id))
            .flat_map(|table| table.values().take(256).cloned().collect::<Vec<_>>())
            .filter(|value| self.interesting(value, 1))
            .take(MAX_CANDIDATES)
            .collect();
        let sensitive = self.is_sensitive(&source);
        for id in &targets {
            if let Some(table) = self.tables.get_mut(*id) {
                table.sensitive |= sensitive;
                for value in &carried {
                    if table.loose.len() < MAX_CANDIDATES {
                        table.loose.push(value.clone());
                    }
                }
            }
        }
        self.escape(&target);
        if may_hold_unknown_table(&target) {
            self.record_stray(&join(carried));
        }
        target
    }

    /// `table.insert(t, v)` and `table.insert(t, position, v)`. Inserting where the code
    /// may not run, or at a position the scanner cannot fold, keeps the value as a
    /// candidate and leaves the table changed by unknown code.
    fn table_insert(&mut self, values: &[Value]) {
        self.mutation_epoch += 1;
        let target = values.first().cloned().unwrap_or(Value::Nil);
        let value = values.last().cloned().unwrap_or(Value::Nil);
        let position = match values.len() {
            2 => None,
            3 => Some(values.get(1).and_then(integer_value)),
            _ => Some(None),
        };
        let tables = tables_in(&target);
        let several = tables.len() > 1 || target.candidates().len() > 1;
        if may_hold_unknown_table(&target) {
            self.record_stray(&value);
        }
        if tables.is_empty() {
            self.escape(&value);
            return;
        }
        for id in tables {
            self.note_table_change(id);
            let (conditional, deferred) = self.table_write_context(id, None);
            let value = if deferred {
                self.deferred_value(&value)
            } else {
                value.clone()
            };
            let sensitive = self.is_sensitive(&value);
            let Some(table) = self.tables.get_mut(id) else {
                continue;
            };
            table.sensitive |= sensitive;
            let exact = !conditional
                && !several
                && !table.escaped
                && table.loose.is_empty()
                && table.entries() < MAX_TABLE_ENTRIES;
            match position {
                None if exact => table.items.push(value),
                Some(Some(position))
                    if exact
                        && position >= 1
                        && position as u64 <= table.items.len() as u64 + 1 =>
                {
                    table.items.insert((position - 1) as usize, value);
                }
                _ => {
                    if table.loose.len() < MAX_CANDIDATES {
                        table.loose.push(value);
                    }
                    self.escape(&Value::Table(id));
                }
            }
        }
    }

    /// `table.remove(t)` and `table.remove(t, position)`.
    fn table_remove(&mut self, values: &[Value]) -> Value {
        self.mutation_epoch += 1;
        let target = values.first().cloned().unwrap_or(Value::Nil);
        // An element of a list of instances, such as `GetChildren()`.
        if let Value::InstanceList(element) = target {
            return *element;
        }
        let tables = tables_in(&target);
        let several = tables.len() > 1 || target.candidates().len() > 1;
        let mut removed = Vec::new();
        for id in tables {
            self.note_table_change(id);
            let (conditional, _) = self.table_write_context(id, None);
            let Some(table) = self.tables.get_mut(id) else {
                continue;
            };
            let position = match values.get(1) {
                None => Some(table.items.len() as i64),
                Some(value) => integer_value(value),
            };
            let exact = !conditional && !several && !table.escaped && table.loose.is_empty();
            match position {
                Some(position)
                    if exact && position >= 1 && position as u64 <= table.items.len() as u64 =>
                {
                    removed.push(table.items.remove((position - 1) as usize));
                }
                Some(_) if exact && table.items.is_empty() => removed.push(Value::Nil),
                _ => {
                    removed.push(Value::Unknown);
                    self.escape(&Value::Table(id));
                }
            }
        }
        if removed.is_empty() {
            Value::Unknown
        } else {
            join(removed)
        }
    }

    fn invoke_dangerous(
        &mut self,
        name: &str,
        values: &[Value],
        args: Option<&FunctionArgs>,
        report: bool,
        site: Site,
    ) -> Option<Value> {
        match name {
            "require" => {
                if report {
                    let target = values.first().cloned().unwrap_or(Value::Nil);
                    self.mark_sink(if self.local_modules_only(&target) {
                        SINK_REQUIRE
                    } else {
                        SINK_REQUIRE | SINK_REQUIRE_INPUT
                    });
                    self.report_require(&target, site, args);
                }
                Some(Value::Unknown)
            }
            "loadstring" => {
                if report {
                    self.mark_sink(SINK_CODE);
                    let suffix = match values.first() {
                        Some(Value::String(payload, _)) => {
                            let hash = sha256(payload.as_bytes());
                            format!(" [payload sha256: {}]", &hash[..12])
                        }
                        _ => String::new(),
                    };
                    self.push(
                        "BG003",
                        Severity::High,
                        Confidence::High,
                        site,
                        "code is built and executed at runtime",
                        &suffix,
                    );
                }
                Some(Value::Unknown)
            }
            "getfenv" | "setfenv" => {
                if report {
                    self.mark_sink(SINK_CODE);
                    // `getfenv().it`: only a name that is not a builtin is read, such as
                    // a test global a runner injected. A test that captures output
                    // saves `print` or `warn`, swaps in a local function and puts the
                    // saved value back. Any other use stays high.
                    let known = match (name, site.end) {
                        ("getfenv", Some(end)) => self.environment_reads.get(&end.bytes()),
                        _ => None,
                    };
                    let low = match known {
                        Some(EnvironmentUse::Read(name)) => Some((
                            "script reads a name that is not a Luau or Roblox global from its environment",
                            name,
                        )),
                        Some(EnvironmentUse::Save(name)) => Some((
                            "script saves an output function from an environment to put it back",
                            name,
                        )),
                        Some(EnvironmentUse::Restore(name)) => Some((
                            "script puts back an output function it saved from an environment",
                            name,
                        )),
                        Some(EnvironmentUse::Replace(name)) => Some((
                            "script replaces an output function in an environment with a local function",
                            name,
                        )),
                        _ => None,
                    }
                    .map(|(message, name)| (message, format!(" [name: {name}]")));
                    match low {
                        Some((message, suffix)) => self.push(
                            "BG004",
                            Severity::Low,
                            Confidence::High,
                            site,
                            message,
                            &suffix,
                        ),
                        None => self.push(
                            "BG004",
                            Severity::High,
                            Confidence::High,
                            site,
                            "script accesses or changes a runtime environment",
                            "",
                        ),
                    }
                }
                Some(if name == "getfenv" {
                    Value::Namespace(ENVIRONMENT.into())
                } else {
                    Value::Unknown
                })
            }
            _ => None,
        }
    }

    fn report_computed_global(&mut self, values: &[Value], site: Site) {
        self.mark_sink(SINK_OTHER);
        self.push(
            "BG004",
            Severity::Medium,
            Confidence::Medium,
            site,
            "a global function is called by a computed name",
            "",
        );
        if let Some(literal) = values.first().and_then(asset_shaped) {
            self.mark_sink(SINK_REQUIRE | SINK_REQUIRE_INPUT);
            self.push(
                "BG001",
                Severity::High,
                Confidence::Medium,
                site,
                "a global called by a computed name receives a numeric asset ID",
                &format!(" [asset id literal: {literal}]"),
            );
        }
    }

    fn report_escaped_values(&mut self, values: &[Value], site: Site) {
        for value in values {
            self.report_callable_escape(value, site);
        }
    }

    fn report_callable_escape(&mut self, value: &Value, site: Site) {
        let mut reported: Vec<&str> = Vec::new();
        for candidate in value.candidates() {
            let Value::Callable(name) = candidate else {
                continue;
            };
            let (rule, message) = match name.as_str() {
                "require" => (
                    "BG001",
                    "the require function escapes as a value and may load a remote module",
                ),
                "loadstring" => (
                    "BG003",
                    "the loadstring function escapes as a value and may execute runtime code",
                ),
                "getfenv" | "setfenv" => (
                    "BG004",
                    "an environment function escapes as a value and may access runtime state",
                ),
                _ => continue,
            };
            if reported.contains(&rule) {
                continue;
            }
            reported.push(rule);
            self.push(rule, Severity::High, Confidence::Medium, site, message, "");
        }
    }

    fn invoke_method(
        &mut self,
        receiver: Value,
        name: &TokenReference,
        args: &FunctionArgs,
        depth: usize,
        report: bool,
        site: Site,
    ) -> Value {
        let method = token_text(name);
        let cuts = self.truncations;
        let values = self.eval_args(args, depth);
        if report {
            for value in &values {
                self.note_value(value, site);
            }
        }
        if report && matches!(receiver, Value::ComputedGlobal) {
            self.report_computed_global(&values, site);
        }
        let cut =
            self.truncations > cuts || self.require_context.is_some_and(|context| context.cut);
        let context = cut.then_some(RequireContext {
            constant: false,
            cut,
        });
        let outer = std::mem::replace(&mut self.require_context, context);
        let result = match receiver {
            Value::Union(receivers) => {
                let results: Vec<Value> = receivers
                    .into_iter()
                    .map(|receiver| {
                        self.method_call(receiver, &method, &values, Some(args), report, site)
                    })
                    .collect();
                join(results)
            }
            receiver => self.method_call(receiver, &method, &values, Some(args), report, site),
        };
        self.require_context = outer;
        result
    }

    fn method_call(
        &mut self,
        receiver: Value,
        method: &str,
        values: &[Value],
        args: Option<&FunctionArgs>,
        report: bool,
        site: Site,
    ) -> Value {
        let first = values.first().cloned();
        if is_string_method(method)
            && matches!(
                receiver,
                Value::String(..)
                    | Value::Number(..)
                    | Value::Sensitive
                    | Value::Remote
                    | Value::ExternalData
                    | Value::ModelData(_)
                    | Value::UnresolvedOrigin(_)
                    | Value::IdLike(_)
            )
        {
            let mut arguments = Vec::with_capacity(values.len() + 1);
            arguments.push(receiver);
            arguments.extend(values.iter().cloned());
            return self.string_method(method, &arguments, args, report, site);
        }
        // Any other method of a plain string, number, boolean or nil raises an error, so
        // the call gives no value; nil stands in for that, as for joining nil.
        if matches!(
            receiver,
            Value::String(_, None) | Value::Number(_, None) | Value::Bool(_) | Value::Nil
        ) {
            return Value::Nil;
        }
        if let Value::Table(id) = receiver {
            // Follows `__index` tables, so methods of a class instance resolve.
            let field = Some(self.index(Value::Table(id), method));
            if let Some(field @ (Value::Function(_) | Value::Callable(_) | Value::Union(_))) = field
            {
                let mut arguments = vec![Value::Table(id)];
                arguments.extend(values.iter().cloned());
                return match field {
                    Value::Union(callables) => {
                        let results: Vec<Value> = callables
                            .into_iter()
                            .map(|callable| {
                                self.invoke_value(callable, arguments.clone(), args, report, site)
                            })
                            .collect();
                        join(results)
                    }
                    callable => self.invoke_value(callable, arguments, args, report, site),
                };
            }
            // A method the scanner cannot see receives the table as `self`.
            self.escape(&Value::Table(id));
        }
        if report {
            self.report_escaped_values(values, site);
        }
        if matches!(
            receiver,
            Value::String(_, Some(_))
                | Value::Number(_, Some(_))
                | Value::ExternalData
                | Value::ModelData(_)
                | Value::UnresolvedOrigin(_)
                | Value::Remote
        ) {
            // An unknown method on data read from the DOM still carries that origin.
            return derived_from(&[receiver]);
        }
        match (&receiver, method) {
            (_, "JSONEncode") => {
                if values.iter().any(|value| self.is_sensitive(value)) {
                    Value::Sensitive
                } else {
                    Value::Unknown
                }
            }
            (_, "UrlEncode") => match first {
                Some(value) if self.is_sensitive(&value) => Value::Sensitive,
                Some(value @ Value::String(..)) => value,
                _ => Value::Unknown,
            },
            (Value::Dom(instance), "FindFirstChild" | "WaitForChild") => {
                // `WaitForChild`'s second argument is a timeout, not a recursive flag.
                let recursive = method == "FindFirstChild"
                    && values.get(1).and_then(Value::truthy) == Some(true);
                match first {
                    Some(Value::String(child, _)) => {
                        match self.dom_index.child(*instance, &child) {
                            ChildLookup::Found(child) => Value::Dom(child),
                            ChildLookup::Ambiguous => Value::ModelDom(*instance),
                            // A descendant search may find it deeper in the content.
                            ChildLookup::Missing if recursive => Value::ModelDom(*instance),
                            ChildLookup::Missing => Value::ExternalDom,
                        }
                    }
                    _ => Value::ModelDom(*instance),
                }
            }
            (Value::Dom(instance), "GetChildren" | "GetDescendants" | "QueryDescendants") => {
                Value::InstanceList(Box::new(Value::ModelDom(*instance)))
            }
            (Value::ModelDom(anchor), "GetChildren" | "GetDescendants" | "QueryDescendants") => {
                Value::InstanceList(Box::new(Value::ModelDom(*anchor)))
            }
            (Value::ExternalDom, "GetChildren" | "GetDescendants" | "QueryDescendants") => {
                Value::InstanceList(Box::new(Value::ExternalDom))
            }
            (receiver, "GetTagged")
                if self.object_kind(receiver).as_deref() == Some("CollectionService") =>
            {
                Value::InstanceList(Box::new(self.tagged(first.as_ref())))
            }
            // An attribute of a player or of an object reached through the game tree is
            // set at runtime.
            (Value::Namespace(namespace), "GetAttribute" | "GetAttributes")
                if is_player_namespace(namespace) || is_instance_namespace(namespace) =>
            {
                Value::ExternalData
            }
            (Value::Dom(instance), "GetAttributes") => self.attribute_table(*instance),
            (Value::ModelDom(anchor), "GetAttributes" | "GetAttribute") => {
                Value::ModelData(*anchor)
            }
            (Value::ExternalDom, "GetAttributes") => Value::ExternalData,
            (Value::Dom(instance), "Clone") => Value::Dom(*instance),
            (Value::Dom(instance), "FindFirstChildOfClass" | "FindFirstChildWhichIsA") => {
                Value::ModelDom(*instance)
            }
            (Value::Dom(instance), "FindFirstAncestorOfClass" | "FindFirstAncestorWhichIsA") => {
                match first {
                    Some(Value::String(class, _)) => self
                        .ancestor(*instance, |node| node.class.as_str() == &class[..])
                        .map(Value::Dom)
                        .unwrap_or(Value::ExternalDom),
                    _ => Value::ExternalDom,
                }
            }
            (
                Value::ModelDom(anchor),
                "FindFirstChild"
                | "WaitForChild"
                | "FindFirstChildOfClass"
                | "FindFirstChildWhichIsA"
                | "FindFirstAncestor"
                | "FindFirstAncestorOfClass"
                | "FindFirstAncestorWhichIsA"
                | "Clone",
            ) => Value::ModelDom(*anchor),
            (Value::ModelDom(anchor), method) if is_string_method(method) => {
                Value::ModelData(*anchor)
            }
            (Value::Dom(instance), "FindFirstAncestor") => match first {
                Some(Value::String(ancestor, _)) => self
                    .ancestor(*instance, |node| node.name.as_str() == &ancestor[..])
                    .map(Value::Dom)
                    .unwrap_or(Value::ExternalDom),
                _ => Value::ExternalDom,
            },
            (Value::Dom(instance), "GetAttribute") => match first {
                Some(Value::String(attribute, _)) => {
                    let origin = Origin {
                        instance: *instance,
                        property: None,
                        attribute: Some(attribute.to_string()),
                    };
                    let values = self
                        .attribute_writes
                        .get(&(*instance, attribute.to_string()));
                    match self
                        .doc
                        .instances
                        .get(*instance)
                        .and_then(|node| node.attributes.get(&attribute[..]))
                    {
                        Some(value) => self.written_read(
                            json_value(value, origin.clone()),
                            origin,
                            self.instance_writes().attribute(&attribute),
                            values,
                        ),
                        // Not stored in the content: it would be set at runtime.
                        None => join(
                            values
                                .into_iter()
                                .flatten()
                                .cloned()
                                .chain([Value::UnresolvedOrigin(origin)]),
                        ),
                    }
                }
                _ => Value::ModelData(*instance),
            },
            (Value::Dom(instance), "SetAttribute") => {
                if let Some(Value::String(attribute, _)) = &first {
                    let value = values.get(1).cloned().unwrap_or(Value::Nil);
                    let slot = self
                        .attribute_writes
                        .entry((*instance, attribute.to_string()))
                        .or_default();
                    if slot.len() < MAX_CANDIDATES {
                        slot.push(value);
                    }
                }
                Value::Nil
            }
            // Every spelling of a service lookup. A service the content does not store
            // keeps its name, so a later call can tell which service it is.
            (
                Value::Dom(_) | Value::ExternalDom | Value::Object(_),
                "GetService" | "FindService" | "getService" | "service",
            ) => match first {
                Some(Value::String(service, _)) => match &receiver {
                    Value::Dom(instance) => match self.dom_index.child(*instance, &service) {
                        ChildLookup::Found(service) => Value::Dom(service),
                        ChildLookup::Missing | ChildLookup::Ambiguous => {
                            Value::Object(service.to_string())
                        }
                    },
                    _ => Value::Object(service.to_string()),
                },
                _ => Value::ExternalDom,
            },
            // Objects that services return. Their `GetAsync` is not an HTTP request.
            (receiver, method) if self.store_object(receiver, method).is_some() => {
                Value::Object(self.store_object(receiver, method).unwrap_or_default())
            }
            (
                Value::ExternalDom | Value::Object(_),
                "FindFirstChildOfClass"
                | "FindFirstChildWhichIsA"
                | "FindFirstAncestorOfClass"
                | "FindFirstAncestorWhichIsA"
                | "Clone"
                | "FindFirstChild"
                | "WaitForChild"
                | "FindFirstAncestor",
            ) => Value::ExternalDom,
            (Value::Object(_), "GetChildren" | "GetDescendants") => {
                Value::InstanceList(Box::new(Value::ExternalDom))
            }
            (Value::ExternalDom | Value::Object(_), "GetAttribute" | "GetAttributes") => {
                Value::ExternalData
            }
            (Value::ExternalDom | Value::Object(_), method) if is_string_method(method) => {
                Value::ExternalData
            }
            (_, "GetPlayerFromCharacter" | "GetPlayerByUserId") => {
                Value::Namespace("player".into())
            }
            // Each element is a player, so `p.Name` in a loop over it is player data.
            (_, "GetPlayers") => Value::InstanceList(Box::new(Value::Namespace("player".into()))),
            (
                Value::Namespace(namespace),
                "FindFirstChild" | "WaitForChild" | "FindFirstAncestor",
            ) if is_instance_namespace(namespace) => match first {
                Some(Value::String(child, _)) => Value::Namespace(format!("{namespace}.{child}")),
                _ => Value::Namespace(namespace.clone()),
            },
            (Value::Namespace(namespace), "wait") if namespace == "task" => {
                if report {
                    self.delay_gate(first.as_ref(), site);
                }
                Value::Unknown
            }
            (_, method) => self.member_call(Some(&receiver), method, values, args, report, site),
        }
    }

    /// An element of `CollectionService:GetTagged(tag)`: an object of the content with
    /// that tag, not pinned down because the game may tag others, or an object outside
    /// the content when the content tags none or the tag is not known.
    fn tagged(&self, tag: Option<&Value>) -> Value {
        let Some(Value::String(tag, _)) = tag else {
            return Value::ExternalDom;
        };
        self.doc
            .instances
            .iter()
            .position(|node| node.tags.iter().any(|name| name == &tag[..]))
            .map(Value::ModelDom)
            .unwrap_or(Value::ExternalDom)
    }

    /// Kind of object a service method returns, for the services whose objects share
    /// method names with `HttpService`.
    fn store_object(&self, receiver: &Value, method: &str) -> Option<String> {
        let kind = self.object_kind(receiver)?;
        let object = match (kind.as_str(), method) {
            ("DataStoreService", "GetDataStore" | "GetGlobalDataStore") => "DataStore",
            ("DataStoreService", "GetOrderedDataStore") => "OrderedDataStore",
            ("MemoryStoreService", "GetSortedMap") => "MemoryStoreSortedMap",
            ("MemoryStoreService", "GetQueue") => "MemoryStoreQueue",
            ("MemoryStoreService", "GetHashMap") => "MemoryStoreHashMap",
            _ => return None,
        };
        Some(object.into())
    }

    /// Class of an engine object, when the scanner knows it.
    fn object_kind(&self, value: &Value) -> Option<String> {
        match value {
            Value::Object(kind) => Some(kind.clone()),
            Value::Dom(instance) => self
                .doc
                .instances
                .get(*instance)
                .map(|node| node.class.clone()),
            _ => None,
        }
    }

    /// Whether a call of an HTTP method name is an HTTP request. A receiver known to
    /// be `HttpService` is; a receiver known to be anything else, such as a DataStore,
    /// never is; an unknown receiver is when the request names a URL.
    fn http_receiver(&self, receiver: Option<&Value>) -> Option<bool> {
        let receiver = receiver?;
        let mut known_other = true;
        for candidate in receiver.candidates() {
            match self.object_kind(candidate) {
                Some(kind) if kind == "HttpService" => return Some(true),
                Some(_) => {}
                None => match candidate {
                    Value::String(..) | Value::Number(..) | Value::Bool(_) | Value::Nil => {}
                    _ => known_other = false,
                },
            }
        }
        if known_other { Some(false) } else { None }
    }

    /// Security-relevant service methods, called as `x:Method(...)` or through an alias.
    fn member_call(
        &mut self,
        receiver: Option<&Value>,
        method: &str,
        values: &[Value],
        args: Option<&FunctionArgs>,
        report: bool,
        site: Site,
    ) -> Value {
        match method {
            "JSONEncode" => {
                if values.iter().any(|value| self.is_sensitive(value)) {
                    Value::Sensitive
                } else {
                    Value::Unknown
                }
            }
            "IsStudio" => {
                if report {
                    self.gate_signal = Some(site);
                    self.note_gate_check();
                }
                Value::Unknown
            }
            "NextInteger" | "NextNumber" => {
                match (
                    values.first().and_then(coerce_number),
                    values.get(1).and_then(coerce_number),
                ) {
                    (Some((low, _)), Some((high, _))) => Value::Range(low, high),
                    _ => Value::Unknown,
                }
            }
            "LoadAsset" | "LoadAssetVersion" | "GetObjects" => {
                if report {
                    self.mark_sink(SINK_OTHER);
                    self.push(
                        "BG007",
                        Severity::High,
                        Confidence::High,
                        site,
                        "content is loaded from an asset at runtime",
                        "",
                    );
                }
                Value::Unknown
            }
            "PostAsync" | "PostAsyncFullUrl" | "RequestAsync" | "GetAsync" => {
                let http = self.http_receiver(receiver);
                if report && http != Some(false) {
                    self.mark_sink(SINK_HTTP);
                    if let Some((severity, confidence, message)) =
                        self.http_verdict(method, values, args, http.is_none())
                    {
                        self.push("BG008", severity, confidence, site, message, "");
                    }
                }
                Value::Remote
            }
            "HttpGet" | "HttpGetAsync" => Value::Remote,
            "JSONDecode" => match derived_from(values) {
                // Decoded data keeps where it came from.
                taint @ (Value::Remote
                | Value::ExternalData
                | Value::ModelData(_)
                | Value::UnresolvedOrigin(_)) => taint,
                _ => Value::Unknown,
            },
            "PromptPurchase"
            | "PromptProductPurchase"
            | "PromptGamePassPurchase"
            | "PromptBundlePurchase"
            | "PromptPremiumPurchase"
            | "PromptSubscriptionPurchase" => {
                if report {
                    self.mark_sink(SINK_OTHER);
                    if self.inserted_context() {
                        self.push(
                            "BG010",
                            Severity::Medium,
                            Confidence::Medium,
                            site,
                            "inserted content starts a purchase prompt",
                            "",
                        );
                    }
                }
                Value::Unknown
            }
            "Teleport"
            | "TeleportAsync"
            | "TeleportToPlaceInstance"
            | "TeleportToPrivateServer"
            | "TeleportPartyAsync" => {
                if report {
                    self.mark_sink(SINK_OTHER);
                    let has_place_id = values.iter().any(|value| {
                        value
                            .candidates()
                            .into_iter()
                            .any(|candidate| matches!(candidate, Value::Number(..)))
                    });
                    // A player list that is a known empty table teleports no one.
                    let players = match method {
                        "TeleportToPrivateServer" => Some(2),
                        "TeleportAsync" | "TeleportPartyAsync" => Some(1),
                        _ => None,
                    };
                    let nobody = players
                        .and_then(|index| values.get(index))
                        .is_some_and(|value| match value {
                            Value::Table(id) => self
                                .table(*id)
                                .is_some_and(|table| !table.escaped && table.entries() == 0),
                            _ => false,
                        });
                    if self.inserted_context() && has_place_id && !nobody {
                        self.push(
                            "BG010",
                            Severity::Medium,
                            Confidence::Medium,
                            site,
                            "inserted content redirects players to another place",
                            "",
                        );
                    }
                }
                Value::Unknown
            }
            // An unknown method keeps an asset-ID-shaped argument visible, and may
            // change any table it receives.
            _ => {
                self.escape_all(values);
                values
                    .iter()
                    .find_map(asset_shaped)
                    .map(Value::IdLike)
                    .unwrap_or(Value::Unknown)
            }
        }
    }

    // ----- folding ------------------------------------------------------------------

    fn fold_tonumber(&mut self, value: Value, base: Option<u32>) -> Value {
        match value {
            Value::Union(values) => {
                let results: Vec<Value> = values
                    .into_iter()
                    .map(|value| self.fold_tonumber(value, base))
                    .collect();
                join(results)
            }
            Value::String(text, origin) => match lua_tonumber(&text, base) {
                Some(number) => Value::Number(number, origin),
                None => match origin {
                    Some(origin) => Value::UnresolvedOrigin(origin),
                    None => Value::Nil,
                },
            },
            Value::Number(number, origin) if base.is_none() => Value::Number(number, origin),
            Value::Number(number, origin) => match lua_tonumber(&format_number(number), base) {
                Some(number) => Value::Number(number, origin),
                None => Value::Nil,
            },
            Value::ExternalData | Value::ExternalDom => Value::ExternalData,
            Value::ModelData(anchor) | Value::ModelDom(anchor) => Value::ModelData(anchor),
            Value::UnresolvedOrigin(origin) => Value::UnresolvedOrigin(origin),
            Value::IdLike(text) => Value::IdLike(text),
            Value::Sensitive => Value::Sensitive,
            Value::Remote => Value::Remote,
            Value::Nil | Value::Bool(_) | Value::Table(_) | Value::Function(_) => Value::Nil,
            _ => Value::Unknown,
        }
    }

    fn fold_tostring(&mut self, value: Value) -> Value {
        match value {
            Value::Union(values) => {
                let results: Vec<Value> = values
                    .into_iter()
                    .map(|value| self.fold_tostring(value))
                    .collect();
                join(results)
            }
            Value::String(text, origin) => Value::String(text, origin),
            Value::Number(number, origin) => {
                Value::String(Text::from(format_number(number)), origin)
            }
            Value::Nil => Value::String("nil".into(), None),
            Value::Bool(value) => Value::String(Text::from(value.to_string()), None),
            Value::ExternalData => Value::ExternalData,
            Value::ModelData(anchor) => Value::ModelData(anchor),
            Value::Remote => Value::Remote,
            Value::UnresolvedOrigin(origin) => Value::UnresolvedOrigin(origin),
            Value::IdLike(text) => Value::IdLike(text),
            value if self.is_sensitive(&value) => Value::Sensitive,
            _ => Value::Unknown,
        }
    }

    fn table_concat(&mut self, values: &[Value]) -> Value {
        let Some(Value::Table(id)) = values.first() else {
            return Value::Unknown;
        };
        let Some(table) = self.table(*id) else {
            return Value::Unknown;
        };
        if table.sensitive || table.items.iter().any(|value| self.is_sensitive(value)) {
            return Value::Sensitive;
        }
        if table.escaped || !table.loose.is_empty() || self.captured_table_changes(*id) {
            let mut values: Vec<Value> = table.values().take(256).cloned().collect();
            values.push(Value::Unknown);
            return derived_from(&values);
        }
        let items = table.items.clone();
        let separator = values
            .get(1)
            .cloned()
            .unwrap_or_else(|| Value::String(Text::from(String::new()), None));
        let Some((separator, separator_origin)) = value_as_string(&separator) else {
            return Value::Unknown;
        };
        let start = values.get(2).and_then(integer_value).unwrap_or(1).max(1) as usize;
        let end = values
            .get(3)
            .and_then(integer_value)
            .unwrap_or(items.len() as i64)
            .max(0) as usize;
        let mut output = String::new();
        let mut origin = separator_origin;
        let mut pieces = Vec::new();
        for index in start..=end.min(items.len()) {
            if index > start {
                output.push_str(&separator);
            }
            let value = &items[index - 1];
            match value_as_string(value) {
                Some((text, value_origin)) => {
                    output.push_str(&text);
                    origin = origin.or(value_origin);
                }
                None => pieces.push(value.clone()),
            }
            if output.len() > self.limits.max_script_bytes {
                self.mark_resolution_limit("constant folding output limit reached");
                return Value::Unknown;
            }
        }
        if !pieces.is_empty() {
            pieces.push(Value::String(Text::from(output), origin));
            return derived_from(&pieces);
        }
        if !self.charge(output.len()) {
            return Value::Unknown;
        }
        Value::String(Text::from(output), origin)
    }

    fn string_char(&mut self, values: &[Value]) -> Value {
        let mut output = String::new();
        for value in values {
            match value {
                Value::Number(number, _) if (0.0..=255.0).contains(number) => {
                    output.push(*number as u8 as char)
                }
                _ => return derived_from(values),
            }
        }
        Value::String(Text::from(output), None)
    }

    /// A string library call that may run a callback: `gsub` with a function
    /// replacement calls it with each match's captures, and `gmatch` lists the matches
    /// for a loop. Everything else folds in [`Analyzer::string_call`].
    fn string_method(
        &mut self,
        method: &str,
        values: &[Value],
        args: Option<&FunctionArgs>,
        report: bool,
        site: Site,
    ) -> Value {
        let callback = method == "gsub"
            && values.get(2).is_some_and(|value| {
                value
                    .candidates()
                    .into_iter()
                    .any(|candidate| match candidate {
                        Value::Function(_) | Value::Callable(_) => true,
                        Value::Table(id) => self.call_handler(*id).is_some(),
                        _ => false,
                    })
            });
        if method != "gmatch" && !callback {
            return self.string_call(method, values);
        }
        let receiver = &values[..values.len().min(1)];
        // Captures of each match, with the receiver's instance origin, or `None` when
        // the receiver or the pattern does not fold.
        let matches = match (
            values.first().and_then(value_as_string),
            values.get(1).and_then(value_as_string),
        ) {
            (Some((text, origin)), Some((pattern, _))) => {
                lua_matches(text.as_bytes(), pattern.as_bytes())
                    .ok()
                    .map(|(matches, complete)| {
                        let mut matches: Vec<Vec<Value>> = matches
                            .into_iter()
                            .map(|captures| {
                                captures
                                    .into_iter()
                                    .map(|value| with_origin(value, origin.clone()))
                                    .collect()
                            })
                            .collect();
                        if !complete {
                            matches.push(vec![Value::Overflow]);
                        }
                        matches
                    })
            }
            _ => None,
        };
        // The result folds only when every match is known.
        let complete = matches.as_ref().is_some_and(|matches| {
            !matches
                .iter()
                .flatten()
                .any(|value| matches!(value, Value::Overflow))
        });
        // The matches are unknown: each one still carries the receiver's data.
        let matches = matches.unwrap_or_else(|| vec![vec![derived_from(receiver)]]);
        if method == "gmatch" {
            return Value::Matches(matches.into_iter().map(Value::Tuple).collect());
        }
        let callback = values.get(2).cloned().unwrap_or(Value::Nil);
        let single = callback.candidates().len() == 1;
        // What the callback returns for each match: the replacement text, or `None` to
        // keep the match, as `gsub` does for nil and false.
        let mut replacements: Option<Vec<Option<String>>> = (complete && single).then(Vec::new);
        let mut results = Vec::new();
        for captures in matches {
            for candidate in callback.candidates() {
                let result = self
                    .invoke_value(candidate.clone(), captures.clone(), args, report, site)
                    .single();
                if let Some(list) = replacements.as_mut() {
                    match &result {
                        Value::String(..) | Value::Number(..) => {
                            list.push(value_as_string(&result).map(|(text, _)| text));
                        }
                        Value::Nil | Value::Bool(false) => list.push(None),
                        _ => replacements = None,
                    }
                }
                results.push(result);
            }
        }
        let folded = match (
            replacements,
            values.first().and_then(value_as_string),
            values.get(1).and_then(value_as_string),
        ) {
            (Some(list), Some((text, origin)), Some((pattern, _))) => {
                let limit = values
                    .get(3)
                    .and_then(integer_value)
                    .and_then(|limit| usize::try_from(limit.max(0)).ok());
                lua_gsub(
                    text.as_bytes(),
                    pattern.as_bytes(),
                    &Replacement::Values(list),
                    limit,
                    self.limits.max_script_bytes,
                )
                .ok()
                .map(|(output, count)| {
                    (
                        output.len(),
                        Value::String(
                            Text::from(String::from_utf8_lossy(&output).into_owned()),
                            origin,
                        ),
                        count,
                    )
                })
            }
            _ => None,
        };
        match folded {
            Some((bytes, text, count)) if self.charge(bytes) => {
                Value::Tuple(vec![text, Value::Number(count as f64, None)])
            }
            // The replacements carry their data into the result.
            _ => {
                let mut sources = receiver.to_vec();
                sources.extend(results);
                Value::Tuple(vec![derived_from(&sources), Value::Unknown])
            }
        }
    }

    /// Fold a string library call. `values[0]` is the receiver.
    fn string_call(&mut self, method: &str, values: &[Value]) -> Value {
        if self.folded_bytes > MAX_FOLDED_BYTES {
            return derived_from(values);
        }
        let receiver = values.first().cloned().unwrap_or(Value::Nil);
        if let Value::Union(receivers) = receiver {
            let results: Vec<Value> = receivers
                .into_iter()
                .map(|receiver| {
                    let mut arguments = values.to_vec();
                    arguments[0] = receiver;
                    self.string_call(method, &arguments)
                })
                .collect();
            return join(results);
        }
        let (text, origin) = match receiver {
            Value::String(text, origin) => (text, origin),
            Value::Number(number, origin) => (Text::from(format_number(number)), origin),
            Value::Sensitive => return Value::Sensitive,
            Value::Remote => return Value::Remote,
            Value::ExternalData | Value::ExternalDom => return Value::ExternalData,
            Value::ModelData(anchor) | Value::ModelDom(anchor) => {
                return Value::ModelData(anchor);
            }
            Value::UnresolvedOrigin(origin) => return Value::UnresolvedOrigin(origin),
            Value::IdLike(text) => return Value::IdLike(text),
            _ => return Value::Unknown,
        };
        let arguments = &values[1..];
        if method == "format" && arguments.iter().any(|value| self.is_sensitive(value)) {
            return Value::Sensitive;
        }
        let origin = origin.or_else(|| arguments.iter().find_map(|value| value.origin().cloned()));
        match self.fold_string(method, &text, arguments) {
            Some(value) => {
                let bytes = match &value {
                    Value::String(text, _) => text.len(),
                    Value::Tuple(values) => values
                        .iter()
                        .map(|value| match value {
                            Value::String(text, _) => text.len(),
                            _ => 0,
                        })
                        .sum(),
                    _ => 0,
                };
                if self.charge(bytes) {
                    with_origin(value, origin)
                } else {
                    Value::Unknown
                }
            }
            None => match origin {
                Some(origin) => Value::UnresolvedOrigin(origin),
                None => {
                    let mut all = arguments.to_vec();
                    all.push(Value::String(text, None));
                    derived_from(&all)
                }
            },
        }
    }

    fn fold_string(&mut self, method: &str, text: &str, arguments: &[Value]) -> Option<Value> {
        let max_bytes = self.limits.max_script_bytes;
        let string_arg = |index: usize| -> Option<String> {
            arguments
                .get(index)
                .and_then(value_as_string)
                .map(|(text, _)| text)
        };
        match method {
            "reverse" => Some(Value::String(
                Text::from(text.chars().rev().collect::<String>()),
                None,
            )),
            "lower" => Some(Value::String(Text::from(text.to_lowercase()), None)),
            "upper" => Some(Value::String(Text::from(text.to_uppercase()), None)),
            "len" => Some(Value::Number(text.len() as f64, None)),
            "sub" => {
                let start = arguments.first().map_or(Some(1), integer_value)?;
                let end = match arguments.get(1) {
                    Some(value) => Some(integer_value(value)?),
                    None => None,
                };
                Some(Value::String(Text::from(lua_sub(text, start, end)), None))
            }
            "rep" => {
                let count = usize::try_from(integer_value(arguments.first()?)?.max(0)).ok()?;
                let separator = match arguments.get(1) {
                    Some(value) => value_as_string(value)?.0,
                    None => String::new(),
                };
                let size = text
                    .len()
                    .checked_mul(count)?
                    .checked_add(separator.len().saturating_mul(count.saturating_sub(1)))?;
                if size > max_bytes || self.folded_bytes.saturating_add(size) > MAX_FOLDED_BYTES {
                    self.mark_resolution_limit("constant folding output limit reached");
                    return None;
                }
                let output = if separator.is_empty() {
                    text.repeat(count)
                } else {
                    let mut output = String::with_capacity(size);
                    for index in 0..count {
                        if index > 0 {
                            output.push_str(&separator);
                        }
                        output.push_str(text);
                    }
                    output
                };
                Some(Value::String(Text::from(output), None))
            }
            "format" => {
                let mut limit_hit = false;
                let value = fold_string_format(text, arguments, max_bytes, &mut limit_hit);
                if limit_hit {
                    self.mark_resolution_limit("constant folding output limit reached");
                }
                match value {
                    Value::Unknown => None,
                    value => Some(value),
                }
            }
            "byte" => {
                let bytes = text.as_bytes();
                let start = arguments.first().map_or(Some(1), integer_value)?;
                let end = match arguments.get(1) {
                    Some(value) => integer_value(value)?,
                    None => start,
                };
                let len = bytes.len() as i64;
                let normalize = |index: i64| if index < 0 { len + index + 1 } else { index };
                let start = normalize(start).max(1);
                let end = normalize(end).min(len);
                if end.saturating_sub(start) > MAX_CALL_ARGUMENTS as i64 {
                    return None;
                }
                Some(Value::Tuple(
                    (start..=end)
                        .map(|index| Value::Number(f64::from(bytes[(index - 1) as usize]), None))
                        .collect(),
                ))
            }
            "split" => {
                let separator = match arguments.first() {
                    Some(value) => value_as_string(value)?.0,
                    None => ",".into(),
                };
                let parts: Vec<String> = if separator.is_empty() {
                    text.chars().map(String::from).collect()
                } else {
                    text.split(separator.as_str()).map(String::from).collect()
                };
                let mut table = ConstantTable::default();
                for part in parts.into_iter().take(MAX_TABLE_ENTRIES) {
                    table.items.push(Value::String(Text::from(part), None));
                }
                Some(self.new_table(table))
            }
            "gsub" => {
                let pattern = string_arg(0)?;
                let limit = match arguments.get(2) {
                    Some(value) => Some(usize::try_from(integer_value(value)?.max(0)).ok()?),
                    None => None,
                };
                let replacement = match arguments.get(1)? {
                    Value::Table(id) => {
                        let table = self.table(*id)?;
                        let mut map = BTreeMap::new();
                        for (key, value) in &table.fields {
                            if let Some((text, _)) = value_as_string(value) {
                                map.insert(key.clone(), text);
                            }
                        }
                        Replacement::Table(map)
                    }
                    value => Replacement::Text(value_as_string(value)?.0),
                };
                let (output, count) = lua_gsub(
                    text.as_bytes(),
                    pattern.as_bytes(),
                    &replacement,
                    limit,
                    max_bytes,
                )
                .ok()?;
                Some(Value::Tuple(vec![
                    Value::String(
                        Text::from(String::from_utf8_lossy(&output).into_owned()),
                        None,
                    ),
                    Value::Number(count as f64, None),
                ]))
            }
            "match" | "find" => {
                let pattern = string_arg(0)?;
                let init = match arguments.get(1) {
                    Some(Value::Nil) | None => 1,
                    Some(value) => integer_value(value)?,
                };
                let plain = method == "find"
                    && arguments
                        .get(2)
                        .is_some_and(|value| !matches!(value, Value::Nil | Value::Bool(false)));
                let found = lua_find(
                    text.as_bytes(),
                    pattern.as_bytes(),
                    init,
                    plain,
                    method == "find",
                )
                .ok()?;
                Some(match found {
                    Some(values) => Value::Tuple(values),
                    None => Value::Nil,
                })
            }
            _ => None,
        }
    }

    fn math_call(&mut self, function: &str, values: &[Value]) -> Value {
        if values.iter().any(|value| self.is_sensitive(value)) {
            return Value::Sensitive;
        }
        let numbers: Option<Vec<(f64, Option<Origin>)>> =
            values.iter().map(coerce_number).collect();
        let Some(numbers) = numbers else {
            return derived_from(values);
        };
        let origin = numbers.iter().find_map(|(_, origin)| origin.clone());
        let n = |index: usize| numbers.get(index).map(|(number, _)| *number);
        if function == "random" {
            // Only the bounds are known.
            return match (n(0), n(1)) {
                (None, _) => Value::Range(0.0, 1.0),
                (Some(high), None) => Value::Range(1.0, high),
                (Some(low), Some(high)) => Value::Range(low, high),
            };
        }
        let result = match function {
            "floor" => n(0).map(f64::floor),
            "ceil" => n(0).map(f64::ceil),
            "abs" => n(0).map(f64::abs),
            "sqrt" => n(0).map(f64::sqrt),
            "sign" => n(0).map(|x| {
                if x > 0.0 {
                    1.0
                } else if x < 0.0 {
                    -1.0
                } else {
                    0.0
                }
            }),
            "round" => n(0).map(f64::round),
            "max" => numbers.iter().map(|(x, _)| *x).reduce(f64::max),
            "min" => numbers.iter().map(|(x, _)| *x).reduce(f64::min),
            "fmod" => match (n(0), n(1)) {
                (Some(a), Some(b)) if b != 0.0 => Some(a % b),
                _ => None,
            },
            "pow" => match (n(0), n(1)) {
                (Some(a), Some(b)) => Some(a.powf(b)),
                _ => None,
            },
            "clamp" => match (n(0), n(1), n(2)) {
                (Some(x), Some(low), Some(high)) if low <= high => Some(x.clamp(low, high)),
                _ => None,
            },
            "modf" => {
                return match n(0) {
                    Some(x) => Value::Tuple(vec![
                        Value::Number(x.trunc(), origin.clone()),
                        Value::Number(x.fract(), None),
                    ]),
                    None => Value::Unknown,
                };
            }
            _ => None,
        };
        result
            .filter(|number| number.is_finite())
            .map(|number| Value::Number(number, origin))
            .unwrap_or(Value::Unknown)
    }

    // ----- sinks --------------------------------------------------------------------

    fn report_require(&mut self, value: &Value, site: Site, args: Option<&FunctionArgs>) {
        let context = self.require_context.unwrap_or_default();
        let candidates = value.candidates();
        let in_set = candidates.len() > 1;
        let mut verdicts = Vec::new();
        for candidate in candidates {
            if let Some(verdict) = self.require_verdict(candidate, in_set) {
                verdicts.push(verdict);
            }
        }
        if context.cut
            || verdicts
                .iter()
                .any(|verdict| matches!(verdict, RequireVerdict::Truncated))
        {
            self.mark_resolution_limit("analysis depth limit reached for a require target");
        }
        if verdicts.is_empty() {
            return;
        }
        // Every candidate is a number, a placeholder or a local module (local modules
        // produce no verdict), so the possible asset IDs are known exactly.
        let resolved = verdicts.iter().all(|verdict| {
            matches!(
                verdict,
                RequireVerdict::Numeric(..) | RequireVerdict::Placeholder
            )
        });
        let mut numeric: Vec<(u64, Option<Origin>)> = Vec::new();
        for verdict in &verdicts {
            if let RequireVerdict::Numeric(asset_id, origin) = verdict
                && !numeric.iter().any(|(seen, _)| seen == asset_id)
            {
                numeric.push((*asset_id, origin.clone()));
            }
        }
        if resolved {
            let label = if numeric.len() == 1 {
                "resolved asset id"
            } else {
                "asset id candidate"
            };
            let (reported, not_applied) = self.apply_trust(numeric, context.constant);
            for (asset_id, origin, label, confidence) in reported
                .into_iter()
                .map(|(id, origin)| (id, origin, label, Confidence::High))
                .chain(
                    not_applied
                        .into_iter()
                        .map(|(id, origin)| (id, origin, TRUST_NOT_APPLIED, Confidence::Medium)),
                )
            {
                match origin {
                    Some(origin) => self.push_property_require(
                        &origin,
                        confidence,
                        site,
                        Some((asset_id, label)),
                    ),
                    None => self.push(
                        "BG001",
                        Severity::High,
                        confidence,
                        site,
                        "module is loaded from a numeric asset ID",
                        &format!(" [{label}: {asset_id}]"),
                    ),
                }
            }
            return;
        }
        // Not fully resolved: no candidate is removed by trust, because the value the
        // code really loads may be one the scanner did not see.
        let mut candidates: Vec<String> = Vec::new();
        let mut literals: Vec<String> = Vec::new();
        let mut pushed = false;
        // A value read from an object that some script may change is its stored ID and
        // an unresolved read of the same property; one finding covers both.
        let mut numeric_origins: Vec<Origin> = Vec::new();
        for (asset_id, origin) in numeric {
            match origin {
                Some(origin) => {
                    pushed = true;
                    self.push_property_require(
                        &origin,
                        Confidence::Medium,
                        site,
                        Some((asset_id, "asset id candidate")),
                    );
                    numeric_origins.push(origin);
                }
                None => candidates.push(asset_id.to_string()),
            }
        }
        for verdict in verdicts {
            match verdict {
                RequireVerdict::IdShaped(literal) => {
                    if !literals.contains(&literal) && !candidates.contains(&literal) {
                        literals.push(literal);
                    }
                }
                RequireVerdict::External => {
                    pushed = true;
                    self.push(
                        "BG002",
                        UNRESOLVED_ORIGIN_SEVERITY,
                        Confidence::Low,
                        site,
                        "value comes from outside the scanned content",
                        "",
                    );
                }
                RequireVerdict::Property(origin) if !numeric_origins.contains(&origin) => {
                    pushed = true;
                    self.push_property_require(&origin, Confidence::Low, site, None);
                }
                RequireVerdict::Property(_) => {}
                RequireVerdict::Model(anchor) => {
                    pushed = true;
                    self.push_model_require(anchor, site);
                }
                RequireVerdict::Remote => {
                    pushed = true;
                    self.push(
                        "BG001",
                        Severity::High,
                        Confidence::Medium,
                        site,
                        "require target is downloaded at runtime",
                        "",
                    );
                }
                RequireVerdict::Numeric(..)
                | RequireVerdict::Placeholder
                | RequireVerdict::Opaque
                | RequireVerdict::Truncated => {}
            }
        }
        const UNRESOLVED_ID: &str =
            "require target contains a numeric asset ID that could not be fully resolved";
        if !candidates.is_empty() {
            // Numbers among unknown values: list them, never as resolved.
            candidates.append(&mut literals);
            let shown: Vec<&str> = candidates.iter().take(4).map(String::as_str).collect();
            let more = candidates.len() - shown.len();
            let label = if candidates.len() == 1 {
                "asset id candidate"
            } else {
                "asset id candidates"
            };
            let suffix = if more > 0 {
                format!(" [{label}: {} and {more} more]", shown.join(", "))
            } else {
                format!(" [{label}: {}]", shown.join(", "))
            };
            self.push(
                "BG001",
                Severity::High,
                Confidence::Medium,
                site,
                UNRESOLVED_ID,
                &suffix,
            );
            return;
        }
        if literals.is_empty()
            && !pushed
            && let Some(literal) = self.id_literal_hint(args)
        {
            literals.push(literal);
        }
        if !literals.is_empty() {
            for literal in literals {
                self.push(
                    "BG001",
                    Severity::High,
                    Confidence::Medium,
                    site,
                    UNRESOLVED_ID,
                    &format!(" [asset id literal: {literal}]"),
                );
            }
        } else if !pushed {
            self.push(
                "BG001",
                Severity::Low,
                Confidence::Low,
                site,
                "dynamic require target is unresolved",
                "",
            );
        }
    }

    /// The one place where `trusted_asset_ids` apply. Callers pass only the IDs of a
    /// fully resolved candidate set. A trusted ID is dropped only when the `require`
    /// argument is a constant (see [`Analyzer::constant_target`]), so a finding goes
    /// away only when every candidate is trusted. The first list is reported as usual;
    /// the second holds trusted IDs read through a value that can change, which are
    /// still reported.
    fn apply_trust(&self, ids: AssetIds, constant: bool) -> (AssetIds, AssetIds) {
        let (trusted, reported): (Vec<_>, Vec<_>) = ids
            .into_iter()
            .partition(|(asset_id, _)| self.trusted.contains(asset_id));
        if constant {
            (reported, Vec::new())
        } else {
            (reported, trusted)
        }
    }

    /// Whether every possible value of a `require` target is a local module, an
    /// instance or a string path, so the call can load nothing else whatever the
    /// function around it receives. Anything with a verdict, a placeholder too, is not.
    fn local_modules_only(&self, target: &Value) -> bool {
        let candidates = target.candidates();
        let in_set = candidates.len() > 1;
        candidates
            .into_iter()
            .all(|candidate| self.require_verdict(candidate, in_set).is_none())
    }

    fn require_verdict(&self, value: &Value, in_set: bool) -> Option<RequireVerdict> {
        match value {
            Value::Number(number, origin) if *number >= 0.0 && number.fract() == 0.0 => {
                // In a set, a small number is a placeholder or an index, not an ID.
                if in_set && *number < ASSET_ID_MIN {
                    Some(RequireVerdict::Placeholder)
                } else {
                    Some(RequireVerdict::Numeric(*number as u64, origin.clone()))
                }
            }
            Value::String(text, origin) => {
                if !text.is_empty()
                    && text.bytes().all(|byte| byte.is_ascii_digit())
                    && let Ok(number) = text.parse::<u64>()
                {
                    self.require_verdict(&Value::Number(number as f64, origin.clone()), in_set)
                } else if in_set && text.is_empty() {
                    Some(RequireVerdict::Placeholder)
                } else {
                    None
                }
            }
            Value::Dom(_) | Value::ExternalDom | Value::ModelDom(_) | Value::Object(_) => None,
            Value::Namespace(namespace) if is_instance_namespace(namespace) => None,
            Value::ExternalData => Some(RequireVerdict::External),
            Value::ModelData(anchor) => Some(RequireVerdict::Model(*anchor)),
            Value::UnresolvedOrigin(origin) => Some(RequireVerdict::Property(origin.clone())),
            Value::IdLike(literal) => Some(RequireVerdict::IdShaped(literal.clone())),
            Value::Partial(text) => Some(match digit_run(text, ASSET_ID_DIGITS) {
                Some(literal) => RequireVerdict::IdShaped(literal),
                None => RequireVerdict::Opaque,
            }),
            Value::Nil | Value::Bool(_) if in_set => Some(RequireVerdict::Placeholder),
            Value::Truncated => Some(RequireVerdict::Truncated),
            Value::Remote => Some(RequireVerdict::Remote),
            _ => Some(RequireVerdict::Opaque),
        }
    }

    /// BG002 for an ID read from an instance property or attribute. `asset_id` carries
    /// the ID and its evidence label when the value folded to a number.
    fn push_property_require(
        &mut self,
        origin: &Origin,
        confidence: Confidence,
        site: Site,
        asset_id: Option<(u64, &str)>,
    ) {
        let origin_name = origin
            .property
            .as_deref()
            .or(origin.attribute.as_deref())
            .unwrap_or("unknown");
        let suffix = match asset_id {
            Some((asset_id, label)) => format!(
                " [{label}: {asset_id}; origin: {} {}]",
                self.doc.path(origin.instance),
                origin_name
            ),
            None => format!(
                " [origin: {} {}]",
                self.doc.path(origin.instance),
                origin_name
            ),
        };
        let related = RelatedLocation {
            instance_path: self.doc.path(origin.instance),
            location: Location {
                property: origin.property.clone(),
                attribute: origin.attribute.clone(),
                ..Location::default()
            },
            message: "asset ID originates here".into(),
            file: self
                .doc
                .instances
                .get(origin.instance)
                .and_then(RelatedLocation::file_of),
        };
        if self.findings.len() >= MAX_FINDINGS_PER_SCRIPT {
            self.note_output_cap();
            return;
        }
        // A value the content stores, such as JSON text in a `StringValue`, is what the
        // script loads even when the scan cannot fold it, so only a value the content
        // does not hold, such as an attribute set at runtime, is the unresolved kind.
        let stored = self.doc.instances.get(origin.instance).is_some_and(|node| {
            origin
                .property
                .as_ref()
                .is_some_and(|property| node.properties.contains_key(property))
                || origin
                    .attribute
                    .as_ref()
                    .is_some_and(|attribute| node.attributes.contains_key(attribute))
        });
        let severity = if confidence == Confidence::Low && !stored {
            UNRESOLVED_ORIGIN_SEVERITY
        } else {
            Severity::Critical
        };
        if let Some(mut finding) = self.make(
            "BG002",
            severity,
            confidence,
            site,
            "module asset ID is read from an instance property or attribute",
            &suffix,
        ) {
            finding.related_locations.push(related);
            self.record(finding);
        }
    }

    /// BG002 for an ID read from an object inside the content that the scanner could
    /// not pin down, such as `GetChildren()[1].Value`.
    fn push_model_require(&mut self, anchor: usize, site: Site) {
        let path = self.doc.path(anchor);
        let related = RelatedLocation {
            instance_path: path.clone(),
            location: Location::default(),
            message: "the value is read from an object at or below this one".into(),
            file: self
                .doc
                .instances
                .get(anchor)
                .and_then(RelatedLocation::file_of),
        };
        if self.findings.len() >= MAX_FINDINGS_PER_SCRIPT {
            self.note_output_cap();
            return;
        }
        // The value is stored in the content when an object at or below the closest
        // known one stores an ID shaped value, or when that object is an `ObjectValue`
        // that stores a reference into the content.
        let holds_id = self
            .dom_index
            .stored_ids(|| stored_ids_below(self.doc))
            .get(anchor)
            .copied()
            .unwrap_or(false);
        let points_into_content = holds_id
            || self.doc.instances.get(anchor).is_some_and(|node| {
                node.class == "ObjectValue"
                    && node.properties.get("Value").is_some_and(stored_reference)
            });
        let severity = if points_into_content {
            Severity::Critical
        } else {
            UNRESOLVED_ORIGIN_SEVERITY
        };
        if let Some(mut finding) = self.make(
            "BG002",
            severity,
            Confidence::Low,
            site,
            "module asset ID is read from an object in the scanned content that could not be resolved",
            &format!(" [origin: unresolved object near {path}]"),
        ) {
            finding.related_locations.push(related);
            self.record(finding);
        }
    }

    /// First asset-ID-shaped literal in the call's argument source, used when the
    /// target cannot be folded.
    fn id_literal_hint(&self, args: Option<&FunctionArgs>) -> Option<String> {
        let site = args.map(args_site)?;
        let mut found = None;
        self.lex_site(site, MAX_LITERAL_SCAN_BYTES, |token_type, _| {
            found = match token_type {
                TokenType::Number { text } => parse_number(text)
                    .filter(|number| is_asset_number(*number))
                    .map(format_number),
                TokenType::StringLiteral { .. } | TokenType::InterpolatedString { .. } => {
                    token_literal(token_type).and_then(|text| digit_run(&text, ASSET_ID_DIGITS))
                }
                _ => None,
            };
            found.is_none()
        });
        found
    }

    /// Verdict for an HTTP request. `needs_url`: the receiver is unknown, so the call
    /// counts as HTTP only when it names a URL.
    fn http_verdict(
        &self,
        method: &str,
        values: &[Value],
        args: Option<&FunctionArgs>,
        needs_url: bool,
    ) -> Option<(Severity, Confidence, &'static str)> {
        const EXFILTRATION: &str =
            "HTTP request may send game or player data to an exfiltration endpoint";
        let mut urls: Vec<String> = Vec::new();
        if let Some(first) = values.first() {
            for candidate in first.candidates() {
                match candidate {
                    Value::String(url, _) => urls.push(url.to_string()),
                    Value::Partial(url) => urls.push(url.clone()),
                    Value::Table(id) => {
                        if let Some(url) = self.table(*id).and_then(|table| table.fields.get("Url"))
                        {
                            for candidate in url.candidates() {
                                match candidate {
                                    Value::String(url, _) => urls.push(url.to_string()),
                                    Value::Partial(url) => urls.push(url.clone()),
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut outbound_sensitive = false;
        if let Some(site) = args.map(args_site) {
            let mut previous_dot = false;
            let mut root = String::new();
            let mut members: Vec<String> = Vec::new();
            self.lex_site(site, MAX_LITERAL_SCAN_BYTES, |token_type, _| {
                match token_type {
                    TokenType::StringLiteral { .. } => {
                        if let Some(text) = token_literal(token_type)
                            && starts_with_http(&text)
                        {
                            urls.push(text);
                        }
                        previous_dot = false;
                    }
                    TokenType::Identifier { identifier } => {
                        let identifier = identifier.to_string();
                        if previous_dot {
                            if is_sensitive_identifier(&identifier)
                                || (identifier == "Name"
                                    && (root.eq_ignore_ascii_case("player")
                                        || root == "Players"
                                        || members.iter().any(|member| member == "LocalPlayer")))
                            {
                                outbound_sensitive = true;
                            }
                            members.push(identifier);
                        } else {
                            root = identifier;
                            members.clear();
                        }
                        previous_dot = false;
                    }
                    TokenType::Symbol {
                        symbol: Symbol::Dot,
                    } => previous_dot = true,
                    TokenType::Symbol {
                        symbol: Symbol::Colon,
                    } => {
                        previous_dot = false;
                        members.push(":".into());
                    }
                    _ => previous_dot = false,
                }
                urls.len() < 64
            });
        }
        if needs_url && !urls.iter().any(|url| starts_with_http(url)) {
            // An unknown receiver without a URL may be a DataStore or another object.
            return None;
        }
        let sends_body = method != "GetAsync";
        let mut ip_host = false;
        for url in &urls {
            match classify_url(url) {
                Some(Endpoint::Webhook | Endpoint::Paste) if sends_body => {
                    return Some((Severity::High, Confidence::High, EXFILTRATION));
                }
                Some(Endpoint::IpHost) => ip_host = true,
                _ => {}
            }
        }
        if outbound_sensitive || values.iter().any(|value| self.is_sensitive(value)) {
            return Some(if sends_body {
                (Severity::High, Confidence::High, EXFILTRATION)
            } else {
                (
                    Severity::Medium,
                    Confidence::Medium,
                    "HTTP GET request carries game or player data in its URL",
                )
            });
        }
        if ip_host && sends_body {
            return Some((
                Severity::Medium,
                Confidence::Medium,
                "HTTP request sends data to a raw IP address",
            ));
        }
        None
    }

    /// Remember webhook-shaped constants so they are reported even when the call that
    /// uses them cannot be traced.
    fn note_value(&mut self, value: &Value, site: Site) {
        for candidate in value.candidates() {
            if let Value::String(text, _) = candidate {
                self.note_string(text, site);
            }
        }
    }

    fn note_string(&mut self, text: &str, site: Site) {
        if self.replay_site.is_some()
            || self.webhook_constants.len() >= MAX_WEBHOOK_CONSTANTS
            || text.len() > 4096
            || !starts_with_http(text)
        {
            return;
        }
        if classify_url(text) == Some(Endpoint::Webhook) {
            let key = normalize_url(text).unwrap_or_else(|| text.to_ascii_lowercase());
            self.webhook_constants.entry(key).or_insert(site);
        }
    }

    fn inserted_context(&self) -> bool {
        let mut current = Some(self.script_id);
        let mut guard = 0usize;
        while let Some(id) = current {
            guard += 1;
            if guard > self.doc.instances.len() {
                break;
            }
            let Some(node) = self.doc.instances.get(id) else {
                break;
            };
            if matches!(
                node.class.as_str(),
                "Model" | "Tool" | "Part" | "MeshPart" | "Accessory"
            ) {
                return true;
            }
            current = node.parent;
        }
        false
    }

    // ----- findings -----------------------------------------------------------------

    /// Lex a bounded slice of the script source for `site`, calling `each` for every
    /// code token until it returns false.
    /// Lex the source of `site`, at most `max_bytes`, and give each token with its byte
    /// offset in the script to `each` until it returns false.
    fn lex_site(
        &self,
        site: Site,
        max_bytes: usize,
        mut each: impl FnMut(&TokenType, usize) -> bool,
    ) {
        let (Some(start), Some(end)) = (site.start, site.end) else {
            return;
        };
        let start = start.bytes();
        let end = end.bytes().min(self.source.len());
        if start >= end || !self.source.is_char_boundary(start) {
            return;
        }
        let limit = self
            .source
            .floor_char_boundary(start.saturating_add(max_bytes).min(end));
        let mut lexer = Lexer::new(&self.source[start..limit], full_moon::LuaVersion::luau());
        while let Some(item) = lexer.consume() {
            let token = match item {
                LexerResult::Ok(token) | LexerResult::Recovered(token, _) => token,
                LexerResult::Fatal(_) => break,
            };
            if matches!(token.token_type(), TokenType::Eof) {
                continue;
            }
            let offset = token
                .start_position()
                .map_or(start, |position| start + position.bytes());
            if !each(token.token_type(), offset) {
                break;
            }
        }
    }

    /// Render evidence from source tokens, so comments and spacing do not change it.
    fn render(&self, site: Site) -> String {
        let (Some(start), Some(end)) = (site.start, site.end) else {
            return String::new();
        };
        let truncated = end.bytes().saturating_sub(start.bytes()) > MAX_EVIDENCE_SOURCE_BYTES;
        let mut rendered = String::new();
        let start_byte = start.bytes();
        let end_byte = end.bytes().min(self.source.len());
        if start_byte >= end_byte || !self.source.is_char_boundary(start_byte) {
            return rendered;
        }
        let limit = self.source.floor_char_boundary(
            start_byte
                .saturating_add(MAX_EVIDENCE_SOURCE_BYTES)
                .min(end_byte),
        );
        let mut lexer = Lexer::new(
            &self.source[start_byte..limit],
            full_moon::LuaVersion::luau(),
        );
        while let Some(item) = lexer.consume() {
            let token = match item {
                LexerResult::Ok(token) | LexerResult::Recovered(token, _) => token,
                LexerResult::Fatal(_) => break,
            };
            if matches!(token.token_type(), TokenType::Eof) {
                continue;
            }
            let text = token.token().to_string();
            if rendered
                .chars()
                .next_back()
                .is_some_and(is_identifier_character)
                && text.chars().next().is_some_and(is_identifier_character)
            {
                rendered.push(' ');
            }
            rendered.push_str(&text);
        }
        if truncated {
            rendered.push_str("...");
        }
        rendered
    }

    /// Build a finding. Inside a replayed function body only results of medium severity
    /// or above that are not already claimed at the same place are kept, and they are
    /// reported at the outermost call site.
    fn make(
        &mut self,
        rule: &str,
        severity: Severity,
        confidence: Confidence,
        site: Site,
        message: &str,
        suffix: &str,
    ) -> Option<Finding> {
        if self.silent > 0 {
            return None;
        }
        let inner = site.location();
        let key = (
            rule.to_string(),
            inner.line,
            inner.column,
            suffix.to_string(),
        );
        let (location, evidence) = match self.replay_site {
            Some(root) => {
                if severity < Severity::Medium
                    || self
                        .normal_findings
                        .get(&key)
                        .is_some_and(|known| *known >= severity)
                {
                    return None;
                }
                (
                    root.location(),
                    format!("{} [via {}]{suffix}", self.render(root), self.render(site)),
                )
            }
            None => {
                let known = self.normal_findings.entry(key).or_insert(severity);
                *known = (*known).max(severity);
                (inner, format!("{}{suffix}", self.render(site)))
            }
        };
        let mut finding = Finding::new(
            rule,
            severity,
            confidence,
            &self.doc.input,
            &self.script_path,
            location,
            message,
            &evidence,
        );
        finding.set_files_from(&self.doc.instances[self.script_id]);
        Some(finding)
    }

    fn push(
        &mut self,
        rule: &str,
        severity: Severity,
        confidence: Confidence,
        site: Site,
        message: &str,
        suffix: &str,
    ) {
        if self.findings.len() >= MAX_FINDINGS_PER_SCRIPT {
            self.note_output_cap();
            return;
        }
        if let Some(finding) = self.make(rule, severity, confidence, site, message, suffix) {
            self.record(finding);
        }
    }

    fn note_output_cap(&mut self) {
        if !self.output_capped {
            self.output_capped = true;
            self.reasons.push(format!(
                "finding output limit reached in {}; additional findings were omitted",
                self.script_path
            ));
        }
    }

    fn record(&mut self, finding: Finding) {
        if is_risky_action(&finding) {
            if self.gated_action.is_none()
                && let Some(gate) = self.current_gate()
            {
                self.gated_action = Some(gate);
            }
            // A call of these functions under a gate gates the action too.
            for index in 0..self.function_stack.len() {
                let id = self.function_stack[index].id;
                if let Some(function) = self.functions.get_mut(id) {
                    function.risky = true;
                }
            }
        }
        let new_path_bytes = finding.instance_path.len().saturating_add(
            finding
                .related_locations
                .iter()
                .map(|related| related.instance_path.len())
                .sum::<usize>(),
        );
        if self.findings.len() >= MAX_FINDINGS_PER_SCRIPT
            || self.finding_path_bytes.saturating_add(new_path_bytes) > MAX_PATH_BYTES_PER_SCRIPT
        {
            self.note_output_cap();
            return;
        }
        self.finding_path_bytes = self.finding_path_bytes.saturating_add(new_path_bytes);
        self.findings.push(finding);
    }

    // ----- gates (BG009) ------------------------------------------------------------

    /// The gate that controls code running here: an enclosing branch whose condition
    /// checks Studio, the creator, the place, the server, the player count or the
    /// clock; an earlier early return behind such a check; an earlier long wait; or a
    /// long `task.delay` that runs this callback.
    fn current_gate(&self) -> Option<Site> {
        self.call_gate
            .or_else(|| self.scopes.iter().rev().find_map(|scope| scope.gate))
    }

    /// Code after a long wait in this block runs only after the delay.
    fn delay_gate(&mut self, seconds: Option<&Value>, site: Site) {
        if seconds
            .and_then(delay_seconds)
            .is_some_and(|seconds| seconds >= 60.0)
            && let Some(scope) = self.scopes.last_mut()
        {
            scope.gate.get_or_insert(site);
        }
    }

    /// Whether a condition reads as a gate: by its text, through a variable assigned
    /// from a gate check, or through a local function that checks one.
    fn condition_gate(&self, expression: &Expression) -> Option<Site> {
        let site = Site::expression(expression);
        let mut gate = false;
        let mut brackets = false;
        let mut previous: [String; 2] = [String::new(), String::new()];
        self.lex_site(site, 1024, |token_type, offset| {
            if let TokenType::Identifier { identifier } = token_type {
                let identifier = identifier.to_string();
                let clock = previous[0] == "os"
                    && previous[1] == "."
                    && matches!(identifier.as_str(), "time" | "date" | "clock");
                // A name after `.` or `:` is a field or a method, not a variable.
                let variable = (previous[1] != "." && previous[1] != ":")
                    .then(|| self.bindings.slot_at(offset, &identifier));
                gate = clock
                    || is_gate_member(&identifier)
                    || variable.as_ref().is_some_and(|slot| {
                        self.gate_names.contains_key(slot)
                            || matches!(
                                self.lookup(slot),
                                Some(Value::Function(id))
                                    if self.functions.get(id).is_some_and(|f| f.checks_gate)
                            )
                    });
                previous = [std::mem::take(&mut previous[1]), identifier];
            } else {
                let text = match token_type {
                    TokenType::Symbol { symbol } => symbol.to_string(),
                    _ => String::new(),
                };
                // A call of the global `time()`, not a field or method named `time`.
                gate = text == "("
                    && previous[1] == "time"
                    && previous[0] != "."
                    && previous[0] != ":";
                brackets |= text == "[";
                previous = [std::mem::take(&mut previous[1]), text];
            }
            !gate
        });
        // A gate member under a bracket key the scanner can fold, such as
        // `game["Place" .. "Id"]`, is the same check.
        if !gate && brackets {
            gate = self.folded_gate(expression);
        }
        gate.then_some(site)
    }

    /// Whether an expression reads a gate member through a bracket key built from
    /// literals and locals holding one string, such as `game["Place" .. "Id"]` or
    /// `os["clock"]()`.
    fn folded_gate(&self, expression: &Expression) -> bool {
        struct Keys<'s, 'a> {
            analyzer: &'s Analyzer<'a>,
            found: bool,
            /// Paths left to check, so a huge condition stays cheap.
            budget: usize,
        }
        impl Keys<'_, '_> {
            fn check<'n>(&mut self, prefix: &Prefix, suffixes: impl Iterator<Item = &'n Suffix>) {
                if self.found || self.budget == 0 {
                    return;
                }
                self.budget -= 1;
                let os = matches!(prefix, Prefix::Name(name) if token_text(name) == "os");
                for (position, suffix) in suffixes.enumerate() {
                    if let Suffix::Index(Index::Brackets { expression, .. }) = suffix
                        && let Some(key) = self.analyzer.folded_key(expression, 0)
                        && (is_gate_member(&key)
                            || (os
                                && position == 0
                                && matches!(key.as_str(), "time" | "date" | "clock")))
                    {
                        self.found = true;
                        return;
                    }
                }
            }
        }
        impl Visitor for Keys<'_, '_> {
            fn visit_var_expression(&mut self, node: &VarExpression) {
                self.check(node.prefix(), node.suffixes());
            }
            fn visit_function_call(&mut self, node: &FunctionCall) {
                self.check(node.prefix(), node.suffixes());
            }
        }
        let mut keys = Keys {
            analyzer: self,
            found: false,
            budget: 256,
        };
        Visit::visit(expression, &mut keys);
        keys.found
    }

    /// The text of a key built only from string literals, interpolated strings without
    /// expressions, concatenations and locals that hold one string, at most 64 bytes.
    fn folded_key(&self, expression: &Expression, depth: usize) -> Option<String> {
        if depth > 16 {
            return None;
        }
        let text = match expression {
            Expression::String(token) => string_value(token),
            Expression::InterpolatedString(string) if string.segments().next().is_none() => {
                interpolated_literal(string.last_string())
            }
            Expression::Parentheses { expression, .. }
            | Expression::TypeAssertion { expression, .. } => {
                self.folded_key(expression, depth + 1)?
            }
            Expression::BinaryOperator { lhs, binop, rhs } if binop_kind(binop) == Op::Concat => {
                let mut text = self.folded_key(lhs, depth + 1)?;
                text.push_str(&self.folded_key(rhs, depth + 1)?);
                text
            }
            Expression::Var(Var::Name(name)) => match self.lookup(&self.slot(name)) {
                Some(Value::String(text, _)) => text.to_string(),
                _ => return None,
            },
            _ => return None,
        };
        (text.len() <= 64).then_some(text)
    }

    /// Gate for a block that starts a branch or a loop body: the if, elseif and else
    /// conditions before it, or the while condition. An `if gate then return end`
    /// also gates the rest of the enclosing block.
    fn branch_gate(&mut self, block: &Block) -> Option<Site> {
        let key = block as *const Block as usize;
        if let Some(entry) = self
            .if_gates
            .last_mut()
            .filter(|entry| entry.blocks.get(entry.next) == Some(&key))
        {
            let signal = self.gate_signal.take();
            let position = entry.next;
            entry.next += 1;
            let then_branch = position == 0;
            let else_branch = entry.has_else && position + 1 == entry.blocks.len();
            let gate = if then_branch {
                entry.gate.or(signal)
            } else if else_branch {
                entry.gate
            } else {
                entry.gate.or(entry.else_if_gate.take()).or(signal)
            };
            entry.gate = gate;
            if then_branch
                && let Some(gate) = gate
                && (matches!(
                    block.last_stmt(),
                    Some(LastStmt::Return(_) | LastStmt::Break(_) | LastStmt::Continue(_))
                ) || ends_with_error(block))
                && self.scopes.len() >= 2
            {
                let enclosing = self.scopes.len() - 2;
                self.scopes[enclosing].gate.get_or_insert(gate);
            }
            return gate;
        }
        if let Some(entry) = self
            .while_gates
            .iter_mut()
            .rev()
            .find(|(body, _)| *body == key)
        {
            let gate = entry.1.or(self.gate_signal.take());
            entry.1 = gate;
            return gate;
        }
        None
    }

    /// Variables assigned from a gate check, so `if not isStudio then` counts.
    fn note_gate_names<'e>(
        &mut self,
        slots: impl Iterator<Item = Option<Slot>>,
        expressions: impl Iterator<Item = &'e Expression>,
    ) {
        for (slot, expression) in slots.zip(expressions) {
            if let Some(slot) = slot
                && let Some(gate) = self.condition_gate(expression)
                && self.gate_names.len() < 256
            {
                self.gate_names.insert(slot, gate);
            }
        }
    }

    /// Mark the functions being defined as gate checks, so `if isLive() then` counts.
    fn note_gate_check(&mut self) {
        for frame in &self.function_stack {
            if let Some(function) = self.functions.get_mut(frame.id) {
                function.checks_gate = true;
            }
        }
    }

    // ----- statements ---------------------------------------------------------------

    /// `a.b.c = value`: the container is everything but the last suffix, so a write
    /// through any alias, field path or `self` reaches the same table.
    fn assign_field(&mut self, target: &VarExpression, value: Value, dependence: &Dependence<'_>) {
        let suffixes: Vec<&Suffix> = target.suffixes().collect();
        let Some((Suffix::Index(last), path)) = suffixes.split_last() else {
            return;
        };
        let root = match target.prefix() {
            Prefix::Name(root) => Some(self.slot(root)),
            _ => None,
        };
        let root_scope = root.as_ref().and_then(|root| self.slot_scope(root));
        let base = self.eval_prefix(target.prefix(), 0);
        // A call in the path gives its first result, such as `select(1, t).id = v`.
        let container = self
            .apply_suffixes(
                base,
                path.iter().copied(),
                0,
                false,
                first_token_of_prefix(target.prefix()),
            )
            .single();
        let key = match last {
            Index::Dot { name, .. } => Value::String(Text::from(token_text(name)), None),
            Index::Brackets { expression, .. } => self.eval(expression, 0),
            _ => Value::Unknown,
        };
        self.unpinned_write(&container, root.as_ref(), path, &value);
        // A property of an object in the content: later reads list the written value.
        if let Value::String(name, _) = &key {
            for candidate in container.candidates() {
                if let Value::Dom(instance) = candidate {
                    let slot = self
                        .dom_writes
                        .entry((*instance, name.to_string()))
                        .or_default();
                    if slot.len() < MAX_CANDIDATES {
                        slot.push(value.clone());
                    }
                }
            }
        }
        let mut tables = tables_in(&container);
        for id in self.global_store(&container, &key, &value, dependence) {
            if !tables.contains(&id) {
                tables.push(id);
            }
        }
        if tables.is_empty() {
            // Stored where the scanner cannot follow it, such as `_G`, an instance or an
            // unknown table: unknown code can now change it.
            self.escape(&value);
            if self.is_sensitive(&value)
                && path.is_empty()
                && let (Some(root), Some(index)) = (root, root_scope)
                && matches!(
                    self.scopes[index].vars.get(&root),
                    Some(Value::Unknown | Value::Nil)
                )
            {
                self.scopes[index].vars.insert(root, Value::Sensitive);
            }
            return;
        }
        let several = container.candidates().len() > 1;
        for id in tables {
            let (conditional, deferred) = self.table_write_context(id, root_scope);
            let in_loop = self.repeats_since(self.table_reference(id, root_scope));
            let self_referencing = root
                .as_ref()
                .is_some_and(|root| self.references(dependence, root));
            let value = if (deferred && self.depends_on_locals(dependence))
                || (in_loop && self_referencing)
            {
                self.deferred_value(&value)
            } else {
                value.clone()
            };
            if let Some(handler) = self.new_index_handler(id, &key) {
                // `__newindex` receives writes to missing keys.
                let site = Site::between(
                    first_token_of_prefix(target.prefix()),
                    last_token_of_suffix(suffixes[suffixes.len() - 1]),
                );
                self.call_function(
                    handler,
                    vec![Value::Table(id), key.clone(), value],
                    true,
                    site,
                );
                continue;
            }
            self.write_table(id, &key, value, conditional || several);
        }
    }

    /// Before a loop body runs, everything it may change already holds the values a
    /// later iteration could see: the current value, plus the assigned literals when
    /// every assignment in the loop is a literal, otherwise an unknown value. The loop
    /// body is visited once, so without this a read before the write would only see
    /// the value from before the loop.
    fn widen_loop(&mut self, token: &TokenReference) {
        let key = token.token().start_position().bytes();
        let Some(info) = self.loop_targets.get(&key).cloned() else {
            return;
        };
        let added = |literals: &Option<Vec<Value>>| -> Vec<Value> {
            literals.clone().unwrap_or_else(|| vec![Value::Unknown])
        };
        if info.overflow {
            // Too many changes to list: any visible variable or table may change.
            self.widened_everything = true;
            let mut tables = Vec::new();
            for scope in &mut self.scopes {
                for value in scope.vars.values_mut() {
                    if holds_table(value) {
                        tables.push(value.clone());
                    }
                    *value = join([value.clone(), Value::Unknown]);
                }
            }
            for value in tables {
                self.escape(&value);
            }
            return;
        }
        for target in &info.targets {
            match target {
                // A local declared in the loop body is not open yet, so only variables
                // that outlive an iteration are widened.
                LoopTarget::Name(slot, literals) => {
                    if literals.is_none() {
                        self.widened_names.insert(slot.clone());
                    }
                    if let Some(index) = self.slot_scope(slot) {
                        let old = self.scopes[index]
                            .vars
                            .get(slot)
                            .cloned()
                            .unwrap_or(Value::Nil);
                        let value = join(std::iter::once(old).chain(added(literals)));
                        self.scopes[index].vars.insert(slot.clone(), value);
                    }
                }
                LoopTarget::Field(root, key, literals) => {
                    if literals.is_none()
                        && let Some(key) = field_key(key)
                    {
                        self.widened_keys.insert(key);
                    }
                    let Some(container) = self.lookup(root) else {
                        continue;
                    };
                    for id in tables_in(&container) {
                        let old = self
                            .table(id)
                            .and_then(|table| table.raw(key).cloned())
                            .unwrap_or(Value::Nil);
                        let value = join(std::iter::once(old).chain(added(literals)));
                        self.write_table(id, key, value, false);
                    }
                }
                LoopTarget::Table(root) => {
                    if let Some(container) = self.lookup(root) {
                        self.escape(&container);
                    }
                }
            }
        }
    }

    /// The `__newindex` function that a write to `key` would call, if the key is absent.
    fn new_index_handler(&self, id: usize, key: &Value) -> Option<usize> {
        let table = self.table(id)?;
        if table.raw(key).is_some() {
            return None;
        }
        match self.table(table.metatable?)?.fields.get("__newindex") {
            Some(Value::Function(handler)) => Some(*handler),
            _ => None,
        }
    }
}

impl Visitor for Analyzer<'_> {
    fn visit_block(&mut self, block: &Block) {
        let key = block as *const Block as usize;
        let pending = self
            .pending_blocks
            .iter()
            .rposition(|pending| pending.block == key)
            .map(|index| self.pending_blocks.remove(index));
        let (conditional, repeats, bindings) = pending
            .map(|pending| (pending.conditional, pending.repeats, pending.bindings))
            .unwrap_or_default();
        self.push_scope(bindings.into_iter().collect(), conditional, false, repeats);
        let gate = self.branch_gate(block);
        if let Some(scope) = self.scopes.last_mut() {
            scope.gate = gate;
        }
    }

    fn visit_block_end(&mut self, block: &Block) {
        if self.repeat_blocks.last() == Some(&(block as *const Block as usize)) {
            self.repeat_blocks.pop();
            // The `until` condition is visited next. It sees the locals of the body, so
            // the body's scope closes after it.
            self.gate_signal = None;
        } else {
            self.scopes.pop();
        }
    }

    fn visit_if_end(&mut self, _node: &If) {
        self.if_gates.pop();
    }

    fn visit_else_if(&mut self, node: &ElseIf) {
        self.gate_signal = None;
        let gate = self.condition_gate(node.condition());
        if let Some(entry) = self.if_gates.last_mut() {
            entry.else_if_gate = gate;
        }
    }

    fn visit_while_end(&mut self, _node: &While) {
        // Code after a loop that waits for a gate runs only once the gate opens.
        if let Some((_, Some(gate))) = self.while_gates.pop()
            && let Some(scope) = self.scopes.last_mut()
        {
            scope.gate.get_or_insert(gate);
        }
    }

    fn visit_repeat_end(&mut self, repeat: &Repeat) {
        let gate = self
            .condition_gate(repeat.until())
            .or(self.gate_signal.take());
        self.scopes.pop();
        if let Some(gate) = gate
            && let Some(scope) = self.scopes.last_mut()
        {
            scope.gate.get_or_insert(gate);
        }
    }

    fn visit_function_body(&mut self, body: &FunctionBody) {
        let id = self.function_id(body);
        let bound = self.pending_params.take();
        let root = bound.is_some();
        let mut arguments = bound.unwrap_or_default().into_iter();
        let mut vars = BTreeMap::new();
        if self.functions[id].method {
            vars.insert(
                Slot::Local(body_key(body)),
                if root {
                    arguments.next().unwrap_or(Value::Nil)
                } else {
                    Value::Unknown
                },
            );
        }
        let first_parameter = self.functions[id].first_parameter.clone();
        for (position, parameter) in body.parameters().iter().enumerate() {
            match parameter {
                Parameter::Name(token) => {
                    let name = token_text(token);
                    let value = if root {
                        arguments.next().unwrap_or(Value::Nil)
                    } else if let Some(value) = first_parameter.clone().filter(|_| position == 0) {
                        value
                    } else if name.to_ascii_lowercase().contains("player") {
                        Value::Namespace(name)
                    } else {
                        Value::Unknown
                    };
                    vars.insert(self.slot(token), value);
                }
                Parameter::Ellipsis(_) => {
                    let value = if root {
                        Value::Tuple(arguments.by_ref().collect())
                    } else {
                        Value::Unknown
                    };
                    vars.insert(Slot::Vararg, value);
                }
                _ => {}
            }
        }
        // A replay runs the body once, now; a definition may run later or never.
        self.push_scope(vars, !root, !root, false);
        let gate = self.functions[id].gate;
        if let Some(scope) = self.scopes.last_mut() {
            scope.gate = gate;
        }
        self.function_stack.push(FunctionFrame {
            id,
            returns: None,
            root,
            scope: self.scopes.len() - 1,
        });
    }

    fn visit_function_body_end(&mut self, body: &FunctionBody) {
        self.scopes.pop();
        let Some(frame) = self.function_stack.pop() else {
            return;
        };
        if frame.root {
            self.replay_returns = Some(frame.returns.unwrap_or(Value::Nil));
            return;
        }
        if self.replay_site.is_some() {
            return;
        }
        let Some(function) = self.functions.get_mut(frame.id) else {
            return;
        };
        function.visited = true;
        function.returns = match (function.returns.take(), frame.returns) {
            (Some(previous), Some(value)) => Some(join([previous, value])),
            (previous, value) => value.or(previous),
        };
        // Wrappers keep their body for replays, and so do small functions, so a call
        // with a URL, an ID or a table can compute what it returns and what it changes.
        if function.body.is_none() {
            function.body_bytes = body_bytes(body);
            let limit = if function.sinks != 0 {
                MAX_REPLAY_BODY_BYTES
            } else {
                MAX_VALUE_REPLAY_BODY_BYTES
            };
            if function.body_bytes <= limit {
                function.body = Some(Rc::new(body.clone()));
            }
        }
        let pending = std::mem::take(&mut function.pending);
        let sinks = function.sinks;
        for (args, site) in pending {
            if sinks != 0 || args.iter().any(holds_table) {
                self.replay(frame.id, args, site);
            }
        }
    }

    fn visit_local_assignment(&mut self, assignment: &LocalAssignment) {
        let values = self.eval_list(assignment.expressions(), 0);
        let site = Site::between(
            Some(assignment.local_token()),
            assignment
                .expressions()
                .iter()
                .last()
                .and_then(last_token_of_expression)
                .or_else(|| assignment.names().iter().last()),
        );
        for value in &values {
            self.note_value(value, site);
        }
        let slots: Vec<Slot> = assignment
            .names()
            .iter()
            .map(|name| self.slot(name))
            .collect();
        self.note_gate_names(
            slots.iter().cloned().map(Some),
            assignment.expressions().iter(),
        );
        let missing = missing_value(assignment.expressions());
        for (index, slot) in slots.into_iter().enumerate() {
            self.define(
                slot,
                values
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| missing.clone()),
            );
        }
    }

    fn visit_const_assignment(&mut self, assignment: &ConstAssignment) {
        let values = self.eval_list(assignment.expressions(), 0);
        for (index, name) in assignment.names().iter().enumerate() {
            self.define(
                self.slot(name),
                values.get(index).cloned().unwrap_or(Value::Nil),
            );
        }
    }

    fn visit_local_function(&mut self, function: &LocalFunction) {
        let id = self.function_id(function.body());
        let slot = self.slot(function.name());
        self.functions[id].escapes = self.facts.function_escapes(&slot);
        self.define(slot, Value::Function(id));
    }

    fn visit_const_function(&mut self, function: &ConstFunction) {
        let id = self.function_id(function.body());
        let slot = self.slot(function.name());
        self.functions[id].escapes = self.facts.function_escapes(&slot);
        self.define(slot, Value::Function(id));
    }

    fn visit_function_declaration(&mut self, declaration: &FunctionDeclaration) {
        let id = self.function_id(declaration.body());
        self.functions[id].escapes = true;
        let name = declaration.name();
        if name.method_name().is_some() {
            self.functions[id].method = true;
        }
        let tokens: Vec<&TokenReference> = name.names().iter().collect();
        let names: Vec<String> = tokens.iter().map(|token| token_text(token)).collect();
        let field = name.method_name().map(token_text).or_else(|| {
            if names.len() >= 2 {
                names.last().cloned()
            } else {
                None
            }
        });
        match (tokens.as_slice(), field) {
            ([single], None) => {
                self.assign(
                    self.slot(single),
                    Value::Function(id),
                    &Dependence::Expressions(Vec::new()),
                );
            }
            ([root, ..], Some(field)) => {
                let path_len = if name.method_name().is_some() {
                    names.len()
                } else {
                    names.len() - 1
                };
                let mut target = self.lookup(&self.slot(root));
                for segment in names.iter().take(path_len).skip(1) {
                    target = target.map(|value| self.index(value, segment));
                }
                if let Some(Value::Table(table)) = target
                    && let Some(table) = self.tables.get_mut(table)
                    && table.entries() < MAX_TABLE_ENTRIES
                {
                    table.fields.insert(field, Value::Function(id));
                }
            }
            _ => {}
        }
    }

    fn visit_assignment(&mut self, assignment: &Assignment) {
        let values = self.eval_list(assignment.expressions(), 0);
        let rhs: Vec<&Expression> = assignment.expressions().iter().collect();
        let dependence = Dependence::Expressions(rhs);
        let site = Site::between(
            assignment
                .variables()
                .iter()
                .next()
                .and_then(first_token_of_var),
            assignment
                .expressions()
                .iter()
                .last()
                .and_then(last_token_of_expression),
        );
        for value in &values {
            self.note_value(value, site);
        }
        let slots: Vec<Option<Slot>> = assignment
            .variables()
            .iter()
            .map(|var| match var {
                Var::Name(name) => Some(self.slot(name)),
                _ => None,
            })
            .collect();
        self.note_gate_names(slots.iter().cloned(), assignment.expressions().iter());
        let missing = missing_value(assignment.expressions());
        for (index, (var, slot)) in assignment.variables().iter().zip(slots).enumerate() {
            let value = values
                .get(index)
                .cloned()
                .unwrap_or_else(|| missing.clone());
            match (var, slot) {
                (_, Some(slot)) => self.assign(slot, value, &dependence),
                (Var::Expression(target), None) => {
                    self.report_callable_escape(&value, site);
                    self.assign_field(target, value, &dependence);
                }
                _ => {}
            }
        }
    }

    fn visit_compound_assignment(&mut self, assignment: &CompoundAssignment) {
        let op = compound_kind(assignment.compound_operator());
        let old = self.eval_var(assignment.lhs(), 0);
        let right = self.eval(assignment.rhs(), 0);
        let site = Site::between(
            first_token_of_var(assignment.lhs()),
            last_token_of_expression(assignment.rhs()),
        );
        let value = self.binary_at(op, old, right, site);
        match assignment.lhs() {
            Var::Name(name) => self.assign(self.slot(name), value, &Dependence::Always),
            Var::Expression(target) => self.assign_field(target, value, &Dependence::Always),
            _ => {}
        }
    }

    fn visit_generic_for(&mut self, generic_for: &GenericFor) {
        let expressions: Vec<&Expression> = generic_for.expressions().iter().collect();
        let mut iterated = expressions.first().copied();
        if let [Expression::FunctionCall(call)] = expressions.as_slice() {
            let mut suffixes = call.suffixes();
            if let (Prefix::Name(name), Some(Suffix::Call(Call::AnonymousCall(args))), None) =
                (call.prefix(), suffixes.next(), suffixes.next())
                && matches!(token_text(name).as_str(), "ipairs" | "pairs")
                && let FunctionArgs::Parentheses { arguments, .. } = &**args
                && arguments.len() == 1
            {
                iterated = arguments.iter().next();
            }
        }
        // `for k, v in next, t` and `for k, v in next, t, nil` iterate `t` like `pairs`.
        let next_form = matches!(
            expressions.as_slice(),
            [Expression::Var(Var::Name(name)), _] | [Expression::Var(Var::Name(name)), _, _]
                if token_text(name) == "next" && self.lookup(&self.slot(name)).is_none()
        );
        if next_form {
            iterated = expressions.get(1).copied();
        }
        let source = match (expressions.len(), iterated) {
            (1, Some(expression)) => Some(self.eval(expression, 0)),
            (_, Some(expression)) if next_form => Some(self.eval(expression, 0)),
            _ => None,
        };
        let mut bindings: Vec<(Slot, Value)> = generic_for
            .names()
            .iter()
            .map(|token| {
                let name = token_text(token);
                let value = if name.to_ascii_lowercase().contains("player") {
                    Value::Namespace(name)
                } else {
                    Value::Unknown
                };
                (self.slot(token), value)
            })
            .collect();
        if let Some(Value::Namespace(namespace)) = &source
            && is_global_table(namespace)
            && let Some(binding) = bindings.get_mut(1)
        {
            binding.1 = Value::ComputedGlobal;
        }
        // Iterating instances or data read from instances yields more of the same.
        if let Some(element) = match &source {
            Some(Value::InstanceList(element)) => Some((**element).clone()),
            Some(data @ (Value::ExternalData | Value::ModelData(_))) => Some(data.clone()),
            _ => None,
        } && let Some(binding) = bindings.get_mut(1)
        {
            binding.1 = element;
        }
        // `for a, b in s:gmatch(p)`: each name takes that capture of every match.
        if let Some(Value::Matches(items)) = &source {
            for (position, binding) in bindings.iter_mut().enumerate() {
                binding.1 = join(items.iter().map(|item| match item {
                    Value::Tuple(values) => values.get(position).cloned().unwrap_or(Value::Nil),
                    value if position == 0 => value.clone(),
                    _ => Value::Nil,
                }));
            }
        }
        if let Some(Value::Table(id)) = source
            && let Some(table) = self.table(id)
        {
            let mut keys: Vec<Value> = table
                .fields
                .keys()
                .take(4 * MAX_CANDIDATES)
                .map(|key| Value::String(Text::from(key.clone()), None))
                .chain(
                    (1..=table.items.len().min(4 * MAX_CANDIDATES))
                        .map(|index| Value::Number(index as f64, None)),
                )
                .collect();
            let mut values: Vec<Value> = table.values().take(4 * MAX_CANDIDATES).cloned().collect();
            if table.entries() > 4 * MAX_CANDIDATES {
                keys.push(Value::Overflow);
                values.push(Value::Overflow);
            }
            match table.fallback.as_deref() {
                // Attributes of an object: what the content stores, or, when it stores
                // none, values set at runtime.
                Some(data @ (Value::ModelData(_) | Value::ExternalData)) => {
                    if values.is_empty() {
                        keys.push(Value::Unknown);
                        values.push(data.clone());
                    }
                }
                Some(_) => {
                    keys.push(Value::Unknown);
                    values.push(Value::Unknown);
                }
                None => {}
            }
            if table.escaped || self.captured_table_changes(id) {
                keys.push(Value::Unknown);
                values.push(Value::Unknown);
            }
            if let Some(binding) = bindings.get_mut(0) {
                binding.1 = join(keys);
            }
            if let Some(binding) = bindings.get_mut(1) {
                binding.1 = join(values);
            }
        }
        self.widen_loop(generic_for.for_token());
        self.pending_blocks.push(PendingBlock {
            block: generic_for.block() as *const Block as usize,
            conditional: true,
            repeats: true,
            bindings,
        });
    }

    fn visit_numeric_for(&mut self, numeric_for: &NumericFor) {
        let start = self.eval(numeric_for.start(), 0);
        let end = self.eval(numeric_for.end(), 0);
        let value = [start, end]
            .iter()
            .find_map(asset_shaped)
            .map(Value::IdLike)
            .unwrap_or(Value::Unknown);
        self.widen_loop(numeric_for.for_token());
        self.pending_blocks.push(PendingBlock {
            block: numeric_for.block() as *const Block as usize,
            conditional: true,
            repeats: true,
            bindings: vec![(self.slot(numeric_for.index_variable()), value)],
        });
    }

    fn visit_while(&mut self, while_loop: &While) {
        self.widen_loop(while_loop.while_token());
        self.pending_blocks.push(PendingBlock {
            block: while_loop.block() as *const Block as usize,
            conditional: true,
            repeats: true,
            bindings: Vec::new(),
        });
        self.gate_signal = None;
        let gate = self.condition_gate(while_loop.condition());
        self.while_gates
            .push((while_loop.block() as *const Block as usize, gate));
    }

    fn visit_repeat(&mut self, repeat: &Repeat) {
        self.widen_loop(repeat.repeat_token());
        self.pending_blocks.push(PendingBlock {
            block: repeat.block() as *const Block as usize,
            conditional: true,
            repeats: true,
            bindings: Vec::new(),
        });
        self.repeat_blocks
            .push(repeat.block() as *const Block as usize);
    }

    fn visit_if(&mut self, node: &If) {
        // Branches may not run, so writes inside keep the old value as a candidate.
        let mut blocks = vec![node.block()];
        if let Some(branches) = node.else_if() {
            blocks.extend(branches.iter().map(ElseIf::block));
        }
        blocks.extend(node.else_block());
        let blocks: Vec<usize> = blocks
            .into_iter()
            .map(|block| block as *const Block as usize)
            .collect();
        // Pushed last block first, so the block visited next is always on top.
        for block in blocks.iter().rev() {
            self.pending_blocks.push(PendingBlock {
                block: *block,
                conditional: true,
                repeats: false,
                bindings: Vec::new(),
            });
        }
        // The condition is visited next; a gate there controls every branch after it.
        self.gate_signal = None;
        let gate = self.condition_gate(node.condition());
        self.if_gates.push(IfGate {
            blocks,
            has_else: node.else_block().is_some(),
            next: 0,
            gate,
            else_if_gate: None,
        });
    }

    fn visit_field(&mut self, field: &Field) {
        let (value, first): (&Expression, _) = match field {
            Field::NameKey { key, value, .. } => (value, Some(key)),
            Field::ExpressionKey {
                brackets, value, ..
            } => (value, Some(brackets.tokens().0)),
            Field::NoKey(value) => (value, first_token_of_expression(value)),
            _ => return,
        };
        if !may_hold_callable(value) {
            return;
        }
        let site = Site::between(first, last_token_of_expression(value));
        let evaluated = self.eval(value, 0);
        self.report_callable_escape(&evaluated, site);
        self.note_value(&evaluated, site);
    }

    fn visit_return(&mut self, return_statement: &Return) {
        let site = Site::between(
            Some(return_statement.token()),
            return_statement
                .returns()
                .iter()
                .last()
                .and_then(last_token_of_expression)
                .or(Some(return_statement.token())),
        );
        let in_function = !self.function_stack.is_empty();
        // A function other code can call hands what it returns to that code. A table it
        // creates is new on each call, so only tables from outside the function count. A
        // replay returns to the call the scanner is following.
        let handed_out = self
            .function_stack
            .last()
            .filter(|frame| {
                !frame.root
                    && self
                        .functions
                        .get(frame.id)
                        .is_some_and(|function| function.escapes)
            })
            .and_then(|frame| self.scopes.get(frame.scope))
            .map(|scope| scope.serial);
        let mut first = None;
        for (index, expression) in return_statement.returns().iter().enumerate() {
            if !in_function && !may_hold_callable(expression) {
                continue;
            }
            // `local function live() return game.PlaceId == ... end` is a gate check.
            if in_function && self.condition_gate(expression).is_some() {
                self.note_gate_check();
            }
            let value = self.eval(expression, 0);
            if let Some(body) = handed_out {
                for id in tables_in(&value) {
                    if self.table(id).is_some_and(|table| table.home < body) {
                        self.escape(&Value::Table(id));
                    }
                }
            }
            self.report_callable_escape(&value, site);
            self.note_value(&value, site);
            if index == 0 {
                first = Some(value);
            }
        }
        if let Some(frame) = self.function_stack.last_mut() {
            let value = first.unwrap_or(Value::Nil);
            frame.returns = Some(match frame.returns.take() {
                Some(previous) => join([previous, value]),
                None => value,
            });
        }
    }

    fn visit_function_call(&mut self, call: &FunctionCall) {
        self.eval_call(call, 0, true);
    }

    fn visit_var_expression(&mut self, expression: &VarExpression) {
        if expression
            .suffixes()
            .any(|suffix| matches!(suffix, Suffix::Call(_)))
        {
            let value = self.eval_prefix(expression.prefix(), 0);
            self.apply_suffixes(
                value,
                expression.suffixes(),
                0,
                true,
                first_token_of_prefix(expression.prefix()),
            );
        }
    }

    fn visit_expression(&mut self, expression: &Expression) {
        if let Expression::String(token) = expression {
            let raw = token_text(token);
            if raw.len() <= 8192
                && (raw.to_ascii_lowercase().contains("http") || raw.contains('\\'))
            {
                let text = string_value(token);
                self.note_string(&text, Site::token(token));
            }
        }
        // A gate inside an expression controls the calls after it:
        // `not RS:IsStudio() and require(id)`, `if gate then require(id) else nil`.
        let gate = match expression {
            Expression::BinaryOperator { lhs, binop, rhs }
                if matches!(binop_kind(binop), Op::And | Op::Or) && holds_call(rhs) =>
            {
                self.condition_gate(lhs)
            }
            Expression::IfExpression(expression)
                if holds_call(expression.if_expression())
                    || holds_call(expression.else_expression()) =>
            {
                self.condition_gate(expression.condition())
            }
            _ => None,
        };
        if let Some(gate) = gate {
            self.expression_gates
                .push((expression as *const Expression as usize, self.call_gate));
            self.call_gate.get_or_insert(gate);
        }
    }

    fn visit_expression_end(&mut self, expression: &Expression) {
        let key = expression as *const Expression as usize;
        if self
            .expression_gates
            .last()
            .is_some_and(|(open, _)| *open == key)
            && let Some((_, outer)) = self.expression_gates.pop()
        {
            self.call_gate = outer;
        }
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        // `assert(gate)`: the code after it runs only when the gate holds.
        if let Stmt::FunctionCall(call) = stmt
            && let Prefix::Name(name) = call.prefix()
            && token_text(name) == "assert"
            && let Some(Suffix::Call(Call::AnonymousCall(args))) = call.suffixes().next()
            && let FunctionArgs::Parentheses { arguments, .. } = &**args
            && let Some(condition) = arguments.iter().next()
            && let Some(gate) = self.condition_gate(condition)
            && let Some(scope) = self.scopes.last_mut()
        {
            scope.gate.get_or_insert(gate);
        }
    }
}

// ----- binding pre-pass ---------------------------------------------------------------

/// Lexical identity of a variable. Every declaration is its own variable, so a fact
/// about one never applies to another variable with the same name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Slot {
    /// A local, parameter, loop variable or local function, by the byte offset of the
    /// name that declares it. The implicit `self` of a method uses the offset of the
    /// method's parameter list.
    Local(usize),
    /// A global, by name.
    Global(String),
    /// `...` of the function being run.
    Vararg,
}

/// The local each variable name of a script refers to, found once by Luau's scope rules
/// before the analysis. A name with no local in scope is a global.
#[derive(Debug, Default)]
struct Bindings {
    /// Byte offset of every name token that declares a local or refers to one, and the
    /// offset of that local's declaration.
    locals: HashMap<usize, usize>,
}

impl Bindings {
    fn run(ast: &full_moon::ast::Ast) -> Bindings {
        let mut resolver = Resolver::default();
        resolver.visit_ast(ast);
        resolver.bindings
    }

    /// The variable a name token declares or refers to.
    fn slot(&self, token: &TokenReference) -> Slot {
        match self.locals.get(&token.token().start_position().bytes()) {
            Some(declaration) => Slot::Local(*declaration),
            None => Slot::Global(token_text(token)),
        }
    }

    /// The variable the name `name` at byte offset `offset` refers to.
    fn slot_at(&self, offset: usize, name: &str) -> Slot {
        if name == "..." {
            return Slot::Vararg;
        }
        match self.locals.get(&offset) {
            Some(declaration) => Slot::Local(*declaration),
            None => Slot::Global(name.to_string()),
        }
    }
}

/// Walks a script in source order and records the declaration each name refers to.
#[derive(Default)]
struct Resolver {
    /// Every name in scope with the offsets of its declarations, innermost last.
    visible: HashMap<String, Vec<usize>>,
    /// Names declared in each open scope, innermost last.
    scopes: Vec<Vec<String>>,
    /// Loop variables, declared when the loop body opens: the body's address and the
    /// names with their offsets.
    pending: Vec<(usize, Vec<(String, usize)>)>,
    /// Repeat bodies being visited. Their locals stay in scope for `until`.
    repeat_bodies: Vec<usize>,
    /// Bodies of `function t:m()` declarations, by [`body_key`], which declare `self`.
    methods: HashSet<usize>,
    bindings: Bindings,
}

impl Resolver {
    fn declare(&mut self, name: String, offset: usize) {
        self.bindings.locals.insert(offset, offset);
        if let Some(scope) = self.scopes.last_mut() {
            self.visible.entry(name.clone()).or_default().push(offset);
            scope.push(name);
        }
    }

    fn declare_token(&mut self, token: &TokenReference) {
        self.declare(token_text(token), token.token().start_position().bytes());
    }

    fn resolve(&mut self, token: &TokenReference) {
        if let Some(declaration) = self
            .visible
            .get(&token_text(token))
            .and_then(|offsets| offsets.last())
        {
            self.bindings
                .locals
                .insert(token.token().start_position().bytes(), *declaration);
        }
    }

    fn open(&mut self) {
        self.scopes.push(Vec::new());
    }

    fn close(&mut self) {
        for name in self.scopes.pop().unwrap_or_default() {
            if let Some(offsets) = self.visible.get_mut(&name) {
                offsets.pop();
                if offsets.is_empty() {
                    self.visible.remove(&name);
                }
            }
        }
    }
}

impl Visitor for Resolver {
    fn visit_block(&mut self, block: &Block) {
        self.open();
        let address = block as *const Block as usize;
        if let Some(index) = self.pending.iter().rposition(|(body, _)| *body == address) {
            let (_, names) = self.pending.remove(index);
            for (name, offset) in names {
                self.declare(name, offset);
            }
        }
    }

    fn visit_block_end(&mut self, block: &Block) {
        // A repeat body's scope closes after its `until` condition.
        if self.repeat_bodies.last() != Some(&(block as *const Block as usize)) {
            self.close();
        }
    }

    fn visit_repeat(&mut self, node: &Repeat) {
        self.repeat_bodies
            .push(node.block() as *const Block as usize);
    }

    fn visit_repeat_end(&mut self, _node: &Repeat) {
        self.repeat_bodies.pop();
        self.close();
    }

    fn visit_function_declaration(&mut self, node: &FunctionDeclaration) {
        if let Some(root) = node.name().names().iter().next() {
            self.resolve(root);
        }
        if node.name().method_name().is_some() {
            self.methods.insert(body_key(node.body()));
        }
    }

    fn visit_function_body(&mut self, body: &FunctionBody) {
        self.open();
        let key = body_key(body);
        if self.methods.contains(&key) {
            self.declare("self".into(), key);
        }
        for parameter in body.parameters() {
            if let Parameter::Name(name) = parameter {
                self.declare_token(name);
            }
        }
    }

    fn visit_function_body_end(&mut self, _body: &FunctionBody) {
        self.close();
    }

    // A local is in scope after its whole statement, so `local x = x` reads the outer one.
    fn visit_local_assignment_end(&mut self, node: &LocalAssignment) {
        for name in node.names() {
            self.declare_token(name);
        }
    }

    fn visit_const_assignment_end(&mut self, node: &ConstAssignment) {
        for name in node.names() {
            self.declare_token(name);
        }
    }

    // A local function is in scope in its own body.
    fn visit_local_function(&mut self, node: &LocalFunction) {
        self.declare_token(node.name());
    }

    fn visit_const_function(&mut self, node: &ConstFunction) {
        self.declare_token(node.name());
    }

    fn visit_numeric_for(&mut self, node: &NumericFor) {
        let variable = node.index_variable();
        self.pending.push((
            node.block() as *const Block as usize,
            vec![(
                token_text(variable),
                variable.token().start_position().bytes(),
            )],
        ));
    }

    fn visit_generic_for(&mut self, node: &GenericFor) {
        let names = node
            .names()
            .iter()
            .map(|name| (token_text(name), name.token().start_position().bytes()))
            .collect();
        self.pending
            .push((node.block() as *const Block as usize, names));
    }

    fn visit_var(&mut self, var: &Var) {
        if let Var::Name(name) = var {
            self.resolve(name);
        }
    }

    fn visit_prefix(&mut self, prefix: &Prefix) {
        if let Prefix::Name(name) = prefix {
            self.resolve(name);
        }
    }
}

// ----- loop pre-pass ------------------------------------------------------------------

/// Something a loop body may change on each iteration.
#[derive(Debug, Clone)]
enum LoopTarget {
    /// A variable, with the assigned values when every assignment is a literal.
    Name(Slot, Option<Vec<Value>>),
    /// A field with a constant key on a table held by a variable.
    Field(Slot, Value, Option<Vec<Value>>),
    /// A table held by a variable, changed in a way the pass does not follow: a computed
    /// key, a longer path, a method call on it, or a call that receives it.
    Table(Slot),
}

/// What [`LoopFrame::targets`] lists each target under.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LoopKey {
    Name(Slot),
    Field(Slot, String),
    Table(Slot),
}

/// Distinct targets listed per loop; past that, the loop may change anything.
const MAX_LOOP_TARGETS: usize = 256;

#[derive(Debug, Default)]
struct LoopInfo {
    targets: Vec<LoopTarget>,
    overflow: bool,
}

#[derive(Default)]
struct LoopFrame {
    key: usize,
    targets: BTreeMap<LoopKey, LoopTarget>,
    overflow: bool,
}

impl LoopFrame {
    fn add(&mut self, target: LoopTarget) {
        let name = match &target {
            LoopTarget::Name(slot, _) => LoopKey::Name(slot.clone()),
            LoopTarget::Field(root, key, _) => match field_key(key) {
                Some(key) => LoopKey::Field(root.clone(), key),
                None => LoopKey::Table(root.clone()),
            },
            LoopTarget::Table(root) => LoopKey::Table(root.clone()),
        };
        let full = self.targets.len() >= MAX_LOOP_TARGETS;
        match self.targets.get_mut(&name) {
            Some(existing) => {
                let new = match target {
                    LoopTarget::Name(_, literals) | LoopTarget::Field(_, _, literals) => literals,
                    LoopTarget::Table(_) => None,
                };
                if let LoopTarget::Name(_, slot) | LoopTarget::Field(_, _, slot) = existing {
                    *slot = match (slot.take(), new) {
                        (Some(mut old), Some(new)) => {
                            old.extend(new);
                            (old.len() <= MAX_CANDIDATES).then_some(old)
                        }
                        _ => None,
                    };
                }
            }
            None if full => self.overflow = true,
            None => {
                self.targets.insert(name, target);
            }
        }
    }
}

/// One pass over the script that lists, for every loop, what its body may change.
/// Each loop's list includes its inner loops and closures defined in it. The loop
/// header (the bounds or the iterated expression) runs once and is not included.
struct LoopScan<'b> {
    bindings: &'b Bindings,
    stack: Vec<LoopFrame>,
    /// Loop bodies not yet entered: block address and the loop's key.
    bodies: Vec<(usize, usize)>,
    done: HashMap<usize, Rc<LoopInfo>>,
}

impl<'b> LoopScan<'b> {
    fn run(ast: &full_moon::ast::Ast, bindings: &'b Bindings) -> HashMap<usize, Rc<LoopInfo>> {
        let mut scan = LoopScan {
            bindings,
            stack: Vec::new(),
            bodies: Vec::new(),
            done: HashMap::new(),
        };
        scan.visit_ast(ast);
        scan.done
    }

    fn expect_body(&mut self, token: &TokenReference, block: &Block) {
        self.bodies.push((
            block as *const Block as usize,
            token.token().start_position().bytes(),
        ));
    }

    fn close(&mut self) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        if let Some(parent) = self.stack.last_mut() {
            parent.overflow |= frame.overflow;
            for target in frame.targets.values() {
                parent.add(target.clone());
            }
        }
        self.done.insert(
            frame.key,
            Rc::new(LoopInfo {
                targets: frame.targets.into_values().collect(),
                overflow: frame.overflow,
            }),
        );
    }

    fn add(&mut self, target: LoopTarget) {
        if let Some(frame) = self.stack.last_mut() {
            frame.add(target);
        }
    }

    fn assigned(&mut self, var: &Var, literal: Option<Value>) {
        match var {
            Var::Name(name) => self.add(LoopTarget::Name(
                self.bindings.slot(name),
                literal.map(|v| vec![v]),
            )),
            Var::Expression(target) => {
                let Prefix::Name(root) = target.prefix() else {
                    return;
                };
                let root = self.bindings.slot(root);
                let mut suffixes = target.suffixes();
                let key = match (suffixes.next(), suffixes.next()) {
                    (Some(Suffix::Index(Index::Dot { name, .. })), None) => {
                        Some(Value::String(Text::from(token_text(name)), None))
                    }
                    (Some(Suffix::Index(Index::Brackets { expression, .. })), None) => {
                        literal_value(expression).filter(|key| {
                            matches!(key, Value::String(..))
                                || matches!(key, Value::Number(number, _) if integer(*number).is_some())
                        })
                    }
                    _ => None,
                };
                match key {
                    Some(key) => self.add(LoopTarget::Field(root, key, literal.map(|v| vec![v]))),
                    None => self.add(LoopTarget::Table(root)),
                }
            }
            _ => {}
        }
    }
}

impl Visitor for LoopScan<'_> {
    fn visit_numeric_for(&mut self, node: &NumericFor) {
        self.expect_body(node.for_token(), node.block());
    }
    fn visit_generic_for(&mut self, node: &GenericFor) {
        self.expect_body(node.for_token(), node.block());
    }
    fn visit_while(&mut self, node: &While) {
        self.expect_body(node.while_token(), node.block());
    }
    fn visit_repeat(&mut self, node: &Repeat) {
        self.expect_body(node.repeat_token(), node.block());
    }
    fn visit_block(&mut self, block: &Block) {
        let address = block as *const Block as usize;
        if let Some(index) = self.bodies.iter().rposition(|(body, _)| *body == address) {
            let (_, key) = self.bodies.remove(index);
            self.stack.push(LoopFrame {
                key,
                ..LoopFrame::default()
            });
            // The frame closes with this block; mark it so the end can be matched.
            self.bodies.push((address, usize::MAX));
        }
    }
    fn visit_block_end(&mut self, block: &Block) {
        let address = block as *const Block as usize;
        if let Some(index) = self
            .bodies
            .iter()
            .rposition(|(body, key)| *body == address && *key == usize::MAX)
        {
            self.bodies.remove(index);
            self.close();
        }
    }

    fn visit_assignment(&mut self, assignment: &Assignment) {
        if self.stack.is_empty() {
            return;
        }
        let values: Vec<&Expression> = assignment.expressions().iter().collect();
        let simple = values.len() == assignment.variables().len();
        for (index, var) in assignment.variables().iter().enumerate() {
            let literal = if simple {
                values.get(index).and_then(|value| literal_value(value))
            } else {
                None
            };
            self.assigned(var, literal);
        }
    }

    fn visit_compound_assignment(&mut self, assignment: &CompoundAssignment) {
        if !self.stack.is_empty() {
            self.assigned(assignment.lhs(), None);
        }
    }

    fn visit_function_declaration(&mut self, declaration: &FunctionDeclaration) {
        if self.stack.is_empty() {
            return;
        }
        let names: Vec<&TokenReference> = declaration.name().names().iter().collect();
        match names.as_slice() {
            [single] if declaration.name().method_name().is_none() => {
                self.add(LoopTarget::Name(self.bindings.slot(single), None));
            }
            [root, ..] => self.add(LoopTarget::Table(self.bindings.slot(root))),
            _ => {}
        }
    }

    fn visit_function_call(&mut self, call: &FunctionCall) {
        if self.stack.is_empty() {
            return;
        }
        // A method call on a table held by a variable, and any variable argument, may
        // be changed by the callee on every iteration.
        if let Prefix::Name(root) = call.prefix()
            && call
                .suffixes()
                .any(|suffix| matches!(suffix, Suffix::Call(Call::MethodCall(_))))
        {
            self.add(LoopTarget::Table(self.bindings.slot(root)));
        }
        for suffix in call.suffixes() {
            let args = match suffix {
                Suffix::Call(Call::AnonymousCall(args)) => args,
                Suffix::Call(Call::MethodCall(method)) => method.args(),
                _ => continue,
            };
            if let FunctionArgs::Parentheses { arguments, .. } = args {
                for argument in arguments.iter() {
                    match argument {
                        Expression::Var(Var::Name(name)) => {
                            self.add(LoopTarget::Table(self.bindings.slot(name)));
                        }
                        Expression::Var(Var::Expression(expression)) => {
                            if let Prefix::Name(name) = expression.prefix() {
                                self.add(LoopTarget::Table(self.bindings.slot(name)));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

// ----- script pre-pass ----------------------------------------------------------------

/// Values assigned to one variable, or to one field key of the tables a write may reach,
/// anywhere in a script.
#[derive(Debug, Clone, Default)]
struct Assigned {
    /// Literal values, at most [`MAX_CANDIDATES`].
    literals: Vec<Value>,
    /// Some assignment is not a literal, or there were too many to list.
    unknown: bool,
}

impl Assigned {
    fn add(&mut self, literal: Option<Value>) {
        match literal {
            Some(value) if self.literals.iter().any(|old| old.same(&value)) => {}
            Some(value) if self.literals.len() < MAX_CANDIDATES => self.literals.push(value),
            _ => self.unknown = true,
        }
    }

    /// The assigned values as candidates, with an unknown value when some assignment
    /// could not be listed.
    fn values(&self) -> impl Iterator<Item = Value> + '_ {
        self.literals
            .iter()
            .cloned()
            .chain(self.unknown.then_some(Value::Unknown))
    }
}

/// The tables a field write in the script may reach, for [`ScriptFacts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TableKey {
    /// Any table other than a contained one (see [`ScriptFacts::contained_tables`]):
    /// the write goes through a field path, a call, a parameter, a global or a local
    /// that may hold any table, or into a `__newindex` value the scan cannot pin down.
    Any,
    /// Tables made by the table constructor at this byte offset: the write goes through
    /// a local that only ever holds them (see [`ScriptScan::pinned_constructor`]), or
    /// into a `__newindex` table they hold (see [`ScriptScan::table_keys`]).
    Constructor(usize),
}

/// What a whole script assigns, collected in one pass before the analysis. Code that
/// runs later than the analysis sees it, such as a function body that the scanner visits
/// where it is defined, uses this to know what else may have been stored by then. Every
/// fact belongs to one variable (see [`Slot`]) or to the tables a write may reach (see
/// [`TableKey`]), never to a name or a key alone.
#[derive(Debug, Default)]
struct ScriptFacts {
    /// Variables assigned anywhere other than by their declaration: `x = v`, `x += v`
    /// and `function x() end`, with the literal values.
    reassigned: HashMap<Slot, Assigned>,
    /// Locals that are never reassigned and whose declaration is a constant expression
    /// of other such locals.
    constant_slots: HashSet<Slot>,
    /// Field keys written, as `s:name`, `n:index` or [`ANY_FIELD`], by the tables the
    /// write may reach, with the literal values.
    field_writes: HashMap<TableKey, HashMap<String, Assigned>>,
    /// A write with a computed key, `table.clear`, or `rawset` used as a value: any key
    /// of these tables may change.
    any_field_write: HashSet<TableKey>,
    /// `table.insert`, `table.remove`, `table.sort` or `table.move`: integer keys of
    /// these tables may change.
    numeric_field_write: HashSet<TableKey>,
    /// `setmetatable` is used, so a missing key may read differently later.
    metatable_change: bool,
    /// A global is written through `getfenv()` under a name the scan cannot read.
    environment_write: bool,
    /// How often each variable is read as a value, other than as the function of a
    /// call, and how often of those as the callback of `pcall`, `task.spawn` and the
    /// like. A local function with other value uses can reach code the scanner cannot
    /// see.
    value_uses: HashMap<Slot, usize>,
    callback_uses: HashMap<Slot, usize>,
    /// Anonymous functions, by the offset of their parameter list, that are called on
    /// the spot or passed as such a callback, so no other code gets them.
    contained_functions: HashSet<usize>,
    /// Table constructors, by offset, whose tables only one local ever holds, and that
    /// local is only indexed: never read as a value, passed, returned, stored, aliased or
    /// used as a method receiver. Only writes through that local reach these tables.
    contained_tables: HashSet<usize>,
}

impl ScriptFacts {
    /// Whether a local function can reach code the scanner cannot see.
    fn function_escapes(&self, slot: &Slot) -> bool {
        self.value_uses.get(slot).copied().unwrap_or(0)
            > self.callback_uses.get(slot).copied().unwrap_or(0)
    }

    /// Adds the keys under which the writes that may reach a table made by
    /// `constructor` (or by no constructor) are filed. A write through a path, a call
    /// or a parameter is filed under [`TableKey::Any`] and cannot reach a contained
    /// table.
    fn extend_tables(&self, constructor: Option<usize>, tables: &mut Vec<TableKey>) {
        match constructor {
            Some(offset) if self.contained_tables.contains(&offset) => {
                tables.push(TableKey::Constructor(offset));
            }
            Some(offset) => tables.extend([TableKey::Any, TableKey::Constructor(offset)]),
            None => tables.push(TableKey::Any),
        }
    }

    /// Values the script writes to `field` of the tables filed under `tables`.
    fn field_values<'f>(
        &'f self,
        tables: &'f [TableKey],
        field: &'f str,
    ) -> impl Iterator<Item = Value> + 'f {
        tables
            .iter()
            .filter_map(move |table| self.field_writes.get(table)?.get(field))
            .flat_map(Assigned::values)
    }

    /// Whether some write with a computed key may reach the tables filed under
    /// `tables`.
    fn any_key_written(&self, tables: &[TableKey]) -> bool {
        tables
            .iter()
            .any(|table| self.any_field_write.contains(table))
    }

    /// Whether some write of an integer key the scan cannot list may reach them.
    fn numeric_key_written(&self, tables: &[TableKey]) -> bool {
        tables
            .iter()
            .any(|table| self.numeric_field_write.contains(table))
    }

    /// Whether any field write may reach the tables filed under `tables`.
    fn table_written(&self, tables: &[TableKey]) -> bool {
        tables.iter().any(|table| {
            self.field_writes.contains_key(table)
                || self.any_field_write.contains(table)
                || self.numeric_field_write.contains(table)
        })
    }

    /// Whether a missing key of a table made by `constructor` may read differently
    /// later because of `setmetatable`. A contained table never gets a metatable, since
    /// that would pass it as a value.
    fn metatable_may_change(&self, constructor: Option<usize>) -> bool {
        self.metatable_change
            && !constructor.is_some_and(|offset| self.contained_tables.contains(&offset))
    }

    /// What a field of the tables filed under `tables` may hold after the script
    /// wrote it again: the values written to `key` (a canonical key of [`field_key`],
    /// or `None` for a key the scanner cannot fold), and an unknown value when a write
    /// the scan cannot list may have changed it.
    fn later_field_values(&self, tables: &[TableKey], key: Option<&str>) -> Vec<Value> {
        let mut later: Vec<Value> = Vec::new();
        if self.any_key_written(tables) {
            later.extend(self.field_values(tables, ANY_FIELD));
            if let Some(key) = key {
                later.extend(self.field_values(tables, key));
            }
            later.push(Value::Unknown);
        } else {
            match key {
                Some(key) => {
                    later.extend(self.field_values(tables, key));
                    if key.starts_with("n:") && self.numeric_key_written(tables) {
                        later.push(Value::Unknown);
                    }
                }
                None => {
                    if self.table_written(tables) {
                        later.push(Value::Unknown);
                    }
                }
            }
        }
        later
    }
}

/// Offset that identifies a function body, as [`Analyzer::function_id`] uses it.
fn body_key(body: &FunctionBody) -> usize {
    body.parameters_parentheses()
        .tokens()
        .0
        .token()
        .start_position()
        .bytes()
}

/// Key of [`ScriptFacts::field_writes`] for writes under a key the scan cannot read.
const ANY_FIELD: &str = "*";

/// Canonical key of the `__newindex` metatable field.
const NEWINDEX: &str = "s:__newindex";

/// Canonical key of a table field for [`ScriptFacts::field_writes`].
fn field_key(key: &Value) -> Option<String> {
    match key {
        Value::String(text, _) => Some(format!("s:{text}")),
        Value::Number(number, _) => integer(*number).map(|index| format!("n:{index}")),
        _ => None,
    }
}

/// Canonical key of the field an assignment target such as `t.k` or `t[1]` writes,
/// or `None` for a key the scan cannot read.
fn target_key(target: &VarExpression) -> Option<String> {
    match target.suffixes().last() {
        Some(Suffix::Index(Index::Dot { name, .. })) => Some(format!("s:{}", token_text(name))),
        Some(Suffix::Index(Index::Brackets { expression, .. })) => {
            literal_value(expression).and_then(|key| field_key(&key))
        }
        _ => None,
    }
}

/// What a local starts with, for [`ScriptScan`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Initializer {
    /// A table constructor, by the byte offset of its `{`.
    Constructor(usize),
    /// The value of another variable.
    Alias(Slot),
    Other,
}

/// What a local's declaration says: the variables its initializer reads when it is a
/// constant expression, or `None`, and what it starts with.
#[derive(Debug, Clone)]
struct Declaration {
    structure: Option<Vec<Slot>>,
    initializer: Initializer,
}

/// A field write as the scan finds it, before the tables it may reach are known.
struct FieldWrite {
    /// The variable the write goes through when it is the whole path, as in `t.k = v`.
    root: Option<Slot>,
    /// Canonical key, or `None` for a key the scan cannot read.
    key: Option<String>,
    literal: Option<Value>,
}

/// Byte offset of a table constructor's `{`, which identifies the tables it makes.
fn constructor_offset(table: &TableConstructor) -> usize {
    table.braces().tokens().0.token().start_position().bytes()
}

/// The table constructor whose tables `expression` holds, by the offset of its `{`.
fn constructor_of(expression: &Expression) -> Option<usize> {
    match expression {
        Expression::TableConstructor(table) => Some(constructor_offset(table)),
        Expression::Parentheses { expression, .. }
        | Expression::TypeAssertion { expression, .. } => constructor_of(expression),
        _ => None,
    }
}

/// The variable a call argument or an assigned root names, when it is a plain name.
fn named_slot(bindings: &Bindings, expression: Option<&Expression>) -> Option<Slot> {
    match expression? {
        Expression::Var(Var::Name(name)) => Some(bindings.slot(name)),
        Expression::Parentheses { expression, .. }
        | Expression::TypeAssertion { expression, .. } => named_slot(bindings, Some(expression)),
        _ => None,
    }
}

/// What a call that [`EnvironmentReads`] recognized does with its environment. BG004
/// is low for it; every other use of an environment stays high.
#[derive(Debug, Clone)]
enum EnvironmentUse {
    /// `getfenv().it`: reads a name that is not in [`ENVIRONMENT_BUILTINS`].
    Read(String),
    /// `local saved = getfenv(fn).print`: saves an output function, where `saved` is
    /// used at least once and every use is a [`EnvironmentUse::Restore`].
    Save(String),
    /// `getfenv(fn).print = saved`: puts such a saved value back under the same key of
    /// the same environment.
    Restore(String),
    /// `getfenv(fn).print = capture`: `capture` is a local function of the script that
    /// is never assigned again and is closed (see [`BodyFacts`]).
    Replace(String),
}

/// Output functions that a test may swap in an environment to capture what code
/// prints, and put back afterwards.
const OUTPUT_FUNCTIONS: [&str; 2] = ["print", "warn"];

/// Globals and library functions an output capture may call. None of them calls a
/// function it is given, uses a metamethod other than `__tostring` of a value it
/// formats (as `print` itself does), or reads or writes a table other than raw.
const CAPTURE_GLOBALS: [&str; 5] = ["select", "tostring", "tonumber", "type", "typeof"];
const CAPTURE_TABLE: [&str; 8] = [
    "insert", "concat", "pack", "unpack", "create", "clear", "remove", "clone",
];
const CAPTURE_STRING: [&str; 12] = [
    "byte", "char", "find", "format", "len", "lower", "match", "rep", "reverse", "split", "sub",
    "upper",
];

/// Capture library functions whose results are never a table or userdata, so an
/// operator on them runs no metamethod.
const PLAIN_RESULTS: [&str; 15] = [
    "tostring", "tonumber", "type", "typeof", "byte", "char", "find", "format", "len", "lower",
    "match", "rep", "reverse", "sub", "upper",
];

/// What a function body may run, for [`EnvironmentUse::Replace`]. A body is closed
/// when it is not `open`, the globals it calls are never assigned and `table` and
/// `string` never get a field written, every table it indexes or measures is a plain
/// table (see [`EnvironmentReads::plain_tables`]), every loop counter it computes with
/// is never assigned, and every child body and every local function it calls is closed
/// and never assigned again. Anything else may run a function that is chosen
/// elsewhere, also later, such as an upvalue, a field, a method, `pcall`, a generic
/// `for` iterator or a metamethod of an operator or an index.
#[derive(Default)]
struct BodyFacts {
    /// A call of anything not in the capture lists or a local function, an index of
    /// anything but a local, a generic `for`, or an operator other than `and`, `or` and
    /// `not` on a value that may be a table.
    open: bool,
    /// Capture globals and libraries the body calls.
    globals: Vec<&'static str>,
    /// Local functions the body calls, by declaration.
    local_calls: Vec<usize>,
    /// Function bodies defined in it, by [`body_key`].
    children: Vec<usize>,
    /// Locals the body indexes or measures with `#`, which must be plain tables.
    tables: Vec<usize>,
    /// Locals used as numbers in operators, which must be numeric `for` counters that
    /// are never assigned.
    counters: Vec<usize>,
}

/// The environment a `getfenv` call names: no argument, a number literal, or a local
/// such as the function under test.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EnvironmentArgument {
    Current,
    Level(String),
    Local(usize),
}

/// A single write `getfenv(..).print = name`.
struct OutputWrite {
    end: usize,
    key: String,
    environment: EnvironmentArgument,
    value: Slot,
}

/// Calls such as `getfenv().it` whose result is only read once, at a constant name
/// that is not in [`ENVIRONMENT_BUILTINS`]: the call takes no argument or one number
/// literal and is followed directly by `.name` or `["name"]`. Each is keyed by the end
/// of the call. A call whose key is the last one of an assignment target, such as
/// `getfenv().x = v`, writes the environment and is left out. Also the saves, restores
/// and replacements of `print` and `warn` that output capturing tests do (see
/// [`EnvironmentUse`]), with the call taking no argument, a number literal or a local.
/// Which function the call reaches is decided by the analyzer.
struct EnvironmentReads<'b> {
    bindings: &'b Bindings,
    reads: HashMap<usize, String>,
    writes: HashSet<usize>,
    /// `local saved = getfenv(..).print`, by the declaration of `saved`: the key, the
    /// environment and the end of the call.
    saves: HashMap<usize, (String, EnvironmentArgument, usize)>,
    output_writes: Vec<OutputWrite>,
    /// Uses of each saved local by name, by declaration, and the locals assigned again.
    uses: HashMap<usize, usize>,
    assigned: HashSet<usize>,
    /// Local functions: the declaration of the name, with the body's [`body_key`].
    local_functions: HashMap<usize, usize>,
    /// Function bodies being walked, innermost last, and the facts of every body.
    frames: Vec<(usize, BodyFacts)>,
    bodies: HashMap<usize, BodyFacts>,
    /// Globals assigned by name or declared with `function`, and globals whose field
    /// is written, such as `table` in `table.insert = f`.
    assigned_globals: HashSet<String>,
    written_fields: HashSet<String>,
    /// `local t = {..}`, `table.pack(..)` or `table.create(..)`, by declaration, with
    /// whether the table library made it, and the uses of each that keep it plain.
    table_locals: HashMap<usize, bool>,
    plain_uses: HashMap<usize, usize>,
    /// Numeric `for` counters, by declaration.
    counters: HashSet<usize>,
}

impl<'b> EnvironmentReads<'b> {
    fn run(ast: &full_moon::ast::Ast, bindings: &'b Bindings) -> HashMap<usize, EnvironmentUse> {
        let mut scan = EnvironmentReads {
            bindings,
            reads: HashMap::new(),
            writes: HashSet::new(),
            saves: HashMap::new(),
            output_writes: Vec::new(),
            uses: HashMap::new(),
            assigned: HashSet::new(),
            local_functions: HashMap::new(),
            frames: Vec::new(),
            bodies: HashMap::new(),
            assigned_globals: HashSet::new(),
            written_fields: HashSet::new(),
            table_locals: HashMap::new(),
            plain_uses: HashMap::new(),
            counters: HashSet::new(),
        };
        scan.visit_ast(ast);
        let writes = std::mem::take(&mut scan.writes);
        let mut uses: HashMap<usize, EnvironmentUse> = scan
            .reads
            .drain()
            .filter(|(end, _)| !writes.contains(end))
            .map(|(end, name)| (end, EnvironmentUse::Read(name)))
            .collect();
        // Writes by the local they write, so each save looks only at its own.
        let mut writes_of: HashMap<usize, Vec<&OutputWrite>> = HashMap::new();
        for write in &scan.output_writes {
            if let Slot::Local(declaration) = write.value {
                writes_of.entry(declaration).or_default().push(write);
            }
        }
        // A saved value counts only when its local is put back and has no other use, and
        // the local that names the environment always names the same one.
        for (declaration, (key, environment, end)) in &scan.saves {
            if scan.assigned.contains(declaration)
                || matches!(environment, EnvironmentArgument::Local(name) if scan.assigned.contains(name))
            {
                continue;
            }
            let restores: Vec<usize> = writes_of
                .get(declaration)
                .into_iter()
                .flatten()
                .filter(|write| write.key == *key && write.environment == *environment)
                .map(|write| write.end)
                .collect();
            if !restores.is_empty()
                && restores.len() == scan.uses.get(declaration).copied().unwrap_or(0)
            {
                uses.insert(*end, EnvironmentUse::Save(key.clone()));
                for end in restores {
                    uses.insert(end, EnvironmentUse::Restore(key.clone()));
                }
            }
        }
        let replacements: Vec<&OutputWrite> = scan
            .output_writes
            .iter()
            .filter(|write| !uses.contains_key(&write.end))
            .collect();
        if replacements.is_empty() {
            return uses;
        }
        let open = scan.open_bodies();
        for write in replacements {
            if let Slot::Local(declaration) = write.value
                && !scan.assigned.contains(&declaration)
                && let Some(body) = scan.local_functions.get(&declaration)
                && scan.bodies.contains_key(body)
                && !open.contains(body)
            {
                uses.insert(write.end, EnvironmentUse::Replace(write.key.clone()));
            }
        }
        uses
    }

    /// Bodies that are not closed (see [`BodyFacts`]): open themselves, or defining or
    /// calling one that is, found by walking callers back from each open body.
    fn open_bodies(&self) -> HashSet<usize> {
        let plain = self.plain_tables();
        let mut open = HashSet::new();
        let mut callers: HashMap<usize, Vec<usize>> = HashMap::new();
        for (key, facts) in &self.bodies {
            let mut own = facts.open
                || facts.globals.iter().any(|name| self.library_changed(name))
                || facts.tables.iter().any(|table| !plain.contains(table))
                || facts.counters.iter().any(|counter| {
                    !self.counters.contains(counter) || self.assigned.contains(counter)
                });
            for child in &facts.children {
                callers.entry(*child).or_default().push(*key);
            }
            for declaration in &facts.local_calls {
                match self.local_functions.get(declaration) {
                    Some(body) if !self.assigned.contains(declaration) => {
                        callers.entry(*body).or_default().push(*key);
                    }
                    _ => own = true,
                }
            }
            if own {
                open.insert(*key);
            }
        }
        let mut work: Vec<usize> = open.iter().copied().collect();
        while let Some(key) = work.pop() {
            for caller in callers.get(&key).into_iter().flatten() {
                if open.insert(*caller) {
                    work.push(*caller);
                }
            }
        }
        open
    }

    /// Whether the script assigns the global `name` or writes a field of it.
    fn library_changed(&self, name: &str) -> bool {
        self.assigned_globals.contains(name) || self.written_fields.contains(name)
    }

    /// Table locals that never get a metatable: made by a constructor, `table.pack` or
    /// `table.create`, never assigned again, and only indexed, measured with `#`,
    /// iterated as `for .. in t`, or passed first to `table.insert`, `concat`, `clear`,
    /// `remove`, `unpack` or `clone`, which keep no reference to it. Any other use, such
    /// as `setmetatable(t, mt)`, a method call, an alias or passing it on, may give it
    /// one.
    fn plain_tables(&self) -> HashSet<usize> {
        self.table_locals
            .iter()
            .filter(|(declaration, library)| {
                !self.assigned.contains(*declaration)
                    && (!**library || !self.library_changed("table"))
                    && self.uses.get(*declaration) == self.plain_uses.get(*declaration)
            })
            .map(|(declaration, _)| *declaration)
            .collect()
    }

    /// Marks the body being walked as open.
    fn mark_open(&mut self) {
        if let Some((_, facts)) = self.frames.last_mut() {
            facts.open = true;
        }
    }

    fn need_table(&mut self, declaration: usize) {
        if let Some((_, facts)) = self.frames.last_mut() {
            facts.tables.push(declaration);
        }
    }

    fn need_global(&mut self, global: &'static str) {
        if let Some((_, facts)) = self.frames.last_mut()
            && !facts.globals.contains(&global)
        {
            facts.globals.push(global);
        }
    }

    /// `name(..)` of a capture global that no local shadows.
    fn global_call(&self, call: &FunctionCall) -> Option<&'static str> {
        let Prefix::Name(name) = call.prefix() else {
            return None;
        };
        let suffixes: Vec<&Suffix> = call.suffixes().collect();
        if !matches!(suffixes.as_slice(), [Suffix::Call(Call::AnonymousCall(_))])
            || self.local_declaration(name).is_some()
        {
            return None;
        }
        let text = token_text(name);
        CAPTURE_GLOBALS
            .iter()
            .copied()
            .find(|global| *global == text)
    }

    /// `table.name(..)` or `string.name(..)` of a capture library function, with the
    /// library, the member and the arguments.
    fn library_call<'c>(
        &self,
        call: &'c FunctionCall,
    ) -> Option<(&'static str, &'static str, &'c FunctionArgs)> {
        let Prefix::Name(name) = call.prefix() else {
            return None;
        };
        let suffixes: Vec<&Suffix> = call.suffixes().collect();
        let [
            Suffix::Index(Index::Dot { name: member, .. }),
            Suffix::Call(Call::AnonymousCall(args)),
        ] = suffixes.as_slice()
        else {
            return None;
        };
        if self.local_declaration(name).is_some() {
            return None;
        }
        let member = token_text(member);
        let (library, members): (&'static str, &[&'static str]) = match token_text(name).as_str() {
            "table" => ("table", &CAPTURE_TABLE),
            "string" => ("string", &CAPTURE_STRING),
            _ => return None,
        };
        let member = members.iter().copied().find(|known| *known == member)?;
        Some((library, member, &**args))
    }

    /// Files a call in the body being walked: `name(..)` of a capture global or a local
    /// function, or `table.name(..)` and `string.name(..)` of a capture library function.
    /// Anything else, including a method call or a chain, makes the body open.
    fn capture_call(&mut self, call: &FunctionCall) {
        if self.frames.is_empty() {
            return;
        }
        if let Prefix::Name(name) = call.prefix()
            && let Some(declaration) = self.local_declaration(name)
            && matches!(
                call.suffixes().collect::<Vec<_>>().as_slice(),
                [Suffix::Call(Call::AnonymousCall(_))]
            )
        {
            if let Some((_, facts)) = self.frames.last_mut() {
                facts.local_calls.push(declaration);
            }
            return;
        }
        match self
            .global_call(call)
            .or_else(|| self.library_call(call).map(|(library, _, _)| library))
        {
            Some(global) => self.need_global(global),
            None => self.mark_open(),
        }
    }

    /// Whether an operand can never be a table or userdata, so an operator on it runs
    /// no metamethod: a literal, `not`, `#`, arithmetic of such operands, a numeric
    /// `for` counter, `select("#", ..)`, an interpolated string, or a capture library
    /// call that returns strings or numbers. Records what that depends on.
    fn plain_operand(&mut self, expression: &Expression) -> bool {
        match expression {
            Expression::Number(_) | Expression::String(_) | Expression::InterpolatedString(_) => {
                true
            }
            Expression::Symbol(token) => {
                matches!(token_text(token).as_str(), "nil" | "true" | "false")
            }
            Expression::Parentheses { expression, .. } => self.plain_operand(expression),
            Expression::UnaryOperator { unop, expression } => match unop {
                UnOp::Not(_) => true,
                UnOp::Hash(_) => self.measurable(expression),
                _ => self.plain_operand(expression),
            },
            Expression::BinaryOperator { lhs, rhs, .. } => {
                self.plain_operand(lhs) && self.plain_operand(rhs)
            }
            Expression::Var(Var::Name(name)) => match self.local_declaration(name) {
                Some(declaration) if self.counters.contains(&declaration) => {
                    if let Some((_, facts)) = self.frames.last_mut() {
                        facts.counters.push(declaration);
                    }
                    true
                }
                _ => false,
            },
            Expression::FunctionCall(call) => {
                if let Some(global) = self.global_call(call) {
                    let counts = global == "select"
                        && matches!(
                            call_arguments(call).and_then(|arguments| arguments.iter().next()),
                            Some(Expression::String(token)) if string_value(token) == "#"
                        );
                    if counts || PLAIN_RESULTS.contains(&global) {
                        self.need_global(global);
                        return true;
                    }
                    return false;
                }
                match self.library_call(call) {
                    Some((library, member, _))
                        if PLAIN_RESULTS.contains(&member)
                            || (library, member) == ("table", "concat") =>
                    {
                        self.need_global(library);
                        true
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Whether `#` of an operand runs no `__len`: a string, a table constructor or a
    /// local that must be a plain table.
    fn measurable(&mut self, expression: &Expression) -> bool {
        match expression {
            Expression::TableConstructor(_) => true,
            Expression::Parentheses { expression, .. } => self.measurable(expression),
            Expression::Var(Var::Name(name)) => match self.local_declaration(name) {
                Some(declaration) => {
                    self.need_table(declaration);
                    true
                }
                None => false,
            },
            other => self.plain_operand(other),
        }
    }

    /// A use of a table local that keeps it plain (see [`Self::plain_tables`]).
    fn plain_use(&mut self, name: &TokenReference) {
        if let Some(declaration) = self.local_declaration(name)
            && self.table_locals.contains_key(&declaration)
        {
            *self.plain_uses.entry(declaration).or_default() += 1;
        }
    }

    /// `getfenv(args).print` or `getfenv(args)["warn"]` as a whole expression: the end
    /// of the call, the key and the environment.
    fn output_access(
        &self,
        target: &VarExpression,
    ) -> Option<(usize, String, EnvironmentArgument)> {
        let Prefix::Name(_) = target.prefix() else {
            return None;
        };
        let suffixes: Vec<&Suffix> = target.suffixes().collect();
        let [
            call @ Suffix::Call(Call::AnonymousCall(args)),
            Suffix::Index(index),
        ] = suffixes.as_slice()
        else {
            return None;
        };
        let key = constant_index(index)?;
        if !OUTPUT_FUNCTIONS.contains(&key.as_str()) {
            return None;
        }
        let FunctionArgs::Parentheses { arguments, .. } = &**args else {
            return None;
        };
        let mut values = arguments.iter();
        let environment = match (values.next(), values.next()) {
            (None, _) => EnvironmentArgument::Current,
            (Some(Expression::Number(number)), None) => {
                EnvironmentArgument::Level(token_text(number))
            }
            (Some(Expression::Var(Var::Name(name))), None) => match self.bindings.slot(name) {
                Slot::Local(declaration) => EnvironmentArgument::Local(declaration),
                _ => return None,
            },
            _ => return None,
        };
        Some((suffix_end(call)?, key, environment))
    }

    /// The local a name refers to, by its declaration.
    fn local_declaration(&self, name: &TokenReference) -> Option<usize> {
        self.bindings
            .locals
            .get(&name.token().start_position().bytes())
            .copied()
    }

    // Only the uses of saved locals and table locals are counted. A use comes after its
    // declaration in source order, which is the order of the walk, so it is known.
    fn count_use(&mut self, name: &TokenReference) {
        if self.saves.is_empty() && self.table_locals.is_empty() {
            return;
        }
        if let Some(declaration) = self.local_declaration(name)
            && (self.saves.contains_key(&declaration)
                || self.table_locals.contains_key(&declaration))
        {
            *self.uses.entry(declaration).or_default() += 1;
        }
    }

    fn count_assignment(&mut self, name: &TokenReference) {
        match self.local_declaration(name) {
            Some(declaration) => {
                self.assigned.insert(declaration);
            }
            None => {
                self.assigned_globals.insert(token_text(name));
            }
        }
    }

    /// A write through a field or an index of a global, such as `table.insert = f`,
    /// writes a field of that global.
    fn field_write(&mut self, target: &VarExpression) {
        if let Prefix::Name(root) = target.prefix()
            && self.local_declaration(root).is_none()
        {
            self.written_fields.insert(token_text(root));
        }
    }

    fn chain<'s>(&mut self, suffixes: impl Iterator<Item = &'s Suffix>) {
        let suffixes: Vec<&Suffix> = suffixes.collect();
        for pair in suffixes.windows(2) {
            let (Suffix::Call(Call::AnonymousCall(args)), Suffix::Index(index)) =
                (pair[0], pair[1])
            else {
                continue;
            };
            if let Some(name) = environment_read_name(args, index)
                && let Some(end) = suffix_end(pair[0])
            {
                self.reads.insert(end, name);
            }
        }
    }

    fn target(&mut self, target: &VarExpression) {
        let suffixes: Vec<&Suffix> = target.suffixes().collect();
        if let [.., call @ Suffix::Call(_), Suffix::Index(_)] = suffixes.as_slice()
            && let Some(end) = suffix_end(call)
        {
            self.writes.insert(end);
        }
    }
}

impl Visitor for EnvironmentReads<'_> {
    fn visit_function_body(&mut self, body: &FunctionBody) {
        let key = body_key(body);
        if let Some((_, parent)) = self.frames.last_mut() {
            parent.children.push(key);
        }
        self.frames.push((key, BodyFacts::default()));
    }

    fn visit_function_body_end(&mut self, _body: &FunctionBody) {
        if let Some((key, facts)) = self.frames.pop() {
            self.bodies.insert(key, facts);
        }
    }

    fn visit_function_call(&mut self, call: &FunctionCall) {
        self.chain(call.suffixes());
        self.capture_call(call);
        // `t.f(..)` passes nothing of `t`, and these library functions keep no
        // reference to the table they get first.
        if let Prefix::Name(name) = call.prefix()
            && matches!(call.suffixes().next(), Some(Suffix::Index(_)))
        {
            self.plain_use(name);
        }
        if let Some(("table", "insert" | "concat" | "clear" | "remove" | "unpack" | "clone", _)) =
            self.library_call(call)
            && let Some(Expression::Var(Var::Name(table))) =
                call_arguments(call).and_then(|arguments| arguments.iter().next())
        {
            self.plain_use(table);
        }
    }

    // A field or index may reach an `__index` or `__newindex` function, except on a
    // local that is a plain table.
    fn visit_var_expression(&mut self, expression: &VarExpression) {
        self.chain(expression.suffixes());
        let mut suffixes = expression.suffixes();
        let first = suffixes.next();
        if let Prefix::Name(name) = expression.prefix() {
            if matches!(first, Some(Suffix::Index(_))) {
                self.plain_use(name);
            }
            if let (Some(Suffix::Index(_)), None, Some(declaration)) =
                (first, suffixes.next(), self.local_declaration(name))
            {
                self.need_table(declaration);
                return;
            }
        }
        self.mark_open();
    }

    // A generic `for` calls its iterator. `for .. in t` keeps `t` plain.
    fn visit_generic_for(&mut self, node: &GenericFor) {
        let mut expressions = node.expressions().iter();
        if let (Some(Expression::Var(Var::Name(name))), None) =
            (expressions.next(), expressions.next())
        {
            self.plain_use(name);
        }
        self.mark_open();
    }

    fn visit_numeric_for(&mut self, node: &NumericFor) {
        self.counters
            .insert(node.index_variable().token().start_position().bytes());
    }

    // An operator other than `and`, `or` and `not` may call a metamethod, unless every
    // operand is plain.
    fn visit_expression(&mut self, expression: &Expression) {
        if let Expression::UnaryOperator {
            unop: UnOp::Hash(_),
            expression: operand,
        } = expression
            && let Expression::Var(Var::Name(name)) = &**operand
        {
            self.plain_use(name);
        }
        if self.frames.is_empty() {
            return;
        }
        let closed = match expression {
            Expression::BinaryOperator { binop, lhs, rhs } => {
                matches!(binop, BinOp::And(_) | BinOp::Or(_))
                    || (self.plain_operand(lhs) && self.plain_operand(rhs))
            }
            Expression::UnaryOperator { unop, expression } => match unop {
                UnOp::Not(_) => true,
                UnOp::Hash(_) => self.measurable(expression),
                _ => self.plain_operand(expression),
            },
            _ => true,
        };
        if !closed {
            self.mark_open();
        }
    }

    fn visit_assignment(&mut self, assignment: &Assignment) {
        for var in assignment.variables() {
            match var {
                Var::Expression(target) => {
                    self.target(target);
                    self.field_write(target);
                }
                Var::Name(name) => self.count_assignment(name),
                _ => {}
            }
        }
        let mut targets = assignment.variables().iter();
        let mut values = assignment.expressions().iter();
        if let (Some(Var::Expression(target)), None, Some(Expression::Var(Var::Name(value))), None) =
            (targets.next(), targets.next(), values.next(), values.next())
            && let Some((end, key, environment)) = self.output_access(target)
        {
            self.output_writes.push(OutputWrite {
                end,
                key,
                environment,
                value: self.bindings.slot(value),
            });
        }
    }

    // A compound operator may call a metamethod.
    fn visit_compound_assignment(&mut self, assignment: &CompoundAssignment) {
        match assignment.lhs() {
            Var::Expression(target) => {
                self.target(target);
                self.field_write(target);
            }
            Var::Name(name) => self.count_assignment(name),
            _ => {}
        }
        self.mark_open();
    }

    fn visit_local_assignment(&mut self, assignment: &LocalAssignment) {
        let mut names = assignment.names().iter();
        let mut values = assignment.expressions().iter();
        let (Some(name), None, Some(value), None) =
            (names.next(), names.next(), values.next(), values.next())
        else {
            return;
        };
        let declaration = name.token().start_position().bytes();
        match value {
            Expression::Var(Var::Expression(read)) => {
                if let Some((end, key, environment)) = self.output_access(read) {
                    self.saves.insert(declaration, (key, environment, end));
                }
            }
            Expression::TableConstructor(_) => {
                self.table_locals.insert(declaration, false);
            }
            Expression::FunctionCall(call) => {
                if let Some(("table", "pack" | "create", _)) = self.library_call(call) {
                    self.table_locals.insert(declaration, true);
                }
            }
            _ => {}
        }
    }

    fn visit_local_function(&mut self, function: &LocalFunction) {
        self.local_functions.insert(
            function.name().token().start_position().bytes(),
            body_key(function.body()),
        );
    }

    // `function name()` and `function name.field()` change or use the local `name`.
    fn visit_function_declaration(&mut self, declaration: &FunctionDeclaration) {
        if let Some(root) = declaration.name().names().iter().next() {
            self.count_use(root);
            self.count_assignment(root);
        }
    }

    fn visit_var(&mut self, var: &Var) {
        if let Var::Name(name) = var {
            self.count_use(name);
        }
    }

    fn visit_prefix(&mut self, prefix: &Prefix) {
        if let Prefix::Name(name) = prefix {
            self.count_use(name);
        }
    }
}

/// The arguments of a call that ends in one parenthesized argument list.
fn call_arguments(call: &FunctionCall) -> Option<&Punctuated<Expression>> {
    match call.suffixes().last() {
        Some(Suffix::Call(Call::AnonymousCall(args))) => match &**args {
            FunctionArgs::Parentheses { arguments, .. } => Some(arguments),
            _ => None,
        },
        _ => None,
    }
}

/// A constant key: `.name` or `["name"]`.
fn constant_index(index: &Index) -> Option<String> {
    match index {
        Index::Dot { name, .. } => Some(token_text(name)),
        Index::Brackets { expression, .. } => match &**expression {
            Expression::String(token) => Some(string_value(token)),
            _ => None,
        },
        _ => None,
    }
}

/// The name `getfenv(args)` followed by `index` reads, when that read reaches no
/// builtin: `args` is empty or one number literal, and `index` is a constant name.
fn environment_read_name(args: &FunctionArgs, index: &Index) -> Option<String> {
    let FunctionArgs::Parentheses { arguments, .. } = args else {
        return None;
    };
    let mut values = arguments.iter();
    match (values.next(), values.next()) {
        (None, _) | (Some(Expression::Number(_)), None) => {}
        _ => return None,
    }
    let name = constant_index(index)?;
    (!ENVIRONMENT_BUILTINS.contains(&name.as_str())).then_some(name)
}

/// Byte offset where a suffix ends, the key of [`EnvironmentReads`]. It matches the end
/// of the site that [`Analyzer::apply_suffixes`] gives the call.
fn suffix_end(suffix: &Suffix) -> Option<usize> {
    last_token_of_suffix(suffix).map(|token| token.token().end_position().bytes())
}

struct ScriptScan<'b> {
    bindings: &'b Bindings,
    facts: ScriptFacts,
    /// The declaration of each local.
    declarations: HashMap<Slot, Declaration>,
    field_writes: Vec<FieldWrite>,
    /// Writes of integer keys, and writes with any key, with the variable they go
    /// through when it is a plain name.
    numeric_writes: Vec<Option<Slot>>,
    any_writes: Vec<Option<Slot>>,
    /// Variables used as the receiver of a method call, `t:m()`, which passes them.
    method_receivers: HashSet<Slot>,
    /// Locals declared as a function.
    local_functions: HashSet<Slot>,
    /// Values stored under the key `__newindex` other than functions, each after the
    /// table it is stored in. As a field of a metatable such a value receives the
    /// writes to missing keys of the tables that have that metatable.
    redirects: Vec<(TableRef, TableRef)>,
    /// The tables those values may hold, filled in [`ScriptScan::finish`].
    redirect_tables: Vec<TableKey>,
    /// The table and the metatable of each call of the global `setmetatable` whose
    /// metatable may be a table.
    metatable_calls: Vec<(TableRef, TableRef)>,
    /// Table constructors written as the metatable of such a call.
    metatable_constructors: HashSet<usize>,
    /// How often each variable is passed as the metatable of such a call.
    metatable_uses: HashMap<Slot, usize>,
    /// `getmetatable` is used, so a metatable may reach code the scan does not see.
    metatable_read: bool,
    /// The constructors whose tables may get a metatable with a `__newindex` table,
    /// or `None` when that may be any table that is not contained. Filled in
    /// [`ScriptScan::finish`].
    redirected: Option<HashSet<usize>>,
}

/// The tables an expression may be, as [`ScriptScan`] finds it: a value stored under
/// the key `__newindex`, the table it is stored in, or an argument of `setmetatable`.
enum TableRef {
    /// The tables of the table constructor at this offset.
    Constructor(usize),
    /// The value of a variable.
    Name(Slot),
    /// Any value.
    Any,
}

impl TableRef {
    /// The tables `expression` may be: those of a constructor written there, the
    /// value of a plain name, or any value.
    fn of(bindings: &Bindings, expression: &Expression) -> Self {
        match (
            constructor_of(expression),
            named_slot(bindings, Some(expression)),
        ) {
            (Some(constructor), _) => TableRef::Constructor(constructor),
            (None, Some(slot)) => TableRef::Name(slot),
            (None, None) => TableRef::Any,
        }
    }
}

impl<'b> ScriptScan<'b> {
    fn run(ast: &full_moon::ast::Ast, bindings: &'b Bindings) -> ScriptFacts {
        let mut scan = ScriptScan {
            bindings,
            facts: ScriptFacts::default(),
            declarations: HashMap::new(),
            field_writes: Vec::new(),
            numeric_writes: Vec::new(),
            any_writes: Vec::new(),
            method_receivers: HashSet::new(),
            local_functions: HashSet::new(),
            redirects: Vec::new(),
            redirect_tables: Vec::new(),
            metatable_calls: Vec::new(),
            metatable_constructors: HashSet::new(),
            metatable_uses: HashMap::new(),
            metatable_read: false,
            redirected: None,
        };
        scan.visit_ast(ast);
        scan.finish()
    }

    /// `t:m()` as the start of a call or a path passes `t` to the method.
    fn note_receiver<'s>(
        &mut self,
        prefix: &Prefix,
        mut suffixes: impl Iterator<Item = &'s Suffix>,
    ) {
        if let (Prefix::Name(root), Some(Suffix::Call(Call::MethodCall(_)))) =
            (prefix, suffixes.next())
        {
            self.method_receivers.insert(self.bindings.slot(root));
        }
    }

    fn declare(&mut self, name: &TokenReference, declaration: Declaration) {
        self.declarations
            .insert(self.bindings.slot(name), declaration);
    }

    fn declare_unknown(&mut self, name: &TokenReference) {
        self.declare(
            name,
            Declaration {
                structure: None,
                initializer: Initializer::Other,
            },
        );
    }

    fn declare_list<'e, 'n>(
        &mut self,
        names: impl Iterator<Item = &'n TokenReference>,
        expressions: impl Iterator<Item = &'e Expression>,
    ) {
        let expressions: Vec<&Expression> = expressions.collect();
        // A call or `...` in the last position fills the names after it.
        let spreads = expressions.last().is_some_and(|last| may_spread(last));
        for (index, name) in names.enumerate() {
            let expression = expressions.get(index).copied();
            let structure = match expression {
                Some(expression) => constant_structure(expression).map(|names| {
                    names
                        .into_iter()
                        .map(|name| self.bindings.slot(name))
                        .collect()
                }),
                None if spreads => None,
                None => Some(Vec::new()),
            };
            let initializer = match (
                expression.and_then(constructor_of),
                named_slot(self.bindings, expression),
            ) {
                (Some(constructor), _) => Initializer::Constructor(constructor),
                (None, Some(slot)) => Initializer::Alias(slot),
                (None, None) => Initializer::Other,
            };
            if let Some(Expression::Function(_)) = expression {
                self.local_functions.insert(self.bindings.slot(name));
            }
            self.declare(
                name,
                Declaration {
                    structure,
                    initializer,
                },
            );
        }
    }

    fn reassign(&mut self, slot: Slot, literal: Option<Value>) {
        self.facts.reassigned.entry(slot).or_default().add(literal);
    }

    fn field_write(&mut self, root: Option<Slot>, key: Option<String>, literal: Option<Value>) {
        self.field_writes.push(FieldWrite { root, key, literal });
    }

    /// `value` stored under the key `__newindex` of `holder`, or `None` when the scan
    /// cannot see it. A function there is called for a write and its own writes count
    /// as usual, and a value that is no table receives nothing.
    fn note_newindex(&mut self, holder: TableRef, value: Option<&Expression>) {
        let redirect = match value {
            Some(Expression::Function(_)) => return,
            Some(value) if literal_value(value).is_some() => return,
            Some(value) => TableRef::of(self.bindings, value),
            None => TableRef::Any,
        };
        self.redirects.push((holder, redirect));
    }

    /// A call of the global `setmetatable` with `arguments`. A metatable that is `nil`
    /// or another literal sets no `__newindex`.
    fn note_metatable_call(&mut self, arguments: &Punctuated<Expression>) {
        let arguments: Vec<&Expression> = arguments.iter().collect();
        let (table, metatable) = match (arguments.first(), arguments.get(1)) {
            (_, Some(metatable)) if literal_value(metatable).is_some() => return,
            (Some(table), Some(metatable)) => (
                TableRef::of(self.bindings, table),
                TableRef::of(self.bindings, metatable),
            ),
            // `setmetatable(f())` takes both from the call.
            (Some(table), None) if may_spread(table) => (TableRef::Any, TableRef::Any),
            _ => return,
        };
        match &metatable {
            TableRef::Constructor(offset) => {
                self.metatable_constructors.insert(*offset);
            }
            TableRef::Name(slot) => *self.metatable_uses.entry(slot.clone()).or_default() += 1,
            TableRef::Any => {}
        }
        self.metatable_calls.push((table, metatable));
    }

    /// The variable `t.k = v` goes through when `t` is a plain name. A longer path or a
    /// call may reach any table.
    fn target_root(&self, target: &VarExpression) -> Option<Slot> {
        let mut suffixes = target.suffixes();
        match (target.prefix(), suffixes.next(), suffixes.next()) {
            (Prefix::Name(root), Some(Suffix::Index(_)), None) => Some(self.bindings.slot(root)),
            _ => None,
        }
    }

    /// The table a write to `target` stores into, as a holder of `__newindex`.
    fn target_table(&self, target: &VarExpression) -> TableRef {
        self.target_root(target)
            .map_or(TableRef::Any, TableRef::Name)
    }

    fn field_target(&mut self, target: &VarExpression, literal: Option<Value>) {
        let key = target_key(target);
        let root = self.target_root(target);
        let mut suffixes = target.suffixes();
        let (first, second) = (suffixes.next(), suffixes.next());
        // `getfenv().x = v` assigns the global `x`.
        if let (Prefix::Name(root), Some(Suffix::Call(_)), Some(_), None) =
            (target.prefix(), first, second, suffixes.next())
            && token_text(root) == "getfenv"
        {
            self.environment_write(key.as_deref(), literal.clone());
        }
        self.field_write(root, key, literal);
    }

    /// A write into the script environment: a global assignment for a name, a field of
    /// the environment table for an integer key, or any global for a key the scan
    /// cannot read.
    fn environment_write(&mut self, key: Option<&str>, literal: Option<Value>) {
        match key {
            Some(key) => {
                if let Some(name) = key.strip_prefix("s:") {
                    self.reassign(Slot::Global(name.to_string()), literal);
                }
            }
            None => self.facts.environment_write = true,
        }
    }

    /// A library function that changes tables, called with `args` or, without them,
    /// used as a value.
    fn library_use(&mut self, name: &str, args: Option<&FunctionArgs>) {
        let arguments: Vec<&Expression> = match args {
            Some(FunctionArgs::Parentheses { arguments, .. }) => arguments.iter().collect(),
            _ => Vec::new(),
        };
        let root = named_slot(self.bindings, arguments.first().copied());
        match name {
            "rawset" => match arguments.get(1) {
                Some(key) => {
                    let key = literal_value(key).and_then(|key| field_key(&key));
                    let literal = arguments.get(2).and_then(|value| literal_value(value));
                    // `rawset(getfenv(), "x", v)` assigns the global `x`.
                    if let Some(Expression::FunctionCall(call)) = arguments.first()
                        && let Prefix::Name(getfenv) = call.prefix()
                        && token_text(getfenv) == "getfenv"
                    {
                        self.environment_write(key.as_deref(), literal.clone());
                    }
                    if key.as_deref() == Some(NEWINDEX) {
                        let holder = arguments
                            .first()
                            .map_or(TableRef::Any, |table| TableRef::of(self.bindings, table));
                        self.note_newindex(holder, arguments.get(2).copied());
                    }
                    self.field_write(root, key, literal);
                }
                None => self.any_writes.push(None),
            },
            "table.insert" | "table.remove" | "table.sort" => {
                self.numeric_writes.push(args.and(root));
            }
            // `table.move(a1, f, e, t, a2)` writes into `a2`, or into `a1` without it.
            "table.move" => {
                let target = match arguments.get(4) {
                    Some(target) => named_slot(self.bindings, Some(target)),
                    None => root,
                };
                self.numeric_writes.push(args.and(target));
            }
            "table.clear" => self.any_writes.push(args.and(root)),
            "setmetatable" => self.facts.metatable_change = true,
            "getmetatable" => self.metatable_read = true,
            _ => {}
        }
    }

    /// The table constructor whose tables `slot` always holds: a local declared with a
    /// constructor, or as an alias of such a local, and never assigned again.
    fn pinned_constructor(&self, slot: &Slot) -> Option<usize> {
        let mut current = slot;
        // Each step follows an alias to an earlier declaration; the bound only guards
        // against a cycle.
        for _ in 0..64 {
            if self.facts.reassigned.contains_key(current) {
                return None;
            }
            match &self.declarations.get(current)?.initializer {
                Initializer::Constructor(constructor) => return Some(*constructor),
                Initializer::Alias(next) => current = next,
                Initializer::Other => return None,
            }
        }
        None
    }

    /// The tables a write through `root` may reach: those of the constructor a pinned
    /// local holds, or any table. A pinned local's table may have a metatable whose
    /// `__newindex` table receives the write instead, when it may get such a metatable
    /// (see [`ScriptScan::redirected`]). A contained table never does: only a table
    /// passed as a value can get a metatable.
    fn table_keys(&self, root: Option<&Slot>) -> Vec<TableKey> {
        match root.and_then(|slot| self.pinned_constructor(slot)) {
            Some(offset)
                if self.facts.contained_tables.contains(&offset)
                    || self
                        .redirected
                        .as_ref()
                        .is_some_and(|tables| !tables.contains(&offset)) =>
            {
                vec![TableKey::Constructor(offset)]
            }
            Some(offset) => std::iter::once(TableKey::Constructor(offset))
                .chain(self.redirect_tables.iter().copied())
                .collect(),
            None => vec![TableKey::Any],
        }
    }

    fn finish(mut self) -> ScriptFacts {
        let reassigned = &self.facts.reassigned;
        let mut constant: HashSet<Slot> = self
            .declarations
            .iter()
            .filter(|(slot, declaration)| {
                !reassigned.contains_key(*slot) && declaration.structure.is_some()
            })
            .map(|(slot, _)| slot.clone())
            .collect();
        // Drop locals that depend on a variable that is not constant, then everything
        // that depends on those, until nothing changes.
        let mut dependents: HashMap<&Slot, Vec<&Slot>> = HashMap::new();
        let mut queue: Vec<Slot> = Vec::new();
        for (slot, declaration) in &self.declarations {
            for dependency in declaration.structure.iter().flatten() {
                dependents.entry(dependency).or_default().push(slot);
            }
            if constant.contains(slot)
                && declaration
                    .structure
                    .iter()
                    .flatten()
                    .any(|dependency| !constant.contains(dependency))
            {
                queue.push(slot.clone());
            }
        }
        for slot in &queue {
            constant.remove(slot);
        }
        while let Some(slot) = queue.pop() {
            for user in dependents.get(&slot).into_iter().flatten() {
                if constant.remove(*user) {
                    queue.push((*user).clone());
                }
            }
        }
        // A table that only its own local holds, and that local is only indexed: no
        // other value can be that table, so no other write reaches it.
        let contained_tables = self
            .declarations
            .iter()
            .filter_map(|(slot, declaration)| match declaration.initializer {
                Initializer::Constructor(offset)
                    if !self.facts.reassigned.contains_key(slot)
                        && !self.facts.value_uses.contains_key(slot)
                        && !self.method_receivers.contains(slot) =>
                {
                    Some(offset)
                }
                _ => None,
            })
            .collect();
        self.facts.contained_tables = contained_tables;
        // A metatable the script makes reaches only the `setmetatable` calls it is
        // written in, or that its local is passed to, when that local is never used as
        // a value otherwise.
        let initializers: HashMap<usize, &Slot> = self
            .declarations
            .iter()
            .filter_map(|(slot, declaration)| match declaration.initializer {
                Initializer::Constructor(offset) => Some((offset, slot)),
                _ => None,
            })
            .collect();
        let seen_only = |offset: usize| {
            self.metatable_constructors.contains(&offset)
                || initializers.get(&offset).is_some_and(|slot| {
                    !self.facts.reassigned.contains_key(*slot)
                        && !self.method_receivers.contains(*slot)
                        && self.facts.value_uses.get(*slot).copied().unwrap_or(0)
                            <= self.metatable_uses.get(*slot).copied().unwrap_or(0)
                })
        };
        // Any table may get a metatable with a `__newindex` table when such a metatable
        // reaches code the scan does not see, or `setmetatable` is not the global.
        let mut anywhere = self.metatable_read
            || self
                .facts
                .reassigned
                .contains_key(&Slot::Global("setmetatable".into()));
        // The tables a `__newindex` value may hold: those of a pinned local or a
        // constructor, none for a local function, any table otherwise.
        let mut redirect_tables: HashSet<TableKey> = HashSet::new();
        // The constructors of the metatables that hold one of those values.
        let mut metatables: HashSet<usize> = HashSet::new();
        for (holder, redirect) in &self.redirects {
            let table = match redirect {
                TableRef::Constructor(offset) => TableKey::Constructor(*offset),
                TableRef::Name(slot)
                    if self.local_functions.contains(slot)
                        && !self.facts.reassigned.contains_key(slot) =>
                {
                    continue;
                }
                TableRef::Name(slot) => self
                    .pinned_constructor(slot)
                    .map_or(TableKey::Any, TableKey::Constructor),
                TableRef::Any => TableKey::Any,
            };
            redirect_tables.insert(table);
            let holder = match holder {
                TableRef::Constructor(offset) => Some(*offset),
                TableRef::Name(slot) => self.pinned_constructor(slot),
                TableRef::Any => None,
            };
            match holder {
                Some(offset) if seen_only(offset) => {
                    metatables.insert(offset);
                }
                _ => anywhere = true,
            }
        }
        // The tables that may get such a metatable: the table of each `setmetatable`
        // call whose metatable may be one. A table the scan cannot pin down there may
        // be any table.
        let mut redirected: HashSet<usize> = HashSet::new();
        for (table, metatable) in &self.metatable_calls {
            let redirects = match metatable {
                TableRef::Constructor(offset) => metatables.contains(offset),
                TableRef::Name(slot) => self
                    .pinned_constructor(slot)
                    .is_none_or(|offset| metatables.contains(&offset)),
                TableRef::Any => true,
            };
            if !redirects {
                continue;
            }
            match table {
                // A new table, which no local holds as its constructor.
                TableRef::Constructor(_) => {}
                TableRef::Name(slot) => match self.pinned_constructor(slot) {
                    Some(offset) => {
                        redirected.insert(offset);
                    }
                    None => anywhere = true,
                },
                TableRef::Any => anywhere = true,
            }
        }
        self.redirect_tables = redirect_tables.into_iter().collect();
        self.redirected = (!anywhere).then_some(redirected);
        // File each field write under the tables it may reach.
        let mut field_writes: HashMap<TableKey, HashMap<String, Assigned>> = HashMap::new();
        let mut any_field_write = HashSet::new();
        for write in &self.field_writes {
            // Any key: the values are kept under `*` for every read.
            let key = write.key.as_deref().unwrap_or(ANY_FIELD);
            for table in self.table_keys(write.root.as_ref()) {
                if write.key.is_none() {
                    any_field_write.insert(table);
                }
                field_writes
                    .entry(table)
                    .or_default()
                    .entry(key.to_string())
                    .or_default()
                    .add(write.literal.clone());
            }
        }
        for root in &self.any_writes {
            any_field_write.extend(self.table_keys(root.as_ref()));
        }
        let numeric_field_write = self
            .numeric_writes
            .iter()
            .flat_map(|root| self.table_keys(root.as_ref()))
            .collect();
        self.facts.constant_slots = constant;
        self.facts.field_writes = field_writes;
        self.facts.any_field_write = any_field_write;
        self.facts.numeric_field_write = numeric_field_write;
        self.facts
    }
}

impl Visitor for ScriptScan<'_> {
    fn visit_local_assignment(&mut self, node: &LocalAssignment) {
        self.declare_list(node.names().iter(), node.expressions().iter());
    }

    fn visit_const_assignment(&mut self, node: &ConstAssignment) {
        self.declare_list(node.names().iter(), node.expressions().iter());
    }

    fn visit_local_function(&mut self, node: &LocalFunction) {
        self.declare_unknown(node.name());
        self.local_functions.insert(self.bindings.slot(node.name()));
    }

    fn visit_const_function(&mut self, node: &ConstFunction) {
        self.declare_unknown(node.name());
        self.local_functions.insert(self.bindings.slot(node.name()));
    }

    fn visit_function_body(&mut self, body: &FunctionBody) {
        for parameter in body.parameters() {
            if let Parameter::Name(name) = parameter {
                self.declare_unknown(name);
            }
        }
    }

    fn visit_numeric_for(&mut self, node: &NumericFor) {
        self.declare_unknown(node.index_variable());
    }

    fn visit_generic_for(&mut self, node: &GenericFor) {
        for name in node.names() {
            self.declare_unknown(name);
        }
    }

    fn visit_assignment(&mut self, node: &Assignment) {
        let values: Vec<&Expression> = node.expressions().iter().collect();
        let spreads = values.last().is_some_and(|last| may_spread(last));
        for (index, var) in node.variables().iter().enumerate() {
            let literal = match values.get(index) {
                Some(value) => literal_value(value),
                None if spreads => None,
                None => Some(Value::Nil),
            };
            match var {
                Var::Name(name) => self.reassign(self.bindings.slot(name), literal),
                Var::Expression(target) => {
                    if target_key(target).as_deref() == Some(NEWINDEX)
                        && !matches!(literal, Some(Value::Nil))
                    {
                        self.note_newindex(self.target_table(target), values.get(index).copied());
                    }
                    self.field_target(target, literal);
                }
                _ => {}
            }
        }
    }

    fn visit_compound_assignment(&mut self, node: &CompoundAssignment) {
        match node.lhs() {
            Var::Name(name) => self.reassign(self.bindings.slot(name), None),
            Var::Expression(target) => {
                if target_key(target).as_deref() == Some(NEWINDEX) {
                    self.note_newindex(self.target_table(target), None);
                }
                self.field_target(target, None);
            }
            _ => {}
        }
    }

    fn visit_function_declaration(&mut self, node: &FunctionDeclaration) {
        let name = node.name();
        let names: Vec<&TokenReference> = name.names().iter().collect();
        match (name.method_name(), names.as_slice()) {
            // `function t:m()` and `function t.m()` go through `t`; a longer path may
            // reach any table.
            (Some(method), [root]) => self.field_write(
                Some(self.bindings.slot(root)),
                Some(format!("s:{}", token_text(method))),
                None,
            ),
            (Some(method), _) => {
                self.field_write(None, Some(format!("s:{}", token_text(method))), None)
            }
            (None, [single]) => self.reassign(self.bindings.slot(single), None),
            (None, [root, last]) => self.field_write(
                Some(self.bindings.slot(root)),
                Some(format!("s:{}", token_text(last))),
                None,
            ),
            (None, [_, .., last]) => {
                self.field_write(None, Some(format!("s:{}", token_text(last))), None)
            }
            _ => {}
        }
    }

    fn visit_var_expression(&mut self, expression: &VarExpression) {
        self.note_receiver(expression.prefix(), expression.suffixes());
    }

    fn visit_table_constructor(&mut self, table: &TableConstructor) {
        for field in table.fields() {
            let (named, value) = match field {
                Field::NameKey { key, value, .. } => (token_text(key) == "__newindex", value),
                Field::ExpressionKey { key, value, .. } => (
                    literal_value(key)
                        .and_then(|key| field_key(&key))
                        .as_deref()
                        == Some(NEWINDEX),
                    value,
                ),
                _ => continue,
            };
            if named {
                self.note_newindex(
                    TableRef::Constructor(constructor_offset(table)),
                    Some(value),
                );
            }
        }
    }

    fn visit_function_call(&mut self, call: &FunctionCall) {
        self.note_receiver(call.prefix(), call.suffixes());
        let mut suffixes = call.suffixes();
        let root = match call.prefix() {
            Prefix::Name(root) => token_text(root),
            // `(function() ... end)()` runs on the spot.
            Prefix::Expression(expression) => {
                if let Expression::Parentheses { expression, .. } = &**expression
                    && let Expression::Function(function) = &**expression
                {
                    self.facts
                        .contained_functions
                        .insert(body_key(function.body()));
                }
                return;
            }
            _ => return,
        };
        let (name, args) = match (suffixes.next(), suffixes.next()) {
            (Some(Suffix::Call(Call::AnonymousCall(args))), _) => (root, args),
            (
                Some(Suffix::Index(Index::Dot { name, .. })),
                Some(Suffix::Call(Call::AnonymousCall(args))),
            ) => (format!("{root}.{}", token_text(name)), args),
            _ => return,
        };
        self.library_use(&name, Some(args));
        if name == "setmetatable"
            && let Prefix::Name(token) = call.prefix()
            && matches!(self.bindings.slot(token), Slot::Global(_))
            && let FunctionArgs::Parentheses { arguments, .. } = &**args
        {
            self.note_metatable_call(arguments);
        }
        // The callback of `pcall` or `task.spawn` runs, and what it returns goes back to
        // the caller or nowhere, so it does not reach other code that way.
        if is_dangerous_wrapper(&name)
            && let FunctionArgs::Parentheses { arguments, .. } = &**args
        {
            let (callback, _) = wrapper_positions(&name, arguments.len());
            match arguments.iter().nth(callback) {
                Some(Expression::Function(function)) => {
                    self.facts
                        .contained_functions
                        .insert(body_key(function.body()));
                }
                Some(Expression::Var(Var::Name(name))) => {
                    *self
                        .facts
                        .callback_uses
                        .entry(self.bindings.slot(name))
                        .or_default() += 1;
                }
                _ => {}
            }
        }
    }

    fn visit_var(&mut self, var: &Var) {
        // A mutating library function taken as a value may change any table, and
        // `getmetatable` may hand a metatable to any code.
        match var {
            Var::Name(name) => {
                let text = token_text(name);
                if matches!(text.as_str(), "rawset" | "setmetatable" | "getmetatable") {
                    self.library_use(&text, None);
                }
                *self
                    .facts
                    .value_uses
                    .entry(self.bindings.slot(name))
                    .or_default() += 1;
            }
            Var::Expression(expression) => {
                let mut suffixes = expression.suffixes();
                if let (Prefix::Name(root), Some(Suffix::Index(Index::Dot { name, .. })), None) =
                    (expression.prefix(), suffixes.next(), suffixes.next())
                    && token_text(root) == "table"
                {
                    self.library_use(&format!("table.{}", token_text(name)), None);
                }
            }
            _ => {}
        }
    }
}

/// What a name past the values of an assignment gets: `nil`, or an unknown value when the
/// last expression is a call or `...` that may give more values than the scanner knows.
fn missing_value(expressions: &Punctuated<Expression>) -> Value {
    if expressions.iter().last().is_some_and(may_spread) {
        Value::Unknown
    } else {
        Value::Nil
    }
}

/// A call or `...`, which can give several values in the last position of a list.
fn may_spread(expression: &Expression) -> bool {
    match expression {
        Expression::FunctionCall(_) => true,
        Expression::Symbol(token) => token_text(token) == "...",
        _ => false,
    }
}

/// The names a constant expression reads, or `None` when it is not built from literals
/// and names only. The left side of `and` and the conditions of an if-expression only
/// choose a value, so they may be anything; `not` and comparisons always give a boolean.
fn constant_structure(expression: &Expression) -> Option<Vec<&TokenReference>> {
    let mut names = Vec::new();
    let mut stack = vec![expression];
    let mut work = 0usize;
    while let Some(expression) = stack.pop() {
        work += 1;
        if work > 65_536 {
            return None;
        }
        match expression {
            Expression::Number(_) | Expression::String(_) => {}
            Expression::Symbol(token) => {
                if !matches!(token_text(token).as_str(), "nil" | "true" | "false") {
                    return None;
                }
            }
            Expression::Parentheses { expression, .. }
            | Expression::TypeAssertion { expression, .. } => stack.push(expression),
            Expression::UnaryOperator { unop, expression } => {
                if !matches!(unop, UnOp::Not(_)) {
                    stack.push(expression);
                }
            }
            Expression::BinaryOperator { lhs, binop, rhs } => match binop_kind(binop) {
                Op::And => stack.push(rhs),
                Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge => {}
                Op::Other => return None,
                _ => {
                    stack.push(lhs);
                    stack.push(rhs);
                }
            },
            Expression::IfExpression(expression) => {
                stack.push(expression.if_expression());
                if let Some(branches) = expression.else_if_expressions() {
                    stack.extend(branches.iter().map(|branch| branch.expression()));
                }
                stack.push(expression.else_expression());
            }
            Expression::InterpolatedString(string) => {
                stack.extend(string.segments().map(|segment| &segment.expression));
            }
            Expression::Var(Var::Name(name)) => names.push(name),
            _ => return None,
        }
    }
    Some(names)
}

/// The value of a literal expression: a number, a string, `nil`, `true` or `false`.
fn literal_value(expression: &Expression) -> Option<Value> {
    match expression {
        Expression::Number(token) => {
            parse_number(&token_text(token)).map(|n| Value::Number(n, None))
        }
        Expression::String(token) => Some(Value::String(Text::from(string_value(token)), None)),
        Expression::Symbol(token) => match token_text(token).as_str() {
            "nil" => Some(Value::Nil),
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        },
        Expression::Parentheses { expression, .. } => literal_value(expression),
        Expression::UnaryOperator {
            unop: UnOp::Minus(_),
            expression,
        } => match literal_value(expression)? {
            Value::Number(number, _) => Some(Value::Number(-number, None)),
            _ => None,
        },
        _ => None,
    }
}

/// Names an assigned expression reads, with their byte offsets, or `None` when that
/// cannot be listed (a compound assignment always reads its target).
fn dependence_names(dependence: &Dependence<'_>) -> Option<Vec<(usize, String)>> {
    #[derive(Default)]
    struct Names {
        names: Vec<(usize, String)>,
        overflow: bool,
    }
    impl Visitor for Names {
        fn visit_var(&mut self, var: &Var) {
            if let Var::Name(name) = var {
                self.add(name);
            }
        }
        fn visit_prefix(&mut self, prefix: &Prefix) {
            if let Prefix::Name(name) = prefix {
                self.add(name);
            }
        }
        fn visit_expression(&mut self, expression: &Expression) {
            if let Expression::Symbol(token) = expression
                && token_text(token) == "..."
            {
                self.add(token);
            }
        }
    }
    impl Names {
        fn add(&mut self, name: &TokenReference) {
            if self.names.len() >= 256 {
                self.overflow = true;
            } else {
                self.names
                    .push((name.token().start_position().bytes(), token_text(name)));
            }
        }
    }
    let Dependence::Expressions(expressions) = dependence else {
        return None;
    };
    let mut names = Names::default();
    for expression in expressions {
        Visit::visit(*expression, &mut names);
    }
    (!names.overflow).then_some(names.names)
}

/// Whether a value may be a table the scanner did not pin down.
fn may_hold_unknown_table(value: &Value) -> bool {
    value.candidates().into_iter().any(|candidate| {
        matches!(
            candidate,
            Value::Unknown | Value::Truncated | Value::Overflow
        )
    })
}

/// A block that ends with a call of `error`, so the code after the `if` that holds it
/// runs only when the condition was false.
fn ends_with_error(block: &Block) -> bool {
    block.last_stmt().is_none()
        && matches!(
            block.stmts().last(),
            Some(Stmt::FunctionCall(call))
                if matches!(call.prefix(), Prefix::Name(name) if token_text(name) == "error")
        )
}

/// A call, possibly in parentheses or after `not`, that a gate in an expression can
/// control.
fn holds_call(expression: &Expression) -> bool {
    match expression {
        Expression::FunctionCall(_) => true,
        Expression::Parentheses { expression, .. }
        | Expression::UnaryOperator { expression, .. }
        | Expression::TypeAssertion { expression, .. } => holds_call(expression),
        Expression::BinaryOperator { lhs, rhs, .. } => holds_call(lhs) || holds_call(rhs),
        Expression::IfExpression(expression) => {
            holds_call(expression.if_expression()) || holds_call(expression.else_expression())
        }
        _ => false,
    }
}

/// Source bytes of a function body, from its parameter list to its `end`.
fn body_bytes(body: &FunctionBody) -> usize {
    let start = body
        .parameters_parentheses()
        .tokens()
        .0
        .token()
        .start_position()
        .bytes();
    let end = body.end_token().token().end_position().bytes();
    end.saturating_sub(start)
}

fn holds_table(value: &Value) -> bool {
    value
        .candidates()
        .into_iter()
        .any(|candidate| match candidate {
            Value::Table(_) => true,
            Value::Tuple(values) => values.iter().any(holds_table),
            _ => false,
        })
}

fn tables_in(value: &Value) -> Vec<usize> {
    let mut tables = Vec::new();
    for candidate in value.candidates() {
        if let Value::Table(id) = candidate
            && !tables.contains(id)
        {
            tables.push(*id);
        }
    }
    tables
}

// ----- source positions ---------------------------------------------------------------
//
// full_moon derives `start_position` and `end_position` by computing both ends of every
// child, which is exponential on nested nodes, and its token iterator is quadratic. These
// helpers walk only the leftmost or rightmost path.

fn first_token_of_expression(mut expression: &Expression) -> Option<&TokenReference> {
    loop {
        match expression {
            Expression::BinaryOperator { lhs, .. } => expression = lhs,
            Expression::TypeAssertion {
                expression: inner, ..
            } => expression = inner,
            Expression::Parentheses { contained, .. } => return Some(contained.tokens().0),
            Expression::UnaryOperator { unop, .. } => return Some(unop.token()),
            Expression::Function(function) => return Some(function.function_token()),
            Expression::FunctionCall(call) => return first_token_of_prefix(call.prefix()),
            Expression::IfExpression(expression) => return Some(expression.if_token()),
            Expression::InterpolatedString(string) => {
                return Some(
                    string
                        .segments()
                        .next()
                        .map(|segment| &segment.literal)
                        .unwrap_or_else(|| string.last_string()),
                );
            }
            Expression::TableConstructor(table) => return Some(table.braces().tokens().0),
            Expression::Number(token) | Expression::String(token) | Expression::Symbol(token) => {
                return Some(token);
            }
            Expression::Var(var) => return first_token_of_var(var),
            _ => return None,
        }
    }
}

fn last_token_of_expression(mut expression: &Expression) -> Option<&TokenReference> {
    loop {
        match expression {
            Expression::BinaryOperator { rhs, .. } => expression = rhs,
            Expression::UnaryOperator {
                expression: inner, ..
            } => expression = inner,
            Expression::IfExpression(inner) => expression = inner.else_expression(),
            Expression::TypeAssertion {
                expression: inner,
                type_assertion,
            } => {
                return type_assertion
                    .tokens()
                    .next_back()
                    .or_else(|| last_token_of_expression(inner));
            }
            Expression::Parentheses { contained, .. } => return Some(contained.tokens().1),
            Expression::Function(function) => return Some(function.body().end_token()),
            Expression::FunctionCall(call) => {
                return call
                    .suffixes()
                    .last()
                    .and_then(last_token_of_suffix)
                    .or_else(|| last_token_of_prefix(call.prefix()));
            }
            Expression::InterpolatedString(string) => return Some(string.last_string()),
            Expression::TableConstructor(table) => return Some(table.braces().tokens().1),
            Expression::Number(token) | Expression::String(token) | Expression::Symbol(token) => {
                return Some(token);
            }
            Expression::Var(var) => return last_token_of_var(var),
            _ => return None,
        }
    }
}

fn first_token_of_prefix(prefix: &Prefix) -> Option<&TokenReference> {
    match prefix {
        Prefix::Name(name) => Some(name),
        Prefix::Expression(expression) => first_token_of_expression(expression),
        _ => None,
    }
}

fn last_token_of_prefix(prefix: &Prefix) -> Option<&TokenReference> {
    match prefix {
        Prefix::Name(name) => Some(name),
        Prefix::Expression(expression) => last_token_of_expression(expression),
        _ => None,
    }
}

fn first_token_of_var(var: &Var) -> Option<&TokenReference> {
    match var {
        Var::Name(name) => Some(name),
        Var::Expression(expression) => first_token_of_prefix(expression.prefix()),
        _ => None,
    }
}

fn last_token_of_var(var: &Var) -> Option<&TokenReference> {
    match var {
        Var::Name(name) => Some(name),
        Var::Expression(expression) => expression
            .suffixes()
            .last()
            .and_then(last_token_of_suffix)
            .or_else(|| last_token_of_prefix(expression.prefix())),
        _ => None,
    }
}

fn last_token_of_suffix(suffix: &Suffix) -> Option<&TokenReference> {
    match suffix {
        Suffix::Index(Index::Brackets { brackets, .. }) => Some(brackets.tokens().1),
        Suffix::Index(Index::Dot { name, .. }) => Some(name),
        Suffix::Call(Call::AnonymousCall(args)) => last_token_of_args(args),
        Suffix::Call(Call::MethodCall(method)) => last_token_of_args(method.args()),
        other => other.tokens().next_back(),
    }
}

fn first_token_of_args(args: &FunctionArgs) -> Option<&TokenReference> {
    match args {
        FunctionArgs::Parentheses { parentheses, .. } => Some(parentheses.tokens().0),
        FunctionArgs::String(token) => Some(token),
        FunctionArgs::TableConstructor(table) => Some(table.braces().tokens().0),
        _ => None,
    }
}

fn last_token_of_args(args: &FunctionArgs) -> Option<&TokenReference> {
    match args {
        FunctionArgs::Parentheses { parentheses, .. } => Some(parentheses.tokens().1),
        FunctionArgs::String(token) => Some(token),
        FunctionArgs::TableConstructor(table) => Some(table.braces().tokens().1),
        _ => None,
    }
}

fn args_site(args: &FunctionArgs) -> Site {
    Site::between(first_token_of_args(args), last_token_of_args(args))
}

/// Expressions whose value can be a dangerous function. Literals and constructors are
/// skipped so large data tables are not evaluated twice.
fn may_hold_callable(expression: &Expression) -> bool {
    match expression {
        Expression::Var(_)
        | Expression::FunctionCall(_)
        | Expression::Parentheses { .. }
        | Expression::IfExpression(_)
        | Expression::TypeAssertion { .. } => true,
        Expression::BinaryOperator { binop, .. } => {
            matches!(binop_kind(binop), Op::And | Op::Or | Op::Concat)
        }
        _ => false,
    }
}

// ----- values -------------------------------------------------------------------------

fn json_value(value: &serde_json::Value, origin: Origin) -> Value {
    match value {
        serde_json::Value::Number(number) => number
            .as_f64()
            .map(|number| Value::Number(number, Some(origin)))
            .unwrap_or(Value::Unknown),
        serde_json::Value::String(text) => Value::String(Text::from(text.clone()), Some(origin)),
        _ => Value::UnresolvedOrigin(origin),
    }
}

fn parse_number(text: &str) -> Option<f64> {
    let normalized: String = text.chars().filter(|character| *character != '_').collect();
    if let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .ok()
            .map(|number| number as f64)
    } else if let Some(binary) = normalized
        .strip_prefix("0b")
        .or_else(|| normalized.strip_prefix("0B"))
    {
        u64::from_str_radix(binary, 2)
            .ok()
            .map(|number| number as f64)
    } else {
        normalized.parse::<f64>().ok()
    }
}

/// Lua `tonumber` on a string: surrounding whitespace, optional sign, decimal, hex and
/// binary forms, or digits in an explicit base from 2 to 36.
fn lua_tonumber(text: &str, base: Option<u32>) -> Option<f64> {
    let text = text
        .trim_matches(|character: char| character.is_ascii_whitespace() || character == '\u{b}');
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if body.is_empty() {
        return None;
    }
    let value = match base {
        Some(base) if base != 10 => {
            if !(2..=36).contains(&base) {
                return None;
            }
            let mut value = 0f64;
            for character in body.chars() {
                let digit = character.to_digit(base)?;
                value = value * f64::from(base) + f64::from(digit);
            }
            value
        }
        _ => {
            if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
                if hex.is_empty() {
                    return None;
                }
                let mut value = 0f64;
                for character in hex.chars() {
                    value = value * 16.0 + f64::from(character.to_digit(16)?);
                }
                value
            } else if let Some(binary) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B"))
            {
                if binary.is_empty() {
                    return None;
                }
                let mut value = 0f64;
                for character in binary.chars() {
                    value = value * 2.0 + f64::from(character.to_digit(2)?);
                }
                value
            } else {
                if !body.bytes().all(|byte| {
                    byte.is_ascii_digit() || matches!(byte, b'.' | b'e' | b'E' | b'+' | b'-')
                }) || !body.bytes().any(|byte| byte.is_ascii_digit())
                {
                    return None;
                }
                body.parse::<f64>().ok()?
            }
        }
    };
    Some(if negative { -value } else { value })
}

fn integer(number: f64) -> Option<i64> {
    (number.fract() == 0.0 && number >= i64::MIN as f64 && number <= i64::MAX as f64)
        .then_some(number as i64)
}

fn integer_value(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number, _) => integer(*number),
        Value::String(text, _) => lua_tonumber(text, None).and_then(integer),
        _ => None,
    }
}

/// Arithmetic operand: numbers, and strings that Lua coerces to numbers.
fn coerce_number(value: &Value) -> Option<(f64, Option<Origin>)> {
    match value {
        Value::Number(number, origin) => Some((*number, origin.clone())),
        Value::String(text, origin) => lua_tonumber(text, None).map(|n| (n, origin.clone())),
        _ => None,
    }
}

fn arithmetic(op: Op, a: f64, b: f64) -> Option<f64> {
    let result = match op {
        Op::Add => a + b,
        Op::Sub => a - b,
        Op::Mul => a * b,
        Op::Div if b != 0.0 => a / b,
        Op::FloorDiv if b != 0.0 => (a / b).floor(),
        Op::Mod if b != 0.0 => a - (a / b).floor() * b,
        Op::Pow => a.powf(b),
        _ => return None,
    };
    result.is_finite().then_some(result)
}

/// Result of an operation that could not be folded: keep where its data came from.
fn derived_from(values: &[Value]) -> Value {
    let values: Vec<&Value> = values.iter().flat_map(Value::candidates).collect();
    if values.iter().any(|value| matches!(value, Value::Sensitive)) {
        return Value::Sensitive;
    }
    if values.iter().any(|value| matches!(value, Value::Remote)) {
        return Value::Remote;
    }
    if values
        .iter()
        .any(|value| matches!(value, Value::ExternalData | Value::ExternalDom))
    {
        return Value::ExternalData;
    }
    for value in &values {
        if let Value::UnresolvedOrigin(origin) = value {
            return Value::UnresolvedOrigin(origin.clone());
        }
    }
    for value in &values {
        if let Some(origin) = value.origin() {
            return Value::UnresolvedOrigin(origin.clone());
        }
    }
    for value in &values {
        if let Value::ModelData(anchor) | Value::ModelDom(anchor) = value {
            return Value::ModelData(*anchor);
        }
    }
    if let Some(literal) = values.iter().find_map(|value| asset_shaped(value)) {
        return Value::IdLike(literal);
    }
    if values.iter().any(|value| matches!(value, Value::Truncated)) {
        return Value::Truncated;
    }
    Value::Unknown
}

/// For each instance, whether it or an object below it stores an asset ID shaped value
/// in a value object's `Value` or an attribute. Each instance is marked once, walking
/// up from every holder until an ancestor is already marked.
fn stored_ids_below(doc: &Document) -> Vec<bool> {
    let mut marked = vec![false; doc.instances.len()];
    for (id, node) in doc.instances.iter().enumerate() {
        let value = node
            .properties
            .get("Value")
            .filter(|_| node.class != "ObjectValue");
        if !value
            .into_iter()
            .chain(node.attributes.values())
            .any(id_shaped_json)
        {
            continue;
        }
        let mut current = Some(id);
        while let Some(index) = current {
            match marked.get_mut(index) {
                Some(seen @ false) => *seen = true,
                _ => break,
            }
            current = doc.instances[index].parent;
        }
    }
    marked
}

fn id_shaped_json(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Number(number) => number.as_f64().is_some_and(is_asset_number),
        serde_json::Value::String(text) => digit_run(text, ASSET_ID_DIGITS).is_some(),
        _ => false,
    }
}

/// Whether an `ObjectValue`'s stored `Value` names an object. A place or model file
/// keeps it as `{"Ref": "<32 hex digits>"}`, all zeros when it is empty; the Studio
/// snapshot keeps the object's name, and leaves an empty one out.
fn stored_reference(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(_) => value
            .get("Ref")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|hex| hex.bytes().any(|digit| digit != b'0')),
        serde_json::Value::String(name) => !name.is_empty(),
        _ => false,
    }
}

/// A stored value whose candidates are all instances, at least one of them not pinned
/// down, as the instance it still is once the exact object is lost: an object outside
/// the content, or one in it near the first unresolved object. [`derived_from`] would
/// turn it into data read from that object. `None` for anything else, and for objects
/// that are all pinned down, which keep their old rule.
fn deferred_instance(value: &Value) -> Option<Value> {
    let candidates = value.candidates();
    if !candidates.iter().all(|candidate| {
        matches!(
            candidate,
            Value::Dom(_) | Value::ModelDom(_) | Value::ExternalDom
        )
    }) {
        return None;
    }
    if candidates
        .iter()
        .any(|candidate| matches!(candidate, Value::ExternalDom))
    {
        return Some(Value::ExternalDom);
    }
    candidates.iter().find_map(|candidate| match candidate {
        Value::ModelDom(anchor) => Some(Value::ModelDom(*anchor)),
        _ => None,
    })
}

/// Text of an asset-ID-shaped value: an integer of at least 1,000,000, or a string with
/// a run of at least seven digits.
fn asset_shaped(value: &Value) -> Option<String> {
    match value {
        Value::Number(number, _) if is_asset_number(*number) => Some(format_number(*number)),
        Value::String(text, _) => digit_run(text, ASSET_ID_DIGITS),
        Value::Partial(text) => digit_run(text, ASSET_ID_DIGITS),
        Value::IdLike(text) => Some(text.clone()),
        Value::Union(values) | Value::Tuple(values) => values.iter().find_map(asset_shaped),
        _ => None,
    }
}

fn is_asset_number(number: f64) -> bool {
    number.fract() == 0.0 && (ASSET_ID_MIN..9.007_199_254_740_992e15).contains(&number)
}

/// First run of at least `minimum` ASCII digits in the first 1 KiB of `text`.
fn digit_run(text: &str, minimum: usize) -> Option<String> {
    let mut run = String::new();
    for character in text.chars().take(1024) {
        if character.is_ascii_digit() {
            run.push(character);
            if run.len() > 32 {
                return Some(run);
            }
        } else {
            if run.len() >= minimum {
                return Some(run);
            }
            run.clear();
        }
    }
    (run.len() >= minimum).then_some(run)
}

fn starts_with_http(text: &str) -> bool {
    let mut skipped = text.len();
    for (count, (index, character)) in text.char_indices().enumerate() {
        if count >= 64 || !character.is_whitespace() {
            skipped = index;
            break;
        }
    }
    let trimmed = &text[skipped..];
    trimmed
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || trimmed
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
        || trimmed
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http%3a"))
}

fn with_origin(value: Value, origin: Option<Origin>) -> Value {
    let Some(origin) = origin else {
        return value;
    };
    match value {
        Value::String(text, None) => Value::String(text, Some(origin)),
        Value::Number(number, None) => Value::Number(number, Some(origin)),
        Value::Tuple(values) => Value::Tuple(
            values
                .into_iter()
                .map(|value| with_origin(value, Some(origin.clone())))
                .collect(),
        ),
        other => other,
    }
}

fn value_as_string(value: &Value) -> Option<(String, Option<Origin>)> {
    match value {
        Value::String(text, origin) => Some((text.to_string(), origin.clone())),
        Value::Number(number, origin) => Some((format_number(*number), origin.clone())),
        _ => None,
    }
}

fn is_receiver_shaped(value: &Value) -> bool {
    value.candidates().into_iter().all(|candidate| {
        matches!(
            candidate,
            Value::Dom(_)
                | Value::ExternalDom
                | Value::ModelDom(_)
                | Value::Object(_)
                | Value::Namespace(_)
        )
    })
}

fn lua_sub(text: &str, start: i64, end: Option<i64>) -> String {
    let characters: Vec<char> = text.chars().collect();
    let len = characters.len() as i64;
    let normalize = |index: i64| if index < 0 { len + index + 1 } else { index };
    let start = normalize(start).max(1);
    let end = normalize(end.unwrap_or(len)).min(len);
    if start > end || end < 1 || start > len {
        String::new()
    } else {
        characters[(start - 1) as usize..end as usize]
            .iter()
            .collect()
    }
}

fn fold_string_format(
    format: &str,
    values: &[Value],
    max_bytes: usize,
    limit_hit: &mut bool,
) -> Value {
    let mut output = String::new();
    let mut arguments = values.iter();
    let mut characters = format.chars().peekable();
    let mut origin = None;
    while let Some(character) = characters.next() {
        if character != '%' {
            output.push(character);
        } else {
            let mut flags = String::new();
            while let Some(flag) = characters.next_if(|c| matches!(c, '-' | '0' | '+' | ' ' | '#'))
            {
                flags.push(flag);
            }
            let mut width = String::new();
            while let Some(digit) = characters.next_if(char::is_ascii_digit) {
                width.push(digit);
            }
            let mut precision = None;
            if characters.next_if_eq(&'.').is_some() {
                let mut digits = String::new();
                while let Some(digit) = characters.next_if(char::is_ascii_digit) {
                    digits.push(digit);
                }
                precision = Some(digits.parse::<usize>().unwrap_or(0));
            }
            let width: usize = width.parse().unwrap_or(0);
            if width > 99 || precision.is_some_and(|precision| precision > 99) {
                return Value::Unknown;
            }
            let conversion = characters.next();
            let piece = match conversion {
                Some('%') => "%".to_string(),
                Some(kind @ ('s' | 'q')) => {
                    let Some(value) = arguments.next() else {
                        return Value::Unknown;
                    };
                    let Some((mut text, value_origin)) = value_as_string(value) else {
                        return Value::Unknown;
                    };
                    origin = origin.or(value_origin);
                    if let Some(precision) = precision {
                        text = text.chars().take(precision).collect();
                    }
                    if kind == 'q' {
                        format!("{text:?}")
                    } else {
                        text
                    }
                }
                Some(kind @ ('d' | 'i' | 'u' | 'c' | 'x' | 'X' | 'o')) => {
                    let Some(value) = arguments.next() else {
                        return Value::Unknown;
                    };
                    let Some(number) = integer_value(value) else {
                        return Value::Unknown;
                    };
                    origin = origin.or_else(|| value.origin().cloned());
                    match kind {
                        'c' => match u8::try_from(number) {
                            Ok(byte) => (byte as char).to_string(),
                            Err(_) => return Value::Unknown,
                        },
                        'x' => format!("{number:x}"),
                        'X' => format!("{number:X}"),
                        'o' => format!("{number:o}"),
                        _ => number.to_string(),
                    }
                }
                Some('f') => {
                    let Some((number, value_origin)) = arguments.next().and_then(coerce_number)
                    else {
                        return Value::Unknown;
                    };
                    origin = origin.or(value_origin);
                    format!("{number:.*}", precision.unwrap_or(6))
                }
                _ => return Value::Unknown,
            };
            if piece.chars().count() < width {
                let padding = width - piece.chars().count();
                if flags.contains('-') {
                    output.push_str(&piece);
                    output.extend(std::iter::repeat_n(' ', padding));
                } else {
                    let fill = if flags.contains('0') { '0' } else { ' ' };
                    output.extend(std::iter::repeat_n(fill, padding));
                    output.push_str(&piece);
                }
            } else {
                output.push_str(&piece);
            }
        }
        if output.len() > max_bytes {
            *limit_hit = true;
            return Value::Unknown;
        }
    }
    if arguments.next().is_some() {
        return Value::Unknown;
    }
    Value::String(Text::from(output), origin)
}

fn bit32_call(function: &str, values: &[Value]) -> Value {
    let numbers: Option<Vec<u32>> = values
        .iter()
        .map(|value| integer_value(value).map(|number| (number.rem_euclid(1 << 32)) as u32))
        .collect();
    let Some(numbers) = numbers else {
        return derived_from(values);
    };
    let n = |index: usize| numbers.get(index).copied().unwrap_or(0);
    let shift = |index: usize| integer_value(values.get(index).unwrap_or(&Value::Nil));
    let result = match function {
        "band" => numbers.iter().fold(u32::MAX, |acc, x| acc & x),
        "bor" => numbers.iter().fold(0, |acc, x| acc | x),
        "bxor" => numbers.iter().fold(0, |acc, x| acc ^ x),
        "bnot" => !n(0),
        "lshift" => match shift(1) {
            Some(amount @ 0..=31) => n(0) << amount,
            Some(_) => 0,
            None => return Value::Unknown,
        },
        "rshift" => match shift(1) {
            Some(amount @ 0..=31) => n(0) >> amount,
            Some(_) => 0,
            None => return Value::Unknown,
        },
        "arshift" => match shift(1) {
            Some(amount @ 0..=31) => ((n(0) as i32) >> amount) as u32,
            Some(_) => {
                if (n(0) as i32) < 0 {
                    u32::MAX
                } else {
                    0
                }
            }
            None => return Value::Unknown,
        },
        "extract" => {
            let field = n(1);
            let width = if values.len() > 2 { n(2) } else { 1 };
            if field > 31 || width == 0 || field.checked_add(width).is_none_or(|end| end > 32) {
                return Value::Unknown;
            }
            (n(0) >> field) & (u32::MAX >> (32 - width))
        }
        "lrotate" | "rrotate" => match shift(1) {
            Some(amount) => {
                let amount = amount.rem_euclid(32) as u32;
                if function == "lrotate" {
                    n(0).rotate_left(amount)
                } else {
                    n(0).rotate_right(amount)
                }
            }
            None => return Value::Unknown,
        },
        "replace" => {
            let field = n(2);
            let width = if values.len() > 3 { n(3) } else { 1 };
            if field > 31 || width == 0 || field.checked_add(width).is_none_or(|end| end > 32) {
                return Value::Unknown;
            }
            let mask = (u32::MAX >> (32 - width)) << field;
            (n(0) & !mask) | ((n(1) << field) & mask)
        }
        _ => return Value::Unknown,
    };
    Value::Number(f64::from(result), None)
}

fn is_string_method(name: &str) -> bool {
    matches!(
        name,
        "reverse"
            | "sub"
            | "lower"
            | "upper"
            | "rep"
            | "format"
            | "byte"
            | "len"
            | "gsub"
            | "gmatch"
            | "match"
            | "find"
            | "split"
    )
}

fn is_security_method(name: &str) -> bool {
    matches!(
        name,
        "IsStudio"
            | "LoadAsset"
            | "LoadAssetVersion"
            | "GetObjects"
            | "PostAsync"
            | "PostAsyncFullUrl"
            | "RequestAsync"
            | "GetAsync"
            | "HttpGet"
            | "HttpGetAsync"
            | "JSONDecode"
            | "JSONEncode"
            | "PromptPurchase"
            | "PromptProductPurchase"
            | "PromptGamePassPurchase"
            | "PromptBundlePurchase"
            | "PromptPremiumPurchase"
            | "PromptSubscriptionPurchase"
            | "Teleport"
            | "TeleportAsync"
            | "TeleportToPlaceInstance"
            | "TeleportToPrivateServer"
            | "TeleportPartyAsync"
    )
}

/// Names that make a condition a gate (BG009): a Studio, creator, place, server, player
/// count or clock check.
fn is_gate_member(name: &str) -> bool {
    matches!(
        name,
        "IsStudio"
            | "CreatorId"
            | "CreatorType"
            | "PlaceId"
            | "GameId"
            | "JobId"
            | "PrivateServerId"
            | "PrivateServerOwnerId"
            | "DateTime"
            | "GetPlayers"
            | "tick"
            | "DistributedGameTime"
    )
}

/// Findings that a gate makes suspicious: a resolved or ID shaped module load, an
/// instance sourced load, runtime code, environment access, runtime asset loads, HTTP
/// exfiltration and inserted prompts or teleports. An unresolved low `require` alone is
/// not one.
fn is_risky_action(finding: &Finding) -> bool {
    match finding.rule_id.as_str() {
        "BG001" | "BG008" => finding.severity >= Severity::High,
        "BG002" | "BG003" | "BG004" | "BG007" | "BG010" => true,
        _ => false,
    }
}

/// Seconds a wait or delay lasts at least: a number, or the lower bound of
/// `math.random(a, b)`.
fn delay_seconds(value: &Value) -> Option<f64> {
    match value {
        Value::Number(seconds, _) => Some(*seconds),
        Value::Range(low, _) => Some(*low),
        _ => None,
    }
}

/// A name that reads as a service, such as `HttpService` in `game.HttpService`.
fn is_service_name(name: &str) -> bool {
    name.len() > "Service".len()
        && name.ends_with("Service")
        && name.starts_with(|character: char| character.is_ascii_uppercase())
}

/// Player, server and experience identifiers that BG008 treats as sensitive on any
/// receiver. A plain `Name` counts only on a player.
fn is_sensitive_identifier(member: &str) -> bool {
    matches!(
        member,
        "UserId"
            | "PlaceId"
            | "JobId"
            | "CreatorId"
            | "AccountAge"
            | "GameId"
            | "PrivateServerId"
            | "PrivateServerOwnerId"
            | "DisplayName"
    )
}

fn is_sensitive_member(namespace: &str, member: &str) -> bool {
    is_sensitive_identifier(member)
        || (member == "Name" && namespace.to_ascii_lowercase().contains("player"))
}

fn is_dangerous_callable(name: &str) -> bool {
    matches!(name, "require" | "loadstring" | "getfenv" | "setfenv")
}

fn is_dangerous_wrapper(name: &str) -> bool {
    matches!(
        name,
        "pcall"
            | "xpcall"
            | "task.spawn"
            | "task.defer"
            | "task.delay"
            | "coroutine.wrap"
            | "coroutine.create"
            | "coroutine.resume"
            | "spawn"
            | "delay"
    )
}

/// Positions of the callback and of the first argument it receives in a call of a
/// function from [`is_dangerous_wrapper`], given the number of arguments.
fn wrapper_positions(name: &str, count: usize) -> (usize, usize) {
    match name {
        "delay" | "task.delay" => (1, 2),
        "xpcall" => (0, if count > 2 { 2 } else { 1 }),
        _ => (0, 1),
    }
}

/// Namespace of the script environment that `getfenv()` returns. Its fields are the
/// script's own globals.
const ENVIRONMENT: &str = "getfenv()";

/// Every name the Luau runtime or the Roblox engine puts in a script environment: the
/// Luau globals and libraries (Luau's builtin definitions), and the Roblox globals and
/// data type constructors (luau-lsp's Roblox definitions), plus legacy aliases such as
/// `Game`, `ypcall` and `printidentity`. Reading one of them through `getfenv()`
/// reaches a real capability, so BG004 stays high for it, except for the save of
/// `print` or `warn` that an output capturing test puts back.
/// Any other name read that way,
/// such as TestEZ's `it` and `expect`, is something a test runner or plugin host put
/// into the environment, and the read alone is reported low.
pub const ENVIRONMENT_BUILTINS: &[&str] = &[
    // Luau
    "_G",
    "_VERSION",
    "assert",
    "bit32",
    "buffer",
    "collectgarbage",
    "coroutine",
    "debug",
    "error",
    "gcinfo",
    "getfenv",
    "getmetatable",
    "integer",
    "ipairs",
    "loadstring",
    "math",
    "newproxy",
    "next",
    "os",
    "pairs",
    "pcall",
    "print",
    "rawequal",
    "rawget",
    "rawlen",
    "rawset",
    "require",
    "select",
    "setfenv",
    "setmetatable",
    "string",
    "table",
    "tonumber",
    "tostring",
    "type",
    "typeof",
    "types",
    "unpack",
    "utf8",
    "vector",
    "xpcall",
    // Roblox globals
    "DebuggerManager",
    "Delay",
    "ElapsedTime",
    "Enum",
    "Game",
    "Instance",
    "LoadLibrary",
    "PluginManager",
    "Spawn",
    "Stats",
    "UserSettings",
    "Version",
    "Wait",
    "Workspace",
    "delay",
    "elapsedTime",
    "game",
    "plugin",
    "printidentity",
    "script",
    "settings",
    "shared",
    "spawn",
    "stats",
    "task",
    "tick",
    "time",
    "version",
    "wait",
    "warn",
    "workspace",
    "ypcall",
    // Roblox data types
    "Axes",
    "BrickColor",
    "CFrame",
    "CatalogSearchParams",
    "Color3",
    "ColorSequence",
    "ColorSequenceKeypoint",
    "Content",
    "DateTime",
    "DockWidgetPluginGuiInfo",
    "Faces",
    "FloatCurveKey",
    "Font",
    "InstanceHandle",
    "NumberRange",
    "NumberSequence",
    "NumberSequenceKeypoint",
    "OverlapParams",
    "Path2DControlPoint",
    "PathWaypoint",
    "PhysicalProperties",
    "Random",
    "Ray",
    "RaycastParams",
    "Rect",
    "Region3",
    "Region3int16",
    "RotationCurveKey",
    "Secret",
    "SecurityCapabilities",
    "SharedTable",
    "TweenInfo",
    "UDim",
    "UDim2",
    "User",
    "ValueCurveKey",
    "Vector2",
    "Vector2int16",
    "Vector3",
    "Vector3int16",
];

/// `_G`, `shared` and the script environment: tables of globals.
fn is_global_table(namespace: &str) -> bool {
    matches!(namespace, "_G" | "shared" | ENVIRONMENT)
}

/// A player, or something read from one, such as `player.Character`.
fn is_player_namespace(namespace: &str) -> bool {
    namespace.to_ascii_lowercase().contains("player")
}

/// Instance and service methods the scanner follows when they are called with a dot
/// or taken as a value, such as `local get = obj.GetAttribute; get(obj, "id")`.
fn is_instance_method(name: &str) -> bool {
    matches!(
        name,
        "FindFirstChild"
            | "WaitForChild"
            | "FindFirstChildOfClass"
            | "FindFirstChildWhichIsA"
            | "FindFirstAncestor"
            | "FindFirstAncestorOfClass"
            | "FindFirstAncestorWhichIsA"
            | "GetChildren"
            | "GetDescendants"
            | "QueryDescendants"
            | "GetAttribute"
            | "GetAttributes"
            | "SetAttribute"
            | "Clone"
            | "GetService"
            | "FindService"
            | "getService"
            | "service"
            | "GetDataStore"
            | "GetGlobalDataStore"
            | "GetOrderedDataStore"
            | "GetSortedMap"
            | "GetQueue"
            | "GetHashMap"
            | "GetTagged"
            | "GetPlayers"
            | "GetPlayerFromCharacter"
            | "GetPlayerByUserId"
    )
}

fn is_instance_namespace(namespace: &str) -> bool {
    namespace == "game"
        || namespace.starts_with("game.")
        || namespace == "workspace"
        || namespace.starts_with("workspace.")
        || namespace == "local-dom"
        || namespace.starts_with("local-dom.")
}

// ----- tokens -------------------------------------------------------------------------

fn token_text(token: &TokenReference) -> String {
    token.token().to_string()
}

fn is_identifier_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn string_value(token: &TokenReference) -> String {
    token_literal(token.token_type())
        .unwrap_or_else(|| token_text(token).trim_matches(['\'', '"']).to_string())
}

/// Decoded text of a string or interpolated string token.
fn token_literal(token_type: &TokenType) -> Option<String> {
    match token_type {
        TokenType::StringLiteral {
            literal,
            quote_type: StringLiteralQuoteType::Brackets,
            ..
        } => Some(literal.to_string()),
        TokenType::StringLiteral { literal, .. }
        | TokenType::InterpolatedString { literal, .. } => {
            Some(decode_luau_string(literal).unwrap_or_else(|| literal.to_string()))
        }
        _ => None,
    }
}

fn interpolated_literal(token: &TokenReference) -> String {
    token_literal(token.token_type()).unwrap_or_default()
}

fn decode_luau_string(literal: &str) -> Option<String> {
    let mut output = String::with_capacity(literal.len());
    let mut characters = literal.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let escaped = characters.next()?;
        match escaped {
            'a' => output.push('\u{7}'),
            'b' => output.push('\u{8}'),
            'f' => output.push('\u{c}'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            'v' => output.push('\u{b}'),
            '\\' => output.push('\\'),
            '"' => output.push('"'),
            '\'' => output.push('\''),
            '\n' => output.push('\n'),
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                output.push('\n');
            }
            'z' => {
                while characters
                    .peek()
                    .is_some_and(|character| character.is_whitespace())
                {
                    characters.next();
                }
            }
            'x' => {
                let first = characters.next()?.to_digit(16)?;
                let second = characters.next()?.to_digit(16)?;
                output.push(char::from_u32(first * 16 + second)?);
            }
            'u' => {
                if characters.next()? != '{' {
                    return None;
                }
                let mut hexadecimal = String::new();
                loop {
                    let next = characters.next()?;
                    if next == '}' {
                        break;
                    }
                    if !next.is_ascii_hexdigit() || hexadecimal.len() == 6 {
                        return None;
                    }
                    hexadecimal.push(next);
                }
                if hexadecimal.is_empty() {
                    return None;
                }
                output.push(char::from_u32(u32::from_str_radix(&hexadecimal, 16).ok()?)?);
            }
            digit if digit.is_ascii_digit() => {
                let mut decimal = digit.to_string();
                for _ in 0..2 {
                    if characters.peek().is_some_and(|next| next.is_ascii_digit()) {
                        decimal.push(characters.next()?);
                    } else {
                        break;
                    }
                }
                let byte = decimal.parse::<u8>().ok()?;
                output.push(byte as char);
            }
            other => output.push(other),
        }
    }
    Some(output)
}

fn format_number(number: f64) -> String {
    if number.fract() == 0.0 && number.abs() < 1e18 {
        format!("{}", number as i128)
    } else {
        number.to_string()
    }
}

fn short_reason(reason: &str) -> String {
    let mut short: String = reason
        .chars()
        .take(240)
        .flat_map(char::escape_default)
        .collect();
    if reason.chars().count() > 240 {
        short.push_str("...");
    }
    short
}

// ----- URLs ---------------------------------------------------------------------------

/// Lowercase, percent-decode (bounded), drop credentials and port, and collapse empty,
/// `.` and `..` path segments. Returns `host/segment/...`.
fn normalize_url(url: &str) -> Option<String> {
    let mut text = url.trim().to_ascii_lowercase();
    for _ in 0..3 {
        if !text.contains('%') {
            break;
        }
        let decoded = percent_decode(&text);
        if decoded == text {
            break;
        }
        text = decoded.to_ascii_lowercase();
    }
    let text = text.replace('\\', "/");
    let rest = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"))?;
    let rest = rest.trim_start_matches('/');
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        format!("[{}]", stripped.split(']').next().unwrap_or(""))
    } else {
        host_port.split(':').next().unwrap_or(host_port).to_string()
    };
    let path = rest[end..].split(['?', '#']).next().unwrap_or("");
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    let mut normalized = host.trim_end_matches('.').to_string();
    for segment in segments {
        normalized.push('/');
        normalized.push_str(segment);
    }
    Some(normalized)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (
                (bytes[index + 1] as char).to_digit(16),
                (bytes[index + 2] as char).to_digit(16),
            )
        {
            output.push((high * 16 + low) as u8);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn classify_url(url: &str) -> Option<Endpoint> {
    if url.len() > 8192 {
        return None;
    }
    let normalized = normalize_url(url)?;
    let mut parts = normalized.split('/');
    let host = parts.next().unwrap_or("");
    let segments: Vec<&str> = parts.collect();
    for (index, segment) in segments.iter().enumerate() {
        if *segment != "webhooks" {
            continue;
        }
        let after_api = index >= 1
            && (segments[index - 1] == "api"
                || (index >= 2
                    && segments[index - 2] == "api"
                    && segments[index - 1]
                        .strip_prefix('v')
                        .is_some_and(|version| {
                            !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
                        })));
        let id_and_token = segments.len() >= index + 3
            && segments[index + 1]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-');
        if after_api || id_and_token {
            return Some(Endpoint::Webhook);
        }
    }
    let host_is = |domain: &str| host == domain || host.ends_with(&format!(".{domain}"));
    if (host_is("discord.com") || host_is("discordapp.com")) && segments.first() == Some(&"api") {
        return Some(Endpoint::Webhook);
    }
    if [
        "pastebin.com",
        "hastebin.com",
        "paste.ee",
        "rentry.co",
        "ghostbin.com",
    ]
    .iter()
    .any(|domain| host_is(domain))
        || host.contains("hastebin")
    {
        return Some(Endpoint::Paste);
    }
    let ipv4 = host.split('.').count() == 4
        && host
            .split('.')
            .all(|part| !part.is_empty() && part.len() <= 3 && part.parse::<u8>().is_ok());
    if ipv4 || host.starts_with('[') {
        return Some(Endpoint::IpHost);
    }
    None
}

// ----- Lua patterns -------------------------------------------------------------------
//
// A bounded port of the Lua 5.1 pattern matcher. Patterns longer than 256 bytes, more
// than 32 captures, deep recursion or too many steps make the fold fail instead.

const MAX_PATTERN_BYTES: usize = 256;
const MAX_PATTERN_STEPS: usize = 200_000;
const CAPTURE_UNFINISHED: isize = -1;
const CAPTURE_POSITION: isize = -2;

enum Replacement {
    Text(String),
    Table(BTreeMap<String, String>),
    /// What a function returned for each match in order; `None` keeps the match.
    Values(Vec<Option<String>>),
}

struct LuaMatcher<'p> {
    source: &'p [u8],
    pattern: &'p [u8],
    level: usize,
    captures: [(usize, isize); 32],
    steps: usize,
    depth: usize,
}

type MatchResult = Result<Option<usize>, ()>;

impl<'p> LuaMatcher<'p> {
    fn new(source: &'p [u8], pattern: &'p [u8]) -> Self {
        Self {
            source,
            pattern,
            level: 0,
            captures: [(0, 0); 32],
            steps: 0,
            depth: 0,
        }
    }

    fn tick(&mut self) -> Result<(), ()> {
        self.steps += 1;
        if self.steps > MAX_PATTERN_STEPS {
            Err(())
        } else {
            Ok(())
        }
    }

    fn class_end(&self, mut p: usize) -> Result<usize, ()> {
        let character = *self.pattern.get(p).ok_or(())?;
        p += 1;
        match character {
            b'%' => {
                if p >= self.pattern.len() {
                    return Err(());
                }
                Ok(p + 1)
            }
            b'[' => {
                if self.pattern.get(p) == Some(&b'^') {
                    p += 1;
                }
                loop {
                    let character = *self.pattern.get(p).ok_or(())?;
                    p += 1;
                    if character == b'%' && p < self.pattern.len() {
                        p += 1;
                    }
                    if self.pattern.get(p) == Some(&b']') {
                        break;
                    }
                }
                Ok(p + 1)
            }
            _ => Ok(p),
        }
    }

    fn single_match(&self, character: u8, p: usize, ep: usize) -> bool {
        match self.pattern[p] {
            b'.' => true,
            b'%' => match_class(character, self.pattern[p + 1]),
            b'[' => self.match_bracket(character, p, ep - 1),
            other => other == character,
        }
    }

    fn match_bracket(&self, character: u8, mut p: usize, end: usize) -> bool {
        let mut sign = true;
        if self.pattern.get(p + 1) == Some(&b'^') {
            sign = false;
            p += 1;
        }
        loop {
            p += 1;
            if p >= end {
                break;
            }
            if self.pattern[p] == b'%' {
                p += 1;
                if p < self.pattern.len() && match_class(character, self.pattern[p]) {
                    return sign;
                }
            } else if self.pattern.get(p + 1) == Some(&b'-') && p + 2 < end {
                p += 2;
                if self.pattern[p - 2] <= character && character <= self.pattern[p] {
                    return sign;
                }
            } else if self.pattern[p] == character {
                return sign;
            }
        }
        !sign
    }

    fn do_match(&mut self, s: usize, p: usize) -> MatchResult {
        self.depth += 1;
        if self.depth > 200 {
            return Err(());
        }
        let result = self.match_here(s, p);
        self.depth -= 1;
        result
    }

    fn match_here(&mut self, mut s: usize, mut p: usize) -> MatchResult {
        loop {
            self.tick()?;
            if p >= self.pattern.len() {
                return Ok(Some(s));
            }
            match self.pattern[p] {
                b'(' => {
                    return if self.pattern.get(p + 1) == Some(&b')') {
                        self.start_capture(s, p + 2, CAPTURE_POSITION)
                    } else {
                        self.start_capture(s, p + 1, CAPTURE_UNFINISHED)
                    };
                }
                b')' => return self.end_capture(s, p + 1),
                b'$' if p + 1 == self.pattern.len() => {
                    return Ok((s == self.source.len()).then_some(s));
                }
                b'%' if self.pattern.get(p + 1) == Some(&b'b') => {
                    match self.match_balance(s, p + 2)? {
                        Some(next) => {
                            s = next;
                            p += 4;
                            continue;
                        }
                        None => return Ok(None),
                    }
                }
                b'%' if self.pattern.get(p + 1) == Some(&b'f') => {
                    p += 2;
                    if self.pattern.get(p) != Some(&b'[') {
                        return Err(());
                    }
                    let ep = self.class_end(p)?;
                    let previous = if s == 0 { 0 } else { self.source[s - 1] };
                    let current = self.source.get(s).copied().unwrap_or(0);
                    if !self.match_bracket(previous, p, ep - 1)
                        && self.match_bracket(current, p, ep - 1)
                    {
                        p = ep;
                        continue;
                    }
                    return Ok(None);
                }
                b'%' if self.pattern.get(p + 1).is_some_and(u8::is_ascii_digit) => {
                    match self.match_capture(s, self.pattern[p + 1])? {
                        Some(next) => {
                            s = next;
                            p += 2;
                            continue;
                        }
                        None => return Ok(None),
                    }
                }
                _ => {
                    let ep = self.class_end(p)?;
                    let matches = s < self.source.len() && self.single_match(self.source[s], p, ep);
                    match self.pattern.get(ep) {
                        Some(b'?') => {
                            if matches && let Some(result) = self.do_match(s + 1, ep + 1)? {
                                return Ok(Some(result));
                            }
                            p = ep + 1;
                        }
                        Some(b'*') => return self.max_expand(s, p, ep),
                        Some(b'+') => {
                            return if matches {
                                self.max_expand(s + 1, p, ep)
                            } else {
                                Ok(None)
                            };
                        }
                        Some(b'-') => return self.min_expand(s, p, ep),
                        _ => {
                            if !matches {
                                return Ok(None);
                            }
                            s += 1;
                            p = ep;
                        }
                    }
                }
            }
        }
    }

    fn max_expand(&mut self, s: usize, p: usize, ep: usize) -> MatchResult {
        let mut count = 0usize;
        while s + count < self.source.len() && self.single_match(self.source[s + count], p, ep) {
            count += 1;
            self.tick()?;
        }
        loop {
            if let Some(result) = self.do_match(s + count, ep + 1)? {
                return Ok(Some(result));
            }
            if count == 0 {
                return Ok(None);
            }
            count -= 1;
        }
    }

    fn min_expand(&mut self, mut s: usize, p: usize, ep: usize) -> MatchResult {
        loop {
            if let Some(result) = self.do_match(s, ep + 1)? {
                return Ok(Some(result));
            }
            if s < self.source.len() && self.single_match(self.source[s], p, ep) {
                s += 1;
            } else {
                return Ok(None);
            }
        }
    }

    fn start_capture(&mut self, s: usize, p: usize, what: isize) -> MatchResult {
        if self.level >= self.captures.len() {
            return Err(());
        }
        self.captures[self.level] = (s, what);
        self.level += 1;
        let result = self.do_match(s, p)?;
        if result.is_none() {
            self.level -= 1;
        }
        Ok(result)
    }

    fn end_capture(&mut self, s: usize, p: usize) -> MatchResult {
        let open = (0..self.level)
            .rev()
            .find(|index| self.captures[*index].1 == CAPTURE_UNFINISHED)
            .ok_or(())?;
        self.captures[open].1 = (s - self.captures[open].0) as isize;
        let result = self.do_match(s, p)?;
        if result.is_none() {
            self.captures[open].1 = CAPTURE_UNFINISHED;
        }
        Ok(result)
    }

    fn match_balance(&mut self, s: usize, p: usize) -> MatchResult {
        if p + 1 >= self.pattern.len() {
            return Err(());
        }
        if self.source.get(s) != Some(&self.pattern[p]) {
            return Ok(None);
        }
        let (open, close) = (self.pattern[p], self.pattern[p + 1]);
        let mut depth = 1usize;
        let mut index = s + 1;
        while index < self.source.len() {
            self.tick()?;
            let character = self.source[index];
            if character == close {
                depth -= 1;
                if depth == 0 {
                    return Ok(Some(index + 1));
                }
            } else if character == open {
                depth += 1;
            }
            index += 1;
        }
        Ok(None)
    }

    fn match_capture(&mut self, s: usize, digit: u8) -> MatchResult {
        let index = usize::from(digit.checked_sub(b'1').ok_or(())?);
        if index >= self.level {
            return Err(());
        }
        let (start, len) = self.captures[index];
        if len < 0 {
            return Err(());
        }
        let len = len as usize;
        if self.source.len() - s >= len
            && self.source[start..start + len] == self.source[s..s + len]
        {
            Ok(Some(s + len))
        } else {
            Ok(None)
        }
    }

    fn capture(&self, index: usize, start: usize, end: usize) -> Result<Value, ()> {
        if index >= self.level {
            if index == 0 {
                return Ok(Value::String(
                    Text::from(String::from_utf8_lossy(&self.source[start..end]).into_owned()),
                    None,
                ));
            }
            return Err(());
        }
        let (capture_start, len) = self.captures[index];
        if len == CAPTURE_POSITION {
            Ok(Value::Number((capture_start + 1) as f64, None))
        } else if len < 0 {
            Err(())
        } else {
            Ok(Value::String(
                Text::from(
                    String::from_utf8_lossy(
                        &self.source[capture_start..capture_start + len as usize],
                    )
                    .into_owned(),
                ),
                None,
            ))
        }
    }
}

fn match_class(character: u8, class: u8) -> bool {
    let result = match class.to_ascii_lowercase() {
        b'a' => character.is_ascii_alphabetic(),
        b'c' => character.is_ascii_control(),
        b'd' => character.is_ascii_digit(),
        b'g' => character.is_ascii_graphic(),
        b'l' => character.is_ascii_lowercase(),
        b'p' => character.is_ascii_punctuation(),
        b's' => character.is_ascii_whitespace() || character == 0x0b,
        b'u' => character.is_ascii_uppercase(),
        b'w' => character.is_ascii_alphanumeric(),
        b'x' => character.is_ascii_hexdigit(),
        b'z' => character == 0,
        _ => return class == character,
    };
    if class.is_ascii_uppercase() {
        !result
    } else {
        result
    }
}

fn has_pattern_specials(pattern: &[u8]) -> bool {
    pattern.iter().any(|byte| b"^$*+?.([%-".contains(byte))
}

/// `string.find` and `string.match`.
fn lua_find(
    source: &[u8],
    pattern: &[u8],
    init: i64,
    plain: bool,
    find: bool,
) -> Result<Option<Vec<Value>>, ()> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(());
    }
    let len = source.len() as i64;
    let init = if init < 0 {
        (len + init + 1).max(1)
    } else {
        init.max(1)
    };
    if init > len + 1 {
        return Ok(None);
    }
    let start = (init - 1) as usize;
    if find && (plain || !has_pattern_specials(pattern)) {
        let found = if pattern.is_empty() {
            Some(start)
        } else {
            source[start..]
                .windows(pattern.len())
                .position(|window| window == pattern)
                .map(|offset| start + offset)
        };
        return Ok(found.map(|index| {
            vec![
                Value::Number((index + 1) as f64, None),
                Value::Number((index + pattern.len()) as f64, None),
            ]
        }));
    }
    let (anchor, pattern) = match pattern.strip_prefix(b"^") {
        Some(rest) => (true, rest),
        None => (false, pattern),
    };
    let mut matcher = LuaMatcher::new(source, pattern);
    let mut position = start;
    loop {
        matcher.level = 0;
        if let Some(end) = matcher.do_match(position, 0)? {
            let mut values = Vec::new();
            if find {
                values.push(Value::Number((position + 1) as f64, None));
                values.push(Value::Number(end as f64, None));
                for index in 0..matcher.level {
                    values.push(matcher.capture(index, position, end)?);
                }
            } else {
                for index in 0..matcher.level.max(1) {
                    values.push(matcher.capture(index, position, end)?);
                }
            }
            return Ok(Some(values));
        }
        position += 1;
        if anchor || position > source.len() {
            return Ok(None);
        }
    }
}

/// Matches kept for `gmatch` loops and `gsub` callbacks.
const MAX_MATCHES: usize = 8;

/// Captures of each match of `pattern` in `source`, as `gmatch` and `gsub` see them
/// (the whole match when the pattern has no captures). The flag is false when more
/// matches exist than are listed.
fn lua_matches(source: &[u8], pattern: &[u8]) -> Result<(Vec<Vec<Value>>, bool), ()> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(());
    }
    let (anchor, pattern) = match pattern.strip_prefix(b"^") {
        Some(rest) => (true, rest),
        None => (false, pattern),
    };
    let mut matcher = LuaMatcher::new(source, pattern);
    let mut matches = Vec::new();
    let mut position = 0usize;
    loop {
        matcher.level = 0;
        let end = matcher.do_match(position, 0)?;
        if let Some(end) = end {
            if matches.len() == MAX_MATCHES {
                return Ok((matches, false));
            }
            let mut captures = Vec::new();
            for index in 0..matcher.level.max(1) {
                captures.push(matcher.capture(index, position, end)?);
            }
            matches.push(captures);
        }
        match end {
            Some(end) if end > position => position = end,
            _ if position < source.len() => position += 1,
            _ => break,
        }
        if anchor {
            break;
        }
    }
    Ok((matches, true))
}

/// `string.gsub` with a string or constant table replacement.
fn lua_gsub(
    source: &[u8],
    pattern: &[u8],
    replacement: &Replacement,
    limit: Option<usize>,
    max_bytes: usize,
) -> Result<(Vec<u8>, usize), ()> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(());
    }
    let (anchor, pattern) = match pattern.strip_prefix(b"^") {
        Some(rest) => (true, rest),
        None => (false, pattern),
    };
    let mut matcher = LuaMatcher::new(source, pattern);
    let mut output = Vec::new();
    let mut position = 0usize;
    let mut count = 0usize;
    while limit.is_none_or(|limit| count < limit) {
        matcher.level = 0;
        let end = matcher.do_match(position, 0)?;
        if let Some(end) = end {
            count += 1;
            match replacement {
                Replacement::Text(text) => {
                    let text = text.as_bytes();
                    let mut index = 0;
                    while index < text.len() {
                        if text[index] == b'%' {
                            index += 1;
                            let next = *text.get(index).ok_or(())?;
                            if next == b'%' {
                                output.push(b'%');
                            } else if next.is_ascii_digit() {
                                let value = if next == b'0' {
                                    Value::String(
                                        Text::from(
                                            String::from_utf8_lossy(&source[position..end])
                                                .into_owned(),
                                        ),
                                        None,
                                    )
                                } else {
                                    matcher.capture(usize::from(next - b'1'), position, end)?
                                };
                                let (text, _) = value_as_string(&value).ok_or(())?;
                                output.extend_from_slice(text.as_bytes());
                            } else {
                                return Err(());
                            }
                        } else {
                            output.push(text[index]);
                        }
                        index += 1;
                    }
                }
                Replacement::Table(map) => {
                    let key = matcher.capture(0, position, end)?;
                    let (key, _) = value_as_string(&key).ok_or(())?;
                    match map.get(&key) {
                        Some(text) => output.extend_from_slice(text.as_bytes()),
                        None => output.extend_from_slice(&source[position..end]),
                    }
                }
                Replacement::Values(values) => match values.get(count - 1).ok_or(())? {
                    Some(text) => output.extend_from_slice(text.as_bytes()),
                    None => output.extend_from_slice(&source[position..end]),
                },
            }
            if output.len() > max_bytes {
                return Err(());
            }
        }
        match end {
            Some(end) if end > position => position = end,
            _ if position < source.len() => {
                output.push(source[position]);
                position += 1;
            }
            _ => break,
        }
        if anchor {
            break;
        }
    }
    if position < source.len() {
        output.extend_from_slice(&source[position..]);
    }
    if output.len() > max_bytes {
        return Err(());
    }
    Ok((output, count))
}
