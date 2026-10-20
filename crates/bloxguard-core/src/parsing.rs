//! Run parser construction, traversal and AST destruction on a bounded large stack.
use crate::model::Limits;
use full_moon::tokenizer::{Lexer, LexerResult, Symbol, Token, TokenType};
use std::cell::Cell;
use std::collections::VecDeque;

thread_local! { static PARSER_WORKER: Cell<bool> = const { Cell::new(false) }; }

/// Stack reserved for the parser worker. The lexical caps in `analysis` allow 1,024
/// nested blocks; at that depth an unoptimized build of the Luau parser needs about
/// 100 MiB, so the reservation leaves at least twice that. The memory is reserved, not
/// committed, until a deep input actually uses it.
pub const PARSER_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Remove the optional UTF-8 byte-order mark before tokenization or parsing.
pub fn source_without_bom(source: &str) -> &str {
    source.strip_prefix('\u{feff}').unwrap_or(source)
}

/// Informational note for a source that [`is_declaration_file`] accepts.
pub const DECLARATION_FILE_NOTE: &str = "type declaration file, not run by Roblox, not scanned";

/// Whether a source the parser rejected is a luau-lsp type declaration file, such as
/// `testez.d.lua`. The first parse error must be at the token right after a `declare`
/// that starts a line, and that token must begin a declaration: `declare function`,
/// `declare class X`, `declare extern type`, or `declare name:`. Luau parses this
/// syntax only with its `allowDeclarationSyntax` option, which is off by default, so
/// such a file does not compile as a script and none of it runs. Any other parse
/// failure, such as an error earlier in the file, is not a declaration file.
pub fn is_declaration_file(source: &str, errors: &[full_moon::Error]) -> bool {
    let Some(full_moon::Error::AstError(error)) = errors.first() else {
        return false;
    };
    let at = error.range().0.bytes();
    let mut lexer = Lexer::new(source, full_moon::LuaVersion::luau());
    // Code tokens, without comments and whitespace: the last two before the current one.
    let mut before: Option<Token> = None;
    let mut previous: Option<Token> = None;
    let mut declared: Option<Token> = None;
    while let Some(LexerResult::Ok(reference) | LexerResult::Recovered(reference, _)) =
        lexer.consume()
    {
        let token = reference.token().clone();
        if let Some(first) = declared {
            return declaration_continues(&first, &token);
        }
        let start = token.start_position().bytes();
        if start > at {
            return false;
        }
        if start == at {
            // `declare` right before the error, with nothing before it on its line.
            let declare = previous
                .as_ref()
                .filter(|declare| is_name(declare, "declare"))
                .is_some_and(|declare| {
                    let line = declare.start_position().line();
                    before
                        .as_ref()
                        .is_none_or(|token| token.end_position().line() < line)
                });
            if !declare {
                return false;
            }
            if matches!(
                token.token_type(),
                TokenType::Symbol {
                    symbol: Symbol::Function
                }
            ) {
                return true;
            }
            declared = Some(token);
            continue;
        }
        before = previous.replace(token);
    }
    false
}

/// Byte offset of the first `declare` that starts a line and begins a declaration, as
/// [`is_declaration_file`] defines them, or `None`. Lexing stops at that declaration.
pub fn first_declaration(source: &str) -> Option<usize> {
    let mut lexer = Lexer::new(source, full_moon::LuaVersion::luau());
    // The last three code tokens, oldest first, each with whether it starts its line.
    let mut window: VecDeque<(Token, bool)> = VecDeque::with_capacity(3);
    let mut last_line = None;
    while let Some(LexerResult::Ok(reference) | LexerResult::Recovered(reference, _)) =
        lexer.consume()
    {
        let token = reference.token().clone();
        let starts_line = last_line.is_none_or(|line| line < token.start_position().line());
        last_line = Some(token.end_position().line());
        if window.len() == 3 {
            window.pop_front();
        }
        window.push_back((token, starts_line));
        let declare_at = |index: usize| {
            window
                .get(index)
                .filter(|(token, starts_line)| *starts_line && is_name(token, "declare"))
                .map(|(token, _)| token.start_position().bytes())
        };
        // `declare name:`, `declare class X` and `declare extern type` end at the
        // newest token, so their `declare` is two back and comes first.
        if window.len() == 3
            && let Some(at) = declare_at(0)
            && declaration_continues(&window[1].0, &window[2].0)
        {
            return Some(at);
        }
        if let Some(at) = window.len().checked_sub(2).and_then(declare_at)
            && matches!(
                window[window.len() - 1].0.token_type(),
                TokenType::Symbol {
                    symbol: Symbol::Function
                }
            )
        {
            return Some(at);
        }
    }
    None
}

/// Whether a source that the parser safety check (see
/// [`crate::analysis::parser_budget`]) rejects is still a type declaration file. The
/// code before its first declaration (see [`first_declaration`]) must pass the check and
/// parse on its own: then `declare` starts a statement, so Luau rejects the file there
/// and none of it runs. Only that code is parsed, so method signatures and
/// `declare function` lines, which have no `end`, never count against the caps.
pub fn is_declaration_file_over_budget(source: &str, limits: &Limits) -> bool {
    if source.len() > limits.max_script_bytes {
        return false;
    }
    let Some(at) = first_declaration(source) else {
        return false;
    };
    let code = &source[..at];
    crate::analysis::parser_budget(code, limits).is_ok() && full_moon::parse(code).is_ok()
}

/// `declare name:`, `declare class X` and `declare extern type`, given the token after
/// `declare` and the one after that.
fn declaration_continues(first: &Token, next: &Token) -> bool {
    let TokenType::Identifier { identifier } = first.token_type() else {
        return false;
    };
    match (identifier.as_str(), next.token_type()) {
        (
            _,
            TokenType::Symbol {
                symbol: Symbol::Colon,
            },
        ) => true,
        ("class", TokenType::Identifier { .. }) => true,
        ("extern", _) => is_name(next, "type"),
        _ => false,
    }
}

fn is_name(token: &Token, name: &str) -> bool {
    matches!(token.token_type(), TokenType::Identifier { identifier } if identifier.as_str() == name)
}

pub fn on_large_stack<T: Send>(work: impl FnOnce() -> T + Send) -> Result<T, String> {
    if PARSER_WORKER.get() {
        return Ok(work());
    }
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("bloxguard-parser".into())
            .stack_size(PARSER_STACK_BYTES)
            .spawn_scoped(scope, || {
                PARSER_WORKER.set(true);
                work()
            })
            .map_err(|error| format!("cannot start parser worker: {error}"))?
            .join()
            .map_err(|_| "parser worker panicked; analysis is incomplete".into())
    })
}
