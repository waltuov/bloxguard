//! Parse-only Roblox security analysis. Scanned content is never executed.
pub const PRODUCT_NAME: &str = "bloxguard";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub mod analysis;
pub mod config;
pub mod engine;
pub mod finding;
pub mod heuristics;
pub mod loading;
pub mod model;
pub mod output;
pub mod parsing;
pub mod report;
pub mod rules;
