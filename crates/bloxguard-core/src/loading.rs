//! Bounded, parse-only loaders for Roblox files, source trees and MCP bundles.

use crate::model::{Bundle, Completeness, Document, InputClock, Instance, Limits};
use rbx_dom_weak::{WeakDom, types::Variant};
use serde_json::{Map, Value};
use std::any::Any;
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Cursor, Read};
use std::panic::{self, AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const SUPPORTED_FILES: &[&str] = &["rbxl", "rbxlx", "rbxm", "rbxmx"];
/// Nested `Item` elements allowed in XML input. rbx_xml decodes children
/// recursively, about 4 KB of stack per level in an unoptimized build, so 2,048
/// levels use about 8 MiB of the parser worker's 256 MiB stack.
const MAX_XML_ITEM_NESTING: usize = 2_048;
/// Nesting of all XML elements. The `roblox` root, `Properties`, a property
/// and the parts of a structured value such as `Font` sit around the deepest
/// `Item`, so this leaves room for them while still bounding other markup.
const MAX_XML_ELEMENT_NESTING: usize = MAX_XML_ITEM_NESTING + 16;
const MAX_PROTECTED_STRING_PROPERTIES: usize = 4_096;

/// Attributes read from one instance. An instance whose attribute data declares
/// more keeps none of them, and the input is partial.
pub const MAX_ATTRIBUTES_PER_INSTANCE: usize = 10_000;
/// Attributes read from one input, from every file, metadata file and bundle
/// instance it holds. Attributes past this keep the input partial.
pub const MAX_ATTRIBUTES_PER_INPUT: usize = 500_000;
/// Bytes of serialized attribute data (`AttributesSerialize`) decoded for one
/// input. Decoding copies names and values, so this bounds that copy.
pub const MAX_ATTRIBUTE_BYTES_PER_INPUT: usize = 32 * 1024 * 1024;

/// What one input may still load. Model files nested in a source tree share the
/// budget of the tree, and its clock.
#[derive(Debug)]
struct InputBudget {
    clock: InputClock,
    /// Attributes read so far.
    attributes: usize,
    /// Bytes of serialized attribute data decoded so far.
    attribute_bytes: usize,
}

impl InputBudget {
    fn new(limits: &Limits) -> Self {
        Self {
            clock: InputClock::start(limits),
            attributes: 0,
            attribute_bytes: 0,
        }
    }

    /// Mark `document` partial once the input's time budget is used up.
    fn check_time(&self, document: &mut Document, limits: &Limits) -> bool {
        let exceeded = self.clock.exceeded();
        if exceeded {
            document.partial(format!("time budget of {} ms exceeded", limits.max_file_ms));
        }
        exceeded
    }

    /// Take `count` attributes with `bytes` of serialized data for an instance
    /// that already holds `held`, or say which cap they would pass. Nothing is
    /// taken when they do not fit.
    fn take_attributes(&mut self, held: usize, count: usize, bytes: usize) -> Result<(), String> {
        let on_instance = held.saturating_add(count);
        if on_instance > MAX_ATTRIBUTES_PER_INSTANCE {
            return Err(format!(
                "{on_instance} attributes on one instance, more than {MAX_ATTRIBUTES_PER_INSTANCE}"
            ));
        }
        let attributes = self.attributes.saturating_add(count);
        if attributes > MAX_ATTRIBUTES_PER_INPUT {
            return Err(format!(
                "{attributes} attributes in the input, more than {MAX_ATTRIBUTES_PER_INPUT}"
            ));
        }
        let attribute_bytes = self.attribute_bytes.saturating_add(bytes);
        if attribute_bytes > MAX_ATTRIBUTE_BYTES_PER_INPUT {
            return Err(format!(
                "{attribute_bytes} bytes of attribute data in the input, more than {MAX_ATTRIBUTE_BYTES_PER_INPUT}"
            ));
        }
        self.attributes = attributes;
        self.attribute_bytes = attribute_bytes;
        Ok(())
    }
}

/// Count the attributes an instance got from JSON (a bundle, a model file or a
/// metadata file) against the caps. Above a cap the instance keeps none.
fn take_listed_attributes(
    document: &mut Document,
    instance: &mut Instance,
    budget: &mut InputBudget,
) {
    let count = instance.attributes.len();
    if count == 0 {
        return;
    }
    if let Err(detail) = budget.take_attributes(0, count, 0) {
        document.partial(attribute_limit_reason(&instance.name, &detail));
        instance.attributes.clear();
    }
}

fn attribute_limit_reason(instance_name: &str, detail: &str) -> String {
    format!("attribute limit reached on {instance_name:?}: {detail}; its attributes were not read")
}

/// What the bounded preflight learned before a decoder runs.
#[derive(Debug, Default)]
struct Preflight {
    /// Reasons that make the input partial.
    warnings: Vec<String>,
    /// Informational notes, such as a skipped value that no rule reads (see
    /// [`skipped_value_risk`]).
    notes: Vec<String>,
    /// `(class, property)` pairs that an XML file stores as a nonempty
    /// `ProtectedString`, the type Roblox uses for script source. Decoders turn
    /// it into an ordinary string, so the type is recorded here first.
    protected_strings: BTreeSet<(String, String)>,
    /// `(value type, class, property)` of each skipped value already reported.
    skipped_values: HashSet<(String, Option<String>, Option<String>)>,
}

/// Skipped values reported per list. A file can repeat a property chunk or
/// element many times, and a full reason list already makes the input partial.
const MAX_SKIPPED_VALUE_REPORTS: usize = 32;

impl Preflight {
    /// Report a value the decoders skip, once per value type, class and
    /// property, as a reason or, when `note`, as a note. Reasons and notes have
    /// separate caps, so notes never keep a reason out.
    fn skipped_value(
        &mut self,
        key: (String, Option<String>, Option<String>),
        message: String,
        note: bool,
    ) {
        let reported = if note {
            &mut self.notes
        } else {
            &mut self.warnings
        };
        if reported.len() < MAX_SKIPPED_VALUE_REPORTS && self.skipped_values.insert(key) {
            reported.push(message);
        }
    }
}

thread_local! {
    static DECODER_PANIC_SUPPRESSION_DEPTH: Cell<usize> = const { Cell::new(0) };
}

static DECODER_PANIC_HOOK: OnceLock<()> = OnceLock::new();

struct DecoderPanicGuard;

impl DecoderPanicGuard {
    fn enter() -> Self {
        DECODER_PANIC_HOOK.get_or_init(|| {
            let previous = panic::take_hook();
            panic::set_hook(Box::new(move |info| {
                let suppressed = DECODER_PANIC_SUPPRESSION_DEPTH
                    .try_with(|depth| depth.get() > 0)
                    .unwrap_or(false);
                if !suppressed {
                    previous(info);
                }
            }));
        });
        DECODER_PANIC_SUPPRESSION_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}

impl Drop for DecoderPanicGuard {
    fn drop(&mut self) {
        DECODER_PANIC_SUPPRESSION_DEPTH.with(|depth| {
            let current = depth.get();
            debug_assert!(current > 0, "decoder panic suppression depth underflow");
            depth.set(current.saturating_sub(1));
        });
    }
}

/// A changed copy of `base`, built on first use and kept for the process.
///
/// It serves the decoders' reflection database. `rbx_reflection` is not a
/// direct dependency, so that type is only ever inferred, never named. The cell
/// is shared by every `T`, so this has exactly one caller.
fn cached_copy<T: Any + Clone + Send + Sync>(base: &T, change: impl FnOnce(&mut T)) -> &'static T {
    static VALUE: OnceLock<Box<dyn Any + Send + Sync>> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            let mut value = base.clone();
            change(&mut value);
            Box::new(value)
        })
        .downcast_ref()
        .expect("the cell holds one type")
}

/// Load a Roblox file, a Luau source file, or a direct source tree.
///
/// A directory produces one document. A single file also produces one document,
/// including unsupported and unreadable files, so callers can report why an
/// explicitly requested input was not scanned.
pub fn load_path(path: &Path, limits: &Limits) -> Vec<Document> {
    let mut budget = InputBudget::new(limits);
    let mut document = load_path_within(path, limits, &mut budget);
    document.time_spent = budget.clock.spent();
    vec![document]
}

fn load_path_within(path: &Path, limits: &Limits, budget: &mut InputBudget) -> Document {
    let input = path.to_string_lossy().into_owned();
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return failed_document(input, format!("cannot read input metadata: {error}"));
        }
    };

    if is_link_or_reparse(&metadata) {
        return failed_document(input, "input is a symbolic link or junction");
    }
    if metadata.is_dir() {
        return load_source_tree(path, limits, budget);
    }
    if !metadata.is_file() {
        return failed_document(input, "input is neither a regular file nor a directory");
    }

    let extension = normalized_extension(path);
    if is_source_extension(&extension) {
        return load_source_file(path, &input, limits);
    }
    if !SUPPORTED_FILES.contains(&extension.as_str()) {
        let mut document = Document {
            input,
            ..Document::default()
        };
        document.partial(format!("unsupported input extension: .{extension}"));
        return document;
    }
    if metadata.len() > limits.max_file_bytes {
        let mut document = Document {
            input,
            ..Document::default()
        };
        document.partial(format!(
            "file size {} exceeds max_file_bytes {}",
            metadata.len(),
            limits.max_file_bytes
        ));
        return document;
    }

    match read_bounded(path, limits.max_file_bytes) {
        Ok(BoundedRead::Bytes(bytes)) => {
            load_bytes_within(&input, &extension, &bytes, limits, budget)
        }
        Ok(BoundedRead::TooLarge(size)) => {
            let mut document = Document {
                input,
                ..Document::default()
            };
            document.partial(format!(
                "file size {size} exceeds max_file_bytes {}",
                limits.max_file_bytes
            ));
            document
        }
        Err(error) => {
            let mut document = Document {
                input,
                ..Document::default()
            };
            document.partial(format!("cannot read input: {error}"));
            document
        }
    }
}

/// Decode an in-memory Roblox file. The extension may include a leading dot.
pub fn load_bytes(input: &str, extension: &str, bytes: &[u8], limits: &Limits) -> Document {
    let mut budget = InputBudget::new(limits);
    let mut document = load_bytes_within(input, extension, bytes, limits, &mut budget);
    document.time_spent = budget.clock.spent();
    document
}

fn load_bytes_within(
    input: &str,
    extension: &str,
    bytes: &[u8],
    limits: &Limits,
    budget: &mut InputBudget,
) -> Document {
    crate::parsing::on_large_stack(|| load_bytes_on_worker(input, extension, bytes, limits, budget))
        .unwrap_or_else(|reason| Document {
            input: input.into(),
            completeness: Completeness::Partial,
            reasons: vec![reason],
            ..Document::default()
        })
}
fn load_bytes_on_worker(
    input: &str,
    extension: &str,
    bytes: &[u8],
    limits: &Limits,
    budget: &mut InputBudget,
) -> Document {
    let mut document = Document {
        input: input.to_owned(),
        ..Document::default()
    };
    if bytes.len() as u64 > limits.max_file_bytes {
        document.partial(format!(
            "file size {} exceeds max_file_bytes {}",
            bytes.len(),
            limits.max_file_bytes
        ));
        return document;
    }

    let extension = extension.trim_start_matches('.').to_ascii_lowercase();
    let preflight = match extension.as_str() {
        "rbxl" | "rbxm" => preflight_binary(bytes, limits),
        "rbxlx" | "rbxmx" => preflight_xml(bytes, limits),
        _ => Err(format!("unsupported input extension: .{extension}")),
    };
    let preflight = match preflight {
        Ok(preflight) => preflight,
        Err(reason) => {
            document.partial(reason);
            return document;
        }
    };
    for warning in preflight.warnings {
        document.partial(warning);
    }
    for note in preflight.notes {
        document.informational(note, None);
    }
    let decoded = {
        let _panic_guard = DecoderPanicGuard::enter();
        catch_unwind(AssertUnwindSafe(|| decode_dom(&extension, bytes)))
    };

    match decoded {
        Ok(Ok(dom)) => append_dom(
            &mut document,
            &dom,
            limits,
            &preflight.protected_strings,
            budget,
        ),
        Ok(Err(error)) => document.partial(format!("could not decode .{extension}: {error}")),
        Err(_) => document.partial(format!(".{extension} decoder panicked on malformed input")),
    }
    budget.check_time(&mut document, limits);
    document
}

/// Run the dependency decoder for a lowercase extension without a dot.
///
/// The decoders get the bundled reflection database with one change: the
/// `Attributes` property reads as its raw blob. rbx_binary and rbx_xml 3.0.1
/// decode attributes with rbx_types, which reserves every declared length
/// before reading it, so a 20 byte blob can ask for tens of GiB, and they keep
/// the raw blob without a word when decoding fails. `read_attributes` checks
/// the blob's lengths and decodes it instead.
fn decode_dom(extension: &str, bytes: &[u8]) -> Result<WeakDom, String> {
    let database = cached_copy(rbx_reflection_database::get_bundled(), |database| {
        let attributes = database
            .classes
            .get_mut("Instance")
            .and_then(|class| class.properties.get_mut("Attributes"));
        if let Some(property) = attributes {
            property.data_type = serde_json::from_str(r#"{"Value":"BinaryString"}"#)
                .expect("a constant reflection data type");
        }
    });
    match extension {
        "rbxl" | "rbxm" => rbx_binary::Deserializer::new()
            .reflection_database(database)
            .deserialize(Cursor::new(bytes))
            .map_err(|error| error.to_string()),
        "rbxlx" | "rbxmx" => rbx_xml::from_reader(
            Cursor::new(bytes),
            rbx_xml::DecodeOptions::new()
                .property_behavior(rbx_xml::DecodePropertyBehavior::ReadUnknown)
                .reflection_database(database),
        )
        .map_err(|error| error.to_string()),
        _ => Err(format!("unsupported input extension: .{extension}")),
    }
}

/// Normalize and validate a flat bundle received through the MCP API.
pub fn load_bundle(bundle: Bundle, input: &str, limits: &Limits) -> Document {
    let mut budget = InputBudget::new(limits);
    let mut document = load_bundle_within(bundle, input, limits, &mut budget);
    document.time_spent = budget.clock.spent();
    document
}

fn load_bundle_within(
    bundle: Bundle,
    input: &str,
    limits: &Limits,
    budget: &mut InputBudget,
) -> Document {
    let mut document = Document {
        input: input.to_owned(),
        ..Document::default()
    };
    if bundle.schema_version != 1 {
        document.partial(format!(
            "unsupported bundle schema_version {}",
            bundle.schema_version
        ));
    }
    if bundle.instances.is_empty() {
        document.failed("bundle contains no instances");
        return document;
    }

    let take = bundle.instances.len().min(limits.max_instances);
    if take < bundle.instances.len() {
        document.partial(format!(
            "instance count {} exceeds max_instances {}",
            bundle.instances.len(),
            limits.max_instances
        ));
    }
    for (index, mut instance) in bundle.instances.into_iter().take(take).enumerate() {
        match instance.parent {
            None => {}
            Some(parent) if parent < index => {}
            Some(parent) => {
                document.partial(format!(
                    "bundle instance {index} has invalid parent {parent}; parents must precede children"
                ));
                instance.parent = None;
            }
        }
        normalize_instance(&mut document, &mut instance, limits, index);
        take_listed_attributes(&mut document, &mut instance, budget);
        mark_unknown_class(&mut document, &instance, index, None, limits);
        document.instances.push(instance);
        if budget.check_time(&mut document, limits) {
            break;
        }
    }
    document
}

/// Load one source string supplied directly by an editor or agent.
pub fn load_source(source: &str, path: &str, class: &str, limits: &Limits) -> Document {
    let clock = InputClock::start(limits);
    let mut document = Document {
        input: path.to_owned(),
        ..Document::default()
    };
    let class = if class.is_empty() {
        "ModuleScript"
    } else {
        class
    };
    let name = source_name(Path::new(path));
    let mut instance = Instance {
        name,
        class: class.to_owned(),
        source_file: Some(path.to_owned()),
        ..Instance::default()
    };
    if source.len() > limits.max_script_bytes {
        document.partial(format!(
            "script source size {} exceeds max_script_bytes {}",
            source.len(),
            limits.max_script_bytes
        ));
    } else {
        instance.source = Some(source.to_owned());
    }
    if !instance.is_script() {
        document.partial(format!("source class {class:?} is not a script class"));
    }
    mark_unknown_class(&mut document, &instance, 0, None, limits);
    document.instances.push(instance);
    document.time_spent = clock.spent();
    document
}

fn load_source_file(path: &Path, input: &str, limits: &Limits) -> Document {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return failed_document(
                input.to_owned(),
                format!("cannot read source metadata: {error}"),
            );
        }
    };
    let mut document = Document {
        input: input.to_owned(),
        ..Document::default()
    };
    let source_stub = || Instance {
        name: source_name(path),
        class: source_class(path).to_owned(),
        source_file: Some(input.to_owned()),
        ..Instance::default()
    };
    if metadata.len() > limits.max_script_bytes as u64 {
        document.partial(format!(
            "script source size {} exceeds max_script_bytes {}",
            metadata.len(),
            limits.max_script_bytes
        ));
        push_instance(&mut document, source_stub(), limits);
        return document;
    }
    match read_bounded(path, limits.max_script_bytes as u64) {
        Ok(BoundedRead::Bytes(bytes)) => match String::from_utf8(bytes) {
            Ok(source) => load_source(&source, input, source_class(path), limits),
            Err(error) => {
                document.partial(format!("source is not valid UTF-8: {error}"));
                push_instance(&mut document, source_stub(), limits);
                document
            }
        },
        Ok(BoundedRead::TooLarge(size)) => {
            document.partial(format!(
                "script source size {size} exceeds max_script_bytes {}",
                limits.max_script_bytes
            ));
            push_instance(&mut document, source_stub(), limits);
            document
        }
        Err(error) => {
            document.partial(format!("cannot read source: {error}"));
            push_instance(&mut document, source_stub(), limits);
            document
        }
    }
}

#[derive(Debug)]
struct PendingDirectory {
    path: PathBuf,
    parent: Option<usize>,
}

fn load_source_tree(root: &Path, limits: &Limits, budget: &mut InputBudget) -> Document {
    let input = root.to_string_lossy().into_owned();
    let mut document = Document {
        input,
        ..Document::default()
    };
    let canonical_root = match fs::canonicalize(root) {
        Ok(path) => path,
        Err(error) => {
            document.failed(format!("cannot resolve source tree root: {error}"));
            return document;
        }
    };
    let mut pending = vec![PendingDirectory {
        path: root.to_owned(),
        parent: None,
    }];
    let mut scanned = 0usize;
    // The walk stopped before it saw every entry, so the tree may still hold
    // supported files.
    let mut cut_short = false;
    let mut rojo_projects = Vec::new();

    while let Some(directory) = pending.pop() {
        if budget.check_time(&mut document, limits) {
            cut_short = true;
            break;
        }
        if !path_stays_in_root(&directory.path, &canonical_root) {
            document.partial(format!(
                "refused path outside source tree: {}",
                directory.path.display()
            ));
            continue;
        }
        let reader = match fs::read_dir(&directory.path) {
            Ok(entries) => entries,
            Err(error) => {
                document.partial(format!(
                    "cannot read directory {}: {error}",
                    directory.path.display()
                ));
                continue;
            }
        };
        let entry_limit = limits.max_instances.saturating_mul(2).max(1_024);
        let mut entries = Vec::new();
        for entry in reader {
            if budget.check_time(&mut document, limits) {
                cut_short = true;
                break;
            }
            match entry {
                Ok(entry) if entries.len() < entry_limit => entries.push(entry),
                Ok(_) => {
                    document.partial(format!(
                        "directory entry count exceeds safety limit {entry_limit} at {}",
                        directory.path.display()
                    ));
                    cut_short = true;
                    break;
                }
                Err(error) => document.partial(format!(
                    "cannot read a directory entry in {}: {error}",
                    directory.path.display()
                )),
            }
        }
        entries.sort_by_key(|entry| {
            let original = entry.file_name().to_string_lossy().into_owned();
            (original.to_lowercase(), original)
        });

        let mut init_sources = Vec::new();
        for entry in &entries {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if is_init_source_name(&name)
                && safe_regular_file(&entry.path(), &canonical_root, &mut document)
            {
                init_sources.push(entry.path());
            }
        }
        init_sources.sort_by_key(|path| {
            let original = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            (
                init_priority(&original.to_ascii_lowercase()),
                original.to_ascii_lowercase(),
            )
        });
        if init_sources.len() > 1 {
            document.partial(format!(
                "multiple init source files in {}; using {}",
                directory.path.display(),
                init_sources[0].display()
            ));
        }
        let init_source = init_sources.first().cloned();
        let directory_name = directory
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("root")
            .to_owned();
        let mut node = Instance {
            name: directory_name,
            class: init_source
                .as_deref()
                .map_or("Folder", source_class)
                .to_owned(),
            parent: directory.parent,
            ..Instance::default()
        };
        if let Some(source_path) = init_source.as_deref() {
            scanned += 1;
            read_source_into(&mut document, &mut node, source_path, limits);
            apply_source_conventions(&mut node, source_path);
        }
        // Rojo builds an init script like a file named after its folder, so
        // `<folder>/<folder name>.meta.json` applies to it before `init.meta.json`.
        let script_stem = directory
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|_| init_source.is_some());
        for stem in script_stem.into_iter().chain(["init"]) {
            apply_metadata(
                &mut document,
                &mut node,
                &directory.path,
                stem,
                &canonical_root,
                limits,
            );
        }
        take_listed_attributes(&mut document, &mut node, budget);
        if let Some(source_path) = init_source.as_deref() {
            ensure_source_class(&mut document, &mut node, source_path);
        }
        if !push_instance(&mut document, node, limits) {
            cut_short = true;
            break;
        }
        let directory_index = document.instances.len() - 1;

        let mut child_directories = Vec::new();
        for entry in entries {
            if budget.check_time(&mut document, limits) {
                cut_short = true;
                break;
            }
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    document.partial(format!(
                        "cannot read metadata for {}: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            if is_link_or_reparse(&metadata) {
                document.partial(format!(
                    "skipped symbolic link or junction: {}",
                    path.display()
                ));
                continue;
            }
            if metadata.is_dir() {
                if should_skip_directory(&entry.file_name().to_string_lossy()) {
                    continue;
                }
                child_directories.push(path);
                continue;
            }
            if !metadata.is_file() || !path_stays_in_root(&path, &canonical_root) {
                if metadata.is_file() {
                    document.partial(format!(
                        "refused file outside source tree: {}",
                        path.display()
                    ));
                }
                continue;
            }
            let lower_name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if lower_name.ends_with(".project.json") || lower_name.ends_with(".project.jsonc") {
                check_rojo_project(&mut document, &path, root, &canonical_root, limits);
                rojo_projects.push(path);
                continue;
            }
            // Metadata files are read with the instance they belong to.
            if is_init_source_name(&lower_name) || is_meta_file_name(&lower_name) {
                continue;
            }
            let extension = normalized_extension(&path);
            if is_source_extension(&extension) {
                scanned += 1;
                let mut instance = Instance {
                    name: source_name(&path),
                    class: source_class(&path).to_owned(),
                    parent: Some(directory_index),
                    ..Instance::default()
                };
                read_source_into(&mut document, &mut instance, &path, limits);
                apply_source_conventions(&mut instance, &path);
                apply_metadata(
                    &mut document,
                    &mut instance,
                    &directory.path,
                    &source_name(&path),
                    &canonical_root,
                    limits,
                );
                take_listed_attributes(&mut document, &mut instance, budget);
                ensure_source_class(&mut document, &mut instance, &path);
                if !push_instance(&mut document, instance, limits) {
                    cut_short = true;
                    break;
                }
            } else if SUPPORTED_FILES.contains(&extension.as_str()) {
                scanned += 1;
                append_nested_model(
                    &mut document,
                    &path,
                    &extension,
                    directory_index,
                    limits,
                    budget,
                );
            } else if lower_name.ends_with(".model.json") || lower_name.ends_with(".model.jsonc") {
                scanned += 1;
                append_json_model(&mut document, &path, directory_index, limits, budget);
            } else if is_rojo_data_file(&lower_name, &extension) {
                check_data_file_metadata(&mut document, &path, &canonical_root, limits);
            }
        }
        for path in child_directories.into_iter().rev() {
            pending.push(PendingDirectory {
                path,
                parent: Some(directory_index),
            });
        }
    }

    if let Some(first) = rojo_projects.first() {
        let others = match rojo_projects.len() - 1 {
            0 => String::new(),
            1 => " and 1 other project file".to_owned(),
            count => format!(" and {count} other project files"),
        };
        document.informational(
            format!(
                "Rojo project mapping in {}{others} was not applied; instance paths follow the folder layout. Run `rojo build` and scan the output for full fidelity",
                first.display()
            ),
            None,
        );
    }
    // A walk cut short has already made the input partial with its reason.
    if scanned == 0 && !cut_short {
        document.failed("source tree contains no supported scripts or Roblox model/place files");
    }
    document
}

/// Properties a project node can set inline that the rules would read.
fn rojo_property_feeds_rules(name: &str) -> bool {
    matches!(name, "Value" | "LinkedSource" | "RunContext" | "Attributes")
        || name.to_ascii_lowercase().contains("source")
        || PACKAGE_LINK_PROPERTIES.contains(&name)
        || crate::heuristics::is_text_property(name)
}

/// Check one Rojo project file without applying its mapping.
///
/// The direct scan reads every source file in the tree, so a project file is
/// only a note unless it pulls in something the scan cannot see: a `$path`
/// outside the scanned tree or inside an excluded folder, or inline
/// properties and attributes that the rules read. Those make the input
/// partial. A `$path` that does not exist is named in a note, because there is
/// nothing in this checkout to scan.
fn check_rojo_project(
    document: &mut Document,
    path: &Path,
    root: &Path,
    canonical_root: &Path,
    limits: &Limits,
) {
    let bytes = match read_bounded(path, limits.max_file_bytes) {
        Ok(BoundedRead::Bytes(bytes)) => bytes,
        Ok(BoundedRead::TooLarge(size)) => {
            document.partial(format!(
                "Rojo project {} size {size} exceeds max_file_bytes {}; its mapping could not be checked",
                path.display(),
                limits.max_file_bytes
            ));
            return;
        }
        Err(error) => {
            document.partial(format!(
                "cannot read Rojo project {}: {error}; its mapping could not be checked",
                path.display()
            ));
            return;
        }
    };
    let project = match parse_jsonc(&bytes) {
        Ok(project) => project,
        Err(error) => {
            document.partial(format!(
                "Rojo project mapping in {} could not be checked: {error}",
                path.display()
            ));
            return;
        }
    };
    let Some(tree) = project.get("tree").filter(|tree| tree.is_object()) else {
        document.partial(format!(
            "Rojo project mapping in {} could not be checked: the file has no tree object",
            path.display()
        ));
        return;
    };
    let project_dir = path.parent().unwrap_or(root);
    let mut nodes = vec![("tree".to_owned(), tree)];
    let mut visited = 0usize;
    while let Some((node_path, node)) = nodes.pop() {
        visited += 1;
        if visited > limits.max_instances {
            document.partial(format!(
                "Rojo project {} has more than {} nodes; its mapping could not be fully checked",
                path.display(),
                limits.max_instances
            ));
            return;
        }
        let Some(object) = node.as_object() else {
            continue;
        };
        let mapped = object.get("$path").and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("optional").and_then(Value::as_str))
        });
        if let Some(mapped) = mapped {
            check_rojo_mapped_path(document, path, project_dir, root, canonical_root, mapped);
        }
        if let Some(properties) = object.get("$properties").and_then(Value::as_object) {
            for name in properties
                .keys()
                .filter(|name| rojo_property_feeds_rules(name))
            {
                document.partial(format!(
                    "Rojo project {} sets {name} inline at {node_path}; direct scans do not read project properties, so build with Rojo and scan the output",
                    path.display()
                ));
            }
        }
        if object
            .get("$attributes")
            .and_then(Value::as_object)
            .is_some_and(|attributes| !attributes.is_empty())
        {
            document.partial(format!(
                "Rojo project {} sets attributes inline at {node_path}; direct scans do not read project attributes, so build with Rojo and scan the output",
                path.display()
            ));
        }
        for (name, child) in object.iter().rev() {
            if !name.starts_with('$') && child.is_object() {
                nodes.push((format!("{node_path}/{name}"), child));
            }
        }
    }
}

fn check_rojo_mapped_path(
    document: &mut Document,
    project: &Path,
    project_dir: &Path,
    root: &Path,
    canonical_root: &Path,
    mapped: &str,
) {
    let target = project_dir.join(mapped);
    // The walk builds every path as `root` joined with names, so the project's
    // folder below the root is known without touching the file system.
    let project_below_root = project_dir.strip_prefix(root).unwrap_or(Path::new(""));
    let anchored = lexically_normalized(&canonical_root.join(project_below_root).join(mapped));
    let canonical = fs::canonicalize(&target).ok();
    let inside = canonical.as_ref().map_or_else(
        || anchored.starts_with(canonical_root),
        |canonical| canonical.starts_with(canonical_root),
    );
    if !inside {
        document.partial(format!(
            "Rojo project {} maps {mapped:?} from outside the scanned tree; that content was not scanned",
            project.display()
        ));
        return;
    }
    let relative = canonical
        .as_deref()
        .and_then(|canonical| canonical.strip_prefix(canonical_root).ok())
        .or_else(|| anchored.strip_prefix(canonical_root).ok());
    let missing = fs::symlink_metadata(&target).is_err();
    // A dependency folder such as `node_modules` before `npm install` holds
    // nothing to scan, like any other missing path, so only an existing one is
    // content the direct scan skips.
    if !missing
        && relative.is_some_and(|relative| {
            relative
                .components()
                .any(|part| should_skip_directory(&part.as_os_str().to_string_lossy()))
        })
    {
        document.partial(format!(
            "Rojo project {} maps {mapped:?} inside a folder that direct scans exclude, so this input stays partial; build with Rojo and scan the output, or also scan that folder and pass --allow-incomplete once the reasons are reviewed",
            project.display()
        ));
        return;
    }
    if missing {
        document.informational(
            format!(
                "Rojo project {} maps {mapped:?}, which does not exist in the scanned tree; create it before scanning if it holds code",
                project.display()
            ),
            None,
        );
    }
}

/// Resolve `.` and `..` in the path text without touching the file system.
fn lexically_normalized(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    normalized.pop();
                } else if !normalized.has_root() {
                    normalized.push("..");
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// Read a Rojo JSON file, of any kind and with either extension, the way Rojo
/// reads it: JSON with `//` and `/* */` comments and trailing commas. One UTF-8
/// byte order mark at the start is dropped.
///
/// Rojo ends a `//` comment only at a line feed, so that reading is tried
/// first, and text after a lone carriage return stays inside the comment. A
/// carriage return also ends a comment only when the file cannot be read the
/// first way, which Rojo refuses anyway, so a file saved with CR line endings
/// is still read. When no reading parses, the strict error names the position
/// in the file as written. Other JSONC forms Rojo's parser accepts, such as
/// unquoted keys or single quoted strings, are refused.
fn parse_jsonc(bytes: &[u8]) -> Result<Value, String> {
    let bytes = without_bom(bytes);
    let strict = match serde_json::from_slice(bytes) {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    let mut comment_error = None;
    for cr_ends_comment in [false, true] {
        if cr_ends_comment && !bytes.contains(&b'\r') {
            break;
        }
        match strip_jsonc(bytes, cr_ends_comment) {
            Ok(stripped) => {
                if let Ok(value) = serde_json::from_slice(&stripped) {
                    return Ok(value);
                }
            }
            Err(error) => {
                comment_error.get_or_insert(error);
            }
        }
    }
    Err(comment_error.unwrap_or_else(|| strict.to_string()))
}

/// Remove `//` and `/* */` comments and trailing commas outside strings, so a
/// JSONC file can be read with the strict JSON parser. A block comment without
/// its closing `*/` is an error, not a comment to the end of the file.
/// Anything else that is not JSON, such as a cut off string or a lone `/`, is
/// left for the parser to refuse.
fn strip_jsonc(bytes: &[u8], cr_ends_comment: bool) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    let mut in_string = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            output.push(byte);
            if byte == b'\\' && index + 1 < bytes.len() {
                output.push(bytes[index + 1]);
                index += 2;
                continue;
            }
            if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        match (byte, bytes.get(index + 1)) {
            (b'"', _) => {
                in_string = true;
                output.push(byte);
                index += 1;
            }
            (b'/', Some(b'/' | b'*')) => {
                index = jsonc_comment_end(bytes, index, cr_ends_comment).ok_or_else(|| {
                    format!("the block comment at byte {index} has no closing */")
                })?;
            }
            // A comma before `}` or `]` is a trailing comma, also when comments
            // sit between them.
            (b',', _) => {
                if !matches!(
                    next_jsonc_token(bytes, index + 1, cr_ends_comment),
                    Some(b'}' | b']')
                ) {
                    output.push(byte);
                }
                index += 1;
            }
            _ => {
                output.push(byte);
                index += 1;
            }
        }
    }
    Ok(output)
}

/// The index after the comment that starts with the `/` at `start`. A line
/// comment ends before its line feed, and before a carriage return too when
/// `cr_ends_comment` is set. `None` for a block comment without `*/`.
fn jsonc_comment_end(bytes: &[u8], start: usize, cr_ends_comment: bool) -> Option<usize> {
    if bytes.get(start + 1) == Some(&b'/') {
        return Some(
            bytes[start..]
                .iter()
                .position(|&byte| byte == b'\n' || (cr_ends_comment && byte == b'\r'))
                .map_or(bytes.len(), |offset| start + offset),
        );
    }
    find_bytes(bytes.get(start + 2..)?, b"*/").map(|offset| start + 2 + offset + 2)
}

/// One UTF-8 byte order mark at the start of a JSON file is dropped, as Windows
/// editors often write one. Anywhere else it stays and the parser refuses it.
fn without_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes)
}

/// The first byte at or after `index` that is not whitespace or a comment.
fn next_jsonc_token(bytes: &[u8], mut index: usize, cr_ends_comment: bool) -> Option<u8> {
    loop {
        match (*bytes.get(index)?, bytes.get(index + 1)) {
            (byte, _) if byte.is_ascii_whitespace() => index += 1,
            (b'/', Some(b'/' | b'*')) => {
                index = jsonc_comment_end(bytes, index, cr_ends_comment)?;
            }
            (byte, _) => return Some(byte),
        }
    }
}

fn append_nested_model(
    document: &mut Document,
    path: &Path,
    extension: &str,
    parent: usize,
    limits: &Limits,
    budget: &mut InputBudget,
) {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            document.partial(format!(
                "cannot read model metadata {}: {error}",
                path.display()
            ));
            return;
        }
    };
    if metadata.len() > limits.max_file_bytes {
        document.partial(format!(
            "nested model {} exceeds max_file_bytes {}",
            path.display(),
            limits.max_file_bytes
        ));
        return;
    }
    let bytes = match read_bounded(path, limits.max_file_bytes) {
        Ok(BoundedRead::Bytes(bytes)) => bytes,
        Ok(BoundedRead::TooLarge(size)) => {
            document.partial(format!(
                "nested model {} size {size} exceeds max_file_bytes {}",
                path.display(),
                limits.max_file_bytes
            ));
            return;
        }
        Err(error) => {
            document.partial(format!(
                "cannot read nested model {}: {error}",
                path.display()
            ));
            return;
        }
    };
    let nested = load_bytes_within(&path.to_string_lossy(), extension, &bytes, limits, budget);
    merge_document(document, nested, Some(parent), limits, budget);
}

fn append_json_model(
    document: &mut Document,
    path: &Path,
    parent: usize,
    limits: &Limits,
    budget: &mut InputBudget,
) {
    let bytes = match read_bounded(path, limits.max_file_bytes) {
        Ok(BoundedRead::Bytes(bytes)) => bytes,
        Ok(BoundedRead::TooLarge(size)) => {
            document.partial(format!(
                "JSON model {} size {size} exceeds max_file_bytes {}",
                path.display(),
                limits.max_file_bytes
            ));
            return;
        }
        Err(error) => {
            document.partial(format!(
                "cannot read JSON model {}: {error}",
                path.display()
            ));
            return;
        }
    };
    let value = match parse_jsonc(&bytes) {
        Ok(value) => value,
        Err(error) => {
            document.partial(format!(
                "cannot decode JSON model {}: {error}",
                path.display()
            ));
            return;
        }
    };
    let container: std::sync::Arc<str> = path.to_string_lossy().into();
    let mut queue = VecDeque::from([(value, Some(parent))]);
    while let Some((value, parent)) = queue.pop_front() {
        if budget.check_time(document, limits) {
            break;
        }
        let Some(object) = value.as_object() else {
            document.partial(format!(
                "JSON model node is not an object in {}",
                path.display()
            ));
            continue;
        };
        let mut instance = instance_from_json_model(object, path);
        instance.parent = parent;
        instance.container_file = Some(std::sync::Arc::clone(&container));
        normalize_instance(document, &mut instance, limits, document.instances.len());
        take_listed_attributes(document, &mut instance, budget);
        let children = object
            .get("Children")
            .or_else(|| object.get("children"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !push_instance(document, instance, limits) {
            break;
        }
        let index = document.instances.len() - 1;
        for child in children {
            queue.push_back((child, Some(index)));
        }
    }
}

fn instance_from_json_model(object: &Map<String, Value>, path: &Path) -> Instance {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("model");
    let fallback = [".model.jsonc", ".model.json"]
        .into_iter()
        .find_map(|suffix| strip_suffix_ignore_ascii_case(file_name, suffix))
        .unwrap_or(file_name)
        .to_owned();
    let name = string_field(object, &["Name", "name"]).unwrap_or(fallback);
    let class = string_field(object, &["ClassName", "className", "$className"])
        .unwrap_or_else(|| "Folder".to_owned());
    let properties = object
        .get("Properties")
        .or_else(|| object.get("properties"))
        .or_else(|| object.get("$properties"))
        .and_then(Value::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    let attributes = object
        .get("Attributes")
        .or_else(|| object.get("attributes"))
        .or_else(|| object.get("$attributes"))
        .and_then(Value::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    Instance {
        name,
        class,
        properties,
        attributes,
        ..Instance::default()
    }
}

fn append_dom(
    document: &mut Document,
    dom: &WeakDom,
    limits: &Limits,
    protected_strings: &BTreeSet<(String, String)>,
    budget: &mut InputBudget,
) {
    let mut queue = VecDeque::new();
    for &child in dom.root().children() {
        queue.push_back((child, None));
    }
    while let Some((referent, parent)) = queue.pop_front() {
        if budget.check_time(document, limits) {
            break;
        }
        let Some(dom_instance) = dom.get_by_ref(referent) else {
            document.partial("decoded DOM contains an invalid instance reference");
            continue;
        };
        let mut instance = Instance {
            name: dom_instance.name.clone(),
            class: dom_instance.class.to_string(),
            parent,
            ..Instance::default()
        };
        let code_hint = extract_dom_properties(
            document,
            &mut instance,
            dom_instance,
            limits,
            protected_strings,
            budget,
        );
        let index = document.instances.len();
        if !push_instance_with_code_hint(document, instance, limits, code_hint.as_deref()) {
            break;
        }
        for &child in dom_instance.children() {
            queue.push_back((child, Some(index)));
        }
    }
}

/// Copy the properties the rules read. Returns a description of a property that
/// can carry code the scanner will not analyze: a `ProtectedString` outside a
/// script's `Source`, or a string on an unknown class that parses as Luau.
fn extract_dom_properties(
    document: &mut Document,
    output: &mut Instance,
    input: &rbx_dom_weak::Instance,
    limits: &Limits,
    protected_strings: &BTreeSet<(String, String)>,
    budget: &mut InputBudget,
) -> Option<String> {
    let unknown_class = !is_known_class(&output.class);
    let mut code_properties = Vec::new();
    for (name, value) in &input.properties {
        let name = name.to_string();
        if !(output.is_script() && name == "Source")
            && protected_strings.contains(&(output.class.clone(), name.clone()))
        {
            code_properties.push(format!("ProtectedString property {name:?}"));
        }
        match value {
            Variant::Attributes(attributes) => {
                match budget.take_attributes(output.attributes.len(), attributes.len(), 0) {
                    Ok(()) => insert_attributes(
                        document,
                        output,
                        &input.name,
                        attributes
                            .iter()
                            .map(|(name, value)| (name.clone(), value.clone())),
                    ),
                    Err(detail) => document.partial(attribute_limit_reason(&input.name, &detail)),
                }
            }
            // The decoders hand over the raw blob (see `decode_dom`). On a class
            // the reflection database does not know, the blob keeps its
            // serialized name.
            _ if name == "Attributes" || (unknown_class && name == "AttributesSerialize") => {
                read_attributes(document, output, &input.name, value, budget);
            }
            Variant::Tags(tags) => output.tags.extend(tags.iter().map(str::to_owned)),
            _ if name == "Source" => match source_from_variant(value) {
                Ok(source) if source.len() <= limits.max_script_bytes => {
                    output.source = Some(source)
                }
                Ok(source) => document.partial(format!(
                    "script {:?} source size {} exceeds max_script_bytes {}",
                    input.name,
                    source.len(),
                    limits.max_script_bytes
                )),
                Err(reason) => document.partial(format!("script {:?} Source {reason}", input.name)),
            },
            _ if name.to_ascii_lowercase().contains("source") => {
                if let Some(Value::String(value)) = variant_to_json(value) {
                    output.properties.insert(name, Value::String(value));
                }
            }
            // Shown text feeds BG012. Only string values matter; flags such as
            // `RichText` share the suffix and are skipped.
            _ if crate::heuristics::is_text_property(&name) => {
                if let Some(Value::String(value)) = variant_to_json(value) {
                    output.properties.insert(name, Value::String(value));
                }
            }
            _ if keep_property(&name, &output.class) => {
                if let Some(value) = variant_to_json(value) {
                    output.properties.insert(name, value);
                } else {
                    document.partial(format!(
                        "property {name:?} on {:?} could not be represented",
                        input.name
                    ));
                }
            }
            // Strings on a class this scanner does not know are dropped unless
            // they look like code. Kept properties are checked when the instance
            // is pushed.
            _ if unknown_class => {
                if let Some(Value::String(text)) = variant_to_json(value)
                    && looks_like_luau_code(&text, limits)
                {
                    code_properties.push(format!("string property {name:?} that parses as Luau"));
                }
            }
            _ => {}
        }
    }
    if output.is_script() && output.source.is_none() {
        document.partial(format!(
            "script {:?} has no readable Source property",
            input.name
        ));
    }
    code_properties.sort();
    code_properties.into_iter().next()
}

/// Copy attributes into the normalized instance. Values are moved, so a long
/// string is not copied a second time.
fn insert_attributes(
    document: &mut Document,
    output: &mut Instance,
    instance_name: &str,
    attributes: impl IntoIterator<Item = (String, Variant)>,
) {
    for (attribute, value) in attributes {
        let value = match value {
            Variant::String(text) => Some(Value::String(text)),
            other => variant_to_json(&other),
        };
        if let Some(value) = value {
            output.attributes.insert(attribute, value);
        } else {
            document.partial(format!(
                "attribute {attribute:?} on {instance_name:?} could not be represented"
            ));
        }
    }
}

/// Decode an `AttributesSerialize` blob into `output`. The blob is first walked
/// without allocating, to check that it holds every byte it declares and to
/// learn its attribute count; the count and the blob size then have to fit in
/// the caps before anything is decoded. A blob that fails either check makes
/// the input partial and leaves the instance without attributes.
fn read_attributes(
    document: &mut Document,
    output: &mut Instance,
    instance_name: &str,
    value: &Variant,
    budget: &mut InputBudget,
) {
    let blob = match value {
        Variant::BinaryString(blob) => {
            <rbx_dom_weak::types::BinaryString as AsRef<[u8]>>::as_ref(blob)
        }
        Variant::String(text) => text.as_bytes(),
        Variant::SharedString(shared) => shared.data(),
        _ => {
            let reason = format!("the value has type {:?}", value.ty());
            document.partial(unreadable_attributes_reason(instance_name, &reason));
            return;
        }
    };
    let count = match check_attribute_blob(blob) {
        Ok(count) => count,
        Err(reason) => {
            document.partial(unreadable_attributes_reason(instance_name, &reason));
            return;
        }
    };
    if let Err(detail) = budget.take_attributes(output.attributes.len(), count, blob.len()) {
        document.partial(attribute_limit_reason(instance_name, &detail));
        return;
    }
    match rbx_dom_weak::types::Attributes::from_reader(blob) {
        Ok(attributes) => insert_attributes(document, output, instance_name, attributes),
        Err(error) => document.partial(unreadable_attributes_reason(
            instance_name,
            &error.to_string(),
        )),
    }
}

fn unreadable_attributes_reason(instance_name: &str, reason: &str) -> String {
    format!("unreadable attributes on {instance_name:?}: {reason}; its attributes were not read")
}

/// Walk a serialized attribute blob as rbx_types 3.1 reads it: a `u32` count,
/// then for each attribute a `u32` length and name, a type byte and the value.
/// Every length and count must fit in the bytes that follow, and every type
/// must be one the reader knows. Bytes after the last attribute are ignored,
/// as the reader ignores them. Returns the declared count; an empty blob holds
/// no attributes.
fn check_attribute_blob(blob: &[u8]) -> Result<usize, String> {
    struct Blob<'a> {
        bytes: &'a [u8],
        at: usize,
        attribute: u64,
    }
    impl Blob<'_> {
        fn take(&mut self, length: u64, what: &str) -> Result<&[u8], String> {
            let left = self.bytes.len() - self.at;
            match usize::try_from(length) {
                Ok(length) if length <= left => {
                    let start = self.at;
                    self.at += length;
                    Ok(&self.bytes[start..self.at])
                }
                _ if self.attribute == 0 => Err(format!(
                    "the attribute {what} needs {length} bytes, but only {left} remain"
                )),
                _ => Err(format!(
                    "attribute {} {what} needs {length} bytes, but only {left} remain",
                    self.attribute
                )),
            }
        }
        fn u32(&mut self, what: &str) -> Result<u32, String> {
            let bytes = self.take(4, what)?;
            Ok(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
        }
        fn string(&mut self, what: &str) -> Result<(), String> {
            let length = self.u32(what)?;
            self.take(u64::from(length), what).map(drop)
        }
    }

    if blob.is_empty() {
        return Ok(0);
    }
    let mut blob = Blob {
        bytes: blob,
        at: 0,
        attribute: 0,
    };
    let count = blob.u32("count")?;
    for attribute in 1..=u64::from(count) {
        blob.attribute = attribute;
        blob.string("name")?;
        let value_type = blob.take(1, "value type")?[0];
        let fixed: u64 = match value_type {
            // A string, and an EnumItem: its enum name and a u32 value.
            0x02 => {
                blob.string("string value")?;
                0
            }
            0x15 => {
                blob.string("enum name")?;
                4
            }
            // Bool; Int32, Float32 and BrickColor; Float64, UDim, Vector2 and
            // NumberRange; Color3 and Vector3; UDim2 and Rect.
            0x03 => 1,
            0x04 | 0x05 | 0x0e => 4,
            0x06 | 0x09 | 0x10 | 0x1b => 8,
            0x0f | 0x11 => 12,
            0x0a | 0x1c => 16,
            // CFrame: a position, a rotation id and a full matrix for id 0.
            0x14 => {
                blob.take(12, "CFrame position")?;
                if blob.take(1, "CFrame rotation id")?[0] == 0 {
                    36
                } else {
                    0
                }
            }
            // NumberSequence and ColorSequence: a count, then keypoints of 12
            // and 20 bytes.
            0x17 => u64::from(blob.u32("NumberSequence length")?) * 12,
            0x19 => u64::from(blob.u32("ColorSequence length")?) * 20,
            // Font: weight, style, family and cached face.
            0x21 => {
                blob.take(3, "Font weight and style")?;
                blob.string("Font family")?;
                blob.string("Font face")?;
                0
            }
            other => {
                return Err(format!(
                    "attribute {attribute} has unknown value type 0x{other:02x}"
                ));
            }
        };
        blob.take(fixed, "value")?;
    }
    Ok(usize::try_from(count).unwrap_or(usize::MAX))
}

fn is_known_class(class: &str) -> bool {
    rbx_reflection_database::get_bundled()
        .classes
        .contains_key(class)
}

/// A string that the Luau parser accepts as at least one statement.
///
/// Text that does not even tokenize as Luau is not code. Text that tokenizes but
/// exceeds the parser budget is treated as code, because it cannot be checked.
/// Nothing is executed; the parser only builds a syntax tree.
fn looks_like_luau_code(text: &str, limits: &Limits) -> bool {
    let text = crate::parsing::source_without_bom(text).trim();
    if text.is_empty() || !text.contains(['(', '=', '"', '\'', '{', '[']) {
        return false;
    }
    if text.len() > limits.max_script_bytes {
        return true;
    }
    let mut lexer = full_moon::tokenizer::Lexer::new(text, full_moon::LuaVersion::luau());
    while let Some(item) = lexer.consume() {
        if !matches!(item, full_moon::tokenizer::LexerResult::Ok(_)) {
            return false;
        }
    }
    if crate::analysis::parser_budget(text, limits).is_err() {
        return true;
    }
    crate::parsing::on_large_stack(|| {
        full_moon::parse(text).is_ok_and(|ast| {
            ast.nodes().stmts().next().is_some() || ast.nodes().last_stmt().is_some()
        })
    })
    .unwrap_or(true)
}

/// A JSON property value that can hold code: a plain string, or a Rojo style
/// typed string such as `{"String": "..."}` or `{"ProtectedString": "..."}`.
fn json_code_property(name: &str, value: &Value, limits: &Limits) -> Option<String> {
    let (protected, text) = match value {
        Value::String(text) => (false, text.as_str()),
        Value::Object(typed) if typed.len() == 1 => {
            let (kind, inner) = typed.iter().next()?;
            (kind == "ProtectedString", inner.as_str()?)
        }
        _ => return None,
    };
    if protected && !text.trim().is_empty() {
        Some(format!("ProtectedString property {name:?}"))
    } else if looks_like_luau_code(text, limits) {
        Some(format!("string property {name:?} that parses as Luau"))
    } else {
        None
    }
}

fn source_from_variant(value: &Variant) -> Result<String, &'static str> {
    match value {
        Variant::String(value) => Ok(value.clone()),
        Variant::SharedString(value) => {
            String::from_utf8(value.as_ref().to_vec()).map_err(|_| "is not valid UTF-8")
        }
        Variant::BinaryString(value) => String::from_utf8(
            <rbx_dom_weak::types::BinaryString as AsRef<[u8]>>::as_ref(value).to_vec(),
        )
        .map_err(|_| "is not valid UTF-8"),
        _ => Err("has an unsupported value type"),
    }
}

fn variant_to_json(value: &Variant) -> Option<Value> {
    match value {
        Variant::Bool(value) => Some(Value::Bool(*value)),
        Variant::Int32(value) => Some((*value).into()),
        Variant::Int64(value) => Some((*value).into()),
        Variant::Float32(value) if value.is_finite() => {
            serde_json::Number::from_f64(*value as f64).map(Value::Number)
        }
        Variant::Float64(value) if value.is_finite() => {
            serde_json::Number::from_f64(*value).map(Value::Number)
        }
        Variant::String(value) => Some(Value::String(value.clone())),
        Variant::ContentId(value) => Some(Value::String(value.as_str().to_owned())),
        // An empty Content or one that points at an object inside the file is not
        // a remote reference. Only a URI can name content outside the file.
        Variant::Content(value) => Some(
            value
                .as_uri()
                .map_or(Value::Null, |value| Value::String(value.to_owned())),
        ),
        Variant::SharedString(value) => String::from_utf8(value.as_ref().to_vec())
            .ok()
            .map(Value::String),
        Variant::BinaryString(value) => String::from_utf8(
            <rbx_dom_weak::types::BinaryString as AsRef<[u8]>>::as_ref(value).to_vec(),
        )
        .ok()
        .map(Value::String),
        _ => serde_json::to_value(value).ok(),
    }
}

/// Package link properties in every spelling the decoders and Studio produce.
///
/// The bundled reflection database migrates `PackageId` and its serialized alias
/// `PackageIdSerialize` to `PackageContent` while decoding a file, so all of them
/// are kept and the BG011 check reads each one.
pub(crate) const PACKAGE_LINK_PROPERTIES: &[&str] = &[
    "PackageId",
    "PackageIdSerialize",
    "PackageContent",
    "PackageContentSerialize",
    "PackageAssetId",
    "PackageLink",
    "PackageSource",
];

fn keep_property(name: &str, class: &str) -> bool {
    matches!(
        name,
        "Disabled"
            | "Enabled"
            | "RunContext"
            | "LinkedSource"
            | "SourceAssetId"
            | "AutoUpdate"
            | "VersionNumber"
    ) || PACKAGE_LINK_PROPERTIES.contains(&name)
        || (class.ends_with("Value") && name == "Value")
}

fn normalize_instance(
    document: &mut Document,
    instance: &mut Instance,
    limits: &Limits,
    index: usize,
) {
    normalize_run_context_property(instance);
    if instance.source.is_none() {
        if let Some(Value::String(source)) = instance.properties.remove("Source") {
            instance.source = Some(source);
        }
    } else {
        instance.properties.remove("Source");
    }
    if let Some(source) = instance.source.as_ref()
        && source.len() > limits.max_script_bytes
    {
        document.partial(format!(
            "bundle instance {index} source size {} exceeds max_script_bytes {}",
            source.len(),
            limits.max_script_bytes
        ));
        instance.source = None;
    }
    if instance.is_script() && instance.source.is_none() {
        document.partial(format!(
            "bundle script instance {index} has no readable Source"
        ));
    }
}

/// Convert every supported serialized RunContext representation to its name.
pub fn normalize_run_context(value: &Value) -> Option<&'static str> {
    if let Some(name) = value.as_str() {
        let name = name.strip_prefix("Enum.RunContext.").unwrap_or(name);
        return ["Legacy", "Server", "Client", "Plugin"]
            .into_iter()
            .find(|candidate| candidate.eq_ignore_ascii_case(name));
    }

    let number = value
        .as_u64()
        .or_else(|| value.get("Enum").and_then(Value::as_u64))
        .or_else(|| {
            value
                .get("EnumItem")
                .and_then(Value::as_object)
                .filter(|item| {
                    item.get("type")
                        .and_then(Value::as_str)
                        .is_none_or(|kind| kind == "RunContext")
                })
                .and_then(|item| item.get("value"))
                .and_then(Value::as_u64)
        })?;
    match number {
        0 => Some("Legacy"),
        1 => Some("Server"),
        2 => Some("Client"),
        3 => Some("Plugin"),
        _ => None,
    }
}

fn normalize_run_context_property(instance: &mut Instance) {
    let Some(value) = instance.properties.get_mut("RunContext") else {
        return;
    };
    if let Some(name) = normalize_run_context(value) {
        *value = Value::String(name.to_owned());
    }
}

fn merge_document(
    document: &mut Document,
    mut nested: Document,
    attach_parent: Option<usize>,
    limits: &Limits,
    budget: &InputBudget,
) {
    if nested.completeness != Completeness::Complete {
        for reason in nested.reasons.drain(..) {
            document.partial(format!("{}: {reason}", nested.input));
        }
    }
    let offset = document.instances.len();
    for diagnostic in nested.diagnostics.drain(..) {
        match diagnostic.instance {
            Some(instance) => document.informational(diagnostic.message, Some(offset + instance)),
            // Without an instance path, the file name says where the note is from.
            None => {
                document.informational(format!("{}: {}", nested.input, diagnostic.message), None)
            }
        }
    }
    let container: std::sync::Arc<str> = nested.input.as_str().into();
    for mut instance in nested.instances {
        instance.parent = match instance.parent {
            Some(parent) => Some(offset + parent),
            None => attach_parent,
        };
        if instance.source_file.is_none() && instance.container_file.is_none() {
            instance.container_file = Some(std::sync::Arc::clone(&container));
        }
        // The nested document already checked classes and code properties and
        // its reasons and diagnostics were merged above.
        if !push_checked_instance(document, instance, limits) || budget.check_time(document, limits)
        {
            break;
        }
    }
}

fn push_instance(document: &mut Document, instance: Instance, limits: &Limits) -> bool {
    push_instance_with_code_hint(document, instance, limits, None)
}

fn push_instance_with_code_hint(
    document: &mut Document,
    mut instance: Instance,
    limits: &Limits,
    code_hint: Option<&str>,
) -> bool {
    if !has_instance_room(document, limits) {
        return false;
    }
    normalize_run_context_property(&mut instance);
    let index = document.instances.len();
    mark_unknown_class(document, &instance, index, code_hint, limits);
    document.instances.push(instance);
    true
}

fn push_checked_instance(document: &mut Document, mut instance: Instance, limits: &Limits) -> bool {
    if !has_instance_room(document, limits) {
        return false;
    }
    normalize_run_context_property(&mut instance);
    document.instances.push(instance);
    true
}

fn has_instance_room(document: &mut Document, limits: &Limits) -> bool {
    if document.instances.len() >= limits.max_instances {
        document.partial(format!(
            "instance count exceeds max_instances {}",
            limits.max_instances
        ));
        false
    } else {
        true
    }
}

fn read_source_into(
    document: &mut Document,
    instance: &mut Instance,
    path: &Path,
    limits: &Limits,
) {
    instance.source_file = Some(path.to_string_lossy().into_owned());
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            document.partial(format!(
                "cannot read source metadata {}: {error}",
                path.display()
            ));
            return;
        }
    };
    if metadata.len() > limits.max_script_bytes as u64 {
        document.partial(format!(
            "script {} size {} exceeds max_script_bytes {}",
            path.display(),
            metadata.len(),
            limits.max_script_bytes
        ));
        return;
    }
    match read_bounded(path, limits.max_script_bytes as u64) {
        Ok(BoundedRead::Bytes(bytes)) => match String::from_utf8(bytes) {
            Ok(source) => instance.source = Some(source),
            Err(error) => document.partial(format!(
                "source {} is not valid UTF-8: {error}",
                path.display()
            )),
        },
        Ok(BoundedRead::TooLarge(size)) => document.partial(format!(
            "script {} size {size} exceeds max_script_bytes {}",
            path.display(),
            limits.max_script_bytes
        )),
        Err(error) => document.partial(format!("cannot read source {}: {error}", path.display())),
    }
}

/// Apply the metadata files Rojo 7.7 reads for one instance, in its order:
/// `<stem>.meta.json`, then `<stem>.meta.jsonc`, both in `folder`. A later
/// file replaces each property it names and, when it lists any, all
/// attributes. Rojo before 7.7 reads only the `.json` file, so a `.jsonc` file
/// next to one, or one that replaces a script file's text, makes the input
/// partial. The caller counts the attributes against the budget once all
/// metadata of the instance is applied.
fn apply_metadata(
    document: &mut Document,
    instance: &mut Instance,
    folder: &Path,
    stem: &str,
    canonical_root: &Path,
    limits: &Limits,
) {
    let mut applied = Vec::new();
    let mut source_meta = None;
    for (path, jsonc) in [
        (folder.join(format!("{stem}.meta.json")), false),
        (folder.join(format!("{stem}.meta.jsonc")), true),
    ] {
        let Some(meta) = read_json_if_exists(&path, canonical_root, document, limits) else {
            continue;
        };
        if meta_properties(&meta).any(|(name, _)| name == "Source") {
            source_meta = Some((path.clone(), jsonc));
        }
        apply_meta(instance, &meta, document, &path);
        // An instance without a script file of its own, such as a folder whose
        // `init.meta.json` sets its class, value or attributes, came from this
        // metadata file.
        if instance.source_file.is_none() && instance.container_file.is_none() {
            instance.container_file = Some(path.to_string_lossy().into());
        }
        applied.push(path);
    }
    if let [json, jsonc] = applied.as_slice() {
        document.partial(format!(
            "{} and {} both set metadata for {:?}; Rojo 7.7 and later apply both, the .jsonc file last, and earlier versions only the .json file",
            json.display(),
            jsonc.display(),
            instance.name
        ));
    }
    if let Some((meta, jsonc)) = source_meta {
        // With both files the reason above already names the version.
        let version_dependent = jsonc && applied.len() == 1;
        take_meta_source(document, instance, &meta, version_dependent, limits);
    }
}

/// Rojo sets a script's `Source` from its file and then applies metadata, so a
/// `Source` in a metadata file replaces the file's text. That text is what the
/// rules read.
fn take_meta_source(
    document: &mut Document,
    instance: &mut Instance,
    meta: &Path,
    version_dependent: bool,
    limits: &Limits,
) {
    if !instance.is_script() {
        return;
    }
    let Some(value) = instance.properties.remove("Source") else {
        return;
    };
    let Value::String(source) = value else {
        document.partial(format!(
            "metadata {} sets Source to a value direct scans do not read",
            meta.display()
        ));
        return;
    };
    if source.len() > limits.max_script_bytes {
        document.partial(format!(
            "metadata {} Source size {} exceeds max_script_bytes {}",
            meta.display(),
            source.len(),
            limits.max_script_bytes
        ));
        instance.source = None;
        return;
    }
    if let Some(file) = instance.source_file.take() {
        if version_dependent {
            document.partial(format!(
                "{} sets Source for {file}; Rojo 7.7 and later use it, earlier versions use the file's own text, which was not scanned",
                meta.display()
            ));
        }
        document.informational(
            format!(
                "{} sets Source for {file}; Rojo uses it instead of the file's text, so that is what was scanned",
                meta.display()
            ),
            None,
        );
    }
    instance.source = Some(source);
    // The scanned text, and the lines a finding counts, come from the metadata.
    instance.container_file = Some(meta.to_string_lossy().into());
}

/// Rojo applies `<stem>.meta.json` and `<stem>.meta.jsonc` to the instance it
/// builds from a data file such as `.json`, `.txt`, `.toml` or `.csv`. Direct
/// scans do not read those files, so metadata that sets a rule input there,
/// such as `Source` or attributes, makes the input partial.
fn check_data_file_metadata(
    document: &mut Document,
    data_file: &Path,
    canonical_root: &Path,
    limits: &Limits,
) {
    let Some(stem) = data_file.file_stem().and_then(|stem| stem.to_str()) else {
        return;
    };
    for suffix in [".meta.json", ".meta.jsonc"] {
        let meta = data_file.with_file_name(format!("{stem}{suffix}"));
        let Some(value) = read_json_if_exists(&meta, canonical_root, document, limits) else {
            continue;
        };
        let sets_rule_inputs = !value.is_object()
            || meta_properties(&value).any(|(name, _)| rojo_property_feeds_rules(name))
            || meta_attributes(&value).next().is_some();
        if sets_rule_inputs {
            document.partial(format!(
                "Rojo applies {} to the instance it builds from {}, which direct scans do not read; build with Rojo and scan the output",
                meta.display(),
                data_file.display()
            ));
        }
    }
}

/// Every property a metadata value lists, under any of the key spellings
/// `apply_meta` accepts.
fn meta_properties(meta: &Value) -> impl Iterator<Item = (&String, &Value)> {
    meta_entries(meta, ["properties", "Properties", "$properties"])
}

/// Every attribute a metadata value lists, under any accepted key spelling.
fn meta_attributes(meta: &Value) -> impl Iterator<Item = (&String, &Value)> {
    meta_entries(meta, ["attributes", "Attributes", "$attributes"])
}

fn meta_entries<'a>(
    meta: &'a Value,
    keys: [&str; 3],
) -> impl Iterator<Item = (&'a String, &'a Value)> {
    keys.into_iter()
        .filter_map(move |key| meta.get(key).and_then(Value::as_object))
        .flatten()
}

fn read_json_if_exists(
    path: &Path,
    canonical_root: &Path,
    document: &mut Document,
    limits: &Limits,
) -> Option<Value> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            document.partial(format!(
                "cannot read metadata file information {}: {error}",
                path.display()
            ));
            return None;
        }
    };
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        document.partial(format!(
            "refused metadata link or non-file: {}",
            path.display()
        ));
        return None;
    }
    if !path_stays_in_root(path, canonical_root) {
        document.partial(format!(
            "refused metadata outside source tree: {}",
            path.display()
        ));
        return None;
    }
    let bytes = match read_bounded(path, limits.max_file_bytes) {
        Ok(BoundedRead::Bytes(bytes)) => bytes,
        Ok(BoundedRead::TooLarge(size)) => {
            document.partial(format!(
                "metadata {} size {size} exceeds max_file_bytes {}",
                path.display(),
                limits.max_file_bytes
            ));
            return None;
        }
        Err(error) => {
            document.partial(format!("cannot read metadata {}: {error}", path.display()));
            return None;
        }
    };
    match parse_jsonc(&bytes) {
        Ok(value) => Some(value),
        Err(error) => {
            document.partial(format!(
                "cannot decode metadata {}: {error}",
                path.display()
            ));
            None
        }
    }
}

fn apply_meta(instance: &mut Instance, meta: &Value, document: &mut Document, path: &Path) {
    let Some(object) = meta.as_object() else {
        document.partial(format!("metadata {} is not a JSON object", path.display()));
        return;
    };
    if let Some(class) = string_field(object, &["className", "ClassName", "$className"]) {
        instance.class = class;
    }
    for key in ["properties", "Properties", "$properties"] {
        if let Some(properties) = object.get(key).and_then(Value::as_object) {
            instance.properties.extend(
                properties
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
            break;
        }
    }
    for key in ["attributes", "Attributes", "$attributes"] {
        if let Some(attributes) = object.get(key).and_then(Value::as_object) {
            // Like Rojo, a nonempty list replaces every attribute an earlier
            // metadata file set, and an empty one leaves them.
            if !attributes.is_empty() {
                instance.attributes = attributes
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect();
            }
            break;
        }
    }
}

fn string_field(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key)?.as_str().map(str::to_owned))
}

/// Decide whether an instance hides code or rule inputs.
///
/// Unknown classes are informational unless they look like a script, carry a
/// property that can hold code, or have an unreadable value. A `ProtectedString`
/// outside a script's `Source` makes any class partial, because the scanner only
/// analyzes the source of `Script`, `LocalScript` and `ModuleScript`.
fn mark_unknown_class(
    document: &mut Document,
    instance: &Instance,
    index: usize,
    code_hint: Option<&str>,
    limits: &Limits,
) {
    let class = &instance.class;
    let unknown = !is_known_class(class);
    let code_property = code_hint.map(str::to_owned).or_else(|| {
        instance.properties.iter().find_map(|(name, value)| {
            if instance.is_script() && name == "Source" {
                return None;
            }
            let protected = value
                .as_object()
                .is_some_and(|typed| typed.len() == 1 && typed.contains_key("ProtectedString"));
            // Shown text such as `Press "E"` can parse as a call, so text
            // properties are judged as text unless they are typed as code.
            let text_like = crate::heuristics::is_text_property(name);
            if protected || (unknown && !text_like) {
                json_code_property(name, value, limits)
            } else {
                None
            }
        })
    });
    if !unknown {
        if let Some(property) = code_property {
            document.partial(format!(
                "instance {index} of class {class:?} has {property}, which is not analyzed as script source"
            ));
        }
        return;
    }
    let source_like = instance.source.is_some()
        || instance.properties.contains_key("Source")
        || instance
            .properties
            .iter()
            .any(|(name, value)| name.to_ascii_lowercase().contains("source") && value.is_string())
        || class.ends_with("Script");
    let unreadable_value = class.ends_with("Value")
        && !instance
            .properties
            .get("Value")
            .is_some_and(|value| value.is_string() || value.is_number() || value.is_boolean());
    if source_like {
        document.partial(format!(
            "instance {index} uses unknown source-like class {class:?}"
        ));
    } else if let Some(property) = code_property {
        document.partial(format!(
            "instance {index} uses unknown class {class:?} with {property}; its code was not scanned"
        ));
    } else if unreadable_value {
        document.partial(format!(
            "instance {index} uses unknown value class {class:?} without a readable Value property"
        ));
    } else {
        document.informational(
            format!("instance {index} uses unknown class {class:?}"),
            Some(index),
        );
    }
}

fn source_class(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".server.lua")
        || name.ends_with(".server.luau")
        || name.ends_with(".plugin.lua")
        || name.ends_with(".plugin.luau")
    {
        "Script"
    } else if name.ends_with(".client.lua") || name.ends_with(".client.luau") {
        "LocalScript"
    } else {
        "ModuleScript"
    }
}

fn source_name(path: &Path) -> String {
    let mut name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source")
        .to_owned();
    for suffix in [
        ".server.luau",
        ".client.luau",
        ".plugin.luau",
        ".server.lua",
        ".client.lua",
        ".plugin.lua",
        ".luau",
        ".lua",
    ] {
        if name.to_ascii_lowercase().ends_with(suffix) {
            name.truncate(name.len() - suffix.len());
            break;
        }
    }
    if name.eq_ignore_ascii_case("init") {
        path.parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .unwrap_or("init")
            .to_owned()
    } else {
        name
    }
}

fn is_init_source_name(name: &str) -> bool {
    matches!(
        name,
        "init.lua"
            | "init.luau"
            | "init.server.lua"
            | "init.server.luau"
            | "init.client.lua"
            | "init.client.luau"
            | "init.plugin.lua"
            | "init.plugin.luau"
    )
}

/// `.meta.json` and `.meta.jsonc` files, which Rojo applies to another
/// instance instead of building one. `name` is lowercase.
fn is_meta_file_name(name: &str) -> bool {
    name.ends_with(".meta.json") || name.ends_with(".meta.jsonc")
}

/// Files Rojo builds an instance from that direct scans do not read: JSON,
/// TOML and YAML data modules, `.txt` string values and `.csv` localization
/// tables. `init.csv` belongs to its folder. `name` is lowercase and is not a
/// project, model or metadata file.
fn is_rojo_data_file(name: &str, extension: &str) -> bool {
    matches!(
        extension,
        "json" | "jsonc" | "toml" | "csv" | "txt" | "yaml" | "yml"
    ) && name != "init.csv"
}

/// `name` without `suffix`, compared without ASCII case.
fn strip_suffix_ignore_ascii_case<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let split = name.len().checked_sub(suffix.len())?;
    name.get(split..)
        .filter(|tail| tail.eq_ignore_ascii_case(suffix))
        .map(|_| &name[..split])
}

fn init_priority(name: &str) -> usize {
    match name {
        "init.luau" => 0,
        "init.lua" => 1,
        "init.server.luau" => 2,
        "init.server.lua" => 3,
        "init.client.luau" => 4,
        "init.client.lua" => 5,
        "init.plugin.lua" => 6,
        "init.plugin.luau" => 7,
        _ => usize::MAX,
    }
}

fn is_source_extension(extension: &str) -> bool {
    matches!(extension, "lua" | "luau")
}

fn should_skip_directory(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".git" | ".hg" | ".svn" | ".cargo-home" | "target" | "node_modules"
    )
}

fn normalized_extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn preflight_binary(bytes: &[u8], limits: &Limits) -> Result<Preflight, String> {
    const HEADER_LEN: usize = 32;
    const CHUNK_HEADER_LEN: usize = 16;
    if bytes.len() < HEADER_LEN {
        return Err("binary input is truncated before its header".to_owned());
    }
    let type_count = u32::from_le_bytes(bytes[16..20].try_into().expect("fixed slice")) as usize;
    let instance_count =
        u32::from_le_bytes(bytes[20..24].try_into().expect("fixed slice")) as usize;
    if type_count > limits.max_instances {
        return Err(format!(
            "binary header type count {type_count} exceeds max_instances {}",
            limits.max_instances
        ));
    }
    if instance_count > limits.max_instances {
        return Err(format!(
            "binary header instance count {instance_count} exceeds max_instances {}",
            limits.max_instances
        ));
    }
    if type_count > instance_count {
        return Err(format!(
            "binary header type count {type_count} exceeds its instance count {instance_count}"
        ));
    }

    let mut cursor = HEADER_LEN;
    let mut decoded_total = 0u64;
    // The class name of each instance type id.
    let mut instance_types: HashMap<u32, String> = HashMap::with_capacity(type_count);
    let mut instances_seen = 0usize;
    let mut saw_end = false;
    let mut preflight = Preflight::default();
    while cursor < bytes.len() {
        if bytes.len() - cursor < CHUNK_HEADER_LEN {
            return Err("binary input is truncated in a chunk header".to_owned());
        }
        let name = &bytes[cursor..cursor + 4];
        let compressed_len = u32::from_le_bytes(
            bytes[cursor + 4..cursor + 8]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        let decoded_len = u32::from_le_bytes(
            bytes[cursor + 8..cursor + 12]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        let reserved = u32::from_le_bytes(
            bytes[cursor + 12..cursor + 16]
                .try_into()
                .expect("fixed slice"),
        );
        if reserved != 0 {
            return Err("binary chunk has a nonzero reserved field".to_owned());
        }
        if compressed_len > 0 && compressed_len < 4 {
            return Err("binary compressed chunk is too short to identify its codec".to_owned());
        }
        decoded_total = decoded_total.saturating_add(decoded_len as u64);
        if decoded_total > limits.max_file_bytes {
            return Err(format!(
                "binary decoded chunk bytes exceed max_file_bytes {}",
                limits.max_file_bytes
            ));
        }
        cursor += CHUNK_HEADER_LEN;
        let stored_len = if compressed_len == 0 {
            decoded_len
        } else {
            compressed_len
        };
        if stored_len > bytes.len() - cursor {
            return Err("binary input is truncated in chunk data".to_owned());
        }
        let stored = &bytes[cursor..cursor + stored_len];
        let decoded = decode_binary_chunk(stored, compressed_len, decoded_len)?;
        match name {
            b"INST" => {
                let (type_id, class, count) = inspect_binary_instance_chunk(&decoded, limits)?;
                if instance_types.len() >= type_count {
                    return Err(format!(
                        "binary input contains more INST chunks than header type count {type_count}"
                    ));
                }
                if instance_types.insert(type_id, class).is_some() {
                    return Err(format!("binary input repeats instance type id {type_id}"));
                }
                instances_seen = instances_seen
                    .checked_add(count)
                    .ok_or_else(|| "binary instance count overflow".to_owned())?;
                if instances_seen > instance_count {
                    return Err(format!(
                        "binary INST chunks declare {instances_seen} instances, more than header count {instance_count}"
                    ));
                }
            }
            b"PROP" => inspect_binary_property_chunk(&decoded, &instance_types, &mut preflight)?,
            b"META" => inspect_binary_meta_chunk(&decoded, limits)?,
            b"SSTR" => inspect_binary_shared_strings_chunk(&decoded, limits)?,
            _ => {}
        }
        cursor += stored_len;
        if name == b"END\0" {
            saw_end = true;
            break;
        }
    }
    if !saw_end {
        return Err("binary input has no END chunk".to_owned());
    }
    if instance_types.len() != type_count || instances_seen != instance_count {
        return Err(format!(
            "binary chunk counts do not match header: {} of {type_count} types and {instances_seen} of {instance_count} instances",
            instance_types.len()
        ));
    }
    Ok(preflight)
}

fn decode_binary_chunk(
    stored: &[u8],
    compressed_len: usize,
    decoded_len: usize,
) -> Result<Vec<u8>, String> {
    let decoded = if compressed_len == 0 {
        stored.to_vec()
    } else if stored.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let decoder = zstd::stream::read::Decoder::new(stored)
            .map_err(|error| format!("cannot start bounded ZSTD chunk decode: {error}"))?;
        let mut decoded = Vec::with_capacity(decoded_len.min(1024 * 1024));
        decoder
            .take(decoded_len.saturating_add(1) as u64)
            .read_to_end(&mut decoded)
            .map_err(|error| format!("cannot decode bounded ZSTD chunk: {error}"))?;
        decoded
    } else {
        lz4_flex::block::decompress(stored, decoded_len)
            .map_err(|error| format!("cannot decode bounded LZ4 chunk: {error}"))?
    };
    if decoded.len() != decoded_len {
        return Err(format!(
            "binary chunk decoded length {} does not match declared length {decoded_len}",
            decoded.len()
        ));
    }
    Ok(decoded)
}

/// The type id, class name and instance count of an INST chunk. A class name
/// longer than any real one is shortened and marked with `...`, so it stays
/// unknown.
fn inspect_binary_instance_chunk(
    chunk: &[u8],
    limits: &Limits,
) -> Result<(u32, String, usize), String> {
    if chunk.len() < 8 {
        return Err("binary INST chunk is truncated before its class name".to_owned());
    }
    let type_id = u32::from_le_bytes(chunk[0..4].try_into().expect("fixed slice"));
    let name_len = u32::from_le_bytes(chunk[4..8].try_into().expect("fixed slice")) as usize;
    let name_end = 8usize
        .checked_add(name_len)
        .ok_or_else(|| "binary INST class-name length overflow".to_owned())?;
    let count_end = name_end
        .checked_add(5)
        .ok_or_else(|| "binary INST count offset overflow".to_owned())?;
    if count_end > chunk.len() {
        return Err("binary INST class-name length exceeds its chunk".to_owned());
    }
    let class = std::str::from_utf8(&chunk[8..name_end])
        .map_err(|_| "binary INST class name is not valid UTF-8".to_owned())?;
    let class = if class.len() > 256 {
        format!("{}...", class.chars().take(64).collect::<String>())
    } else {
        class.to_owned()
    };
    let count = u32::from_le_bytes(
        chunk[name_end + 1..count_end]
            .try_into()
            .expect("fixed slice"),
    ) as usize;
    if count > limits.max_instances {
        return Err(format!(
            "binary INST count {count} exceeds max_instances {}",
            limits.max_instances
        ));
    }
    let referent_bytes = count
        .checked_mul(4)
        .ok_or_else(|| "binary INST referent byte count overflow".to_owned())?;
    if referent_bytes > chunk.len() - count_end {
        return Err("binary INST count exceeds the referent data in its chunk".to_owned());
    }
    Ok((type_id, class, count))
}

/// Check a PROP chunk. A value type the decoder does not know is skipped with
/// the whole property, which makes the input partial unless
/// [`skipped_value_risk`] finds nothing it could hide.
fn inspect_binary_property_chunk(
    chunk: &[u8],
    instance_types: &HashMap<u32, String>,
    preflight: &mut Preflight,
) -> Result<(), String> {
    if chunk.len() < 8 {
        return Err("binary PROP chunk is truncated before its property name".to_owned());
    }
    let type_id = u32::from_le_bytes(chunk[0..4].try_into().expect("fixed slice"));
    let Some(class) = instance_types.get(&type_id) else {
        return Err(format!(
            "binary PROP chunk refers to unknown type id {type_id}"
        ));
    };
    let name_len = u32::from_le_bytes(chunk[4..8].try_into().expect("fixed slice")) as usize;
    let type_offset = 8usize
        .checked_add(name_len)
        .ok_or_else(|| "binary PROP property-name length overflow".to_owned())?;
    if type_offset > chunk.len() {
        return Err("binary PROP property-name length exceeds its chunk".to_owned());
    }
    if type_offset >= chunk.len() {
        preflight.skipped_value(
            ("none".to_owned(), None, None),
            "binary property has no readable value type and was skipped".to_owned(),
            false,
        );
        return Ok(());
    }
    let property_name = std::str::from_utf8(&chunk[8..type_offset])
        .map_err(|_| "binary PROP property name is not valid UTF-8".to_owned())?;
    let value_type = chunk[type_offset];
    if !binary_property_type_supported(value_type) {
        let skipped = format!(
            "binary property {property_name:?} of class {class:?} uses unsupported value type 0x{value_type:02x} and was skipped"
        );
        let risk = skipped_value_risk(class, property_name);
        let message = format!("{skipped}; {}", risk.unwrap_or(NO_RISK));
        preflight.skipped_value(
            (
                format!("0x{value_type:02x}"),
                Some(class.clone()),
                Some(property_name.to_owned()),
            ),
            message,
            risk.is_none(),
        );
    }
    Ok(())
}

/// Note text for a skipped value that [`skipped_value_risk`] clears.
const NO_RISK: &str = "no rule reads it and its class cannot hold code";

/// Why a property value that the decoders skip, because they do not know its
/// value type, could hide code or a rule input. `None` only when the class is
/// in the bundled reflection database, cannot hold code, and the rules read
/// no property of that name on it. Newer Studio versions write new value
/// types, such as 0x23 on `Terrain`, before the decoders know them.
fn skipped_value_risk(class: &str, property: &str) -> Option<&'static str> {
    if !is_known_class(class) {
        Some("its class is not in the bundled reflection database")
    } else if class_can_hold_code(class) {
        Some("its class can hold code")
    } else if property_feeds_rules(class, property) {
        Some("a rule may read this property")
    } else {
        None
    }
}

/// A class that can hold script source: a class named `...Script`, or one that
/// is or inherits `LuaSourceContainer` or a class with a `Source` property in
/// the bundled reflection database. A class the database does not know counts.
fn class_can_hold_code(class: &str) -> bool {
    let database = rbx_reflection_database::get_bundled();
    let Some(descriptor) = database.classes.get(class) else {
        return true;
    };
    class.ends_with("Script")
        || database.superclasses_iter(descriptor).any(|ancestor| {
            ancestor.name == "LuaSourceContainer" || ancestor.properties.contains_key("Source")
        })
}

/// Whether the rules can read `property` of `class` once a file is decoded:
/// every property `extract_dom_properties` keeps, the instance name and tags,
/// `Value` and `Package...` in any letter case, and every property of a value
/// object or a `PackageLink`.
fn property_feeds_rules(class: &str, property: &str) -> bool {
    let lower = property.to_ascii_lowercase();
    class == "PackageLink"
        || class.ends_with("Value")
        || matches!(
            lower.as_str(),
            "name" | "tags" | "value" | "attributes" | "attributesserialize"
        )
        || lower.contains("source")
        || lower.starts_with("package")
        || crate::heuristics::is_text_property(property)
        || keep_property(property, class)
}

fn inspect_binary_meta_chunk(chunk: &[u8], limits: &Limits) -> Result<(), String> {
    if chunk.len() < 4 {
        return Err("binary META chunk is truncated before its entry count".to_owned());
    }
    let count = u32::from_le_bytes(chunk[0..4].try_into().expect("fixed slice")) as usize;
    if count > limits.max_instances {
        return Err(format!(
            "binary META entry count {count} exceeds max_instances {}",
            limits.max_instances
        ));
    }
    let mut cursor = 4;
    for _ in 0..count {
        skip_binary_string(chunk, &mut cursor, "META key")?;
        skip_binary_string(chunk, &mut cursor, "META value")?;
    }
    Ok(())
}

fn inspect_binary_shared_strings_chunk(chunk: &[u8], limits: &Limits) -> Result<(), String> {
    if chunk.len() < 8 {
        return Err("binary SSTR chunk is truncated before its entry count".to_owned());
    }
    let count = u32::from_le_bytes(chunk[4..8].try_into().expect("fixed slice")) as usize;
    if count > limits.max_instances {
        return Err(format!(
            "binary SSTR entry count {count} exceeds max_instances {}",
            limits.max_instances
        ));
    }
    let mut cursor = 8usize;
    for _ in 0..count {
        cursor = cursor
            .checked_add(16)
            .filter(|end| *end <= chunk.len())
            .ok_or_else(|| "binary SSTR hash exceeds its chunk".to_owned())?;
        skip_binary_string(chunk, &mut cursor, "SSTR value")?;
    }
    Ok(())
}

fn skip_binary_string(chunk: &[u8], cursor: &mut usize, label: &str) -> Result<(), String> {
    let length_end = cursor
        .checked_add(4)
        .filter(|end| *end <= chunk.len())
        .ok_or_else(|| format!("binary {label} is truncated before its length"))?;
    let length =
        u32::from_le_bytes(chunk[*cursor..length_end].try_into().expect("fixed slice")) as usize;
    *cursor = length_end
        .checked_add(length)
        .filter(|end| *end <= chunk.len())
        .ok_or_else(|| format!("binary {label} length exceeds its chunk"))?;
    Ok(())
}

fn binary_property_type_supported(value: u8) -> bool {
    matches!(
        value,
        0x01..=0x0e
            | 0x10
            | 0x12..=0x1c
            | 0x1e..=0x22
    )
}

fn preflight_xml(bytes: &[u8], limits: &Limits) -> Result<Preflight, String> {
    let mut cursor = 0usize;
    let mut item_depth = 0usize;
    let mut item_count = 0usize;
    let mut stack: Vec<Vec<u8>> = Vec::new();
    // The class of each open `Item`, `None` when it cannot be read.
    let mut item_classes: Vec<Option<String>> = Vec::new();
    let mut protected_strings = BTreeSet::new();
    let mut pending_protected: Option<PendingProtectedString> = None;
    // A `ProtectedString` whose `Item` class or own name could not be read, so
    // the check keyed by them cannot be trusted.
    let mut unreadable_name = false;
    let mut preflight = Preflight::default();
    while let Some(relative) = bytes[cursor..].iter().position(|byte| *byte == b'<') {
        let start = cursor + relative;
        if let Some(open) = pending_protected.as_mut()
            && !trim_ascii(&bytes[cursor..start]).is_empty()
        {
            open.has_text = true;
        }
        if bytes[start..].starts_with(b"<!--") {
            let Some(end) = find_bytes(&bytes[start + 4..], b"-->") else {
                return Err("XML input has an unterminated comment".to_owned());
            };
            cursor = start + 4 + end + 3;
            continue;
        }
        if bytes[start..].starts_with(b"<![CDATA[") {
            let Some(end) = find_bytes(&bytes[start + 9..], b"]]>") else {
                return Err("XML input has an unterminated CDATA section".to_owned());
            };
            if let Some(open) = pending_protected.as_mut()
                && !trim_ascii(&bytes[start + 9..start + 9 + end]).is_empty()
            {
                open.has_text = true;
            }
            cursor = start + 9 + end + 3;
            continue;
        }
        let Some(end) = xml_tag_end(bytes, start + 1) else {
            return Err("XML input has an unterminated tag".to_owned());
        };
        let mut inside = &bytes[start + 1..end];
        inside = trim_ascii(inside);
        let closing = inside.first() == Some(&b'/');
        if closing {
            inside = trim_ascii(&inside[1..]);
        }
        let self_closing = inside.last() == Some(&b'/');
        if self_closing {
            inside = trim_ascii(&inside[..inside.len() - 1]);
        }
        let name_end = inside
            .iter()
            .position(|byte| byte.is_ascii_whitespace())
            .unwrap_or(inside.len());
        // rbx_xml matches elements by local name, so `x:Item` is an `Item`.
        let name = xml_local_name(&inside[..name_end]);
        if closing {
            if name == b"Item" {
                item_depth = item_depth.saturating_sub(1);
                item_classes.pop();
            }
            if pending_protected
                .as_ref()
                .is_some_and(|open| open.depth == stack.len())
                && let Some(open) = pending_protected.take()
                && open.has_text
            {
                let key = (open.class, open.property);
                if protected_strings.len() >= MAX_PROTECTED_STRING_PROPERTIES
                    && !protected_strings.contains(&key)
                {
                    return Err(format!(
                        "XML input has more than {MAX_PROTECTED_STRING_PROPERTIES} distinct ProtectedString properties"
                    ));
                }
                protected_strings.insert(key);
            }
            stack.pop();
        } else {
            if let Some(open) = pending_protected.as_mut() {
                // Markup inside a ProtectedString is unusual; count it as content.
                open.has_text = true;
            }
            if name == b"ProtectedString"
                && !self_closing
                && stack.last().is_some_and(|parent| parent == b"Properties")
            {
                match (item_classes.last(), xml_name_attribute(inside, b"name")) {
                    (Some(Some(class)), Some(property)) => {
                        pending_protected = Some(PendingProtectedString {
                            class: class.clone(),
                            property,
                            depth: stack.len() + 1,
                            has_text: false,
                        });
                    }
                    _ => unreadable_name = true,
                }
            }
            if stack.last().is_some_and(|parent| parent == b"Properties")
                && !xml_property_type_supported(name)
            {
                // The owner is the `Item` right around `Properties`.
                let class = item_classes
                    .last()
                    .filter(|_| stack.len() >= 2 && stack[stack.len() - 2] == b"Item")
                    .cloned()
                    .flatten();
                let property = xml_name_attribute(inside, b"name");
                let type_name = String::from_utf8_lossy(name);
                let (message, note) = match (&class, &property) {
                    (Some(class), Some(property)) => {
                        let skipped = format!(
                            "XML property {property:?} of class {class:?} uses unsupported value type {type_name:?} and was skipped"
                        );
                        match skipped_value_risk(class, property) {
                            Some(risk) => (format!("{skipped}; {risk}"), false),
                            None => (format!("{skipped}; {NO_RISK}"), true),
                        }
                    }
                    _ => (
                        format!(
                            "XML property uses unsupported value type {type_name:?} and was skipped; its class or name could not be read"
                        ),
                        false,
                    ),
                };
                preflight.skipped_value((type_name.into_owned(), class, property), message, note);
            }
            if name == b"Item" {
                item_count += 1;
                if item_count > limits.max_instances {
                    return Err(format!(
                        "XML instance count exceeds max_instances {}",
                        limits.max_instances
                    ));
                }
                if !self_closing {
                    item_depth += 1;
                    if item_depth > MAX_XML_ITEM_NESTING {
                        return Err(format!(
                            "XML Item nesting exceeds the safe parser limit of {MAX_XML_ITEM_NESTING} nested Item elements"
                        ));
                    }
                    item_classes.push(xml_name_attribute(inside, b"class"));
                }
            }
            if !self_closing && !name.starts_with(b"?") && !name.starts_with(b"!") {
                if stack.len() >= MAX_XML_ELEMENT_NESTING {
                    return Err(format!(
                        "XML element nesting exceeds the safe parser limit {MAX_XML_ELEMENT_NESTING}"
                    ));
                }
                stack.push(name.to_vec());
            }
        }
        cursor = end + 1;
    }
    if unreadable_name {
        preflight.warnings.push(
            "XML input has a ProtectedString whose Item class or name could not be read".to_owned(),
        );
    }
    preflight.protected_strings = protected_strings;
    Ok(preflight)
}

/// The value of the attribute `key` in a start tag's inner bytes (the element
/// name, then its attributes), without entity decoding. The attributes are read
/// in order as `name = "value"` or `name = 'value'` pairs, so text inside
/// another attribute's value never counts. A name is compared by its local part
/// after any `prefix:`, as rbx_xml compares it. `None` when the key is missing,
/// appears twice, or the tag does not read as such pairs.
fn xml_attribute<'a>(inside: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let skip_space = |mut at: usize| {
        while inside.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        at
    };
    let mut cursor = inside.iter().position(u8::is_ascii_whitespace)?;
    let mut found = None;
    loop {
        cursor = skip_space(cursor);
        if cursor >= inside.len() {
            return found;
        }
        let name_start = cursor;
        while inside
            .get(cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
        {
            cursor += 1;
        }
        let name = xml_local_name(&inside[name_start..cursor]);
        cursor = skip_space(cursor);
        if inside.get(cursor) != Some(&b'=') {
            return None;
        }
        cursor = skip_space(cursor + 1);
        let quote = *inside.get(cursor)?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        let value_start = cursor + 1;
        let length = inside[value_start..]
            .iter()
            .position(|byte| *byte == quote)?;
        if name == key {
            if found.is_some() {
                return None;
            }
            found = Some(&inside[value_start..value_start + length]);
        }
        cursor = value_start + length + 1;
    }
}

/// The local part of an XML element or attribute name, after any `prefix:`.
fn xml_local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

/// The attribute `key` as a class or property name, or `None` when it cannot
/// be read as one: missing or doubled, not UTF-8, or with an entity, which
/// reads differently once decoded. Names in Roblox XML are plain identifiers.
fn xml_name_attribute(inside: &[u8], key: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(xml_attribute(inside, key)?).ok()?;
    (!value.contains('&')).then(|| value.to_owned())
}

/// An open `ProtectedString` element seen by the single preflight pass.
struct PendingProtectedString {
    class: String,
    property: String,
    /// Element stack depth while the element is open.
    depth: usize,
    has_text: bool,
}

fn xml_property_type_supported(name: &[u8]) -> bool {
    matches!(
        name,
        b"Axes"
            | b"BinaryString"
            | b"bool"
            | b"CoordinateFrame"
            | b"Color3"
            | b"Color3uint8"
            | b"ColorSequence"
            | b"Content"
            | b"ContentId"
            | b"token"
            | b"Faces"
            | b"float"
            | b"double"
            | b"Font"
            | b"int"
            | b"int64"
            | b"NumberRange"
            | b"NumberSequence"
            | b"OptionalCoordinateFrame"
            | b"PhysicalProperties"
            | b"Ray"
            | b"Rect2D"
            | b"SecurityCapabilities"
            | b"string"
            | b"UDim"
            | b"UDim2"
            | b"UniqueId"
            | b"Vector2"
            | b"Vector2int16"
            | b"Vector3"
            | b"Vector3int16"
            | b"ProtectedString"
            | b"Ref"
            | b"SharedString"
            | b"NetAssetRef"
    )
}

fn xml_tag_end(bytes: &[u8], mut cursor: usize) -> Option<usize> {
    let mut quote = None;
    while cursor < bytes.len() {
        match (quote, bytes[cursor]) {
            (None, b'\'' | b'"') => quote = Some(bytes[cursor]),
            (Some(expected), found) if expected == found => quote = None,
            (None, b'>') => return Some(cursor),
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

enum BoundedRead {
    Bytes(Vec<u8>),
    TooLarge(u64),
}

fn read_bounded(path: &Path, max_bytes: u64) -> std::io::Result<BoundedRead> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > max_bytes {
        return Ok(BoundedRead::TooLarge(metadata.len()));
    }
    let file = fs::File::open(path)?;
    let capacity = metadata.len().min(max_bytes).min(1024 * 1024) as usize;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        Ok(BoundedRead::TooLarge(bytes.len() as u64))
    } else {
        Ok(BoundedRead::Bytes(bytes))
    }
}

fn path_stays_in_root(path: &Path, canonical_root: &Path) -> bool {
    fs::canonicalize(path).is_ok_and(|canonical| canonical.starts_with(canonical_root))
}

fn safe_regular_file(path: &Path, canonical_root: &Path, document: &mut Document) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            document.partial(format!(
                "cannot read metadata for {}: {error}",
                path.display()
            ));
            return false;
        }
    };
    if is_link_or_reparse(&metadata) {
        document.partial(format!(
            "skipped symbolic link or junction: {}",
            path.display()
        ));
        return false;
    }
    if !metadata.is_file() {
        document.partial(format!("refused non-file source: {}", path.display()));
        return false;
    }
    if !path_stays_in_root(path, canonical_root) {
        document.partial(format!(
            "refused file outside source tree: {}",
            path.display()
        ));
        return false;
    }
    true
}

fn failed_document(input: String, reason: impl Into<String>) -> Document {
    let mut document = Document {
        input,
        ..Document::default()
    };
    document.failed(reason);
    document
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn apply_source_conventions(instance: &mut Instance, path: &Path) {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".plugin.lua") || name.ends_with(".plugin.luau") {
        instance
            .properties
            .insert("RunContext".to_owned(), Value::String("Plugin".to_owned()));
    }
}

fn ensure_source_class(document: &mut Document, instance: &mut Instance, path: &Path) {
    if !instance.is_script() {
        document.partial(format!(
            "metadata for source {} selected non-script class {:?}; using {}",
            path.display(),
            instance.class,
            source_class(path)
        ));
        instance.class = source_class(path).to_owned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// One attribute `FAKE` holding the Float64 999000000004131.
    fn valid_blob() -> Vec<u8> {
        let mut blob = 1u32.to_le_bytes().to_vec();
        blob.extend(4u32.to_le_bytes());
        blob.extend(b"FAKE\x06");
        blob.extend(999_000_000_004_131f64.to_le_bytes());
        blob
    }

    fn binary_string(value: &[u8]) -> Vec<u8> {
        let mut out = (value.len() as u32).to_le_bytes().to_vec();
        out.extend(value);
        out
    }

    fn chunk(name: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = name.to_vec();
        out.extend(0u32.to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(data);
        out
    }

    fn binary_model(blob: &[u8]) -> Vec<u8> {
        let mut out = b"<roblox!\x89\xff\r\n\x1a\n\0\0".to_vec();
        out.extend(1u32.to_le_bytes());
        out.extend(1u32.to_le_bytes());
        out.extend(0u64.to_le_bytes());
        let mut inst = 0u32.to_le_bytes().to_vec();
        inst.extend(binary_string(b"Folder"));
        inst.extend(b"\0");
        inst.extend(1u32.to_le_bytes());
        inst.extend([0; 4]);
        out.extend(chunk(b"INST", &inst));
        let mut prop = 0u32.to_le_bytes().to_vec();
        prop.extend(binary_string(b"AttributesSerialize"));
        prop.push(0x01);
        prop.extend(binary_string(blob));
        out.extend(chunk(b"PROP", &prop));
        out.extend(chunk(b"PRNT", b"\0\x01\0\0\0\0\0\0\0\0\0\0\x01"));
        out.extend(chunk(b"END\0", b"</roblox>"));
        out
    }

    fn xml_model(blob: &[u8]) -> Vec<u8> {
        const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::new();
        for group in blob.chunks(3) {
            let bits = group.iter().enumerate().fold(0u32, |bits, (index, byte)| {
                bits | (u32::from(*byte) << (16 - 8 * index))
            });
            for index in 0..4 {
                if index <= group.len() {
                    encoded.push(BASE64[((bits >> (18 - 6 * index)) & 63) as usize] as char);
                } else {
                    encoded.push('=');
                }
            }
        }
        format!(
            r#"<roblox version="4"><Item class="Folder" referent="RBX1"><Properties><string name="Name">FAKE</string><BinaryString name="AttributesSerialize">{encoded}</BinaryString></Properties></Item></roblox>"#
        )
        .into_bytes()
    }

    /// Every way to load an input records the time it took, so analysis and
    /// inventory continue the same budget.
    #[test]
    fn every_loader_records_the_time_it_used() {
        let limits = Limits::default();
        let tree = tempfile::Builder::new()
            .prefix("bloxguard_FAKE_clock_")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("create repository-local temp directory");
        std::fs::write(tree.path().join("FAKE_a.server.luau"), "return 1").unwrap();
        std::fs::write(tree.path().join("FAKE_b.rbxm"), binary_model(&valid_blob())).unwrap();
        let file = tree.path().join("FAKE_b.rbxm");
        let bundle = Bundle {
            schema_version: 1,
            instances: vec![Instance {
                name: "FAKE".into(),
                class: "Folder".into(),
                ..Instance::default()
            }],
        };
        for (label, document) in [
            ("tree", load_path(tree.path(), &limits).remove(0)),
            ("file", load_path(&file, &limits).remove(0)),
            (
                "bytes",
                load_bytes("FAKE.rbxm", "rbxm", &binary_model(&valid_blob()), &limits),
            ),
            ("bundle", load_bundle(bundle, "mcp/bundle", &limits)),
            (
                "source",
                load_source("return 1", "FAKE.luau", "ModuleScript", &limits),
            ),
        ] {
            assert_eq!(
                document.completeness,
                Completeness::Complete,
                "{label}: {:?}",
                document.reasons
            );
            assert!(document.time_spent > Duration::ZERO, "{label}");
        }
    }

    #[test]
    fn decoders_hand_attribute_blobs_over_unread() {
        // Valid and invalid blobs both arrive as the raw bytes, so no decoder
        // ever runs rbx_types on them.
        let invalid = [1, 0, 0, 0, 4, 0, 0, 0, b'F', b'A', b'K', b'E', 0xff].to_vec();
        for blob in [valid_blob(), invalid, Vec::new()] {
            for (extension, bytes) in [("rbxm", binary_model(&blob)), ("rbxmx", xml_model(&blob))] {
                let dom = decode_dom(extension, &bytes).expect(extension);
                let folder = dom.get_by_ref(dom.root().children()[0]).expect(extension);
                match folder.properties.get(&rbx_dom_weak::ustr("Attributes")) {
                    Some(Variant::BinaryString(raw)) => {
                        assert_eq!(
                            <_ as AsRef<[u8]>>::as_ref(raw),
                            blob.as_slice(),
                            "{extension}"
                        );
                    }
                    other => panic!("{extension}: {other:?}"),
                }
            }
        }
        // And the scanner reads the valid one itself.
        let document = load_bytes(
            "FAKE.rbxm",
            "rbxm",
            &binary_model(&valid_blob()),
            &Limits::default(),
        );
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{:?}",
            document.reasons
        );
        assert_eq!(
            document.instances[0].attributes.get("FAKE"),
            Some(&Value::from(999_000_000_004_131f64))
        );
    }

    /// A file names a property by its serialized spelling, so every alias or
    /// migrated name the bundled reflection database links to a rule input
    /// must count as a rule input too. `Instance.AttributesSerialize` and
    /// `PackageLink.PackageIdSerialize` are such spellings.
    #[test]
    fn every_spelling_of_a_rule_input_is_a_rule_input() {
        let database = rbx_reflection_database::get_bundled();
        let mut linked_inputs = 0;
        for class in database.classes.values() {
            let is_property = |name: &str| {
                database
                    .superclasses_iter(class)
                    .any(|ancestor| ancestor.properties.contains_key(name))
            };
            for property in class.properties.values() {
                let kind = serde_json::to_value(&property.kind).expect("kind serializes");
                let mut names = vec![property.name.to_owned()];
                let mut pending = vec![&kind];
                while let Some(value) = pending.pop() {
                    match value {
                        Value::String(text) if is_property(text) => names.push(text.clone()),
                        Value::Array(items) => pending.extend(items),
                        Value::Object(fields) => pending.extend(fields.values()),
                        _ => {}
                    }
                }
                if names.len() > 1
                    && names
                        .iter()
                        .any(|name| property_feeds_rules(class.name, name))
                {
                    linked_inputs += 1;
                    for name in &names {
                        assert!(
                            property_feeds_rules(class.name, name),
                            "{}.{name} is linked to a rule input: {names:?}",
                            class.name
                        );
                    }
                }
            }
        }
        assert!(linked_inputs >= 4, "{linked_inputs}");
    }

    /// Attributes are read in order, in both quote kinds, so `class="..."` inside
    /// another value, or in an attribute whose name ends in `class`, never counts.
    #[test]
    fn xml_attributes_are_read_in_order() {
        for (inside, key, expected) in [
            (
                r#"Item class="Script" referent="FAKE1""#,
                "class",
                Some("Script"),
            ),
            (
                r#"Item class='Script' referent='FAKE1'"#,
                "class",
                Some("Script"),
            ),
            (
                r#"Item referent='FAKE1 class="Folder"' class="Part""#,
                "class",
                Some("Part"),
            ),
            (
                r#"Item referent="FAKE1 class='Folder'" class='Part'"#,
                "class",
                Some("Part"),
            ),
            (
                r#"Item xclass="Folder" class="Part""#,
                "class",
                Some("Part"),
            ),
            (r#"Item xclass="Folder""#, "class", None),
            (r#"Item class = "Part""#, "class", Some("Part")),
            ("Item class\t=\n'Part'", "class", Some("Part")),
            (r#"Item x:class="Script""#, "class", Some("Script")),
            (r#"Item class="Folder" x:class="Script""#, "class", None),
            (r#"Item class="Folder" class="Part""#, "class", None),
            ("Item class=Part", "class", None),
            (r#"Item class="Part"#, "class", None),
            (r#"Item referent="FAKE1" class"#, "class", None),
            ("Item", "class", None),
            (r#"string name="Te&#120;t""#, "name", Some("Te&#120;t")),
        ] {
            let value = xml_attribute(inside.as_bytes(), key.as_bytes())
                .map(|value| std::str::from_utf8(value).expect("UTF-8 fixture"));
            assert_eq!(value, expected, "{inside}");
        }
        assert_eq!(
            xml_name_attribute(br#"Item class="Part""#, b"class").as_deref(),
            Some("Part")
        );
        assert_eq!(
            xml_name_attribute(br#"string name="Te&#120;t""#, b"name"),
            None
        );
        assert_eq!(xml_local_name(b"x:Item"), b"Item");
        assert_eq!(xml_local_name(b"Item"), b"Item");
    }

    #[test]
    fn only_known_classes_that_cannot_hold_code_clear_skipped_values() {
        for class in [
            "Script",
            "LocalScript",
            "ModuleScript",
            "CoreScript",
            "FAKEFutureScript",
        ] {
            assert!(class_can_hold_code(class), "{class}");
        }
        for class in ["Terrain", "Folder", "Workspace", "Part", "PackageLink"] {
            assert!(!class_can_hold_code(class), "{class}");
        }
        assert_eq!(skipped_value_risk("Terrain", "FAKE_VoxelMap"), None);
        assert!(skipped_value_risk("FAKEFutureClass", "FAKE_VoxelMap").is_some());
    }
}
