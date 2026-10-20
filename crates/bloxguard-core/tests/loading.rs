use bloxguard_core::loading::{load_bundle, load_bytes, load_path, load_source};
use bloxguard_core::model::{Bundle, Completeness, Instance, Limits};
use bloxguard_core::{engine, output};
use rbx_dom_weak::{
    InstanceBuilder, WeakDom,
    types::{Content, Enum},
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

const FAKE_SOURCE: &str = "return 999000000000001";

fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("bloxguard_FAKE_loader_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory")
}

fn fake_dom() -> WeakDom {
    WeakDom::new(
        InstanceBuilder::new("DataModel").with_child(
            InstanceBuilder::new("Folder")
                .with_name("FAKE Root")
                .with_child(
                    InstanceBuilder::new("Script")
                        .with_name("FAKE Script")
                        .with_property("Source", FAKE_SOURCE)
                        .with_property("Disabled", false),
                ),
        ),
    )
}

fn client_context_dom() -> WeakDom {
    let script = |name: &str| {
        InstanceBuilder::new("Script")
            .with_name(name)
            .with_property("Source", "return true")
            .with_property("RunContext", Enum::from_u32(2))
    };
    WeakDom::new(
        InstanceBuilder::new("DataModel")
            .with_child(
                InstanceBuilder::new("ServerScriptService")
                    .with_child(script("FAKE Server Container Client Script")),
            )
            .with_child(
                InstanceBuilder::new("Workspace").with_child(
                    InstanceBuilder::new("Model")
                        .with_name("FAKE Model")
                        .with_child(script("FAKE Workspace Client Script")),
                ),
            ),
    )
}

fn encode_binary(dom: &WeakDom) -> Vec<u8> {
    let mut bytes = Vec::new();
    rbx_binary::to_writer(&mut bytes, dom, dom.root().children())
        .expect("encode synthetic binary fixture");
    bytes
}

fn encode_binary_uncompressed(dom: &WeakDom) -> Vec<u8> {
    let mut bytes = Vec::new();
    rbx_binary::Serializer::new()
        .reflection_database(rbx_reflection_database::get_bundled())
        .compression_type(rbx_binary::CompressionType::None)
        .serialize(&mut bytes, dom, dom.root().children())
        .expect("encode uncompressed synthetic binary fixture");
    bytes
}

fn replace_binary_property_type(bytes: &mut [u8], property: &str, replacement: u8) {
    let mut cursor = 32usize;
    while bytes.len().saturating_sub(cursor) >= 16 {
        let name = &bytes[cursor..cursor + 4];
        let compressed_len =
            u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        let decoded_len =
            u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
        assert_eq!(compressed_len, 0, "fixture must be uncompressed");
        let payload = cursor + 16;
        if name == b"PROP" {
            let name_len =
                u32::from_le_bytes(bytes[payload + 4..payload + 8].try_into().unwrap()) as usize;
            let type_offset = payload + 8 + name_len;
            if &bytes[payload + 8..type_offset] == property.as_bytes() {
                bytes[type_offset] = replacement;
                return;
            }
        }
        cursor = payload + decoded_len;
    }
    panic!("property {property:?} not found in synthetic binary fixture");
}

fn replace_binary_chunk_u32(
    bytes: &mut [u8],
    chunk_name: &[u8; 4],
    payload_offset: usize,
    value: u32,
) {
    let mut cursor = 32usize;
    while bytes.len().saturating_sub(cursor) >= 16 {
        let name = &bytes[cursor..cursor + 4];
        let compressed_len =
            u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        let decoded_len =
            u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
        assert_eq!(compressed_len, 0, "fixture must be uncompressed");
        let payload = cursor + 16;
        if name == chunk_name {
            bytes[payload + payload_offset..payload + payload_offset + 4]
                .copy_from_slice(&value.to_le_bytes());
            return;
        }
        cursor = payload + decoded_len;
    }
    panic!("chunk {chunk_name:?} not found in synthetic binary fixture");
}

fn truncate_uncompressed_binary_property_tail(bytes: &mut Vec<u8>, property: &str, remove: usize) {
    let mut cursor = 32usize;
    while bytes.len().saturating_sub(cursor) >= 16 {
        let name = &bytes[cursor..cursor + 4];
        let compressed_len =
            u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        let decoded_len =
            u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
        assert_eq!(compressed_len, 0, "fixture must be uncompressed");
        let payload = cursor + 16;
        if name == b"PROP" {
            let name_len =
                u32::from_le_bytes(bytes[payload + 4..payload + 8].try_into().unwrap()) as usize;
            let property_start = payload + 8;
            let property_end = property_start + name_len;
            if &bytes[property_start..property_end] == property.as_bytes() {
                assert!(remove <= decoded_len);
                bytes.drain(payload + decoded_len - remove..payload + decoded_len);
                bytes[cursor + 8..cursor + 12]
                    .copy_from_slice(&((decoded_len - remove) as u32).to_le_bytes());
                return;
            }
        }
        cursor = payload + decoded_len;
    }
    panic!("property {property:?} not found in synthetic binary fixture");
}

fn encode_xml(dom: &WeakDom) -> Vec<u8> {
    let mut bytes = Vec::new();
    rbx_xml::to_writer_default(&mut bytes, dom, dom.root().children())
        .expect("encode synthetic XML fixture");
    bytes
}

fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).expect("write synthetic fixture")
}

#[cfg(unix)]
fn symlink_file(original: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(original, link)
}

#[cfg(windows)]
fn symlink_file(original: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(original, link)
}

#[cfg(unix)]
fn symlink_dir(original: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(original, link)
}

#[cfg(windows)]
fn symlink_dir(original: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(original, link)
}

#[test]
fn all_four_roblox_formats_load_script_source() {
    let dom = fake_dom();
    for (extension, bytes) in [
        ("rbxl", encode_binary(&dom)),
        ("rbxm", encode_binary(&dom)),
        ("rbxlx", encode_xml(&dom)),
        ("rbxmx", encode_xml(&dom)),
    ] {
        let document = load_bytes(
            &format!("FAKE.{extension}"),
            extension,
            &bytes,
            &Limits::default(),
        );
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{extension}: {:?}",
            document.reasons
        );
        let script = document
            .instances
            .iter()
            .find(|instance| instance.is_script())
            .expect("script instance");
        assert_eq!(script.source.as_deref(), Some(FAKE_SOURCE));
        assert_eq!(script.properties.get("Disabled"), Some(&json!(false)));
        let script_index = document
            .instances
            .iter()
            .position(|instance| instance.is_script())
            .unwrap();
        assert_eq!(
            document.path(script_index),
            "/FAKE\\u{20}Root/FAKE\\u{20}Script"
        );
    }
}

#[test]
fn run_context_is_normalized_across_files_bundles_and_inventory() {
    let dom = client_context_dom();
    let bundle = Bundle {
        schema_version: 1,
        instances: vec![
            Instance {
                name: "ServerScriptService".into(),
                class: "ServerScriptService".into(),
                ..Instance::default()
            },
            Instance {
                name: "FAKE Server Container Client Script".into(),
                class: "Script".into(),
                parent: Some(0),
                properties: [("RunContext".into(), json!("Enum.RunContext.Client"))].into(),
                source: Some("return true".into()),
                ..Instance::default()
            },
            Instance {
                name: "Workspace".into(),
                class: "Workspace".into(),
                ..Instance::default()
            },
            Instance {
                name: "FAKE Model".into(),
                class: "Model".into(),
                parent: Some(2),
                ..Instance::default()
            },
            Instance {
                name: "FAKE Workspace Client Script".into(),
                class: "Script".into(),
                parent: Some(3),
                properties: [("RunContext".into(), json!({ "Enum": 2 }))].into(),
                source: Some("return true".into()),
                ..Instance::default()
            },
        ],
    };
    let documents = [
        (
            "rbxm",
            load_bytes(
                "FAKE RunContext.rbxm",
                "rbxm",
                &encode_binary(&dom),
                &Limits::default(),
            ),
        ),
        (
            "rbxmx",
            load_bytes(
                "FAKE RunContext.rbxmx",
                "rbxmx",
                &encode_xml(&dom),
                &Limits::default(),
            ),
        ),
        (
            "bundle",
            load_bundle(bundle, "FAKE RunContext bundle", &Limits::default()),
        ),
    ];

    for (format, document) in documents {
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{format}: {:?}",
            document.reasons
        );
        let scripts: Vec<_> = document
            .instances
            .iter()
            .filter(|instance| instance.is_script())
            .collect();
        assert_eq!(scripts.len(), 2, "{format}");
        assert!(
            scripts
                .iter()
                .all(|script| { script.properties.get("RunContext") == Some(&json!("Client")) })
        );

        let inventory = engine::inventory_documents(vec![document.clone()]);
        assert_eq!(inventory.inventory.len(), 2, "{format}");
        assert!(
            inventory
                .inventory
                .iter()
                .all(|script| { script.run_context.as_ref() == Some(&json!("Client")) })
        );

        let report = engine::scan_documents(vec![document], &Default::default());
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.rule_id == "BG006")
                .count(),
            2,
            "{format}"
        );
    }
}

#[test]
fn loaded_inventory_snapshot() {
    let document = load_bytes(
        "FAKE inventory.rbxmx",
        "rbxmx",
        &encode_xml(&fake_dom()),
        &Limits::default(),
    );
    let report = engine::inventory_documents(vec![document]);
    insta::assert_snapshot!("loaded_inventory", output::inventory_human(&report));
}

#[test]
fn corrupted_truncated_and_random_inputs_never_panic() {
    let valid_binary = encode_binary(&fake_dom());
    let valid_xml = encode_xml(&fake_dom());
    let inputs = [
        ("rbxm", Vec::new()),
        ("rbxm", valid_binary[..valid_binary.len() / 2].to_vec()),
        ("rbxl", (0u8..=127).collect()),
        ("rbxmx", b"<roblox><Item".to_vec()),
        ("rbxlx", valid_xml[..valid_xml.len() / 2].to_vec()),
        ("rbxmx", vec![0xff; 257]),
    ];
    for (extension, bytes) in inputs {
        let result = std::panic::catch_unwind(|| {
            load_bytes("FAKE corrupt", extension, &bytes, &Limits::default())
        });
        let document = result.expect("loader must contain malformed parser inputs");
        assert_ne!(document.completeness, Completeness::Complete, "{extension}");
        assert!(!document.reasons.is_empty());
    }
}

#[test]
fn decoder_panic_hook_child() {
    if std::env::var_os("BLOXGUARD_FAKE_DECODER_PANIC_CHILD").is_none() {
        return;
    }

    std::panic::set_hook(Box::new(|info| eprintln!("FAKE_PREVIOUS_HOOK: {info}")));
    let dom = WeakDom::new(
        InstanceBuilder::new("DataModel").with_child(
            InstanceBuilder::new("Animation")
                .with_property("AnimationContent", Content::from_uri("rbxassetid://0")),
        ),
    );
    let mut bytes = encode_binary_uncompressed(&dom);
    truncate_uncompressed_binary_property_tail(&mut bytes, "AnimationContent", 4);
    let document = load_bytes(
        "FAKE decoder panic.rbxm",
        "rbxm",
        &bytes,
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("decoder panicked on malformed input"))
    );

    let unrelated = std::thread::spawn(|| panic!("FAKE unrelated panic remains visible")).join();
    assert!(unrelated.is_err());
}

#[test]
fn decoder_panic_hook_suppresses_only_the_decoder_thread() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "decoder_panic_hook_child", "--nocapture"])
        .env("BLOXGUARD_FAKE_DECODER_PANIC_CHILD", "1")
        .output()
        .expect("run isolated panic-hook child test");
    assert!(
        output.status.success(),
        "child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.matches("FAKE_PREVIOUS_HOOK:").count(), 1, "{stderr}");
    assert!(stderr.contains("FAKE unrelated panic remains visible"));
    assert!(!stderr.contains("called `Result::unwrap()`"), "{stderr}");
}

#[test]
fn source_and_metadata_links_cannot_escape_the_scan_root() {
    let temp = temp_dir();
    let root = temp.path().join("FAKE link root");
    let package = root.join("Package");
    fs::create_dir_all(&package).unwrap();

    let outside_source = temp.path().join("FAKE outside init.luau");
    write(&outside_source, "return 999000000000004");
    if let Err(error) = symlink_file(&outside_source, &root.join("init.luau")) {
        eprintln!("skipping symlink regression because link creation is unavailable: {error}");
        return;
    }

    write(root.join("Safe.luau"), "return 1");
    let outside_meta = temp.path().join("FAKE outside meta.json");
    write(&outside_meta, br#"{"properties":{"Disabled":true}}"#);
    symlink_file(&outside_meta, &root.join("Safe.meta.json")).unwrap();

    write(package.join("init.luau"), "return 2");
    symlink_file(&outside_meta, &package.join("init.meta.json")).unwrap();

    let outside_directory = temp.path().join("FAKE outside directory");
    fs::create_dir_all(&outside_directory).unwrap();
    write(
        outside_directory.join("Escaped.server.luau"),
        "return 999000000000005",
    );
    if let Err(error) = symlink_dir(&outside_directory, &root.join("Linked")) {
        eprintln!("directory link creation unavailable: {error}");
    }

    let document = load_path(&root, &Limits::default()).pop().unwrap();
    assert_ne!(document.completeness, Completeness::Complete);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("symbolic link") || reason.contains("metadata link"))
    );
    assert!(document.instances.iter().all(|instance| {
        instance.source.as_deref() != Some("return 999000000000004")
            && instance.source.as_deref() != Some("return 999000000000005")
    }));
    let safe = document
        .instances
        .iter()
        .find(|instance| instance.name == "Safe")
        .unwrap();
    assert!(!safe.properties.contains_key("Disabled"));
    let package = document
        .instances
        .iter()
        .find(|instance| instance.name == "Package")
        .unwrap();
    assert!(package.properties.is_empty());
}

#[test]
fn binary_preflight_rejects_declared_decompression_bomb() {
    let mut bytes = encode_binary(&fake_dom());
    let first_chunk_decoded_length = 32 + 8;
    bytes[first_chunk_decoded_length..first_chunk_decoded_length + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    let document = load_bytes("FAKE bomb.rbxm", "rbxm", &bytes, &Limits::default());
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("decoded chunk bytes"))
    );
}

#[test]
fn binary_preflight_rejects_oom_shaped_header_and_string_lengths() {
    let valid = encode_binary_uncompressed(&fake_dom());

    let mut huge_type_count = valid.clone();
    huge_type_count[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    let result = std::panic::catch_unwind(|| {
        load_bytes(
            "FAKE huge types.rbxm",
            "rbxm",
            &huge_type_count,
            &Limits::default(),
        )
    });
    let document = result.expect("huge header count must not panic or allocate from the claim");
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("type count"))
    );

    let mut impossible_counts = valid.clone();
    impossible_counts[16..20].copy_from_slice(&2u32.to_le_bytes());
    impossible_counts[20..24].copy_from_slice(&1u32.to_le_bytes());
    let document = load_bytes(
        "FAKE impossible counts.rbxm",
        "rbxm",
        &impossible_counts,
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("exceeds its instance count"))
    );

    let mut huge_class_name = valid.clone();
    replace_binary_chunk_u32(&mut huge_class_name, b"INST", 4, u32::MAX);
    let document = load_bytes(
        "FAKE huge class.rbxm",
        "rbxm",
        &huge_class_name,
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("class-name length"))
    );

    let mut huge_property_name = valid;
    replace_binary_chunk_u32(&mut huge_property_name, b"PROP", 4, u32::MAX);
    let document = load_bytes(
        "FAKE huge property.rbxm",
        "rbxm",
        &huge_property_name,
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("property-name length"))
    );
}

#[test]
fn unknown_binary_and_xml_property_types_are_partial() {
    let mut binary = encode_binary_uncompressed(&fake_dom());
    replace_binary_property_type(&mut binary, "Source", 0x0f);
    let binary_document = load_bytes("FAKE unknown.rbxm", "rbxm", &binary, &Limits::default());
    assert_eq!(binary_document.completeness, Completeness::Partial);
    assert!(
        binary_document
            .reasons
            .iter()
            .any(|reason| reason.contains("unsupported value type 0x0f"))
    );

    // On a script class. The same type on a plain Folder is only a note, see
    // `unsupported_value_types_are_notes_only_where_nothing_can_hide`.
    let xml = br#"<roblox version="4"><Item class="Script" referent="FAKE1"><Properties><string name="Name">FAKE Script</string><ProtectedString name="Source"><![CDATA[return true]]></ProtectedString><FAKEFutureType name="Future">inert</FAKEFutureType></Properties></Item></roblox>"#;
    let xml_document = load_bytes("FAKE unknown.rbxmx", "rbxmx", xml, &Limits::default());
    assert_eq!(xml_document.completeness, Completeness::Partial);
    assert!(
        xml_document
            .reasons
            .iter()
            .any(|reason| reason.contains("FAKEFutureType"))
    );
}

/// Set the value type byte of `property` on `class` in an uncompressed binary
/// fixture.
fn set_binary_value_type(bytes: &mut [u8], class: &str, property: &str, value_type: u8) {
    let mut classes = std::collections::HashMap::new();
    let mut cursor = 32usize;
    while bytes.len().saturating_sub(cursor) >= 16 {
        let chunk: [u8; 4] = bytes[cursor..cursor + 4].try_into().unwrap();
        let compressed_len =
            u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        let decoded_len =
            u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
        assert_eq!(compressed_len, 0, "fixture must be uncompressed");
        let payload = cursor + 16;
        if &chunk == b"INST" || &chunk == b"PROP" {
            let type_id = u32::from_le_bytes(bytes[payload..payload + 4].try_into().unwrap());
            let name_len =
                u32::from_le_bytes(bytes[payload + 4..payload + 8].try_into().unwrap()) as usize;
            let name = bytes[payload + 8..payload + 8 + name_len].to_vec();
            if &chunk == b"INST" {
                classes.insert(type_id, name);
            } else if classes.get(&type_id).map(Vec::as_slice) == Some(class.as_bytes())
                && name == property.as_bytes()
            {
                bytes[payload + 8 + name_len] = value_type;
                return;
            }
        }
        cursor = payload + decoded_len;
    }
    panic!("{class}.{property} not found in synthetic binary fixture");
}

/// A binary place with a Terrain, a Folder holding a script, and `extra`.
fn place_with(extra: InstanceBuilder) -> WeakDom {
    WeakDom::new(
        InstanceBuilder::new("DataModel")
            .with_child(
                InstanceBuilder::new("Workspace").with_child(
                    InstanceBuilder::new("Terrain")
                        .with_name("Terrain")
                        .with_property("FAKE_VoxelMap", "FAKE inert"),
                ),
            )
            .with_child(
                InstanceBuilder::new("Folder")
                    .with_name("FAKE Folder")
                    .with_property("FAKE_GridMap", "FAKE inert")
                    .with_child(
                        InstanceBuilder::new("Script")
                            .with_name("FAKE Script")
                            .with_property("Source", FAKE_SOURCE),
                    )
                    .with_child(extra),
            ),
    )
}

fn notes(document: &bloxguard_core::model::Document) -> Vec<&str> {
    document
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect()
}

/// Current Studio writes value type 0x23, which the decoders do not know, on
/// `Terrain`. A skipped value is only a note when the class is known, cannot
/// hold code, and no rule reads the property; every other script of the file
/// is still read.
#[test]
fn unsupported_value_types_are_notes_only_where_nothing_can_hide() {
    let mut binary = encode_binary_uncompressed(&place_with(InstanceBuilder::new("Folder")));
    set_binary_value_type(&mut binary, "Terrain", "FAKE_VoxelMap", 0x23);
    set_binary_value_type(&mut binary, "Folder", "FAKE_GridMap", 0x23);
    let document = load_bytes("FAKE current.rbxl", "rbxl", &binary, &Limits::default());
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    let binary_notes = notes(&document);
    for (class, property) in [("Terrain", "FAKE_VoxelMap"), ("Folder", "FAKE_GridMap")] {
        assert!(
            binary_notes.contains(&format!(
                "binary property {property:?} of class {class:?} uses unsupported value type 0x23 and was skipped; no rule reads it and its class cannot hold code"
            ).as_str()),
            "{binary_notes:?}"
        );
    }
    let script = document
        .instances
        .iter()
        .find(|instance| instance.class == "Script")
        .expect("script");
    assert_eq!(script.source.as_deref(), Some(FAKE_SOURCE));

    let xml = br#"<roblox version="4">
        <Item class="Folder" referent="FAKE1"><Properties>
            <string name="Name">FAKE Folder</string>
            <FAKEFutureType name="Future">inert</FAKEFutureType>
        </Properties></Item>
        <Item class="Terrain" referent="FAKE2"><Properties>
            <string name="Name">Terrain</string>
            <FAKEFutureType name="FAKE_VoxelMap">inert</FAKEFutureType>
        </Properties></Item>
        <Item class="Script" referent="FAKE3"><Properties>
            <string name="Name">FAKE Script</string>
            <ProtectedString name="Source"><![CDATA[return true]]></ProtectedString>
        </Properties></Item>
    </roblox>"#;
    let document = load_bytes("FAKE current.rbxlx", "rbxlx", xml, &Limits::default());
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    assert_eq!(
        notes(&document),
        [
            "XML property \"Future\" of class \"Folder\" uses unsupported value type \"FAKEFutureType\" and was skipped; no rule reads it and its class cannot hold code",
            "XML property \"FAKE_VoxelMap\" of class \"Terrain\" uses unsupported value type \"FAKEFutureType\" and was skipped; no rule reads it and its class cannot hold code",
        ]
    );
    assert_eq!(document.instances[2].source.as_deref(), Some("return true"));
}

/// The same skipped value stays partial on a class that can hold code, on a
/// property a rule may read, and on a class the reflection database does not
/// know. A note in the same file does not hide it.
#[test]
fn unsupported_value_types_stay_partial_where_code_or_rule_inputs_can_hide() {
    let text = |class: &str, property: &str| {
        InstanceBuilder::new(class)
            .with_name("FAKE Target")
            .with_property(property, "FAKE inert")
    };
    let script = |class: &str| text(class, "FAKE_Flag").with_property("Source", FAKE_SOURCE);
    let cases = [
        (
            "Script",
            "FAKE_Flag",
            script("Script"),
            "its class can hold code",
        ),
        (
            "ModuleScript",
            "FAKE_Flag",
            script("ModuleScript"),
            "its class can hold code",
        ),
        (
            "Script",
            "Source",
            script("Script"),
            "its class can hold code",
        ),
        (
            "Folder",
            "Source",
            text("Folder", "Source"),
            "a rule may read this property",
        ),
        (
            "Folder",
            "LinkedSource",
            text("Folder", "LinkedSource"),
            "a rule may read this property",
        ),
        (
            "Folder",
            "Value",
            text("Folder", "Value"),
            "a rule may read this property",
        ),
        (
            "StringValue",
            "Value",
            text("StringValue", "Value"),
            "a rule may read this property",
        ),
        (
            "StringValue",
            "FAKE_Flag",
            text("StringValue", "FAKE_Flag"),
            "a rule may read this property",
        ),
        (
            "TextLabel",
            "Text",
            text("TextLabel", "Text"),
            "a rule may read this property",
        ),
        (
            "Folder",
            "FAKE_ToolTipText",
            text("Folder", "FAKE_ToolTipText"),
            "a rule may read this property",
        ),
        (
            "Folder",
            "PackageAssetId",
            text("Folder", "PackageAssetId"),
            "a rule may read this property",
        ),
        (
            "Folder",
            "PackageFAKE_Future",
            text("Folder", "PackageFAKE_Future"),
            "a rule may read this property",
        ),
        (
            "PackageLink",
            "FAKE_Flag",
            text("PackageLink", "FAKE_Flag"),
            "a rule may read this property",
        ),
        (
            "Folder",
            "Disabled",
            text("Folder", "Disabled"),
            "a rule may read this property",
        ),
        (
            "Folder",
            "Name",
            text("Folder", "FAKE_Other"),
            "a rule may read this property",
        ),
        (
            "FAKEFutureClass",
            "FAKE_Flag",
            text("FAKEFutureClass", "FAKE_Flag"),
            "its class is not in the bundled reflection database",
        ),
    ];
    for (class, property, extra, risk) in cases {
        let mut binary = encode_binary_uncompressed(&place_with(extra));
        // The ordinary Terrain note must not hide the risky value.
        set_binary_value_type(&mut binary, "Terrain", "FAKE_VoxelMap", 0x23);
        set_binary_value_type(&mut binary, class, property, 0x23);
        let document = load_bytes("FAKE risky.rbxl", "rbxl", &binary, &Limits::default());
        let label = format!("binary {class}.{property}");
        assert_eq!(document.completeness, Completeness::Partial, "{label}");
        let expected = format!(
            "binary property {property:?} of class {class:?} uses unsupported value type 0x23 and was skipped; {risk}"
        );
        assert!(
            document.reasons.contains(&expected),
            "{label}: {:?}",
            document.reasons
        );
    }

    let xml_cases = [
        ("Script", "FAKE_Flag", "its class can hold code"),
        ("Folder", "Source", "a rule may read this property"),
        ("Folder", "Value", "a rule may read this property"),
        ("TextLabel", "Text", "a rule may read this property"),
        ("Folder", "LinkedSource", "a rule may read this property"),
        ("PackageLink", "PackageId", "a rule may read this property"),
        (
            "Folder",
            "AttributesSerialize",
            "a rule may read this property",
        ),
        ("Folder", "Attributes", "a rule may read this property"),
        ("Folder", "Tags", "a rule may read this property"),
        (
            "FAKEFutureClass",
            "FAKE_Flag",
            "its class is not in the bundled reflection database",
        ),
    ];
    for (class, property, risk) in xml_cases {
        // The harmless Folder value comes first with the same type name.
        let xml = format!(
            r#"<roblox version="4">
            <Item class="Folder" referent="FAKE1"><Properties>
                <string name="Name">FAKE Folder</string>
                <FAKEFutureType name="Future">inert</FAKEFutureType>
            </Properties></Item>
            <Item class="{class}" referent="FAKE2"><Properties>
                <string name="Name">FAKE Target</string>
                <FAKEFutureType name="{property}">inert</FAKEFutureType>
            </Properties></Item>
        </roblox>"#
        );
        let document = load_bytes(
            "FAKE risky.rbxmx",
            "rbxmx",
            xml.as_bytes(),
            &Limits::default(),
        );
        let label = format!("XML {class}.{property}");
        assert_eq!(document.completeness, Completeness::Partial, "{label}");
        let expected = format!(
            "XML property {property:?} of class {class:?} uses unsupported value type \"FAKEFutureType\" and was skipped; {risk}"
        );
        assert!(
            document.reasons.contains(&expected),
            "{label}: {:?}",
            document.reasons
        );
    }
}

/// An XML name with an entity reads differently once decoded, so it is not
/// trusted. Notes have their own cap, so many harmless values do not push a
/// risky one out of the report.
#[test]
fn unsupported_xml_values_with_entities_or_after_many_notes_stay_partial() {
    let entity = br#"<roblox version="4"><Item class="TextLabel" referent="FAKE1"><Properties>
        <string name="Name">FAKE Label</string>
        <FAKEFutureType name="Te&#120;t">inert</FAKEFutureType>
    </Properties></Item></roblox>"#;
    let document = load_bytes("FAKE entity.rbxmx", "rbxmx", entity, &Limits::default());
    assert_eq!(document.completeness, Completeness::Partial);
    assert_eq!(
        document.reasons,
        [
            "XML property uses unsupported value type \"FAKEFutureType\" and was skipped; its class or name could not be read"
        ]
    );

    // `Properties` that is not right inside an `Item` has no owner to judge.
    let wrapped = br#"<roblox version="4"><Item class="Folder" referent="FAKE1"><Properties>
        <string name="Name">FAKE Folder</string></Properties>
        <FAKEWrapper><Properties><FAKEFutureType name="FAKE_Flag">inert</FAKEFutureType></Properties></FAKEWrapper>
    </Item></roblox>"#;
    let document = load_bytes("FAKE wrapped.rbxmx", "rbxmx", wrapped, &Limits::default());
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.ends_with("its class or name could not be read")),
        "{:?}",
        document.reasons
    );

    let harmless: String = (0..40)
        .map(|index| format!("<FAKEFutureType name=\"FAKE_{index}\">inert</FAKEFutureType>"))
        .collect();
    let many = format!(
        r#"<roblox version="4"><Item class="Folder" referent="FAKE1"><Properties>
        <string name="Name">FAKE Folder</string>{harmless}</Properties></Item>
        <Item class="Folder" referent="FAKE2"><Properties>
        <string name="Name">FAKE Other</string><FAKEFutureType name="Source">inert</FAKEFutureType>
        </Properties></Item></roblox>"#
    );
    let document = load_bytes(
        "FAKE many.rbxmx",
        "rbxmx",
        many.as_bytes(),
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert_eq!(
        document.reasons,
        [
            "XML property \"Source\" of class \"Folder\" uses unsupported value type \"FAKEFutureType\" and was skipped; a rule may read this property"
        ]
    );
    assert_eq!(document.diagnostics.len(), 32);
}

/// The chunks of an uncompressed binary fixture, after its 32 byte header.
fn binary_chunks(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut cursor = 32usize;
    while bytes.len().saturating_sub(cursor) >= 16 {
        let compressed_len =
            u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        let decoded_len =
            u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
        assert_eq!(compressed_len, 0, "fixture must be uncompressed");
        chunks.push(bytes[cursor..cursor + 16 + decoded_len].to_vec());
        cursor += 16 + decoded_len;
    }
    chunks
}

/// The PROP chunk of an uncompressed binary fixture that names `property`.
fn prop_chunk_position(chunks: &[Vec<u8>], property: &str) -> usize {
    chunks
        .iter()
        .position(|chunk| {
            &chunk[..4] == b"PROP" && {
                let name_len = u32::from_le_bytes(chunk[20..24].try_into().unwrap()) as usize;
                &chunk[24..24 + name_len] == property.as_bytes()
            }
        })
        .unwrap_or_else(|| panic!("{property} not found"))
}

/// A binary file can repeat a property chunk. Skipped values are reported once
/// per value type, class and property, notes have their own cap of 32, and a
/// risky value after hundreds of harmless chunks still makes the input partial.
/// The binary preflight kept one note per chunk on `2536d7e`.
#[test]
fn repeated_binary_chunks_are_reported_once_and_never_hide_a_risky_one() {
    let dom = place_with(
        InstanceBuilder::new("Script")
            .with_name("FAKE Risky")
            .with_property("Source", FAKE_SOURCE)
            .with_property("FAKE_Flag", "FAKE inert"),
    );
    let mut binary = encode_binary_uncompressed(&dom);
    set_binary_value_type(&mut binary, "Terrain", "FAKE_VoxelMap", 0x23);
    set_binary_value_type(&mut binary, "Script", "FAKE_Flag", 0x23);
    let header = binary[..32].to_vec();
    let mut chunks = binary_chunks(&binary);
    let risky = chunks.remove(prop_chunk_position(&chunks, "FAKE_Flag"));
    let harmless = chunks[prop_chunk_position(&chunks, "FAKE_VoxelMap")].clone();
    let end = chunks.pop().expect("END chunk");
    assert_eq!(&end[..4], b"END\0");
    let risky_reason = "binary property \"FAKE_Flag\" of class \"Script\" uses unsupported value type 0x23 and was skipped; its class can hold code";

    for (label, extra, expected_notes) in [
        ("duplicates", vec![harmless.clone(); 500], 1),
        (
            "distinct names",
            (0..40)
                .map(|index| {
                    // Same length as `FAKE_VoxelMap`, so the chunk lengths hold.
                    let mut chunk = harmless.clone();
                    let name = format!("FAKE_VoxelM{index:02}");
                    chunk[24..24 + name.len()].copy_from_slice(name.as_bytes());
                    chunk
                })
                .collect(),
            32,
        ),
    ] {
        let mut file = header.clone();
        for chunk in chunks.iter().chain(&extra).chain([&risky, &end]) {
            file.extend(chunk);
        }
        let document = load_bytes("FAKE repeated.rbxl", "rbxl", &file, &Limits::default());
        assert_eq!(document.completeness, Completeness::Partial, "{label}");
        assert_eq!(
            document.reasons,
            [risky_reason],
            "{label}: {:?}",
            document.reasons
        );
        assert_eq!(document.diagnostics.len(), expected_notes, "{label}");
    }
}

/// A model file in a source tree keeps the scan complete, and its note names
/// the file.
#[test]
fn unsupported_value_note_in_a_nested_model_names_the_file() {
    let root = temp_dir();
    let mut binary = encode_binary_uncompressed(&place_with(InstanceBuilder::new("Folder")));
    set_binary_value_type(&mut binary, "Terrain", "FAKE_VoxelMap", 0x23);
    write(root.path().join("FAKE_map.rbxm"), &binary);
    write(root.path().join("FAKE_main.server.luau"), FAKE_SOURCE);
    let document = load_path(root.path(), &Limits::default()).remove(0);
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    let nested = root.path().join("FAKE_map.rbxm");
    let expected = format!(
        "{}: binary property \"FAKE_VoxelMap\" of class \"Terrain\" uses unsupported value type 0x23 and was skipped; no rule reads it and its class cannot hold code",
        nested.display()
    );
    assert!(
        notes(&document).contains(&expected.as_str()),
        "{:?}",
        notes(&document)
    );
}

fn xml_item(start_tag: &str, properties: &str) -> String {
    format!(
        r#"<roblox version="4">{start_tag}<Properties><string name="Name">FAKE Target</string>{properties}</Properties></Item></roblox>"#
    )
}

/// The XML checks read an `Item`'s attributes in order, as rbx_xml does. A
/// `class="..."` inside another attribute's value, in either quote kind, or in
/// an attribute whose name only ends in `class`, does not name the class: the
/// decoded Script is judged as a Script and a `ProtectedString` on a Part is
/// still found. Complete on `4820d4b` for the first shape (a decoded Script judged
/// as "Folder").
#[test]
fn xml_class_is_read_from_the_class_attribute_only() {
    let skipped = r#"<ProtectedString name="Source"><![CDATA[return true]]></ProtectedString><FAKEFutureType name="FAKE_Flag">inert</FAKEFutureType>"#;
    for start_tag in [
        r#"<Item referent='FAKE1 class="Folder"' class="Script">"#,
        r#"<Item referent="FAKE1 class='Folder'" class='Script'>"#,
        r#"<Item xclass="Folder" class="Script" referent="FAKE1">"#,
        r#"<Item referent="FAKE1" class = "Script">"#,
    ] {
        let xml = xml_item(start_tag, skipped);
        let document = load_bytes(
            "FAKE quoted.rbxmx",
            "rbxmx",
            xml.as_bytes(),
            &Limits::default(),
        );
        assert_eq!(document.completeness, Completeness::Partial, "{start_tag}");
        assert!(
            document.reasons.contains(
                &"XML property \"FAKE_Flag\" of class \"Script\" uses unsupported value type \"FAKEFutureType\" and was skipped; its class can hold code".to_owned()
            ),
            "{start_tag}: {:?}",
            document.reasons
        );
        assert!(document.diagnostics.is_empty(), "{start_tag}");
    }

    let protected =
        r#"<ProtectedString name="FAKE_Code"><![CDATA[return 999000000019201]]></ProtectedString>"#;
    for start_tag in [
        r#"<Item referent='FAKE1 class="Folder"' class="Part">"#,
        r#"<Item referent="FAKE1 class='Folder'" class='Part'>"#,
    ] {
        let xml = xml_item(start_tag, protected);
        let document = load_bytes(
            "FAKE quoted.rbxmx",
            "rbxmx",
            xml.as_bytes(),
            &Limits::default(),
        );
        assert_eq!(document.completeness, Completeness::Partial, "{start_tag}");
        assert!(
            document.reasons.iter().any(|reason| reason
                .contains("class \"Part\" has ProtectedString property \"FAKE_Code\"")),
            "{start_tag}: {:?}",
            document.reasons
        );
    }

    // Control: whitespace around `=` and single quotes still read as written,
    // so the ordinary Terrain value stays a note.
    let xml = xml_item(
        "<Item referent = 'FAKE1' class = 'Terrain'>",
        r#"<FAKEFutureType name = 'FAKE_VoxelMap'>inert</FAKEFutureType>"#,
    );
    let document = load_bytes(
        "FAKE spaced.rbxmx",
        "rbxmx",
        xml.as_bytes(),
        &Limits::default(),
    );
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    assert_eq!(
        notes(&document),
        [
            "XML property \"FAKE_VoxelMap\" of class \"Terrain\" uses unsupported value type \"FAKEFutureType\" and was skipped; no rule reads it and its class cannot hold code"
        ]
    );
}

/// rbx_xml compares element and attribute names without a namespace prefix and
/// keeps the last of two `class` attributes. A class or `ProtectedString` name the
/// preflight cannot pin down (given twice, or written with an entity) makes the
/// input partial, and a prefixed `Item` is still an `Item`. Guards the
/// conservative side of the in-order reading.
#[test]
fn xml_names_the_preflight_cannot_pin_down_stay_partial() {
    let protected =
        r#"<ProtectedString name="FAKE_Code"><![CDATA[return 999000000019202]]></ProtectedString>"#;
    let unreadable = "XML input has a ProtectedString whose Item class or name could not be read";
    for (label, xml) in [
        (
            "class given twice",
            format!(
                r#"<roblox version="4" xmlns:x="urn:FAKE"><Item class="Folder" x:class="Part" referent="FAKE1"><Properties><string name="Name">FAKE Target</string>{protected}</Properties></Item></roblox>"#
            ),
        ),
        (
            "class with an entity",
            xml_item(r#"<Item class="Pa&#114;t" referent="FAKE1">"#, protected),
        ),
        (
            "ProtectedString name with an entity",
            xml_item(
                r#"<Item class="Part" referent="FAKE1">"#,
                r#"<ProtectedString name="FAKE_C&#111;de"><![CDATA[return 999000000019203]]></ProtectedString>"#,
            ),
        ),
    ] {
        let document = load_bytes(
            "FAKE names.rbxmx",
            "rbxmx",
            xml.as_bytes(),
            &Limits::default(),
        );
        assert_eq!(document.completeness, Completeness::Partial, "{label}");
        assert!(
            document.reasons.contains(&unreadable.to_owned()),
            "{label}: {:?}",
            document.reasons
        );
    }

    let prefixed = format!(
        r#"<roblox version="4" xmlns:x="urn:FAKE"><x:Item class="Part" referent="FAKE1"><x:Properties><x:string name="Name">FAKE Target</x:string>{}</x:Properties></x:Item></roblox>"#,
        protected
            .replace("<ProtectedString", "<x:ProtectedString")
            .replace("</ProtectedString>", "</x:ProtectedString>")
    );
    let document = load_bytes(
        "FAKE prefixed.rbxmx",
        "rbxmx",
        prefixed.as_bytes(),
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason
                .contains("class \"Part\" has ProtectedString property \"FAKE_Code\"")),
        "{:?}",
        document.reasons
    );

    // Control: the header Studio writes, with its namespace attributes, stays
    // complete.
    let studio = r#"<roblox xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://www.roblox.com/roblox.xsd" version="4">
        <Item class="Script" referent="RBXFAKE1"><Properties>
            <string name="Name">FAKE Script</string>
            <ProtectedString name="Source"><![CDATA[return true]]></ProtectedString>
        </Properties></Item>
    </roblox>"#;
    let document = load_bytes(
        "FAKE studio.rbxmx",
        "rbxmx",
        studio.as_bytes(),
        &Limits::default(),
    );
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    assert!(document.diagnostics.is_empty());
}

#[test]
fn harmless_unknown_classes_are_informational_but_source_like_classes_are_partial() {
    let harmless = br#"<roblox version="4">
        <Item class="FAKEFutureWidget" referent="FAKE1"><Properties>
            <string name="Name">FAKE Future Widget</string>
        </Properties></Item>
        <Item class="Script" referent="FAKE2"><Properties>
            <string name="Name">FAKE Normal Script</string>
            <ProtectedString name="Source"><![CDATA[return true]]></ProtectedString>
        </Properties></Item>
    </roblox>"#;
    let document = load_bytes(
        "FAKE future place.rbxlx",
        "rbxlx",
        harmless,
        &Limits::default(),
    );
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    assert!(document.reasons.is_empty());
    assert_eq!(document.diagnostics.len(), 1);
    assert_eq!(document.diagnostics[0].instance, Some(0));
    assert!(
        document.diagnostics[0]
            .message
            .contains("unknown class \"FAKEFutureWidget\"")
    );
    assert_eq!(document.instances[1].source.as_deref(), Some("return true"));

    let source_like = br#"<roblox version="4">
        <Item class="FAKEFutureSourceContainer" referent="FAKE1"><Properties>
            <string name="Name">FAKE Future Source</string>
            <ProtectedString name="Source"><![CDATA[return true]]></ProtectedString>
        </Properties></Item>
    </roblox>"#;
    let document = load_bytes(
        "FAKE future source.rbxmx",
        "rbxmx",
        source_like,
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("unknown source-like class"))
    );

    let future_source_property = br#"<roblox version="4">
        <Item class="FAKEFutureWidget" referent="FAKE1"><Properties>
            <string name="Name">FAKE Future Source Property</string>
            <string name="SourceText">return true</string>
        </Properties></Item>
    </roblox>"#;
    let document = load_bytes(
        "FAKE future source property.rbxmx",
        "rbxmx",
        future_source_property,
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert_eq!(
        document.instances[0].properties.get("SourceText"),
        Some(&json!("return true"))
    );
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("unknown source-like class"))
    );
}

#[test]
fn unknown_value_classes_are_complete_only_when_value_is_readable() {
    let document = load_bundle(
        Bundle {
            schema_version: 1,
            instances: vec![Instance {
                name: "FAKE Future Value".into(),
                class: "FAKEFutureValue".into(),
                properties: [("Value".into(), json!(999000000000412_u64))].into(),
                ..Instance::default()
            }],
        },
        "FAKE readable future value",
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Complete);
    assert_eq!(
        document.instances[0].properties.get("Value"),
        Some(&json!(999000000000412_u64))
    );
    assert_eq!(document.diagnostics.len(), 1);

    let document = load_bundle(
        Bundle {
            schema_version: 1,
            instances: vec![Instance {
                name: "FAKE Unreadable Future Value".into(),
                class: "FAKEFutureValue".into(),
                properties: [("Value".into(), json!({ "opaque": true }))].into(),
                ..Instance::default()
            }],
        },
        "FAKE unreadable future value",
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("without a readable Value property"))
    );
}

#[test]
fn xml_preflight_rejects_pathological_item_nesting() {
    let mut xml = String::from("<roblox version=\"4\">");
    for index in 0..2_049 {
        xml.push_str(&format!(
            "<Item class=\"Folder\" referent=\"FAKE{index}\"><Properties>"
        ));
        xml.push_str("<string name=\"Name\">FAKE</string></Properties>");
    }
    for _ in 0..2_049 {
        xml.push_str("</Item>");
    }
    xml.push_str("</roblox>");
    let limits = Limits {
        max_instances: 3_000,
        ..Limits::default()
    };
    let document = load_bytes("FAKE deep.rbxmx", "rbxmx", xml.as_bytes(), &limits);
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("safe parser limit"))
    );
}

#[test]
fn source_tree_applies_rojo_names_metadata_and_nested_models() {
    let temp = temp_dir();
    let root = temp.path().join("FAKE source tree");
    let package = root.join("Package");
    fs::create_dir_all(&package).unwrap();
    write(root.join("Server.server.luau"), "return 1");
    write(root.join("Client.client.lua"), "return 2");
    write(root.join("Plugin.plugin.luau"), "return 3");
    write(root.join("Shared.luau"), "return 4");
    write(
        root.join("Server.meta.json"),
        br#"{"properties":{"Disabled":true},"attributes":{"FakeId":999000000000002}}"#,
    );
    write(package.join("init.luau"), "return 5");
    write(package.join("init.server.lua"), "return 6");
    write(
        package.join("init.meta.json"),
        br#"{"className":"ModuleScript","attributes":{"Kind":"FAKE"}}"#,
    );
    write(
        root.join("Tree.model.json"),
        br#"{"Name":"FAKE JSON","ClassName":"Folder","Children":[{"Name":"FAKE Value","ClassName":"NumberValue","Properties":{"Value":999000000000003}}]}"#,
    );
    write(root.join("Nested.rbxmx"), encode_xml(&fake_dom()));

    let document = load_path(&root, &Limits::default()).pop().unwrap();
    assert_eq!(
        document.completeness,
        Completeness::Partial,
        "init ambiguity should be visible"
    );
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("multiple init source"))
    );

    let by_name = |name: &str| {
        document
            .instances
            .iter()
            .find(|instance| instance.name == name)
            .unwrap()
    };
    assert_eq!(by_name("Server").class, "Script");
    assert_eq!(
        by_name("Server").properties.get("Disabled"),
        Some(&json!(true))
    );
    assert_eq!(by_name("Client").class, "LocalScript");
    assert_eq!(by_name("Shared").class, "ModuleScript");
    assert_eq!(by_name("Plugin").class, "Script");
    assert_eq!(
        by_name("Plugin").properties.get("RunContext"),
        Some(&json!("Plugin"))
    );
    assert_eq!(by_name("Package").class, "ModuleScript");
    assert_eq!(by_name("Package").source.as_deref(), Some("return 5"));
    assert_eq!(
        by_name("FAKE Value").properties.get("Value"),
        Some(&json!(999000000000003u64))
    );
    assert_eq!(by_name("FAKE Script").source.as_deref(), Some(FAKE_SOURCE));
}

#[test]
fn empty_source_tree_is_failed() {
    let temp = temp_dir();
    write(temp.path().join("README.txt"), "FAKE documentation only");
    let document = load_path(temp.path(), &Limits::default()).pop().unwrap();
    assert_eq!(document.completeness, Completeness::Failed);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("no supported"))
    );
}

#[test]
fn version_control_and_cache_directories_are_not_scanned() {
    let temp = temp_dir();
    write(temp.path().join("Safe.luau"), "return 1");
    for directory in [
        ".git",
        ".hg",
        ".svn",
        ".cargo-home",
        "target",
        "node_modules",
    ] {
        let path = temp.path().join(directory);
        fs::create_dir_all(&path).unwrap();
        write(
            path.join("FAKE ignored.server.luau"),
            "return 999000000000006",
        );
    }
    let document = load_path(temp.path(), &Limits::default()).pop().unwrap();
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    assert!(
        document
            .instances
            .iter()
            .any(|instance| instance.name == "Safe")
    );
    assert!(
        document
            .instances
            .iter()
            .all(|instance| instance.name != "FAKE ignored")
    );
}

#[test]
fn rojo_project_mapping_marks_direct_scan_partial() {
    let temp = temp_dir();
    write(
        temp.path().join("default.project.json"),
        br#"{"name":"FAKE"}"#,
    );
    write(temp.path().join("Safe.luau"), "return 1");
    let document = load_path(temp.path(), &Limits::default()).pop().unwrap();
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document
            .instances
            .iter()
            .any(|instance| instance.name == "Safe")
    );
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("Rojo project mapping"))
    );
}

#[test]
fn bundle_validates_parents_and_extracts_source_property() {
    let bundle = Bundle {
        schema_version: 1,
        instances: vec![
            Instance {
                name: "FAKE Root".into(),
                class: "Folder".into(),
                ..Instance::default()
            },
            Instance {
                name: "FAKE Script".into(),
                class: "Script".into(),
                parent: Some(0),
                properties: [("Source".into(), json!(FAKE_SOURCE))].into(),
                ..Instance::default()
            },
            Instance {
                name: "FAKE Invalid".into(),
                class: "Folder".into(),
                parent: Some(99),
                ..Instance::default()
            },
        ],
    };
    let document = load_bundle(bundle, "FAKE bundle", &Limits::default());
    assert_eq!(document.completeness, Completeness::Partial);
    assert_eq!(document.instances[1].source.as_deref(), Some(FAKE_SOURCE));
    assert!(!document.instances[1].properties.contains_key("Source"));
    assert_eq!(document.instances[2].parent, None);
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("parents must precede children"))
    );
}

#[test]
fn studio_snapshot_empty_arrays_load_and_preserve_attribute_ids() {
    let bundle: Bundle = serde_json::from_value(json!({
        "schema_version": 1,
        "instances": [
            {
                "name": "FAKE Model",
                "class": "Model",
                "properties": [],
                "attributes": { "FAKE_id": 999000000000228_u64 },
                "tags": []
            },
            {
                "name": "FAKE Loader",
                "class": "Script",
                "parent": 0,
                "properties": [],
                "attributes": [],
                "tags": [],
                "source": "require(script.Parent:GetAttribute(\"FAKE_id\"))"
            }
        ]
    }))
    .expect("Studio-shaped bundle should deserialize");

    let document = load_bundle(bundle, "FAKE Studio snapshot", &Limits::default());
    assert_eq!(document.completeness, Completeness::Complete);
    let report = engine::scan_documents(vec![document], &Default::default());
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "BG002"
            && finding
                .related_locations
                .iter()
                .any(|related| related.location.attribute.as_deref() == Some("FAKE_id"))
    }));
}

#[test]
fn bundle_maps_reject_nonempty_arrays() {
    let result = serde_json::from_value::<Bundle>(json!({
        "schema_version": 1,
        "instances": [{
            "name": "FAKE",
            "class": "Folder",
            "properties": ["not", "a", "map"]
        }]
    }));
    assert!(result.is_err());
}

#[test]
fn ten_thousand_deep_flat_bundle_is_iterative() {
    let mut instances = Vec::with_capacity(10_000);
    for index in 0usize..10_000 {
        instances.push(Instance {
            name: format!("FAKE {index}"),
            class: "Folder".into(),
            parent: index.checked_sub(1),
            ..Instance::default()
        });
    }
    let limits = Limits {
        max_instances: 10_001,
        max_depth: 1,
        ..Limits::default()
    };
    let document = load_bundle(
        Bundle {
            schema_version: 1,
            instances,
        },
        "FAKE deep bundle",
        &limits,
    );
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    assert_eq!(document.instances.len(), 10_000);
    assert!(document.path(9_999).ends_with("/FAKE\\u{20}9999"));
}

#[test]
fn ten_thousand_deep_generated_binary_is_iterative() {
    let mut dom = WeakDom::new(InstanceBuilder::new("DataModel"));
    let mut parent = dom.root_ref();
    for index in 0..10_000 {
        parent = dom.insert(
            parent,
            InstanceBuilder::new("Folder").with_name(format!("FAKE {index}")),
        );
    }
    let bytes = encode_binary(&dom);
    let limits = Limits {
        max_instances: 10_001,
        ..Limits::default()
    };
    let result = std::panic::catch_unwind(|| load_bytes("FAKE deep.rbxm", "rbxm", &bytes, &limits));
    let document = result.expect("deep binary must not panic");
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    assert_eq!(document.instances.len(), 10_000);
}

#[test]
fn unicode_spaces_long_paths_and_large_source_are_bounded() {
    let temp = temp_dir();
    let mut directory = temp.path().join("FAKE long path");
    for index in 0..10 {
        directory = directory.join(format!("FAKE segment {index:02} abcdefghijkl"));
    }
    fs::create_dir_all(&directory).unwrap();
    let source_path = directory.join("FAKE café with spaces.server.luau");
    write(&source_path, "return 1");
    let document = load_path(temp.path(), &Limits::default()).pop().unwrap();
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    assert!(document.instances.iter().any(|instance| {
        instance.name == "FAKE café with spaces" && instance.source.as_deref() == Some("return 1")
    }));

    let oversized = temp.path().join("FAKE oversized.luau");
    write(&oversized, "123456789");
    let limits = Limits {
        max_script_bytes: 8,
        ..Limits::default()
    };
    let document = load_path(&oversized, &limits).pop().unwrap();
    assert_eq!(document.completeness, Completeness::Partial);
    assert_eq!(document.instances.len(), 1);
    assert!(document.instances[0].source.is_none());
}

#[test]
fn non_string_bundle_source_is_partial() {
    let bundle = Bundle {
        schema_version: 1,
        instances: vec![Instance {
            name: "FAKE undecodable Source".into(),
            class: "Script".into(),
            properties: [("Source".into(), json!({ "bytes": [255, 254] }))].into(),
            ..Instance::default()
        }],
    };
    let document = load_bundle(bundle, "FAKE undecodable bundle", &Limits::default());
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(document.instances[0].source.is_none());
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains("no readable Source"))
    );
}

#[test]
fn direct_source_and_limits_report_incompleteness() {
    let limits = Limits {
        max_script_bytes: 4,
        ..Limits::default()
    };
    let document = load_source("return 1", "FAKE Source.luau", "ModuleScript", &limits);
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(document.instances[0].source.is_none());

    let unknown = load_source(
        "",
        "FAKE Source.luau",
        "FAKEUnknownClass",
        &Limits::default(),
    );
    assert_eq!(unknown.completeness, Completeness::Partial);
    assert!(
        unknown
            .reasons
            .iter()
            .any(|reason| reason.contains("unknown source-like class"))
    );
}

#[test]
fn unsupported_explicit_file_is_partial() {
    let temp = temp_dir();
    let path: PathBuf = temp.path().join("FAKE.txt");
    write(&path, "FAKE");
    let document = load_path(&path, &Limits::default()).pop().unwrap();
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(document.instances.is_empty());
}
