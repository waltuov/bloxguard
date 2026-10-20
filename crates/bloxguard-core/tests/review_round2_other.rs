//! Review round 2 (fix round 3) items 4, 9 and 10 that live outside the
//! analysis module. Every fixture is synthetic: FAKE names, IDs in the reserved
//! 999000000000000 range and inert text. Nothing here executes Luau.

use bloxguard_core::config::Config;
use bloxguard_core::engine::scan_documents;
use bloxguard_core::finding::{Confidence, Finding, Severity};
use bloxguard_core::loading::{load_bundle, load_bytes};
use bloxguard_core::model::{Bundle, Completeness, Document, Instance, Limits};
use rbx_dom_weak::{
    InstanceBuilder, WeakDom,
    types::{Content, ContentId},
};
use serde_json::{Value, json};

fn scan(document: Document) -> bloxguard_core::report::ScanReport {
    scan_documents(vec![document], &Config::default())
}

fn rule_findings<'a>(
    report: &'a bloxguard_core::report::ScanReport,
    rule: &str,
) -> Vec<&'a Finding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule)
        .collect()
}

fn bundle(instances: Vec<Instance>, label: &str) -> Document {
    load_bundle(
        Bundle {
            schema_version: 1,
            instances,
        },
        label,
        &Limits::default(),
    )
}

fn instance(name: &str, class: &str, parent: Option<usize>) -> Instance {
    Instance {
        name: name.into(),
        class: class.into(),
        parent,
        ..Instance::default()
    }
}

fn with_property(mut instance: Instance, name: &str, value: Value) -> Instance {
    instance.properties.insert(name.into(), value);
    instance
}

fn model_dom(child: InstanceBuilder) -> WeakDom {
    WeakDom::new(
        InstanceBuilder::new("DataModel").with_child(
            InstanceBuilder::new("Model")
                .with_name("FAKE_Model")
                .with_child(child),
        ),
    )
}

fn encode_rbxm(dom: &WeakDom) -> Vec<u8> {
    let mut bytes = Vec::new();
    rbx_binary::to_writer(&mut bytes, dom, dom.root().children()).expect("encode synthetic rbxm");
    bytes
}

fn encode_rbxmx(dom: &WeakDom) -> Vec<u8> {
    let mut bytes = Vec::new();
    rbx_xml::to_writer_default(&mut bytes, dom, dom.root().children())
        .expect("encode synthetic rbxmx");
    bytes
}

/// Studio style XML with one PackageLink property written by hand, so the test
/// covers serialized names that the encoders above never emit.
fn package_link_xml(property: &str) -> Vec<u8> {
    format!(
        r#"<roblox version="4">
  <Item class="Model" referent="FAKE0">
    <Properties><string name="Name">FAKE_PackageRoot</string></Properties>
    <Item class="PackageLink" referent="FAKE1">
      <Properties>
        <string name="Name">PackageLink</string>
        <bool name="AutoUpdate">true</bool>
        {property}
      </Properties>
    </Item>
  </Item>
</roblox>"#
    )
    .into_bytes()
}

// Item 4: BG011 on .rbxm and .rbxmx files.

#[test]
fn round2_04_package_links_in_files_and_bundles_report_bg011() {
    let external: Vec<(&str, Document)> = vec![
        (
            "rbxm PackageId",
            load_bytes(
                "FAKE_package.rbxm",
                "rbxm",
                &encode_rbxm(&model_dom(
                    InstanceBuilder::new("PackageLink").with_property(
                        "PackageId",
                        ContentId::from("rbxassetid://999000000000501"),
                    ),
                )),
                &Limits::default(),
            ),
        ),
        (
            "rbxm PackageContent",
            load_bytes(
                "FAKE_package.rbxm",
                "rbxm",
                &encode_rbxm(&model_dom(
                    InstanceBuilder::new("PackageLink").with_property(
                        "PackageContent",
                        Content::from_uri("rbxassetid://999000000000502"),
                    ),
                )),
                &Limits::default(),
            ),
        ),
        (
            "rbxmx PackageId",
            load_bytes(
                "FAKE_package.rbxmx",
                "rbxmx",
                &encode_rbxmx(&model_dom(
                    InstanceBuilder::new("PackageLink").with_property(
                        "PackageId",
                        ContentId::from("rbxassetid://999000000000503"),
                    ),
                )),
                &Limits::default(),
            ),
        ),
        (
            "rbxmx legacy PackageIdSerialize url",
            load_bytes(
                "FAKE_package.rbxmx",
                "rbxmx",
                &package_link_xml(
                    r#"<Content name="PackageIdSerialize"><url>rbxassetid://999000000000504</url></Content>"#,
                ),
                &Limits::default(),
            ),
        ),
        (
            "rbxmx PackageContentSerialize uri",
            load_bytes(
                "FAKE_package.rbxmx",
                "rbxmx",
                &package_link_xml(
                    r#"<Content name="PackageContentSerialize"><uri>rbxassetid://999000000000505</uri></Content>"#,
                ),
                &Limits::default(),
            ),
        ),
        (
            "bundle raw PackageIdSerialize",
            bundle(
                vec![with_property(
                    instance("PackageLink", "PackageLink", None),
                    "PackageIdSerialize",
                    json!("rbxassetid://999000000000506"),
                )],
                "FAKE package bundle",
            ),
        ),
        (
            "bundle with both spellings",
            bundle(
                vec![with_property(
                    with_property(
                        instance("PackageLink", "PackageLink", None),
                        "PackageIdSerialize",
                        json!("rbxassetid://999000000000507"),
                    ),
                    "PackageContent",
                    json!("rbxassetid://999000000000507"),
                )],
                "FAKE package bundle both",
            ),
        ),
    ];
    for (label, document) in external {
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{label}: {:?}",
            document.reasons
        );
        let report = scan(document);
        assert_eq!(report.completeness, Completeness::Complete, "{label}");
        let findings = rule_findings(&report, "BG011");
        assert_eq!(findings.len(), 1, "{label}: {:?}", report.findings);
        let finding = findings[0];
        assert_eq!(finding.severity, Severity::Medium, "{label}");
        assert_eq!(finding.confidence, Confidence::Medium, "{label}");
        assert!(
            finding.evidence.contains("rbxassetid://99900000000050"),
            "{label}: {}",
            finding.evidence
        );
        assert!(
            finding
                .location
                .property
                .as_deref()
                .is_some_and(|property| property.starts_with("Package")),
            "{label}: {:?}",
            finding.location
        );
        assert!(finding.instance_path.ends_with("/PackageLink"), "{label}");
    }
}

#[test]
fn round2_04_empty_package_links_stay_complete_and_quiet() {
    let clean: Vec<(&str, Document)> = vec![
        (
            "rbxm empty Content",
            load_bytes(
                "FAKE_draft.rbxm",
                "rbxm",
                &encode_rbxm(&model_dom(
                    InstanceBuilder::new("PackageLink")
                        .with_property("PackageContent", Content::none()),
                )),
                &Limits::default(),
            ),
        ),
        (
            "rbxmx empty Content",
            load_bytes(
                "FAKE_draft.rbxmx",
                "rbxmx",
                &encode_rbxmx(&model_dom(
                    InstanceBuilder::new("PackageLink")
                        .with_property("PackageContent", Content::none()),
                )),
                &Limits::default(),
            ),
        ),
        (
            "rbxmx null PackageIdSerialize",
            load_bytes(
                "FAKE_draft.rbxmx",
                "rbxmx",
                &package_link_xml(r#"<Content name="PackageIdSerialize"><null></null></Content>"#),
                &Limits::default(),
            ),
        ),
        (
            "bundle zero asset",
            bundle(
                vec![with_property(
                    instance("PackageLink", "PackageLink", None),
                    "PackageIdSerialize",
                    json!("rbxassetid://0"),
                )],
                "FAKE zero package",
            ),
        ),
        (
            "bundle bare scheme",
            bundle(
                vec![with_property(
                    instance("PackageLink", "PackageLink", None),
                    "PackageContent",
                    json!("rbxassetid://"),
                )],
                "FAKE bare package",
            ),
        ),
    ];
    for (label, document) in clean {
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{label}: {:?}",
            document.reasons
        );
        let report = scan(document);
        assert!(
            rule_findings(&report, "BG011").is_empty(),
            "{label}: {:?}",
            report.findings
        );
    }
}

#[test]
fn round2_04_bg011_page_confidence_matches_the_rule_and_findings() {
    let page = include_str!("../../../docs/rules/BG011.md");
    let rule = bloxguard_core::rules::rule("BG011").expect("BG011 metadata");
    assert_eq!(rule.confidence, Confidence::Medium);
    assert_eq!(rule.default_severity, Severity::Medium);
    assert!(
        page.contains("Default severity: medium. Default confidence: medium."),
        "BG011.md must state the confidence the code emits"
    );
}

// Item 9: BG012 reads shown text, names and string attributes.

fn script(name: &str, parent: Option<usize>, source: &str) -> Instance {
    Instance {
        name: name.into(),
        class: "Script".into(),
        parent,
        source: Some(source.into()),
        ..Instance::default()
    }
}

fn with_attribute(mut instance: Instance, name: &str, value: Value) -> Instance {
    instance.attributes.insert(name.into(), value);
    instance
}

fn gui_text(class: &str, property: &str, text: &str) -> Vec<Instance> {
    vec![
        instance("FAKE_Model", "Model", None),
        instance("FAKE_Gui", "SurfaceGui", Some(0)),
        with_property(
            instance("FAKE_Label", class, Some(1)),
            property,
            json!(text),
        ),
    ]
}

fn bg012(report: &bloxguard_core::report::ScanReport) -> Vec<&Finding> {
    rule_findings(report, "BG012")
}

/// Label, instances, expected property location and expected attribute location.
type TextCase = (
    &'static str,
    Vec<Instance>,
    Option<&'static str>,
    Option<&'static str>,
);

#[test]
fn round2_09_bg012_reads_text_properties_attributes_names_and_cmd_bar() {
    let cases: Vec<TextCase> = vec![
        (
            "TextLabel Text",
            gui_text(
                "TextLabel",
                "Text",
                "Paste this into the command bar to repair the FAKE model",
            ),
            Some("Text"),
            None,
        ),
        (
            "TextButton cmd bar",
            gui_text(
                "TextButton",
                "Text",
                "Run this in the cmd bar: require(999000000000601)",
            ),
            Some("Text"),
            None,
        ),
        (
            "TextBox placeholder with hyphenated surface",
            gui_text(
                "TextBox",
                "PlaceholderText",
                "Open the Command-Bar and paste the following FAKE setup line",
            ),
            Some("PlaceholderText"),
            None,
        ),
        (
            "ProximityPrompt action text",
            gui_text("ProximityPrompt", "ActionText", "copy this into the CMDBAR"),
            Some("ActionText"),
            None,
        ),
        (
            "Model string attribute",
            vec![with_attribute(
                instance("FAKE_Model", "Model", None),
                "FAKE_Setup",
                json!("To enable lighting, type workspace.FAKE_Enable() in the dev console"),
            )],
            None,
            Some("FAKE_Setup"),
        ),
        (
            "Script string attribute",
            vec![with_attribute(
                script("FAKE_Script", None, "return true"),
                "FAKE_Note",
                json!("Execute the following in the command bar: game:GetService('FAKE')"),
            )],
            None,
            Some("FAKE_Note"),
        ),
        (
            "instance name",
            vec![instance(
                "READ ME paste this in the command bar",
                "Folder",
                None,
            )],
            Some("Name"),
            None,
        ),
        (
            "fullwidth and Cyrillic look-alike letters",
            gui_text(
                "TextLabel",
                "Text",
                "\u{ff30}\u{ff41}\u{ff53}\u{ff54}\u{ff45} this into the \u{0441}ommand bar",
            ),
            Some("Text"),
            None,
        ),
        (
            "zero width and combining marks inside the surface",
            gui_text(
                "TextLabel",
                "Text",
                "Run this in the com\u{200b}mand ba\u{0301}r: script.Parent:Destroy()",
            ),
            Some("Text"),
            None,
        ),
    ];
    for (label, instances, property, attribute) in cases {
        let document = bundle(instances, label);
        assert_eq!(document.completeness, Completeness::Complete, "{label}");
        let report = scan(document);
        let findings = bg012(&report);
        assert_eq!(findings.len(), 1, "{label}: {:?}", report.findings);
        assert_eq!(findings[0].severity, Severity::High, "{label}");
        assert_eq!(findings[0].confidence, Confidence::High, "{label}");
        assert_eq!(
            findings[0].location.property.as_deref(),
            property,
            "{label}"
        );
        assert_eq!(
            findings[0].location.attribute.as_deref(),
            attribute,
            "{label}"
        );
        assert_eq!(findings[0].location.line, None, "{label}");
    }
}

#[test]
fn round2_09_bg012_source_text_matches_cmd_bar_and_folded_surfaces() {
    for (label, source, confidence) in [
        (
            "string with cmd bar",
            "local FAKE_tip = 'Type this into the cmd bar to finish FAKE setup'",
            Confidence::High,
        ),
        (
            "comment with dev console and code",
            "-- running workspace.FAKE:Destroy() from the dev console fixes it\nreturn true",
            Confidence::Medium,
        ),
        (
            "string with fullwidth surface",
            "local FAKE_tip = 'copy this into the \u{ff43}\u{ff4d}\u{ff44} bar'",
            Confidence::High,
        ),
    ] {
        let report = scan(bundle(vec![script("FAKE_Script", None, source)], label));
        let findings = bg012(&report);
        assert_eq!(findings.len(), 1, "{label}: {:?}", report.findings);
        assert_eq!(findings[0].confidence, confidence, "{label}");
    }
}

#[test]
fn round2_09_bg012_ordinary_interface_text_stays_quiet() {
    let cases: Vec<(&str, Vec<Instance>)> = vec![
        (
            "description of the command bar",
            gui_text(
                "TextLabel",
                "Text",
                "The command bar runs Luau during development.",
            ),
        ),
        (
            "chat hint",
            gui_text("TextBox", "PlaceholderText", "Press Enter to chat"),
        ),
        (
            "disabled notice",
            gui_text(
                "TextLabel",
                "Text",
                "The cmd bar is disabled in this FAKE game.",
            ),
        ),
        (
            "developer console mention without code",
            gui_text(
                "TextLabel",
                "Text",
                "Run the game to see the developer console output.",
            ),
        ),
        (
            "attribute named cmd",
            vec![with_attribute(
                instance("FAKE_Model", "Model", None),
                "cmd",
                json!("Open the FAKE menu"),
            )],
        ),
        (
            "compound name",
            vec![instance("CommandBarHelp", "Folder", None)],
        ),
        (
            "rich text flag shares the Text suffix",
            vec![with_property(
                instance("FAKE_Label", "TextLabel", None),
                "RichText",
                json!(true),
            )],
        ),
    ];
    for (label, instances) in cases {
        let document = bundle(instances, label);
        assert_eq!(document.completeness, Completeness::Complete, "{label}");
        let report = scan(document);
        assert!(bg012(&report).is_empty(), "{label}: {:?}", report.findings);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.severity < Severity::High),
            "{label}: {:?}",
            report.findings
        );
    }
}

#[test]
fn round2_09_bg012_text_and_attributes_survive_file_loading() {
    let dom = WeakDom::new(
        InstanceBuilder::new("DataModel").with_child(
            InstanceBuilder::new("Model")
                .with_name("FAKE_Model")
                .with_child(
                    InstanceBuilder::new("SurfaceGui").with_child(
                        InstanceBuilder::new("TextLabel")
                            .with_name("FAKE_Label")
                            .with_property(
                                "Text",
                                "Paste this into the command bar: require(999000000000602)",
                            )
                            .with_property("RichText", true),
                    ),
                )
                .with_child(
                    InstanceBuilder::new("Configuration")
                        .with_name("FAKE_Config")
                        .with_property("Attributes", {
                            let mut attributes = rbx_dom_weak::types::Attributes::new();
                            attributes.insert(
                                "FAKE_Help".into(),
                                "Run this in the cmd bar: game.Workspace.FAKE:Destroy()".into(),
                            );
                            attributes
                        }),
                ),
        ),
    );
    for (extension, bytes) in [("rbxm", encode_rbxm(&dom)), ("rbxmx", encode_rbxmx(&dom))] {
        let document = load_bytes(
            &format!("FAKE_text.{extension}"),
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
        let report = scan(document);
        let mut locations = bg012(&report)
            .iter()
            .map(|finding| {
                (
                    finding.instance_path.clone(),
                    finding.location.property.clone(),
                    finding.location.attribute.clone(),
                )
            })
            .collect::<Vec<_>>();
        locations.sort();
        assert_eq!(
            locations,
            vec![
                (
                    "/FAKE_Model/FAKE_Config".to_owned(),
                    None,
                    Some("FAKE_Help".to_owned())
                ),
                (
                    "/FAKE_Model/SurfaceGui/FAKE_Label".to_owned(),
                    Some("Text".to_owned()),
                    None
                ),
            ],
            "{extension}"
        );
    }
}

// Item 9: BG006 folds names before comparing them with core names.

fn bg006_for_name(name: &str) -> usize {
    let report = scan(bundle(
        vec![
            instance("FAKE_Model", "Model", None),
            script(name, Some(0), "return true"),
        ],
        "FAKE BG006 name",
    ));
    rule_findings(&report, "BG006").len()
}

#[test]
fn round2_09_bg006_folds_combining_fullwidth_and_lookalike_names() {
    for name in [
        // Fullwidth letters.
        "\u{ff37}\u{ff4f}\u{ff52}\u{ff4b}\u{ff53}\u{ff50}\u{ff41}\u{ff43}\u{ff45}",
        // Combining marks after ASCII letters.
        "Workspace\u{0301}",
        "Wo\u{0308}rkspace",
        "Pla\u{0323}yers",
        // Precomposed accents.
        "W\u{00f6}rkspace",
        "Repl\u{00ed}catedStorage",
        // Mathematical bold letters.
        "\u{1d416}\u{1d428}\u{1d42b}\u{1d424}\u{1d42c}\u{1d429}\u{1d41a}\u{1d41c}\u{1d41e}",
        // Mixed fullwidth and Cyrillic.
        "\u{ff2c}ightin\u{0261}",
        // ASCII look-alikes and padding.
        "P1ayers",
        "W0rkspace",
        "ServerScriptServlce",
        "Lighting ",
        "\u{3000}StarterGui",
        // Roman numeral and letterlike symbols.
        "\u{216c}ighting",
        "Workspac\u{212f}",
    ] {
        assert_eq!(bg006_for_name(name), 1, "{name:?}");
    }
}

#[test]
fn round2_09_bg006_distinct_names_with_unicode_stay_quiet() {
    for name in [
        "Caf\u{00e9}\u{5de5}\u{5177}",
        "\u{ff26}\u{ff41}\u{ff4b}\u{ff45}_Loader",
        "W\u{00f6}rkshop",
        "Players2",
        "Lighting_Controller",
        "Pl\u{0430}yers_FAKE",
        "Workspace\u{4e2d}",
        "FAKE_Loader\u{0301}",
    ] {
        assert_eq!(bg006_for_name(name), 0, "{name:?}");
    }
}

// Item 9: evidence escapes only control, bidirectional and invisible format
// characters.

fn evidence_of(text: &str) -> String {
    Finding::new(
        "BG001",
        Severity::High,
        Confidence::High,
        "FAKE_input",
        "/FAKE",
        bloxguard_core::finding::Location::default(),
        "FAKE message",
        text,
    )
    .evidence
}

#[test]
fn round2_09_evidence_reads_like_source() {
    for (raw, expected) in [
        (r#"WaitForChild("Packages")"#, r#"WaitForChild("Packages")"#),
        ("print('FAKE')", "print('FAKE')"),
        (r#"print("a\n\\b")"#, r#"print("a\n\\b")"#),
        (
            "local s = \"Caf\u{e9} \u{4e2d}\u{6587} \u{1f642}\"",
            "local s = \"Caf\u{e9} \u{4e2d}\u{6587} \u{1f642}\"",
        ),
        ("a\nb\tc\rd", r"a\nb\tc\rd"),
        ("FAKE\u{1b}[31m", r"FAKE\u{1b}[31m"),
        (
            "bell\u{7}nul\u{0}del\u{7f}c1\u{85}",
            r"bell\u{7}nul\u{0}del\u{7f}c1\u{85}",
        ),
        ("abc\u{202e}cba", r"abc\u{202e}cba"),
        ("isolate\u{2066}x\u{2069}", r"isolate\u{2066}x\u{2069}"),
        ("rtl\u{200f}mark\u{61c}", r"rtl\u{200f}mark\u{61c}"),
        ("requ\u{200b}ire\u{feff}", r"requ\u{200b}ire\u{feff}"),
        ("line\u{2028}break", r"line\u{2028}break"),
        ("tag\u{e0041}", r"tag\u{e0041}"),
    ] {
        assert_eq!(evidence_of(raw), expected, "{raw:?}");
    }
}

#[test]
fn round2_09_evidence_never_carries_raw_controls_and_never_splits_an_escape() {
    let ranges = [
        0u32..0x3000,
        0xfe00..0x10000,
        0x1_f000..0x1_f100,
        0xe_0000..0xe_0100,
    ];
    for code in ranges.into_iter().flatten() {
        let Some(character) = char::from_u32(code) else {
            continue;
        };
        let rendered = evidence_of(&format!("x{character}y"));
        assert!(
            !rendered.chars().any(|c| c.is_control()
                || matches!(c, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')),
            "U+{code:04X} rendered as {rendered:?}"
        );
        assert!(
            rendered.starts_with('x') && rendered.ends_with('y'),
            "U+{code:04X}"
        );
    }

    // Length limits: 180 characters, 300 bytes, a marker when cut, and an escape
    // either whole or absent.
    assert_eq!(evidence_of(&"a".repeat(180)), "a".repeat(180));
    assert_eq!(
        evidence_of(&"a".repeat(181)),
        format!("{}...", "a".repeat(180))
    );
    let wide = evidence_of(&"\u{e9}".repeat(200));
    assert!(wide.ends_with("...") && wide.len() <= 303, "{}", wide.len());
    // Three-byte characters push an escape across the 300 byte limit.
    for wide_prefix in 94..101 {
        let rendered = evidence_of(&format!("{}\u{1b}", "\u{4e2d}".repeat(wide_prefix)));
        let body = rendered.trim_end_matches("...");
        assert!(body.len() <= 300, "{wide_prefix}: {}", body.len());
        if wide_prefix * 3 + 6 <= 300 {
            assert!(body.ends_with(r"\u{1b}"), "{wide_prefix}: {rendered:?}");
        } else {
            assert!(!body.contains('\\'), "split escape: {rendered:?}");
            assert!(rendered.ends_with("..."), "{wide_prefix}");
        }
    }
    let near_limit = evidence_of(&format!("{}\u{202e}tail", "\u{4e2d}".repeat(98)));
    let body = near_limit.trim_end_matches("...");
    assert!(
        !body.contains('\\') || body.contains(r"\u{202e}"),
        "split escape: {near_limit:?}"
    );
    assert!(near_limit.len() <= 303);
}

#[test]
fn round2_09_evidence_rendering_does_not_change_fingerprints() {
    let quoted = Finding::new(
        "BG001",
        Severity::High,
        Confidence::High,
        "FAKE_input",
        "/FAKE",
        bloxguard_core::finding::Location::default(),
        "FAKE message",
        r#"require(game:GetService("ReplicatedStorage"):WaitForChild("FAKE"))"#,
    );
    // The fingerprint hashes rule, path and whitespace-normalized raw evidence,
    // so the rendering change cannot invalidate an existing baseline entry.
    let mut identity = Vec::new();
    for component in [
        "BG001",
        "/FAKE",
        r#"require(game:GetService("ReplicatedStorage"):WaitForChild("FAKE"))"#,
    ] {
        identity.extend_from_slice(&(component.len() as u64).to_le_bytes());
        identity.extend_from_slice(component.as_bytes());
    }
    assert_eq!(quoted.fingerprint, bloxguard_core::model::sha256(&identity));
}

// Item 9: a class the scanner does not analyze must not hide code and stay
// complete.

fn xml_item(class: &str, properties: &str) -> Vec<u8> {
    format!(
        r#"<roblox version="4">
  <Item class="{class}" referent="FAKE1">
    <Properties>
      <string name="Name">FAKE_{class}</string>
      {properties}
    </Properties>
  </Item>
</roblox>"#
    )
    .into_bytes()
}

fn assert_partial_mentions(label: &str, document: &Document, property: &str) {
    assert_eq!(
        document.completeness,
        Completeness::Partial,
        "{label}: {:?}",
        document.reasons
    );
    assert!(
        document
            .reasons
            .iter()
            .any(|reason| reason.contains(&format!("{property:?}"))
                && (reason.contains("not scanned") || reason.contains("not analyzed"))),
        "{label}: {:?}",
        document.reasons
    );
    // The scan report keeps the input partial, so CI cannot mistake it for clean.
    assert_eq!(
        scan(document.clone()).completeness,
        Completeness::Partial,
        "{label}"
    );
}

#[test]
fn round2_09_code_carrying_properties_on_unanalyzed_classes_are_partial() {
    let limits = Limits::default();
    let xml_cases = [
        (
            "unknown class ProtectedString with code",
            xml_item(
                "FAKEFutureRunner",
                r#"<ProtectedString name="Body"><![CDATA[require(999000000000701)]]></ProtectedString>"#,
            ),
            "Body",
        ),
        (
            "unknown class ProtectedString that is not valid Luau",
            xml_item(
                "FAKEFutureRunner",
                r#"<ProtectedString name="Code">FAKE @@ not luau @@</ProtectedString>"#,
            ),
            "Code",
        ),
        (
            "unknown class plain string that parses as Luau",
            xml_item(
                "FAKEFutureRunner",
                r#"<string name="Payload">local FAKE = require(999000000000703)</string>"#,
            ),
            "Payload",
        ),
        (
            "known non-script class with a ProtectedString",
            xml_item(
                "Folder",
                r#"<ProtectedString name="Body"><![CDATA[return 999000000000704]]></ProtectedString>"#,
            ),
            "Body",
        ),
        (
            "known script-like class the analyzer skips",
            xml_item(
                "CoreScript",
                r#"<ProtectedString name="Source"><![CDATA[require(999000000000705)]]></ProtectedString>"#,
            ),
            "Source",
        ),
    ];
    for (label, bytes, property) in xml_cases {
        let document = load_bytes("FAKE_future.rbxmx", "rbxmx", &bytes, &limits);
        assert_partial_mentions(label, &document, property);
    }

    let binary_dom = model_dom(
        InstanceBuilder::new("FAKEFutureRunner")
            .with_name("FAKE_Runner")
            .with_property("Body", "game:GetService('FAKE'):Run()"),
    );
    let document = load_bytes(
        "FAKE_future.rbxm",
        "rbxm",
        &encode_rbxm(&binary_dom),
        &limits,
    );
    assert_partial_mentions("binary unknown class string", &document, "Body");

    let bundle_cases = [
        (
            "bundle plain code string",
            with_property(
                instance("FAKE_Runner", "FAKEFutureRunner", None),
                "Body",
                json!("local FAKE = require(999000000000706)"),
            ),
            "Body",
        ),
        (
            "bundle typed ProtectedString on unknown class",
            with_property(
                instance("FAKE_Runner", "FAKEFutureRunner", None),
                "Code",
                json!({"ProtectedString": "FAKE text"}),
            ),
            "Code",
        ),
        (
            "bundle typed ProtectedString on known class",
            with_property(
                instance("FAKE_Folder", "Folder", None),
                "Body",
                json!({"ProtectedString": "return 999000000000707"}),
            ),
            "Body",
        ),
        (
            "bundle typed String code",
            with_property(
                instance("FAKE_Runner", "FAKEFutureRunner", None),
                "Script",
                json!({"String": "print('FAKE')"}),
            ),
            "Script",
        ),
    ];
    for (label, item, property) in bundle_cases {
        let document = bundle(vec![item], label);
        assert_partial_mentions(label, &document, property);
    }

    let temp = tempfile::Builder::new()
        .prefix("bloxguard_FAKE_round2_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory");
    std::fs::write(temp.path().join("Main.server.luau"), "return true").unwrap();
    std::fs::write(
        temp.path().join("FAKE_Runner.model.json"),
        r#"{"ClassName":"FAKEFutureRunner","Properties":{"Body":"require(999000000000708)"}}"#,
    )
    .unwrap();
    let document = bloxguard_core::loading::load_path(temp.path(), &limits)
        .pop()
        .unwrap();
    assert_partial_mentions("model.json unknown class", &document, "Body");
}

#[test]
fn round2_09_harmless_unknown_classes_stay_complete_with_a_note() {
    let limits = Limits::default();
    let xml_cases = [
        (
            "empty ProtectedString",
            xml_item(
                "FAKEFutureWidget",
                r#"<ProtectedString name="Body"></ProtectedString>"#,
            ),
        ),
        (
            "whitespace CDATA ProtectedString",
            xml_item(
                "FAKEFutureWidget",
                r#"<ProtectedString name="Body"><![CDATA[   ]]></ProtectedString>"#,
            ),
        ),
        (
            "plain label",
            xml_item(
                "FAKEFutureWidget",
                r#"<string name="Label">Press E to open</string>"#,
            ),
        ),
        (
            "apostrophe text",
            xml_item(
                "FAKEFutureWidget",
                r#"<string name="Hint">Don't (really) panic</string>"#,
            ),
        ),
    ];
    for (label, bytes) in xml_cases {
        let document = load_bytes("FAKE_future.rbxmx", "rbxmx", &bytes, &limits);
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{label}: {:?}",
            document.reasons
        );
        assert_eq!(document.diagnostics.len(), 1, "{label}");
    }

    for (label, item) in [
        (
            "quoted shown text",
            with_property(
                instance("FAKE_Widget", "FAKEFutureWidget", None),
                "Text",
                json!("Press \"E\""),
            ),
        ),
        (
            "JSON text",
            with_property(
                instance("FAKE_Widget", "FAKEFutureWidget", None),
                "Config",
                json!("{\"FAKE\": 1}"),
            ),
        ),
        (
            "single word",
            with_property(
                instance("FAKE_Widget", "FAKEFutureWidget", None),
                "Mode",
                json!("FAKE"),
            ),
        ),
        (
            "comment only",
            with_property(
                instance("FAKE_Widget", "FAKEFutureWidget", None),
                "Notes",
                json!("-- FAKE (note) = nothing"),
            ),
        ),
    ] {
        let document = bundle(vec![item], label);
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{label}: {:?}",
            document.reasons
        );
        assert_eq!(document.diagnostics.len(), 1, "{label}");
    }

    let normal_script = xml_item(
        "Script",
        r#"<ProtectedString name="Source"><![CDATA[return true]]></ProtectedString>"#,
    );
    let document = load_bytes("FAKE_script.rbxmx", "rbxmx", &normal_script, &limits);
    assert_eq!(document.completeness, Completeness::Complete);
    assert!(document.diagnostics.is_empty());
}

#[test]
fn round2_09_protected_string_preflight_stays_linear_on_hostile_markup() {
    // Thousands of ProtectedString elements closed by the wrong tag and
    // without content must not make the preflight scan ahead repeatedly.
    let mut properties = String::new();
    for _ in 0..20_000 {
        properties.push_str(r#"<ProtectedString name="FAKE"></x>"#);
    }
    let bytes = xml_item("FAKEFutureWidget", &properties);
    let started = std::time::Instant::now();
    let document = load_bytes("FAKE_hostile.rbxmx", "rbxmx", &bytes, &Limits::default());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_ne!(document.completeness, Completeness::Complete);
}

// Item 9: a Rojo project file is a note unless it maps content the direct scan
// cannot see.

/// The shape `rojo init` creates, plus Wally packages, tool files and a
/// workflow. Everything is synthetic.
const ROJO_PLACE_PROJECT: &str = r#"{
  "name": "FAKE_place",
  "tree": {
    "$className": "DataModel",
    "ReplicatedStorage": {
      "Shared": { "$path": "src/shared" },
      "Packages": { "$path": "Packages" }
    },
    "ServerScriptService": { "Server": { "$path": "src/server" } },
    "StarterPlayer": {
      "StarterPlayerScripts": { "Client": { "$path": "src/client" } }
    },
    "Workspace": {
      "$properties": { "FilteringEnabled": true },
      "Baseplate": {
        "$className": "Part",
        "$properties": {
          "Anchored": true,
          "Color": [0.38823, 0.37254, 0.38823],
          "Locked": true,
          "Position": [0, -10, 0],
          "Size": [512, 20, 512]
        }
      }
    },
    "Lighting": { "$properties": { "Ambient": [0, 0, 0], "Brightness": 2 } },
    "SoundService": { "$properties": { "RespectFilteringEnabled": true } }
  }
}"#;

fn write_tree(root: &std::path::Path, files: &[(&str, &str)]) {
    for (relative, contents) in files {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}

fn rojo_repo(project: &str) -> tempfile::TempDir {
    let temp = tempfile::Builder::new()
        .prefix("bloxguard_FAKE_rojo_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory");
    write_tree(
        temp.path(),
        &[
            ("default.project.json", project),
            ("src/server/init.server.luau", "print('FAKE server')"),
            ("src/client/Main.client.luau", "print('FAKE client')"),
            (
                "src/shared/FAKE_Util.luau",
                "local Packages = game:GetService('ReplicatedStorage'):WaitForChild('Packages')\nlocal Promise = require(Packages.Promise)\nreturn Promise",
            ),
            (
                "Packages/_Index/fake_promise@4.0.0/promise/default.project.json",
                r#"{"name":"promise","tree":{"$path":"lib"}}"#,
            ),
            (
                "Packages/_Index/fake_promise@4.0.0/promise/lib/init.lua",
                "return {}",
            ),
            (
                "Packages/Promise.lua",
                "return require(script.Parent._Index['fake_promise@4.0.0']['promise'])",
            ),
            ("wally.toml", "[package]\nname = 'fake/place'\n"),
            ("aftman.toml", "[tools]\n"),
            ("selene.toml", "std = 'roblox'\n"),
            ("README.md", "# FAKE place\n"),
            (".github/workflows/ci.yml", "name: FAKE\n"),
        ],
    );
    temp
}

fn load_tree(path: &std::path::Path) -> Document {
    bloxguard_core::loading::load_path(path, &Limits::default())
        .pop()
        .expect("one document")
}

#[test]
fn round2_09_typical_rojo_repository_root_is_complete_with_a_note() {
    let repo = rojo_repo(ROJO_PLACE_PROJECT);
    let document = load_tree(repo.path());
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    let notes: Vec<_> = document
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect();
    assert!(
        notes
            .iter()
            .any(|note| note.contains("Rojo project mapping")
                && note.contains("and 1 other project file")
                && note.contains("rojo build")),
        "{notes:?}"
    );
    let report = scan(document);
    assert_eq!(report.completeness, Completeness::Complete);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.severity < Severity::High),
        "{:?}",
        report.findings
    );

    // JSONC comments and trailing commas, and Packages not installed yet.
    let jsonc = r#"{
      // FAKE comment
      "name": "FAKE_place",
      "tree": {
        "$className": "DataModel",
        /* FAKE block */
        "ReplicatedStorage": { "Packages": { "$path": { "optional": "FAKE_NotInstalled" } }, },
        "ServerScriptService": { "Server": { "$path": "src/server" } },
      },
    }"#;
    let repo = rojo_repo(jsonc);
    std::fs::rename(
        repo.path().join("default.project.json"),
        repo.path().join("default.project.jsonc"),
    )
    .unwrap();
    let document = load_tree(repo.path());
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    assert!(
        document
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("does not exist")),
        "{:?}",
        document.diagnostics
    );
}

#[test]
fn round2_09_rojo_projects_that_hide_content_keep_the_scan_partial() {
    let outside = tempfile::Builder::new()
        .prefix("bloxguard_FAKE_outside_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory");
    write_tree(outside.path(), &[("FAKE_Shared.luau", "return true")]);
    let absolute_outside = outside.path().to_string_lossy().replace('\\', "/");
    let cases = [
        (
            "parent folder",
            r#"{"name":"FAKE","tree":{"Shared":{"$path":"../FAKE_shared"}}}"#.to_owned(),
            "outside the scanned tree",
        ),
        (
            "absolute folder",
            format!(r#"{{"name":"FAKE","tree":{{"Shared":{{"$path":"{absolute_outside}"}}}}}}"#),
            "outside the scanned tree",
        ),
        (
            "excluded folder",
            r#"{"name":"FAKE","tree":{"Deps":{"$path":"node_modules/@fake"}}}"#.to_owned(),
            "exclude",
        ),
        (
            "inline source",
            r#"{"name":"FAKE","tree":{"ServerScriptService":{"FAKE_Inline":{"$className":"Script","$properties":{"Source":"require(999000000000801)"}}}}}"#.to_owned(),
            "sets Source inline",
        ),
        (
            "inline value object",
            r#"{"name":"FAKE","tree":{"FAKE_Id":{"$className":"NumberValue","$properties":{"Value":999000000000802}}}}"#.to_owned(),
            "sets Value inline",
        ),
        (
            "inline attributes",
            r#"{"name":"FAKE","tree":{"FAKE_Model":{"$className":"Model","$attributes":{"FAKE_asset":999000000000803}}}}"#.to_owned(),
            "attributes inline",
        ),
        (
            "inline shown text",
            r#"{"name":"FAKE","tree":{"FAKE_Label":{"$className":"TextLabel","$properties":{"Text":"FAKE"}}}}"#.to_owned(),
            "sets Text inline",
        ),
        (
            "malformed JSON",
            r#"{"name":"FAKE","tree":"#.to_owned(),
            "could not be checked",
        ),
        (
            "no tree",
            r#"{"name":"FAKE"}"#.to_owned(),
            "no tree object",
        ),
    ];
    for (label, project, reason) in cases {
        let repo = rojo_repo(&project);
        std::fs::create_dir_all(repo.path().join("node_modules/@fake")).unwrap();
        let document = load_tree(repo.path());
        assert_eq!(
            document.completeness,
            Completeness::Partial,
            "{label}: {:?}",
            document.reasons
        );
        assert!(
            document.reasons.iter().any(|item| item.contains(reason)),
            "{label}: {:?}",
            document.reasons
        );
    }
}

/// A project that maps `node_modules` before `npm install` (react-lua, RbxUtil,
/// reflex and Nevermore in the clean corpus) has nothing there to scan, so the
/// scan stays complete with the same note as any other missing path. Once the
/// folder exists, the content the direct scan skips makes the input partial.
#[test]
fn corpus_dependency_folder_not_installed_is_a_note() {
    for mapped in ["node_modules/@rbxts", "node_modules", "../node_modules"] {
        let project = format!(r#"{{"name":"FAKE","tree":{{"Deps":{{"$path":"{mapped}"}}}}}}"#);
        let repo = rojo_repo(&project);
        if mapped.starts_with("..") {
            // Keep the project below the root so `..` stays inside the tree.
            std::fs::create_dir_all(repo.path().join("sub")).unwrap();
            std::fs::rename(
                repo.path().join("default.project.json"),
                repo.path().join("sub/default.project.json"),
            )
            .unwrap();
        }
        let document = load_tree(repo.path());
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{mapped}: {:?}",
            document.reasons
        );
        assert!(
            document
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("does not exist")),
            "{mapped}: {:?}",
            document.diagnostics
        );

        let installed = if mapped.starts_with("..") {
            repo.path().join("node_modules")
        } else {
            repo.path().join(mapped)
        };
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(installed.join("FAKE_dep.lua"), "return {}").unwrap();
        let document = load_tree(repo.path());
        assert_eq!(
            document.completeness,
            Completeness::Partial,
            "{mapped} installed: {:?}",
            document.reasons
        );
        assert!(
            document
                .reasons
                .iter()
                .any(|item| item.contains("direct scans exclude")),
            "{mapped} installed: {:?}",
            document.reasons
        );
    }
}
