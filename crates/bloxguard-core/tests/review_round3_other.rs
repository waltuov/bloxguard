//! Review round 3 (fix round 4) items 11 to 14, which live outside the analysis
//! module. Every fixture is synthetic: FAKE names, IDs in the reserved
//! 999000000000000 range and inert text. Nothing here executes Luau.

use bloxguard_core::config::Config;
use bloxguard_core::engine::scan_documents;
use bloxguard_core::loading::load_bytes;
use bloxguard_core::model::{
    Completeness, Document, DomIndex, Instance, Limits, MAX_INSTANCE_PATH_BYTES, escape_name,
    escaped_name_len,
};

/// Small deterministic generator, so every run tries the same shapes.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

fn instance(name: &str, class: &str, parent: Option<usize>) -> Instance {
    Instance {
        name: name.into(),
        class: class.into(),
        parent,
        ..Instance::default()
    }
}

fn script(name: &str, parent: Option<usize>, source: &str) -> Instance {
    Instance {
        source: Some(source.into()),
        ..instance(name, "ModuleScript", parent)
    }
}

// ---------------------------------------------------------------------------
// Item 11: instance paths are built in one pass, with the same text as before.
// The reference tests guard that text and pass on the old code by design; the
// path work budget test is the one that fails without the fix.
// ---------------------------------------------------------------------------

/// The path algorithm before round 4, kept as the reference for its output.
fn reference_escape_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '/' && c != '\\' {
                c.to_string()
            } else {
                format!("\\u{{{:x}}}", c as u32)
            }
        })
        .collect()
}

fn reference_path(document: &Document, id: usize) -> String {
    let mut segments = Vec::new();
    let mut current = Some(id);
    let mut path_bytes = 0usize;
    for _ in 0..=document.instances.len() {
        let Some(index) = current else { break };
        let Some(node) = document.instances.get(index) else {
            segments.push("<invalid-parent>".to_owned());
            break;
        };
        if node.name.len().saturating_add(path_bytes) > MAX_INSTANCE_PATH_BYTES {
            return format!("/<path-limit>/instance-{id}");
        }
        let escaped = reference_escape_name(&node.name);
        path_bytes = path_bytes.saturating_add(escaped.len()).saturating_add(1);
        if path_bytes > MAX_INSTANCE_PATH_BYTES {
            return format!("/<path-limit>/instance-{id}");
        }
        segments.push(escaped);
        current = node.parent;
    }
    if current.is_some() {
        segments.push("<cycle>".to_owned());
    }
    segments.reverse();
    format!("/{}", segments.join("/"))
}

const NAME_PIECES: &[&str] = &[
    "",
    "a",
    "Part",
    "FAKE_Script",
    "a/b",
    "a\\b",
    " ",
    "\t",
    "\0",
    "\u{7f}",
    "\u{1f}",
    "é",
    "日本語",
    "\u{202e}",
    "\u{200b}",
    "\u{feff}",
    "\u{10ffff}",
    "😀",
    "~!@#$%^&*()",
    "\u{301}",
    "Ｗｏｒｋｓｐａｃｅ",
];

fn generated_name(rng: &mut Lcg) -> String {
    (0..rng.below(4))
        .map(|_| NAME_PIECES[rng.below(NAME_PIECES.len())])
        .collect()
}

#[test]
fn item11_escaping_matches_the_reference_for_generated_names() {
    let mut rng = Lcg(11);
    let mut names: Vec<String> = NAME_PIECES
        .iter()
        .map(|piece| (*piece).to_owned())
        .collect();
    names.extend((0..2_000).map(|_| generated_name(&mut rng)));
    // Every code point class near the escape boundary.
    names.extend(
        [
            0u32, 0x9, 0x20, 0x21, 0x2f, 0x5c, 0x7e, 0x7f, 0x80, 0xff, 0x100, 0xfff,
        ]
        .into_iter()
        .chain([0x1000, 0xffff, 0x10000, 0xfffff, 0x100000, 0x10ffff])
        .filter_map(char::from_u32)
        .map(String::from),
    );
    for name in &names {
        let expected = reference_escape_name(name);
        assert_eq!(escape_name(name), expected, "{name:?}");
        assert_eq!(escaped_name_len(name), expected.len(), "{name:?}");
    }
}

#[test]
fn item11_paths_match_the_reference_on_generated_trees_cycles_and_bad_parents() {
    let mut rng = Lcg(1_100);
    for round in 0..60 {
        let count = 1 + rng.below(80);
        let mut document = Document {
            input: format!("FAKE_tree_{round}"),
            ..Document::default()
        };
        for id in 0..count {
            let parent = match rng.below(10) {
                0 => None,
                _ if id == 0 => None,
                _ => Some(rng.below(id)),
            };
            document
                .instances
                .push(instance(&generated_name(&mut rng), "Folder", parent));
        }
        // Loaders never produce these, but the path must stay bounded and identical.
        if round % 3 == 1 {
            let at = rng.below(count);
            document.instances[at].parent = Some(rng.below(count));
        }
        if round % 5 == 2 {
            let at = rng.below(count);
            document.instances[at].parent = Some(count + rng.below(5));
        }
        let index = DomIndex::new(&document);
        let ordered = document
            .instances
            .iter()
            .enumerate()
            .all(|(id, node)| node.parent.is_none_or(|parent| parent < id));
        for id in 0..count + 2 {
            let path = document.path(id);
            assert_eq!(path, reference_path(&document, id), "round {round} id {id}");
            if ordered && id < count {
                assert_eq!(index.path_bytes(id), path.len(), "round {round} id {id}");
            }
        }
    }
}

#[test]
fn item11_path_limit_boundary_is_unchanged() {
    for (root_bytes, child, limited) in [
        (MAX_INSTANCE_PATH_BYTES - 1, None, false),
        (MAX_INSTANCE_PATH_BYTES, None, true),
        (MAX_INSTANCE_PATH_BYTES - 3, Some("a"), false),
        (MAX_INSTANCE_PATH_BYTES - 2, Some("a"), true),
        // One escaped character is six bytes in the path.
        (MAX_INSTANCE_PATH_BYTES - 8, Some(" "), false),
        (MAX_INSTANCE_PATH_BYTES - 7, Some(" "), true),
    ] {
        let mut document = Document::default();
        document
            .instances
            .push(instance(&"x".repeat(root_bytes), "Folder", None));
        if let Some(name) = child {
            document.instances.push(instance(name, "Folder", Some(0)));
        }
        let id = document.instances.len() - 1;
        let path = document.path(id);
        assert_eq!(path, reference_path(&document, id));
        assert_eq!(path.starts_with("/<path-limit>/"), limited, "{root_bytes}");
        if !limited {
            assert_eq!(path.len(), DomIndex::new(&document).path_bytes(id));
        }
    }
}

/// A model with `levels` ModuleScripts, each one inside the previous one.
fn script_chain(levels: usize) -> Document {
    let mut instances = vec![instance("FAKE_Root", "Model", None)];
    for level in 0..levels {
        let parent = instances.len() - 1;
        instances.push(script(&format!("M{level}"), Some(parent), "return 1"));
    }
    Document {
        input: "FAKE_chain.rbxm".into(),
        instances,
        ..Document::default()
    }
}

#[test]
fn item11_path_work_over_the_budget_is_partial_with_a_reason_instead_of_slow() {
    // A 500 KB root name makes every script path about 500 KB, so 2,500 levels
    // need about 1.25 GB of path text: over the 1 GiB analysis path budget.
    // Before round 4 this ran into the 30 second time budget.
    // The path budget must stop the scan on any machine, so the time budget is
    // raised well above what slow CI runners need for a debug build.
    let mut document = script_chain(2_500);
    document.instances[0].name = format!("FAKE_{}", "x".repeat(500_000));
    let mut config = Config::default();
    config.limits.max_file_ms = 600_000;
    let started = std::time::Instant::now();
    let report = scan_documents(vec![document], &config);
    let reasons = &report.inputs[0].reasons;
    assert_eq!(report.completeness, Completeness::Partial);
    assert!(
        reasons
            .iter()
            .any(|reason| reason
                == "instance path work limit reached; deeply nested scripts unexamined"),
        "{reasons:?}"
    );
    assert!(
        reasons.iter().all(|reason| !reason.contains("time budget")),
        "{reasons:?} after {:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// Item 12: the XML cap counts nested Item elements, as the docs say.
// ---------------------------------------------------------------------------

const ITEM_REASON: &str =
    "XML Item nesting exceeds the safe parser limit of 2048 nested Item elements";

/// `items` nested Item elements. The deepest level holds a TextLabel with a
/// structured `Font` value (three elements below `Properties`) and a Script.
fn xml_item_chain(items: usize) -> Vec<u8> {
    let mut xml = String::from(r#"<roblox version="4">"#);
    for level in 0..items - 1 {
        xml.push_str(&format!(
            r#"<Item class="Folder" referent="RBXF{level}"><Properties><string name="Name">F{level}</string></Properties>"#
        ));
    }
    xml.push_str(concat!(
        r#"<Item class="TextLabel" referent="RBXL"><Properties><string name="Name">FAKE_Label</string>"#,
        r#"<Font name="FontFace"><Family><url>rbxasset://fonts/families/FAKE.json</url></Family>"#,
        r#"<Weight>400</Weight><Style>Normal</Style></Font></Properties></Item>"#,
        r#"<Item class="Script" referent="RBXS"><Properties><string name="Name">FAKE_Deep</string>"#,
        r#"<ProtectedString name="Source"><![CDATA[require(999000000004120)]]></ProtectedString>"#,
        r#"</Properties></Item>"#,
    ));
    xml.push_str(&"</Item>".repeat(items - 1));
    xml.push_str("</roblox>");
    xml.into_bytes()
}

#[test]
fn item12_xml_accepts_exactly_2048_nested_items_including_structured_values() {
    for (items, accepted) in [
        (1, true),
        (2, true),
        (2_000, true),
        (2_045, true),
        (2_046, true),
        (2_047, true),
        (2_048, true),
        (2_049, false),
        (2_050, false),
        (4_096, false),
    ] {
        let document = load_bytes(
            "FAKE_deep.rbxmx",
            "rbxmx",
            &xml_item_chain(items),
            &Limits::default(),
        );
        if accepted {
            assert_eq!(
                document.completeness,
                Completeness::Complete,
                "{items}: {:?}",
                document.reasons
            );
            // The deepest level was decoded and the script there is analyzed.
            assert_eq!(document.instances.len(), items + 1, "{items}");
            let report = scan_documents(vec![document], &Config::default());
            assert_eq!(report.completeness, Completeness::Complete, "{items}");
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == "BG001"
                        && finding.instance_path.ends_with("/FAKE_Deep")),
                "{items}"
            );
        } else {
            assert_eq!(document.completeness, Completeness::Partial, "{items}");
            assert_eq!(document.reasons, [ITEM_REASON], "{items}");
            assert!(document.instances.is_empty(), "{items}");
        }
    }
}

#[test]
fn item12_review_d01_and_a50_shapes_follow_the_documented_cap() {
    // D01: a Script inside 2,047 or 2,048 Folders.
    for (folders, accepted) in [(2_047, true), (2_048, false)] {
        let mut xml = String::from(r#"<roblox version="4">"#);
        for level in 0..folders {
            xml.push_str(&format!(
                r#"<Item class="Folder" referent="RBX{level}"><Properties><string name="Name">F{level}</string></Properties>"#
            ));
        }
        xml.push_str(r#"<Item class="Script" referent="RBXS"><Properties><string name="Name">FAKE_S</string><ProtectedString name="Source"><![CDATA[return true]]></ProtectedString></Properties></Item>"#);
        xml.push_str(&"</Item>".repeat(folders));
        xml.push_str("</roblox>");
        let document = load_bytes(
            "FAKE_D01.rbxmx",
            "rbxmx",
            xml.as_bytes(),
            &Limits::default(),
        );
        let expected = if accepted {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        assert_eq!(
            document.completeness, expected,
            "{folders}: {:?}",
            document.reasons
        );
    }
    // A50: 2,047 levels with a ModuleScript beside every Folder.
    let mut deep = String::from(
        r#"<Item class="Script" referent="RBXD"><Properties><string name="Name">FAKE_DeepScript</string><ProtectedString name="Source"><![CDATA[return true]]></ProtectedString></Properties></Item>"#,
    );
    for level in 0..2_047 {
        deep = format!(
            r#"<Item class="Folder" referent="RBXF{level}"><Properties><string name="Name">FAKE_L{level}</string></Properties>{deep}<Item class="ModuleScript" referent="RBXM{level}"><Properties><string name="Name">FAKE_M{level}</string><ProtectedString name="Source"><![CDATA[return {level}]]></ProtectedString></Properties></Item></Item>"#
        );
    }
    let xml = format!(r#"<roblox version="4">{deep}</roblox>"#);
    let document = load_bytes(
        "FAKE_A50.rbxmx",
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
    let report = scan_documents(vec![document], &Config::default());
    assert_eq!(report.inputs[0].script_count, 2_048);
    assert_eq!(
        report.completeness,
        Completeness::Complete,
        "{:?}",
        report.inputs[0].reasons
    );
}

#[test]
fn item12_other_xml_markup_nesting_stays_bounded() {
    // Markup nested inside one property value, and between the roblox root and an Item.
    let inside_value = format!(
        r#"<roblox version="4"><Item class="Folder" referent="RBX0"><Properties><string name="Name">F</string><Font name="FontFace">{}{}</Font></Properties></Item></roblox>"#,
        "<Family>".repeat(3_000),
        "</Family>".repeat(3_000)
    );
    let around_items = format!(
        r#"<roblox version="4">{}<Item class="Folder" referent="RBX0"><Properties><string name="Name">F</string></Properties></Item>{}</roblox>"#,
        "<FAKE_Wrapper>".repeat(2_100),
        "</FAKE_Wrapper>".repeat(2_100)
    );
    for (label, xml) in [
        ("inside a value", inside_value),
        ("around items", around_items),
    ] {
        let document = load_bytes("FAKE.rbxmx", "rbxmx", xml.as_bytes(), &Limits::default());
        assert_eq!(document.completeness, Completeness::Partial, "{label}");
        assert_eq!(
            document.reasons,
            ["XML element nesting exceeds the safe parser limit 2064"],
            "{label}"
        );
    }
}

// ---------------------------------------------------------------------------
// Item 13: BG005 measures \u{...} escapes and needs a real dispatch loop.
// ---------------------------------------------------------------------------

fn bg005_evidence(source: &str) -> Vec<String> {
    let document = Document {
        input: "FAKE_bg005.luau".into(),
        instances: vec![Instance {
            source_file: Some("FAKE_bg005.luau".into()),
            ..script("FAKE_Script", None, source)
        }],
        ..Document::default()
    };
    bloxguard_core::heuristics::analyze(&document, &Limits::default())
        .findings
        .into_iter()
        .filter(|finding| finding.rule_id == "BG005")
        .map(|finding| finding.evidence)
        .collect()
}

#[test]
fn item13_escapes_are_measured_by_their_real_length_in_generated_literals() {
    let escapes = [
        r"\065",
        r"\65",
        r"\6",
        r"\x41",
        r"\X4a",
        r"\u{41}",
        r"\u{3042}",
        r"\u{10FFFF}",
    ];
    let mut checked = 0;
    for escape in escapes {
        for count in [11, 12, 40] {
            for plain in 0..=2 {
                for filler in ["", r"\z   ", "\\z\n\t "] {
                    let unit = format!("{escape}{}{filler}", "a".repeat(plain));
                    let source =
                        format!("local FAKE_s = \"{}\"\nreturn FAKE_s", unit.repeat(count));
                    // At most one other byte per escape, or at most five source
                    // bytes per escape counted the old way.
                    let expected = count >= 12
                        && (plain <= 1 || (filler.is_empty() && escape.len() + plain <= 5));
                    let evidence = bg005_evidence(&source);
                    assert_eq!(
                        !evidence.is_empty(),
                        expected,
                        "{escape} x{count} plain {plain} filler {filler:?}: {evidence:?}"
                    );
                    if expected {
                        assert!(
                            evidence[0].starts_with(&format!(
                                "dense escaped string literal ({count} encoded"
                            )),
                            "{evidence:?}"
                        );
                    }
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 216);
}

#[test]
fn item13_review_unicode_escape_shapes_report_bg005() {
    // A15 and C68 from the round 3 review.
    let a15 = format!(
        "local s = \"{}\"\nreturn s\n",
        r"\u{10FFFF}\z   \u{41}".repeat(2_000)
    );
    let c68 = format!(
        "local s = \"{}\"\nreturn s\n",
        (0..400)
            .map(|index| format!("\\u{{{:x}}}", 0x100 + index * 17 % 0x1f00))
            .collect::<String>()
    );
    for source in [a15, c68] {
        let evidence = bg005_evidence(&source);
        assert_eq!(evidence.len(), 1, "{evidence:?}");
        assert!(evidence[0].starts_with("dense escaped string literal"));
    }
    // Text with a few escapes, and escaped quotes or backslashes, stays quiet.
    for source in [
        r#"local s = "Press \u{2318} or \u{2303} then 日本語のテキスト \u{1F600} to continue"; return s"#,
        r#"local s = "\\1\\2\\3\\4\\5\\6\\7\\8\\9\\1\\2\\3\\4"; return s"#,
        r#"local s = "\"\n\t\"\n\t\"\n\t\"\n\t\"\n\t\"\n\t\"\n\t"; return s"#,
    ] {
        assert!(bg005_evidence(source).is_empty(), "{source}");
    }
}

/// Every VM below has enough tokens, indexes and numbers for the old gates.
const VM_DATA: &str = "local FAKE_code = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7}\nlocal FAKE_prog = {{1, 2}, {3, 4}, {2, 7}}\nlocal FAKE_stack = {}\nlocal FAKE_ok = true\nlocal function a() FAKE_stack[1] = 1 end\nlocal function b() FAKE_stack[2] = 2 end\nlocal function c() FAKE_stack[3] = 3 end\nlocal function d() FAKE_stack[4] = 4 end\n";

fn vm_dispatch(style: usize, subject: &str) -> String {
    match style {
        0 => format!(
            "if {subject} == 1 then a() elseif {subject} == 2 then b() elseif {subject} == 3 then c() else d() end"
        ),
        1 => format!(
            "if 1 == {subject} then a() elseif 2 == {subject} then b() elseif 3 == {subject} then c() end"
        ),
        2 => format!(
            "if {subject} <= 2 then if {subject} <= 1 then a() else b() end else if {subject} <= 4 then c() else d() end end"
        ),
        3 => format!(
            "if ({subject} == 1) then a() elseif ({subject} == 2) then b() elseif ({subject} == 0x3) then c() end"
        ),
        _ => format!(
            "if {subject} == 1 and FAKE_ok then a() elseif FAKE_ok and {subject} > 5 then b() elseif {subject} ~= 3 then c() end"
        ),
    }
}

fn vm_body(subject_form: usize, style: usize) -> String {
    match subject_form {
        0 => format!("local op = FAKE_code[pc]\n{}", vm_dispatch(style, "op")),
        1 => vm_dispatch(style, "FAKE_code[pc]"),
        2 => format!(
            "local inst = FAKE_prog[pc]\n{}",
            vm_dispatch(style, "inst[1]")
        ),
        _ => format!("op = FAKE_code[pc]\n{}", vm_dispatch(style, "op")),
    }
}

fn in_loop(kind: usize, body: &str) -> String {
    match kind {
        0 => format!("local pc = 1\nwhile pc <= #FAKE_code do\n{body}\npc = pc + 1\nend"),
        1 => format!("local pc = 1\nrepeat\n{body}\npc = pc + 1\nuntil pc > #FAKE_code"),
        2 => format!("for pc = 1, #FAKE_code do\n{body}\nend"),
        _ => format!("for pc, _ in ipairs(FAKE_code) do\n{body}\nend"),
    }
}

#[test]
fn item13_generated_vm_dispatch_loops_report_bg005() {
    let mut checked = 0;
    for kind in 0..4 {
        for subject_form in 0..4 {
            for style in 0..5 {
                let body = vm_body(subject_form, style);
                // Also inside a function, as obfuscators wrap their VM.
                for wrapped in [false, true] {
                    let program = in_loop(kind, &body);
                    let program = if wrapped {
                        format!("return function(...)\nlocal op\n{program}\nend")
                    } else {
                        format!("local op\n{program}")
                    };
                    let source = format!("{VM_DATA}{program}\nreturn FAKE_stack\n");
                    let evidence = bg005_evidence(&source);
                    assert_eq!(evidence.len(), 1, "{source}");
                    assert!(evidence[0].starts_with("VM-like loop"), "{evidence:?}");
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 160);
}

#[test]
fn item13_loops_without_a_numeric_dispatch_on_indexed_data_stay_quiet() {
    let quiet = [
        // A table of handlers, as in network dispatchers.
        "local pc = 1\nwhile pc <= #FAKE_code do\nlocal id = FAKE_code[pc]\nlocal handler = FAKE_stack[id]\nif handler then handler() end\nif id == 9 then break end\npc = pc + 1\nend",
        // A state machine whose state comes from constants.
        "local state = 1\nwhile true do\nif state == 1 then state = 2 elseif state == 2 then state = 3 elseif state == 3 then break end\nend",
        // Comparisons with strings.
        "for i = 1, #FAKE_code do\nlocal kind = FAKE_prog[i]\nif kind == \"a\" then a() elseif kind == \"b\" then b() elseif kind == \"c\" then c() end\nend",
        // A dispatch chain outside any loop.
        "local op = FAKE_code[1]\nif op == 1 then a() elseif op == 2 then b() elseif op == 3 then c() end",
        // Only two constants.
        "for pc = 1, #FAKE_code do\nlocal op = FAKE_code[pc]\nif op == 1 then a() elseif op == 2 then b() else c() end\nend",
        // The comparisons sit in a function declared inside the loop.
        "for pc = 1, #FAKE_code do\nlocal step = function()\nlocal op = FAKE_code[pc]\nif op == 1 then a() elseif op == 2 then b() elseif op == 3 then c() end\nend\nstep()\nend",
        // Three subjects with one constant each.
        "for pc = 1, #FAKE_code do\nlocal x, y, z = FAKE_code[pc], FAKE_code[pc + 1], FAKE_code[pc + 2]\nif x == 1 then a() end\nif y == 2 then b() end\nif z == 3 then c() end\nend",
    ];
    for program in quiet {
        let source = format!("{VM_DATA}{program}\nreturn FAKE_stack\n");
        assert!(bg005_evidence(&source).is_empty(), "{source}");
    }
}

/// B04 and B15 from the round 3 review: clean files that got BG005 medium.
const REVIEW_B04: &str = r##"--!native
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")
local remote = ReplicatedStorage:WaitForChild("FAKE_Net"):WaitForChild("Reliable") :: RemoteEvent

local Net = {}
local queue: { buffer } = {}
local handlers: { [number]: (Player?, buffer, number) -> () } = {}

local function writePacket(id: number, payload: string): buffer
	local b = buffer.create(3 + #payload)
	buffer.writeu8(b, 0, id)
	buffer.writeu16(b, 1, #payload)
	buffer.writestring(b, 3, payload)
	return b
end

function Net.define(id: number, handler)
	assert(handlers[id] == nil, "packet id in use")
	handlers[id] = handler
end

function Net.send(id: number, payload: string)
	table.insert(queue, writePacket(id, payload))
end

local function flush()
	if #queue == 0 then return end
	local total = 0
	for _, b in queue do total += buffer.len(b) end
	local out = buffer.create(total)
	local offset = 0
	for _, b in queue do
		buffer.copy(out, offset, b)
		offset += buffer.len(b)
	end
	table.clear(queue)
	if RunService:IsServer() then remote:FireAllClients(out) else remote:FireServer(out) end
end

local function dispatch(player: Player?, b: buffer)
	local offset = 0
	while offset < buffer.len(b) do
		local id = buffer.readu8(b, offset)
		local len = buffer.readu16(b, offset + 1)
		local handler = handlers[id]
		if handler then handler(player, b, offset + 3) end
		offset += 3 + len
		local crc = bit32.band(bit32.bxor(id, len), 0xFF)
		if crc == 0x100 then break end
	end
end

if RunService:IsServer() then
	remote.OnServerEvent:Connect(dispatch)
else
	remote.OnClientEvent:Connect(function(b) dispatch(nil, b) end)
end
RunService.Heartbeat:Connect(flush)
return Net
"##;

const REVIEW_B15: &str = r##"local Promise = require(script.Parent.Promise)
local TS = {}
TS.Promise = Promise

local function isPlugin(object)
	return game:GetService("RunService"):IsStudio() and object:FindFirstAncestorWhichIsA("Plugin") ~= nil
end

function TS.getModule(object, scope, moduleName)
	if moduleName == nil then
		moduleName = scope
		scope = "@rbxts"
	end
	local globalModules = script.Parent:FindFirstChild("node_modules")
	if not globalModules then error("Could not find any modules!", 2) end
	repeat
		local modules = object:FindFirstChild("node_modules")
		if modules and modules ~= globalModules then modules = modules:FindFirstChild("@rbxts") end
		if modules then
			local module = modules:FindFirstChild(moduleName)
			if module then return module end
		end
		object = object.Parent
	until object == nil or object == globalModules
	local scoped = globalModules:FindFirstChild(scope)
	return (scoped and scoped:FindFirstChild(moduleName)) or error("Could not find module: " .. moduleName, 2)
end

local currentlyLoading = {}
local registeredLibraries = {}

function TS.import(caller, module, ...)
	for i = 1, select("#", ...) do
		module = module:WaitForChild((select(i, ...)))
	end
	if module.ClassName ~= "ModuleScript" then
		error("Failed to import! Expected ModuleScript, got " .. module.ClassName, 2)
	end
	currentlyLoading[caller] = module
	local currentModule = module
	local depth = 0
	while currentModule do
		depth = depth + 1
		currentModule = currentlyLoading[currentModule]
		if currentModule == module then error("Failed to import! Detected a circular dependency chain", 2) end
	end
	if not isPlugin(module) then
		local existingModule = registeredLibraries[module]
		if existingModule then return existingModule end
	end
	local data = require(module)
	if currentlyLoading[caller] == module then currentlyLoading[caller] = nil end
	return data
end

function TS.instanceof(obj, class)
	if type(class) == "table" and type(class.instanceof) == "function" then return class.instanceof(obj) end
	if type(obj) == "table" then
		obj = getmetatable(obj)
		while obj ~= nil do
			if obj == class then return true end
			local mt = getmetatable(obj)
			obj = mt and mt.__index or nil
		end
	end
	return false
end

function TS.async(callback)
	return function(...)
		local n = select("#", ...)
		local args = { ... }
		return Promise.new(function(resolve, reject)
			coroutine.wrap(function()
				local ok, result = pcall(callback, unpack(args, 1, n))
				if ok then resolve(result) else reject(result) end
			end)()
		end)
	end
end
return TS
"##;

#[test]
fn item13_bg005_page_examples_report_bg005() {
    let page = include_str!("../../../docs/rules/BG005.md");
    let example = page
        .split("```luau\n")
        .nth(1)
        .and_then(|rest| rest.split("```").next())
        .expect("BG005 page example");
    let lines: Vec<_> = example.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        assert_eq!(bg005_evidence(line).len(), 1, "{line}");
    }
}

#[test]
fn item13_review_b04_and_b15_have_no_bg005() {
    for (label, source) in [("B04", REVIEW_B04), ("B15", REVIEW_B15)] {
        assert!(bg005_evidence(source).is_empty(), "{label}");
    }
    // The C34 VM module from the same review still reports BG005.
    let ops = (0..400)
        .map(|index| (index * 7 % 40).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let c34 = format!(
        "local ops = {{{ops}}}\nlocal stack, pc = {{}}, 1\nreturn function(src)\n\twhile pc <= #ops do\n\t\tlocal op = ops[pc]\n\t\tif op == 1 then stack[#stack + 1] = src:byte(pc) elseif op == 2 then stack[#stack] = nil elseif op == 3 then pc = pc + stack[#stack] elseif op == 4 then stack[1] = stack[1] .. src elseif op == 5 then pc = pc - 1 else pc = pc + 1 end\n\t\tpc = pc + 1\n\tend\n\treturn function() return stack[1] end\nend"
    );
    let evidence = bg005_evidence(&c34);
    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].starts_with("VM-like loop"));
}

// ---------------------------------------------------------------------------
// Item 14: human output keeps readable text and escapes hidden characters.
// ---------------------------------------------------------------------------

#[test]
fn item14_human_output_keeps_readable_text_next_to_an_escaped_bidi_control() {
    let source = "loadstring(\"print('日本語のテキスト café naïve Ελληνικά \u{202e}FAKE')\")()";
    let document = Document {
        input: "FAKE_日本_café.server.luau".into(),
        instances: vec![Instance {
            source_file: Some("src/FAKE_日本_café\u{1b}[2J.server.luau".into()),
            ..script("FAKE_日本", None, source)
        }],
        ..Document::default()
    };
    let report = scan_documents(vec![document], &Config::default());
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "BG003")
        .expect("BG003 for loadstring");
    let human = bloxguard_core::output::human(&report);
    let inventory = bloxguard_core::output::inventory_human(&report);
    // Evidence: readable text as written, the bidi control as an escape.
    assert!(
        finding.evidence.contains(r"\u{202e}FAKE"),
        "{}",
        finding.evidence
    );
    assert!(
        human.contains("日本語のテキスト café naïve Ελληνικά \\u{202e}FAKE"),
        "{human}"
    );
    for rendered in [&human, &inventory] {
        assert!(!rendered.contains('\u{202e}'), "{rendered}");
        assert!(!rendered.contains('\u{1b}'), "{rendered}");
        // Input labels and file names are readable; their controls are escaped.
        assert!(
            rendered.contains("FAKE_日本_café.server.luau"),
            "{rendered}"
        );
        assert!(
            rendered.contains("src/FAKE_日本_café\\u{1b}[2J.server.luau"),
            "{rendered}"
        );
        // The instance path keeps the escaped form that JSON and suppressions use.
        assert!(rendered.contains(r"/FAKE_\u{65e5}\u{672c}"), "{rendered}");
        assert!(!rendered.contains("    /FAKE_日本 ("), "{rendered}");
        assert!(!rendered.contains("\n/FAKE_日本\n"), "{rendered}");
    }
}

#[test]
fn item14_human_output_escapes_exactly_the_characters_evidence_escapes() {
    use bloxguard_core::finding::{Confidence, Finding, Severity};
    use bloxguard_core::report::{InputReport, ScanReport};

    let characters = (0u32..=0x3100)
        .chain(0xd7f0..=0xd7ff)
        .chain(0xe000..=0xe010)
        .chain(0xfe00..=0xffff)
        .chain(0x1_f300..=0x1_f310)
        .chain(0xe_0000..=0xe_0100)
        .chain(0x10_fff0..=0x10_ffff)
        .filter_map(char::from_u32);
    let mut escaped = 0;
    let mut kept = 0;
    for character in characters {
        let text = format!("FAKE{character}FAKE");
        let evidence = Finding::new(
            "BG001",
            Severity::Low,
            Confidence::Low,
            "FAKE",
            "/FAKE",
            Default::default(),
            "FAKE",
            &text,
        )
        .evidence;
        let hidden = evidence != text;
        let report = ScanReport {
            inputs: vec![InputReport {
                input: text.clone(),
                completeness: Completeness::Complete,
                reasons: vec![],
                diagnostics: vec![],
                instance_count: 0,
                script_count: 0,
            }],
            ..ScanReport::default()
        };
        let human = bloxguard_core::output::human(&report);
        let escape = format!("FAKE\\u{{{:x}}}FAKE", character as u32);
        if hidden {
            assert!(
                human.contains(&escape),
                "U+{:04X} kept raw",
                character as u32
            );
            escaped += 1;
        } else {
            assert!(human.contains(&text), "U+{:04X} escaped", character as u32);
            kept += 1;
        }
    }
    // C0 and C1 controls, DEL and the hidden format set, and everything else kept.
    assert!(escaped > 200 && kept > 10_000, "{escaped} {kept}");
}
