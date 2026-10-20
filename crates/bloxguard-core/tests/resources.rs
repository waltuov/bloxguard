use bloxguard_core::{
    config::Config,
    engine::{inventory_documents, scan_documents},
    model::{ChildLookup, Completeness, Document, DomIndex, Instance, MAX_REPORT_PATH_BYTES},
};

#[test]
fn child_index_preserves_ambiguity_and_unique_matches() {
    let document = Document {
        instances: vec![
            Instance {
                name: "FAKE_root".into(),
                class: "Folder".into(),
                ..Instance::default()
            },
            Instance {
                name: "FAKE_duplicate".into(),
                class: "Folder".into(),
                parent: Some(0),
                ..Instance::default()
            },
            Instance {
                name: "FAKE_duplicate".into(),
                class: "Folder".into(),
                parent: Some(0),
                ..Instance::default()
            },
            Instance {
                name: "FAKE_unique".into(),
                class: "ModuleScript".into(),
                parent: Some(0),
                source: Some("return {}".into()),
                ..Instance::default()
            },
        ],
        ..Document::default()
    };
    let index = DomIndex::new(&document);
    assert_eq!(index.child(0, "FAKE_duplicate"), ChildLookup::Ambiguous);
    assert_eq!(index.child(0, "FAKE_unique"), ChildLookup::Found(3));
    assert_eq!(index.child(0, "FAKE_missing"), ChildLookup::Missing);
}

#[test]
fn deep_script_inventory_has_bounded_output_and_is_partial() {
    let mut document = Document {
        input: "FAKE deep inventory".into(),
        ..Document::default()
    };
    for id in 0usize..10_000 {
        document.instances.push(Instance {
            name: format!("FAKE_{id}"),
            class: "ModuleScript".into(),
            parent: id.checked_sub(1),
            source: Some("return 0".into()),
            ..Instance::default()
        });
    }
    let report = inventory_documents(vec![document]);
    assert_eq!(report.completeness, Completeness::Partial);
    assert!(report.inventory.len() < 10_000);
    let bytes: usize = report
        .inventory
        .iter()
        .map(|entry| serde_json::to_vec(entry).unwrap().len())
        .sum();
    assert!(bytes <= MAX_REPORT_PATH_BYTES);
}

#[test]
fn identical_findings_from_distinct_inputs_are_not_deduplicated() {
    let documents = ["FAKE_a/FAKE_same.luau", "FAKE_b/FAKE_same.luau"]
        .iter()
        .map(|path| {
            bloxguard_core::loading::load_source(
                "require(999000000000001)",
                path,
                "ModuleScript",
                &Default::default(),
            )
        })
        .collect();
    let report = scan_documents(documents, &Config::default());
    assert_eq!(report.findings.len(), 2);
    assert_ne!(report.findings[0].input, report.findings[1].input);
}
