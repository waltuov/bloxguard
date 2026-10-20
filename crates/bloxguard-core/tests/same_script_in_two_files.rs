//! Two place files in one scanned folder can hold the same script at the same
//! instance path, as when a developer keeps several copies of a game. Each file
//! keeps its own finding, so a second infected file is not hidden behind the
//! first. Every fixture is synthetic and defanged.

use bloxguard_core::engine::scan_paths;
use std::fs;

/// A place with one infected free model: a weld script that requires a fake ID.
const PLACE: &str = r#"<roblox version="4">
	<Item class="Workspace" referent="RBX0">
		<Properties>
			<string name="Name">Workspace</string>
		</Properties>
		<Item class="Model" referent="RBX1">
			<Properties>
				<string name="Name">FAKE_FreeCarKit</string>
			</Properties>
			<Item class="Script" referent="RBX2">
				<Properties>
					<string name="Name">Weld</string>
					<ProtectedString name="Source"><![CDATA[require(999000000004243)
]]></ProtectedString>
				</Properties>
			</Item>
		</Item>
	</Item>
</roblox>
"#;

fn bg001_files(folder: &std::path::Path) -> Vec<String> {
    let report = scan_paths(
        std::slice::from_ref(&folder.to_path_buf()),
        &Default::default(),
    );
    let mut files: Vec<String> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "BG001")
        .map(|finding| {
            finding
                .container_file
                .clone()
                .expect("a finding in a nested place names its file")
        })
        .collect();
    files.sort();
    files
}

#[test]
fn the_same_script_in_two_place_files_is_reported_for_each_file() {
    let temp = tempfile::Builder::new()
        .prefix("bloxguard_FAKE_two_places_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    let folder = temp.path().join("FAKE_games");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("FAKE_GameA.rbxlx"), PLACE).unwrap();
    assert_eq!(bg001_files(&folder).len(), 1);

    fs::write(folder.join("FAKE_GameB.rbxlx"), PLACE).unwrap();
    let files = bg001_files(&folder);
    assert_eq!(files.len(), 2, "{files:?}");
    assert!(files[0].ends_with("FAKE_GameA.rbxlx"), "{files:?}");
    assert!(files[1].ends_with("FAKE_GameB.rbxlx"), "{files:?}");
}
