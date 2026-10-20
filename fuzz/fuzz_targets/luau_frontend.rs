#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        let config = bloxguard_core::config::Config::default();
        let document = bloxguard_core::loading::load_source(
            source,
            "FAKE fuzz.luau",
            "Script",
            &config.limits,
        );
        let _ = bloxguard_core::engine::scan_documents(vec![document], &config);
    }
});
