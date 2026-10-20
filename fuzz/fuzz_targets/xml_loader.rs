#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bloxguard_core::loading::load_bytes(
        "FAKE fuzz.rbxmx",
        "rbxmx",
        data,
        &bloxguard_core::model::Limits::default(),
    );
});
