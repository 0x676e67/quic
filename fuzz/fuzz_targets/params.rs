#![cfg_attr(fuzzing, no_main)]

#[cfg(not(fuzzing))]
fn main() {}

#[cfg(fuzzing)]
mod target {
    use libfuzzer_sys::fuzz_target;
    use proto::{Side, transport_parameters::TransportParameters};

    fuzz_target!(|data: &[u8]| {
        let mut data = data;
        let _ = TransportParameters::read(Side::Client, &mut data);
    });
}
