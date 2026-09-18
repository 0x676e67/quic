#![cfg_attr(fuzzing, no_main)]

use libfuzzer_sys::fuzz_target;
use proto::{transport_parameters::TransportParameters, Side};

#[cfg(fuzzing)]
mod target {
    use libfuzzer_sys::fuzz_target;
    use proto::{transport_parameters::TransportParameters, Side};

    fuzz_target!(|data: &[u8]| {
        let mut data = data;
        let _ = TransportParameters::read(Side::Client, &mut data);
    });
}
