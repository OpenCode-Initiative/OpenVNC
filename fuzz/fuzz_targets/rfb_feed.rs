#![no_main]
use libfuzzer_sys::fuzz_target;
use openvnc_rfb::{Client, Config};

fuzz_target!(|data: &[u8]| {
    let mut c = Client::new(Config::default());
    // fatias de tamanho variavel exercitam a retomada do parser
    for chunk in data.chunks(7) {
        if c.feed(chunk).is_err() {
            break;
        }
        while c.poll_event().is_some() {}
    }
});
