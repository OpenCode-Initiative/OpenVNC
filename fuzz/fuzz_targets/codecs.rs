#![no_main]
use libfuzzer_sys::fuzz_target;
use openvnc_codecs::{encoding, CodecState, RectDecoder};
use openvnc_core::{PixelFormat, Rect};
use openvnc_framebuffer::Framebuffer;

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let enc = [encoding::RAW, encoding::COPY_RECT, encoding::HEXTILE, encoding::ZRLE, encoding::TIGHT][usize::from(data[0] % 5)];
    let rect = Rect { x: u16::from(data[1] % 32), y: u16::from(data[2] % 32), width: u16::from(data[3] % 80), height: u16::from(data[4] % 80) };
    let mut fb = Framebuffer::new(64, 64, 1 << 20).unwrap();
    let mut st = CodecState::default();
    let pf = PixelFormat::RGBX8888;
    let Ok(mut d) = RectDecoder::new(rect, enc) else { return };
    let mut input = &data[5..];
    while let Ok(p) = d.decode(input, &pf, &mut fb, &mut st) {
        input = &input[p.consumed..];
        if p.done || p.consumed == 0 {
            break;
        }
    }
});
