//! Benchmarks de encode/decode sobre um quadro sintetico 1280x720.
#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use openvnc_codecs::{encoding, CodecState, EncoderState, RectDecoder};
use openvnc_core::{PixelFormat, Rect};
use openvnc_framebuffer::{Framebuffer, DEFAULT_MAX_BYTES};
use openvnc_platform::{ScreenCapture, TestPattern};

const W: u16 = 1280;
const H: u16 = 720;

fn frame() -> Framebuffer {
    let mut fb = Framebuffer::new(W, H, DEFAULT_MAX_BYTES).unwrap();
    TestPattern::new(W, H).capture(&mut fb).unwrap();
    fb
}

fn bench(c: &mut Criterion) {
    let fb = frame();
    let pf = PixelFormat::RGBX8888;
    let r = Rect::new(0, 0, W, H);
    let mut g = c.benchmark_group("1280x720");
    g.throughput(Throughput::Bytes(u64::from(W) * u64::from(H) * 4));
    for (name, enc) in [
        ("raw", encoding::RAW),
        ("hextile", encoding::HEXTILE),
        ("zrle", encoding::ZRLE),
    ] {
        g.bench_function(format!("encode/{name}"), |b| {
            let mut st = EncoderState::default();
            let mut out = Vec::new();
            b.iter(|| {
                out.clear();
                st.encode_rect(&fb, r, enc, &pf, &mut out).unwrap();
            })
        });
        // stream para decodificar: cada iteracao usa estados novos e
        // pareados, porque o zlib do ZRLE e continuo
        let mut st = EncoderState::default();
        let mut bytes = Vec::new();
        st.encode_rect(&fb, r, enc, &pf, &mut bytes).unwrap();
        let payload = bytes[12..].to_vec();
        let mut dst = Framebuffer::new(W, H, DEFAULT_MAX_BYTES).unwrap();
        g.bench_function(format!("decode/{name}"), |b| {
            b.iter(|| {
                let mut cs = CodecState::default();
                let mut d = RectDecoder::new(r, enc).unwrap();
                let p = d.decode(&payload, &pf, &mut dst, &mut cs).unwrap();
                assert!(p.done);
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
