use super::*;
use openvnc_core::input::keysym;

fn server_init(w: u16, h: u16, name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&h.to_be_bytes());
    v.extend_from_slice(&PixelFormat::RGBX8888.to_bytes());
    v.extend_from_slice(&(name.len() as u32).to_be_bytes());
    v.extend_from_slice(name.as_bytes());
    v
}

fn raw_update(r: Rect, px: [u8; 4]) -> Vec<u8> {
    let mut v = vec![0, 0, 0, 1];
    for x in [r.x, r.y, r.width, r.height] {
        v.extend_from_slice(&x.to_be_bytes());
    }
    v.extend_from_slice(&0i32.to_be_bytes());
    for _ in 0..r.area() {
        v.extend_from_slice(&px);
    }
    v
}

/// Script completo do servidor para cada versao com security None.
fn script(version: &[u8; 12]) -> Vec<u8> {
    let mut s = version.to_vec();
    match version {
        b"RFB 003.003\n" => s.extend_from_slice(&1u32.to_be_bytes()),
        b"RFB 003.007\n" => s.extend_from_slice(&[1, 1]),
        _ => {
            s.extend_from_slice(&[2, 2, 1]);
            s.extend_from_slice(&0u32.to_be_bytes());
        }
    }
    s.extend(server_init(4, 2, "desk"));
    s.extend(raw_update(Rect::new(1, 1, 2, 1), [10, 20, 30, 0]));
    s.push(2); // bell
    s.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 2, b'h', 0xE9]);
    s
}

fn run(chunks: &[&[u8]]) -> (Client, Vec<Event>, Vec<u8>) {
    let mut c = Client::new(Config::default());
    let mut out = Vec::new();
    for ch in chunks {
        c.feed(ch).unwrap();
        out.extend(c.take_output());
    }
    let mut ev = Vec::new();
    while let Some(e) = c.poll_event() {
        ev.push(e);
    }
    (c, ev, out)
}

#[test]
fn handshake_all_versions_whole_and_bytewise() {
    for (banner, ver) in [
        (b"RFB 003.003\n", ProtocolVersion::V3_3),
        (b"RFB 003.007\n", ProtocolVersion::V3_7),
        (b"RFB 003.008\n", ProtocolVersion::V3_8),
    ] {
        let s = script(banner);
        let (c1, ev1, out1) = run(&[&s]);
        let bytes: Vec<&[u8]> = s.chunks(1).collect();
        let (c2, ev2, out2) = run(&bytes);
        assert_eq!(ev1, ev2);
        assert_eq!(out1, out2);
        assert_eq!(&out1[..12], ver.banner());
        assert!(
            matches!(&ev1[0], Event::Connected { width: 4, height: 2, name, version, .. } if name == "desk" && *version == ver)
        );
        assert_eq!(ev1[1], Event::UpdateComplete);
        assert_eq!(ev1[2], Event::Bell);
        assert_eq!(ev1[3], Event::CutText("h\u{e9}".into()));
        assert_eq!(
            c1.framebuffer().unwrap().pixel(2, 1),
            Some([10, 20, 30, 255])
        );
        assert_eq!(
            c2.framebuffer().unwrap().data(),
            c1.framebuffer().unwrap().data()
        );
        // 3.3 nao envia escolha de seguranca; ClientInit shared=1 em seguida
        let after = if ver == ProtocolVersion::V3_3 { 12 } else { 13 };
        assert_eq!(out1[after], 1);
        // SetPixelFormat vem logo depois
        assert_eq!(out1[after + 1], 0);
    }
}

#[test]
fn version_negotiation() {
    assert_eq!(
        ProtocolVersion::negotiate(b"RFB 003.005\n").unwrap(),
        ProtocolVersion::V3_3
    );
    assert_eq!(
        ProtocolVersion::negotiate(b"RFB 003.889\n").unwrap(),
        ProtocolVersion::V3_8
    );
    assert_eq!(
        ProtocolVersion::negotiate(b"RFB 004.001\n").unwrap(),
        ProtocolVersion::V3_8
    );
    assert!(ProtocolVersion::negotiate(b"RFB 002.000\n").is_err());
    assert!(ProtocolVersion::negotiate(b"HTTP/1.1 200").is_err());
    assert!(ProtocolVersion::negotiate(b"RFB 003.00x\n").is_err());
}

#[test]
fn vnc_auth_flow_and_failure_reason_38() {
    let cfg = Config {
        password: Some(Password::new("pw")),
        ..Config::default()
    };
    let mut c = Client::new(cfg);
    let mut s = b"RFB 003.008\n".to_vec();
    s.extend_from_slice(&[1, 2]);
    s.extend_from_slice(&[0xAB; 16]);
    c.feed(&s).unwrap();
    let out = c.take_output();
    assert_eq!(out.len(), 12 + 1 + 16);
    assert_eq!(out[12], 2);
    assert_eq!(
        &out[13..],
        &openvnc_security::vnc_auth_response(&Password::new("pw"), &[0xAB; 16])
    );
    let mut fail = 1u32.to_be_bytes().to_vec();
    fail.extend_from_slice(&5u32.to_be_bytes());
    fail.extend_from_slice(b"nope!");
    let err = c.feed(&fail).unwrap_err().to_string();
    assert!(err.contains("nope!"), "{err}");
    assert!(c.feed(&[0]).is_err());
}

#[test]
fn auth_without_password_fails() {
    let mut c = Client::new(Config::default());
    assert!(c.feed(b"RFB 003.008\n\x01\x02").is_err());
}

#[test]
fn server_refusal_33() {
    let mut c = Client::new(Config::default());
    let mut s = b"RFB 003.003\n".to_vec();
    s.extend_from_slice(&0u32.to_be_bytes());
    s.extend_from_slice(&3u32.to_be_bytes());
    s.extend_from_slice(b"bye");
    assert!(c.feed(&s).unwrap_err().to_string().contains("bye"));
}

#[test]
fn limits_enforced() {
    let mut base = script(b"RFB 003.008\n");
    base.truncate(12 + 3 + 4);
    // largura acima do limite
    let mut s = base.clone();
    s.extend(server_init(20000, 1, ""));
    assert!(Client::new(Config::default()).feed(&s).is_err());
    // nome gigante
    let mut s = base.clone();
    let mut si = server_init(1, 1, "");
    si[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
    s.extend(si);
    assert!(Client::new(Config::default()).feed(&s).is_err());
    // cut text gigante
    let mut s = base;
    s.extend(server_init(1, 1, ""));
    s.extend_from_slice(&[3, 0, 0, 0]);
    s.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(Client::new(Config::default()).feed(&s).is_err());
}

#[test]
fn unannounced_encoding_and_unknown_message_rejected() {
    let mut base = script(b"RFB 003.008\n");
    base.truncate(12 + 3 + 4);
    base.extend(server_init(4, 4, ""));
    let mut s = base.clone();
    s.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1]);
    s.extend_from_slice(&7i32.to_be_bytes());
    assert!(Client::new(Config::default()).feed(&s).is_err());
    let mut s = base;
    s.push(99);
    assert!(Client::new(Config::default()).feed(&s).is_err());
}

#[test]
fn truncated_input_never_panics() {
    let s = script(b"RFB 003.008\n");
    for n in 0..s.len() {
        let mut c = Client::new(Config::default());
        c.feed(&s[..n]).unwrap();
    }
}

#[test]
fn client_messages_encoding() {
    let mut c = Client::new(Config::default());
    c.send_key(KeyEvent {
        down: true,
        keysym: keysym::RETURN,
    });
    c.send_pointer(PointerEvent {
        buttons: 1,
        x: 258,
        y: 3,
    });
    c.send_cut_text("a\u{263A}");
    assert_eq!(
        c.take_output(),
        vec![4, 1, 0, 0, 0, 0, 0xff, 0x0d, 5, 1, 1, 2, 0, 3, 6, 0, 0, 0, 0, 0, 0, 2, b'a', b'?']
    );
}
