use super::*;

fn samples() -> Vec<Message> {
    vec![
        Message::ClientHello {
            min_version: 0,
            max_version: 0,
            capabilities: vec![capability::TILE_RAW, capability::TILE_ZLIB],
            name: "cli".into(),
        },
        Message::ServerHello {
            version: 0,
            capabilities: vec![1],
            auth_methods: vec![auth_method::PASSWORD],
            name: "srv".into(),
        },
        Message::AuthRequest {
            method: auth_method::DEVICE,
            user: "dev".into(),
            secret: vec![1, 2, 3],
        },
        Message::OidcConfig {
            issuer: "https://idp.empresa.local/realms/ti".into(),
            client_id: "openvnc".into(),
            scope: "openid profile".into(),
        },
        Message::AuthRequest {
            method: 3,
            user: String::new(),
            secret: vec![b'a'; 20_000],
        },
        Message::AuthResult {
            ok: false,
            reason: "nao".into(),
        },
        Message::DisplayInfo {
            width: 1920,
            height: 1080,
            name: ":0".into(),
        },
        Message::FrameUpdate {
            seq: 7,
            rects: vec![FrameRect {
                x: 1,
                y: 2,
                width: 1,
                height: 1,
                encoding: encoding::RAW,
                data: vec![1, 2, 3, 255],
            }],
        },
        Message::FrameAck { seq: 7 },
        Message::InputEvent(Input::Pointer {
            x: 3,
            y: 4,
            buttons: 1,
        }),
        Message::InputEvent(Input::Key {
            keysym: 0xff0d,
            down: true,
        }),
        Message::CursorUpdate {
            hot_x: 0,
            hot_y: 0,
            width: 1,
            height: 1,
            rgba: vec![0, 0, 0, 255],
        },
        Message::Clipboard { text: "ola".into() },
        Message::FileOffer {
            id: 1,
            name: "a.txt".into(),
            size: 3,
        },
        Message::FileAccept {
            id: 1,
            accept: true,
        },
        Message::FileChunk {
            id: 1,
            offset: 0,
            data: b"abc".to_vec(),
        },
        Message::FileEnd {
            id: 1,
            sha256: [9; 32],
        },
        Message::Ping { nonce: 5 },
        Message::Pong { nonce: 5 },
        Message::Close {
            code: close_code::NORMAL,
            reason: String::new(),
        },
    ]
}

#[test]
fn roundtrip_byte_a_byte() {
    let mut d = Decoder::default();
    for m in samples() {
        for b in encode(&m).unwrap() {
            d.feed(&[b]);
        }
        assert_eq!(d.next_message().unwrap(), Some(m));
    }
    assert_eq!(d.next_message().unwrap(), None);
}

#[test]
fn limite_de_payload_antes_de_alocar() {
    let mut h = vec![0, 0, 0, 0x11, 0, 0];
    h.extend_from_slice(&u32::MAX.to_be_bytes());
    let mut d = Decoder::new(1024);
    d.feed(&h);
    assert!(d.next_message().is_err());
}

#[test]
fn versao_e_flags_invalidas() {
    let mut b = encode(&Message::Ping { nonce: 1 }).unwrap();
    b[1] = 9;
    let mut d = Decoder::default();
    d.feed(&b);
    assert!(d.next_message().is_err());
    let mut b = encode(&Message::Ping { nonce: 1 }).unwrap();
    b[5] = 1;
    let mut d = Decoder::default();
    d.feed(&b);
    assert!(d.next_message().is_err());
}

#[test]
fn bytes_sobrando_e_tipo_desconhecido() {
    assert!(decode_payload(msg_type::PING, &[0; 9]).is_err());
    assert!(decode_payload(0x7777, &[]).is_err());
}

#[test]
fn nome_de_arquivo_perigoso() {
    for n in ["../x", "a/b", "c:x", "a\\b", "", "..", "a\nb"] {
        assert!(sanitize_file_name(n).is_err(), "{n}");
    }
    let m = Message::FileOffer {
        id: 1,
        name: "../etc".into(),
        size: 1,
    };
    let b = encode(&m).unwrap();
    let mut d = Decoder::default();
    d.feed(&b);
    assert!(d.next_message().is_err());
}

#[test]
fn negociacao() {
    assert_eq!(negotiate_capabilities(&[1, 2, 3], &[3, 1]), vec![1, 3]);
    assert_eq!(negotiate_version(0, 2), Some(0));
    assert_eq!(negotiate_version(1, 2), None);
}

// ------------------------------------------- explorador e bloqueio de entrada

fn fs_samples() -> Vec<Message> {
    let ops = vec![
        FsOp::Roots,
        FsOp::List {
            path: r"C:\Users".into(),
        },
        FsOp::Mkdir {
            path: "/tmp/nova".into(),
        },
        FsOp::Rename {
            from: "/a".into(),
            to: "/b".into(),
        },
        FsOp::Delete { path: "/x".into() },
        FsOp::Read {
            path: "/f".into(),
            offset: 7,
            len: 65536,
        },
        FsOp::Write {
            path: "/f".into(),
            offset: 0,
            overwrite: true,
            data: vec![1, 2, 3],
        },
    ];
    let replies = vec![
        FsReply::Ok,
        FsReply::Error {
            message: "negado".into(),
        },
        FsReply::Roots {
            roots: vec!["C:\\".into(), "D:\\".into()],
        },
        FsReply::Entries {
            path: "/home".into(),
            entries: vec![
                FsEntry {
                    name: "a.txt".into(),
                    is_dir: false,
                    size: 10,
                    modified: 1_700_000_000,
                },
                FsEntry {
                    name: "pasta".into(),
                    is_dir: true,
                    size: 0,
                    modified: 0,
                },
            ],
        },
        FsReply::Data {
            data: vec![9; 100],
            eof: true,
        },
    ];
    let mut v: Vec<Message> = ops
        .into_iter()
        .enumerate()
        .map(|(i, op)| Message::FsRequest { id: i as u32, op })
        .collect();
    v.extend(
        replies
            .into_iter()
            .enumerate()
            .map(|(i, reply)| Message::FsResponse { id: i as u32, reply }),
    );
    v.push(Message::InputLock { on: true });
    v.push(Message::InputLock { on: false });
    v.push(Message::InputLockState {
        on: false,
        reason: "nao suportado".into(),
    });
    v
}

#[test]
fn fs_e_bloqueio_roundtrip() {
    let mut d = Decoder::default();
    for m in fs_samples() {
        for b in encode(&m).unwrap() {
            d.feed(&[b]);
        }
        assert_eq!(d.next_message().unwrap(), Some(m));
    }
    assert_eq!(d.next_message().unwrap(), None);
}

#[test]
fn fs_invalidos() {
    // operacao desconhecida
    assert!(decode_payload(msg_type::FS_REQUEST, &[0, 0, 0, 1, 99]).is_err());
    // bool invalido no bloqueio
    assert!(decode_payload(msg_type::INPUT_LOCK, &[2]).is_err());
    // nome de entrada com separador
    let m = Message::FsResponse {
        id: 1,
        reply: FsReply::Entries {
            path: "/".into(),
            entries: vec![FsEntry {
                name: "../x".into(),
                is_dir: false,
                size: 0,
                modified: 0,
            }],
        },
    };
    let b = encode(&m).unwrap();
    assert!(decode_payload(msg_type::FS_RESPONSE, &b[HEADER_LEN..]).is_err());
    // bloco grande demais
    let m = Message::FsRequest {
        id: 1,
        op: FsOp::Write {
            path: "/f".into(),
            offset: 0,
            overwrite: false,
            data: vec![0; MAX_FILE_CHUNK + 1],
        },
    };
    assert!(encode(&m).is_err());
    // contagem de entradas acima do limite e recusada antes de alocar
    let mut p = vec![0, 0, 0, 1, 3, 0, 1, b'/'];
    p.extend_from_slice(&(MAX_FS_ENTRIES as u32 + 1).to_be_bytes());
    assert!(decode_payload(msg_type::FS_RESPONSE, &p).is_err());
}
