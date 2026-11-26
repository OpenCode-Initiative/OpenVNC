//! C ABI estavel do OpenVNC (v0).
//!
//! Expoe o protocolo nativo sans-IO por handles opacos. Regras: todas as
//! funcoes retornam [`OPENVNC_OK`], [`OPENVNC_AGAIN`] ou um codigo
//! negativo; buffers alocados pela biblioteca so sao liberados com
//! [`openvnc_buffer_free`]; nenhum panic atravessa a fronteira. O header C
//! esta em `include/openvnc.h`.
#![allow(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use openvnc_protocol::{encode, Decoder, Input, Message, DEFAULT_MAX_PAYLOAD};

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Sucesso.
pub const OPENVNC_OK: i32 = 0;
/// Ainda nao ha mensagem completa.
pub const OPENVNC_AGAIN: i32 = 1;
/// Ponteiro nulo ou argumento invalido.
pub const OPENVNC_EINVAL: i32 = -1;
/// Erro de protocolo (fatal para a conexao).
pub const OPENVNC_EPROTO: i32 = -2;
/// Panic interno capturado.
pub const OPENVNC_EPANIC: i32 = -3;

/// Handle opaco de decodificador.
pub struct OpenvncDecoder {
    inner: Decoder,
    last: Option<Message>,
}

/// Buffer alocado pela biblioteca.
#[repr(C)]
pub struct OpenvncBuffer {
    /// Dados.
    pub data: *mut u8,
    /// Tamanho.
    pub len: usize,
}

fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(OPENVNC_EPANIC)
}

fn give(v: Vec<u8>, out: &mut OpenvncBuffer) {
    let b = v.into_boxed_slice();
    out.len = b.len();
    out.data = Box::into_raw(b) as *mut u8;
}

fn encode_into(m: &Message, out: &mut OpenvncBuffer) -> i32 {
    match encode(m) {
        Ok(v) => {
            give(v, out);
            OPENVNC_OK
        }
        Err(_) => OPENVNC_EPROTO,
    }
}

/// Versao do protocolo implementada.
#[no_mangle]
pub extern "C" fn openvnc_protocol_version() -> u16 {
    openvnc_protocol::PROTOCOL_VERSION
}

/// Cria um decodificador. `max_payload` 0 usa o padrao. Liberar com
/// [`openvnc_decoder_free`].
#[no_mangle]
pub extern "C" fn openvnc_decoder_new(max_payload: u32) -> *mut OpenvncDecoder {
    let max = if max_payload == 0 {
        DEFAULT_MAX_PAYLOAD
    } else {
        max_payload
    };
    Box::into_raw(Box::new(OpenvncDecoder {
        inner: Decoder::new(max),
        last: None,
    }))
}

/// Libera um decodificador (aceita nulo).
///
/// # Safety
/// `d` deve vir de [`openvnc_decoder_new`] e nao ser usado depois.
#[no_mangle]
pub unsafe extern "C" fn openvnc_decoder_free(d: *mut OpenvncDecoder) {
    if !d.is_null() {
        drop(Box::from_raw(d));
    }
}

/// Acrescenta bytes recebidos.
///
/// # Safety
/// `d` valido; `data` aponta para `len` bytes legiveis (ou `len` 0).
#[no_mangle]
pub unsafe extern "C" fn openvnc_decoder_feed(
    d: *mut OpenvncDecoder,
    data: *const u8,
    len: usize,
) -> i32 {
    guard(|| {
        let Some(d) = d.as_mut() else {
            return OPENVNC_EINVAL;
        };
        if len == 0 {
            return OPENVNC_OK;
        }
        if data.is_null() {
            return OPENVNC_EINVAL;
        }
        d.inner.feed(std::slice::from_raw_parts(data, len));
        OPENVNC_OK
    })
}

/// Avanca para a proxima mensagem. Em [`OPENVNC_OK`], `*msg_type` recebe
/// o codigo; os detalhes saem das funcoes `openvnc_msg_*`.
///
/// # Safety
/// `d` valido; `msg_type` gravavel.
#[no_mangle]
pub unsafe extern "C" fn openvnc_decoder_next(d: *mut OpenvncDecoder, msg_type: *mut u16) -> i32 {
    guard(|| {
        let (Some(d), Some(t)) = (d.as_mut(), msg_type.as_mut()) else {
            return OPENVNC_EINVAL;
        };
        match d.inner.next_message() {
            Ok(Some(m)) => {
                *t = m.type_code();
                d.last = Some(m);
                OPENVNC_OK
            }
            Ok(None) => OPENVNC_AGAIN,
            Err(_) => OPENVNC_EPROTO,
        }
    })
}

/// Ultima mensagem como evento de ponteiro.
///
/// # Safety
/// Ponteiros validos e gravaveis.
#[no_mangle]
pub unsafe extern "C" fn openvnc_msg_pointer(
    d: *const OpenvncDecoder,
    x: *mut u16,
    y: *mut u16,
    buttons: *mut u8,
) -> i32 {
    guard(|| {
        let (Some(d), Some(x), Some(y), Some(b)) =
            (d.as_ref(), x.as_mut(), y.as_mut(), buttons.as_mut())
        else {
            return OPENVNC_EINVAL;
        };
        match d.last {
            Some(Message::InputEvent(Input::Pointer {
                x: px,
                y: py,
                buttons: pb,
            })) => {
                (*x, *y, *b) = (px, py, pb);
                OPENVNC_OK
            }
            _ => OPENVNC_EINVAL,
        }
    })
}

/// Ultima mensagem como tecla.
///
/// # Safety
/// Ponteiros validos e gravaveis.
#[no_mangle]
pub unsafe extern "C" fn openvnc_msg_key(
    d: *const OpenvncDecoder,
    keysym: *mut u32,
    down: *mut u8,
) -> i32 {
    guard(|| {
        let (Some(d), Some(k), Some(dn)) = (d.as_ref(), keysym.as_mut(), down.as_mut()) else {
            return OPENVNC_EINVAL;
        };
        match d.last {
            Some(Message::InputEvent(Input::Key {
                keysym: ks,
                down: kd,
            })) => {
                *k = ks;
                *dn = u8::from(kd);
                OPENVNC_OK
            }
            _ => OPENVNC_EINVAL,
        }
    })
}

/// Ultima mensagem como texto de clipboard (UTF-8, sem NUL) em `out`.
///
/// # Safety
/// Ponteiros validos; liberar `out` com [`openvnc_buffer_free`].
#[no_mangle]
pub unsafe extern "C" fn openvnc_msg_clipboard(
    d: *const OpenvncDecoder,
    out: *mut OpenvncBuffer,
) -> i32 {
    guard(|| {
        let (Some(d), Some(out)) = (d.as_ref(), out.as_mut()) else {
            return OPENVNC_EINVAL;
        };
        match &d.last {
            Some(Message::Clipboard { text }) => {
                give(text.as_bytes().to_vec(), out);
                OPENVNC_OK
            }
            _ => OPENVNC_EINVAL,
        }
    })
}

/// Codifica um INPUT_EVENT de ponteiro.
///
/// # Safety
/// `out` gravavel.
#[no_mangle]
pub unsafe extern "C" fn openvnc_encode_pointer(
    x: u16,
    y: u16,
    buttons: u8,
    out: *mut OpenvncBuffer,
) -> i32 {
    guard(|| {
        let Some(out) = out.as_mut() else {
            return OPENVNC_EINVAL;
        };
        encode_into(&Message::InputEvent(Input::Pointer { x, y, buttons }), out)
    })
}

/// Codifica um INPUT_EVENT de tecla.
///
/// # Safety
/// `out` gravavel.
#[no_mangle]
pub unsafe extern "C" fn openvnc_encode_key(keysym: u32, down: u8, out: *mut OpenvncBuffer) -> i32 {
    guard(|| {
        let Some(out) = out.as_mut() else {
            return OPENVNC_EINVAL;
        };
        encode_into(
            &Message::InputEvent(Input::Key {
                keysym,
                down: down != 0,
            }),
            out,
        )
    })
}

/// Codifica um CLIPBOARD a partir de `len` bytes UTF-8.
///
/// # Safety
/// `text` aponta para `len` bytes legiveis; `out` gravavel.
#[no_mangle]
pub unsafe extern "C" fn openvnc_encode_clipboard(
    text: *const u8,
    len: usize,
    out: *mut OpenvncBuffer,
) -> i32 {
    guard(|| {
        let Some(out) = out.as_mut() else {
            return OPENVNC_EINVAL;
        };
        let bytes: &[u8] = if len == 0 {
            &[]
        } else if text.is_null() {
            return OPENVNC_EINVAL;
        } else {
            std::slice::from_raw_parts(text, len)
        };
        let Ok(s) = std::str::from_utf8(bytes) else {
            return OPENVNC_EINVAL;
        };
        encode_into(
            &Message::Clipboard {
                text: s.to_string(),
            },
            out,
        )
    })
}

/// Libera um buffer da biblioteca (aceita vazio) e o zera.
///
/// # Safety
/// `b` deve ter sido preenchido por esta biblioteca.
#[no_mangle]
pub unsafe extern "C" fn openvnc_buffer_free(b: *mut OpenvncBuffer) {
    let Some(b) = b.as_mut() else { return };
    if !b.data.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            b.data, b.len,
        )));
    }
    b.data = std::ptr::null_mut();
    b.len = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// O header e escrito a mao; este teste impede que ele divirja do Rust:
    /// toda funcao exportada precisa estar declarada e todo codigo de
    /// retorno precisa ter o mesmo valor.
    #[test]
    fn header_em_sincronia() {
        let h = include_str!("../include/openvnc.h");
        let src = include_str!("lib.rs");
        let mut n = 0;
        for l in src.lines() {
            let l = l.trim();
            if let Some(rest) = l.strip_prefix("pub ") {
                if let Some(i) = rest.find("extern \"C\" fn ") {
                    let name = &rest[i + 14..];
                    let name = &name[..name.find('(').unwrap()];
                    assert!(h.contains(&format!("{name}(")), "{name} ausente do header");
                    n += 1;
                }
            }
        }
        let decl = h
            .lines()
            .filter_map(|l| l.split('(').next())
            .filter_map(|l| l.rsplit([' ', '*']).next())
            .filter(|n| n.starts_with("openvnc_"))
            .count();
        assert_eq!(decl, n, "header declara funcoes que o Rust nao exporta");
        for (k, v) in [
            ("OPENVNC_OK", OPENVNC_OK),
            ("OPENVNC_AGAIN", OPENVNC_AGAIN),
            ("OPENVNC_EINVAL", OPENVNC_EINVAL),
            ("OPENVNC_EPROTO", OPENVNC_EPROTO),
            ("OPENVNC_EPANIC", OPENVNC_EPANIC),
        ] {
            let want = if v < 0 {
                format!("#define {k} ({v})")
            } else {
                format!("#define {k} {v}")
            };
            assert!(h.contains(&want), "{k} diverge do header");
        }
    }

    #[test]
    fn roundtrip_pela_abi() {
        unsafe {
            let mut buf = OpenvncBuffer {
                data: std::ptr::null_mut(),
                len: 0,
            };
            assert_eq!(openvnc_encode_pointer(10, 20, 1, &mut buf), OPENVNC_OK);
            let d = openvnc_decoder_new(0);
            let mut t = 0u16;
            assert_eq!(openvnc_decoder_next(d, &mut t), OPENVNC_AGAIN);
            assert_eq!(openvnc_decoder_feed(d, buf.data, buf.len), OPENVNC_OK);
            assert_eq!(openvnc_decoder_next(d, &mut t), OPENVNC_OK);
            assert_eq!(t, openvnc_protocol::msg_type::INPUT_EVENT);
            let (mut x, mut y, mut b) = (0, 0, 0);
            assert_eq!(openvnc_msg_pointer(d, &mut x, &mut y, &mut b), OPENVNC_OK);
            assert_eq!((x, y, b), (10, 20, 1));
            let (mut k, mut dn) = (0, 0);
            assert_eq!(openvnc_msg_key(d, &mut k, &mut dn), OPENVNC_EINVAL);
            openvnc_buffer_free(&mut buf);
            assert!(buf.data.is_null());

            let txt = "ola";
            assert_eq!(
                openvnc_encode_clipboard(txt.as_ptr(), txt.len(), &mut buf),
                OPENVNC_OK
            );
            openvnc_decoder_feed(d, buf.data, buf.len);
            openvnc_buffer_free(&mut buf);
            assert_eq!(openvnc_decoder_next(d, &mut t), OPENVNC_OK);
            assert_eq!(openvnc_msg_clipboard(d, &mut buf), OPENVNC_OK);
            assert_eq!(std::slice::from_raw_parts(buf.data, buf.len), b"ola");
            openvnc_buffer_free(&mut buf);

            let lixo = [0xffu8; 10];
            openvnc_decoder_feed(d, lixo.as_ptr(), lixo.len());
            assert_eq!(openvnc_decoder_next(d, &mut t), OPENVNC_EPROTO);
            openvnc_decoder_free(d);
            assert_eq!(
                openvnc_decoder_next(std::ptr::null_mut(), &mut t),
                OPENVNC_EINVAL
            );
        }
    }
}
