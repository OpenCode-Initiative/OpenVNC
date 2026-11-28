//! Cliente RFB 3.3/3.7/3.8 (RFC 6143) como maquina de estados *sans-IO*.
//!
//! O chamador entrega bytes recebidos com [`Client::feed`], envia os bytes
//! de [`Client::take_output`] e consome eventos com [`Client::poll_event`].
//! Nenhum I/O, thread ou relogio e usado aqui, o que torna o parser
//! deterministico, testavel por fixtures e fuzzavel.

use std::collections::VecDeque;

use openvnc_codecs::{encoding, CodecState, RectDecoder};
use openvnc_core::{check_limit, Error, KeyEvent, PixelFormat, PointerEvent, Rect, Result};
use openvnc_framebuffer::Framebuffer;
pub use openvnc_security::Password;

pub mod server;
pub use server::{PlainVerifier, Server, ServerConfig, ServerEvent};

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Versao de protocolo negociada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolVersion {
    /// RFB 003.003
    V3_3,
    /// RFB 003.007
    V3_7,
    /// RFB 003.008
    V3_8,
}

impl ProtocolVersion {
    fn banner(self) -> &'static [u8; 12] {
        match self {
            ProtocolVersion::V3_3 => b"RFB 003.003\n",
            ProtocolVersion::V3_7 => b"RFB 003.007\n",
            ProtocolVersion::V3_8 => b"RFB 003.008\n",
        }
    }

    /// Escolhe a versao a responder dado o banner do servidor.
    pub fn negotiate(banner: &[u8; 12]) -> Result<Self> {
        let bad = || Error::Protocol("banner RFB invalido".into());
        if &banner[..4] != b"RFB " || banner[7] != b'.' || banner[11] != b'\n' {
            return Err(bad());
        }
        let num = |s: &[u8]| -> Result<u32> {
            if !s.iter().all(u8::is_ascii_digit) {
                return Err(bad());
            }
            Ok(s.iter().fold(0, |a, d| a * 10 + u32::from(d - b'0')))
        };
        let major = num(&banner[4..7])?;
        let minor = num(&banner[8..11])?;
        Ok(match (major, minor) {
            (0..=2, _) => return Err(Error::Unsupported(format!("RFB {major}.{minor}"))),
            (3, 0..=6) => ProtocolVersion::V3_3,
            (3, 7) => ProtocolVersion::V3_7,
            _ => ProtocolVersion::V3_8,
        })
    }
}

/// Tipos de seguranca RFB.
pub mod security_type {
    /// Invalido / falha.
    pub const INVALID: u8 = 0;
    /// Sem autenticacao.
    pub const NONE: u8 = 1;
    /// VNC Authentication (DES, inseguro).
    pub const VNC_AUTH: u8 = 2;
    /// VeNCrypt (TLS + sub-tipo de autenticacao).
    pub const VENCRYPT: u8 = 19;
}

/// Sub-tipos VeNCrypt. So os `X509*` sao suportados: os `TLS*` usam
/// Diffie-Hellman anonimo (sem autenticacao do servidor, vulneravel a MITM)
/// e o rustls nao os implementa de proposito.
pub mod vencrypt {
    /// Usuario/senha sem TLS (recusado).
    pub const PLAIN: u32 = 256;
    /// TLS anonimo, sem auth (recusado).
    pub const TLS_NONE: u32 = 257;
    /// TLS anonimo + VNC Auth (recusado).
    pub const TLS_VNC: u32 = 258;
    /// TLS anonimo + usuario/senha (recusado).
    pub const TLS_PLAIN: u32 = 259;
    /// TLS com certificado, sem auth.
    pub const X509_NONE: u32 = 260;
    /// TLS com certificado + VNC Auth.
    pub const X509_VNC: u32 = 261;
    /// TLS com certificado + usuario/senha.
    pub const X509_PLAIN: u32 = 262;
}

/// Configuracao e limites do cliente.
#[derive(Debug, Clone)]
pub struct Config {
    /// Senha para VNC Auth (ou VeNCrypt X509Vnc/X509Plain).
    pub password: Option<Password>,
    /// Usuario para VeNCrypt X509Plain (com `password`). No servidor de
    /// referencia e o id do dispositivo pareado.
    pub username: Option<String>,
    /// Exigir VeNCrypt (TLS). Se o servidor nao oferecer, a conexao falha:
    /// **nunca** ha fallback para um tipo sem criptografia.
    pub require_tls: bool,
    /// Pedir sessao compartilhada no ClientInit.
    pub shared: bool,
    /// Limite do nome do desktop (bytes).
    pub max_name_len: u32,
    /// Limite de texto de clipboard (bytes).
    pub max_cut_text: u32,
    /// Limite de lado do framebuffer.
    pub max_dimension: u16,
    /// Limite de memoria do framebuffer.
    pub max_fb_bytes: u64,
    /// Limite de motivo de falha (bytes).
    pub max_reason_len: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            password: None,
            username: None,
            require_tls: false,
            shared: true,
            max_name_len: 4096,
            max_cut_text: 1024 * 1024,
            max_dimension: 16384,
            max_fb_bytes: openvnc_framebuffer::DEFAULT_MAX_BYTES,
            max_reason_len: 4096,
        }
    }
}

/// Eventos para a aplicacao.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Handshake concluido.
    Connected {
        /// Largura.
        width: u16,
        /// Altura.
        height: u16,
        /// Nome do desktop.
        name: String,
        /// Versao negociada.
        version: ProtocolVersion,
        /// Autenticacao usada.
        security: u8,
    },
    /// VeNCrypt negociado: o driver deve fazer o handshake TLS sobre o
    /// socket (depois de enviar `take_output`) e chamar
    /// [`Client::tls_established`]. Nada pode ser lido antes disso.
    StartTls,
    /// Um FramebufferUpdate completo foi aplicado.
    UpdateComplete,
    /// Bell.
    Bell,
    /// Clipboard do servidor (Latin-1 convertido).
    CutText(String),
    /// O servidor mudou o tamanho da tela (DesktopSize/ExtendedDesktopSize).
    /// O framebuffer foi recriado e uma atualizacao completa foi pedida.
    Resized {
        /// Largura nova.
        width: u16,
        /// Altura nova.
        height: u16,
    },
    /// Formato do cursor (pseudo-encoding Cursor). `rgba` tem
    /// `width * height * 4` bytes; alfa 0 onde a mascara e transparente.
    Cursor {
        /// Ponto quente x.
        hot_x: u16,
        /// Ponto quente y.
        hot_y: u16,
        /// Largura.
        width: u16,
        /// Altura.
        height: u16,
        /// Pixels RGBA.
        rgba: Vec<u8>,
    },
}

/// Encodings anunciados — apenas os implementados por completo.
pub const ANNOUNCED_ENCODINGS: [i32; 9] = [
    encoding::ZRLE,
    encoding::TIGHT,
    encoding::HEXTILE,
    encoding::COPY_RECT,
    encoding::RAW,
    encoding::CURSOR,
    encoding::EXTENDED_DESKTOP_SIZE,
    encoding::DESKTOP_SIZE,
    encoding::JPEG_QUALITY_8,
];

/// Maior cursor aceito (lado).
const MAX_CURSOR: u16 = 256;

#[derive(Debug)]
enum State {
    Version,
    SecurityTypes33,
    SecurityTypes,
    FailureReason,
    VeVersion,
    VeAck,
    VeSubtypes,
    VeSubAck,
    TlsPending,
    VncChallenge,
    SecurityResult,
    ServerInit,
    MessageType,
    UpdateHeader,
    RectHeader {
        remaining: u16,
    },
    RectData {
        remaining: u16,
        dec: RectDecoder,
    },
    Pseudo {
        remaining: u16,
        rect: Rect,
        enc: i32,
    },
    ColourMap,
    CutText,
    Failed,
}

/// Cliente RFB sans-IO.
#[derive(Debug)]
pub struct Client {
    cfg: Config,
    state: State,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    events: VecDeque<Event>,
    version: ProtocolVersion,
    security: u8,
    subtype: Option<u32>,
    pf: PixelFormat,
    fb: Option<Framebuffer>,
    codecs: CodecState,
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| char::from(c)).collect()
}

impl Client {
    /// Cria um cliente aguardando o banner do servidor.
    pub fn new(cfg: Config) -> Self {
        Client {
            cfg,
            state: State::Version,
            inbuf: Vec::new(),
            out: Vec::new(),
            events: VecDeque::new(),
            version: ProtocolVersion::V3_8,
            security: 0,
            subtype: None,
            pf: PixelFormat::RGBX8888,
            fb: None,
            codecs: CodecState::default(),
        }
    }

    /// Bytes a enviar ao servidor (esvazia o buffer).
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Proximo evento pendente.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Framebuffer (apos ServerInit).
    pub fn framebuffer(&self) -> Option<&Framebuffer> {
        self.fb.as_ref()
    }

    /// Framebuffer mutavel (ex.: para `take_damage`).
    pub fn framebuffer_mut(&mut self) -> Option<&mut Framebuffer> {
        self.fb.as_mut()
    }

    /// Sub-tipo VeNCrypt em uso (`None` = sem TLS).
    pub fn tls_subtype(&self) -> Option<u32> {
        self.subtype
    }

    /// Chamado pelo driver quando o handshake TLS terminou. Daqui em diante
    /// todos os bytes de `feed`/`take_output` passam pelo TLS.
    pub fn tls_established(&mut self) -> Result<()> {
        if !matches!(self.state, State::TlsPending) {
            return Err(Error::Protocol("tls_established fora de hora".into()));
        }
        self.state = match self.subtype {
            Some(vencrypt::X509_VNC) => State::VncChallenge,
            Some(vencrypt::X509_PLAIN) => {
                let user = self.cfg.username.clone().unwrap_or_default();
                let pw = self.cfg.password.clone().unwrap_or_default();
                self.out
                    .extend_from_slice(&(user.len() as u32).to_be_bytes());
                self.out
                    .extend_from_slice(&(pw.expose().len() as u32).to_be_bytes());
                self.out.extend_from_slice(user.as_bytes());
                self.out.extend_from_slice(pw.expose().as_bytes());
                State::SecurityResult
            }
            _ => State::SecurityResult,
        };
        self.feed(&[])
    }

    /// Handshake concluido?
    pub fn is_connected(&self) -> bool {
        self.fb.is_some() && !matches!(self.state, State::Failed)
    }

    /// Processa bytes recebidos. Apos um erro o cliente fica inutilizavel.
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        if matches!(self.state, State::Failed) {
            return Err(Error::Protocol("sessao encerrada por erro anterior".into()));
        }
        let mut buf = std::mem::take(&mut self.inbuf);
        buf.extend_from_slice(data);
        let mut pos = 0;
        let res = loop {
            match self.step(&buf[pos..]) {
                Ok(Some(n)) => pos += n,
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        buf.drain(..pos);
        self.inbuf = buf;
        if res.is_err() {
            self.state = State::Failed;
        }
        res
    }

    fn need(&self, buf: &[u8], n: usize) -> bool {
        buf.len() >= n
    }

    /// Um passo da maquina de estados. `Some(n)` = consumiu n bytes e
    /// pode continuar; `None` = precisa de mais dados.
    fn step(&mut self, buf: &[u8]) -> Result<Option<usize>> {
        let state = std::mem::replace(&mut self.state, State::Failed);
        let (next, used) = self.transition(state, buf)?;
        self.state = next;
        Ok(used)
    }

    fn transition(&mut self, state: State, b: &[u8]) -> Result<(State, Option<usize>)> {
        macro_rules! wait {
            ($s:expr) => {
                return Ok(($s, None))
            };
        }
        match state {
            State::Version => {
                if !self.need(b, 12) {
                    wait!(State::Version);
                }
                let banner: [u8; 12] = b[..12].try_into().expect("12 bytes");
                self.version = ProtocolVersion::negotiate(&banner)?;
                self.out.extend_from_slice(self.version.banner());
                tracing::debug!(version = ?self.version, "versao negociada");
                let next = if self.version == ProtocolVersion::V3_3 {
                    State::SecurityTypes33
                } else {
                    State::SecurityTypes
                };
                Ok((next, Some(12)))
            }
            State::SecurityTypes33 => {
                if !self.need(b, 4) {
                    wait!(State::SecurityTypes33);
                }
                let t = be32(b);
                if self.cfg.require_tls && t != 0 {
                    return Err(Error::Unsupported(
                        "servidor RFB 3.3 nao suporta VeNCrypt; TLS exigido, conexao recusada"
                            .into(),
                    ));
                }
                match t {
                    0 => Ok((State::FailureReason, Some(4))),
                    1 | 2 => {
                        let t = t as u8;
                        self.check_choice(t)?;
                        self.security = t;
                        Ok((self.after_security_chosen(), Some(4)))
                    }
                    other => Err(Error::Unsupported(format!("security type {other}"))),
                }
            }
            State::SecurityTypes => {
                if !self.need(b, 1) {
                    wait!(State::SecurityTypes);
                }
                let n = usize::from(b[0]);
                if n == 0 {
                    return Ok((State::FailureReason, Some(1)));
                }
                if !self.need(b, 1 + n) {
                    wait!(State::SecurityTypes);
                }
                let types = &b[1..1 + n];
                let chosen = if self.cfg.require_tls {
                    if !types.contains(&security_type::VENCRYPT) {
                        return Err(Error::Unsupported(format!(
                            "TLS exigido mas o servidor nao oferece VeNCrypt (tipos {types:?}); \
                             sem downgrade"
                        )));
                    }
                    security_type::VENCRYPT
                } else if types.contains(&security_type::NONE) {
                    security_type::NONE
                } else if types.contains(&security_type::VNC_AUTH) {
                    security_type::VNC_AUTH
                } else if types.contains(&security_type::VENCRYPT) {
                    return Err(Error::Unsupported(
                        "servidor so aceita VeNCrypt (TLS); ative o TLS no cliente".into(),
                    ));
                } else {
                    return Err(Error::Unsupported(format!(
                        "nenhum tipo de seguranca suportado: {types:?}"
                    )));
                };
                self.check_choice(chosen)?;
                self.security = chosen;
                self.out.push(chosen);
                Ok((self.after_security_chosen(), Some(1 + n)))
            }
            State::FailureReason => {
                if !self.need(b, 4) {
                    wait!(State::FailureReason);
                }
                let len = be32(b);
                check_limit(
                    "reason length",
                    u64::from(len),
                    u64::from(self.cfg.max_reason_len),
                )?;
                let len = len as usize;
                if !self.need(b, 4 + len) {
                    wait!(State::FailureReason);
                }
                let reason = String::from_utf8_lossy(&b[4..4 + len]).into_owned();
                Err(Error::Protocol(format!("servidor recusou: {reason}")))
            }
            State::VeVersion => {
                if !self.need(b, 2) {
                    wait!(State::VeVersion);
                }
                if (b[0], b[1]) < (0, 2) {
                    return Err(Error::Unsupported(format!(
                        "VeNCrypt {}.{} (minimo 0.2)",
                        b[0], b[1]
                    )));
                }
                self.out.extend_from_slice(&[0, 2]);
                Ok((State::VeAck, Some(2)))
            }
            State::VeAck => {
                if !self.need(b, 1) {
                    wait!(State::VeAck);
                }
                if b[0] != 0 {
                    return Err(Error::Protocol("servidor recusou VeNCrypt 0.2".into()));
                }
                Ok((State::VeSubtypes, Some(1)))
            }
            State::VeSubtypes => {
                if !self.need(b, 1) {
                    wait!(State::VeSubtypes);
                }
                let n = usize::from(b[0]);
                if !self.need(b, 1 + 4 * n) {
                    wait!(State::VeSubtypes);
                }
                let subs: Vec<u32> = (0..n).map(|i| be32(&b[1 + 4 * i..])).collect();
                let want: &[u32] = match (&self.cfg.username, &self.cfg.password) {
                    (Some(_), Some(_)) => &[vencrypt::X509_PLAIN],
                    (None, Some(_)) => &[vencrypt::X509_VNC, vencrypt::X509_PLAIN],
                    _ => &[vencrypt::X509_NONE],
                };
                let chosen = want.iter().copied().find(|t| subs.contains(t));
                let Some(chosen) = chosen else {
                    return Err(Error::Unsupported(format!(
                        "nenhum sub-tipo VeNCrypt com certificado compativel com as \
                         credenciais dadas (servidor oferece {subs:?})"
                    )));
                };
                if chosen == vencrypt::X509_PLAIN && self.cfg.username.is_none() {
                    // so senha: usuario padrao da senha de acesso remoto
                    self.cfg.username = Some("openvnc".into());
                }
                self.subtype = Some(chosen);
                self.out.extend_from_slice(&chosen.to_be_bytes());
                Ok((State::VeSubAck, Some(1 + 4 * n)))
            }
            State::VeSubAck => {
                if !self.need(b, 1) {
                    wait!(State::VeSubAck);
                }
                if b[0] != 1 {
                    return Err(Error::Protocol(
                        "servidor recusou o sub-tipo VeNCrypt".into(),
                    ));
                }
                self.events.push_back(Event::StartTls);
                Ok((State::TlsPending, Some(1)))
            }
            State::TlsPending => {
                if !b.is_empty() {
                    return Err(Error::Protocol(
                        "dados recebidos antes do handshake TLS".into(),
                    ));
                }
                wait!(State::TlsPending);
            }
            State::VncChallenge => {
                if !self.need(b, 16) {
                    wait!(State::VncChallenge);
                }
                let ch: [u8; 16] = b[..16].try_into().expect("16 bytes");
                let pw = self.cfg.password.as_ref().expect("checado em check_choice");
                self.out
                    .extend_from_slice(&openvnc_security::vnc_auth_response(pw, &ch));
                Ok((State::SecurityResult, Some(16)))
            }
            State::SecurityResult => {
                if !self.need(b, 4) {
                    wait!(State::SecurityResult);
                }
                match be32(b) {
                    0 => {
                        self.send_client_init();
                        Ok((State::ServerInit, Some(4)))
                    }
                    _ if self.version == ProtocolVersion::V3_8 => {
                        Ok((State::FailureReason, Some(4)))
                    }
                    _ => Err(Error::Protocol("autenticacao falhou".into())),
                }
            }
            State::ServerInit => {
                if !self.need(b, 24) {
                    wait!(State::ServerInit);
                }
                let w = be16(&b[0..]);
                let h = be16(&b[2..]);
                let max = u64::from(self.cfg.max_dimension);
                check_limit("framebuffer width", u64::from(w), max)?;
                check_limit("framebuffer height", u64::from(h), max)?;
                // valida o formato do servidor mesmo que pecamos outro
                PixelFormat::parse(b[4..20].try_into().expect("16 bytes"))?;
                let name_len = be32(&b[20..]);
                check_limit(
                    "desktop name",
                    u64::from(name_len),
                    u64::from(self.cfg.max_name_len),
                )?;
                let total = 24 + name_len as usize;
                if !self.need(b, total) {
                    wait!(State::ServerInit);
                }
                let name = String::from_utf8_lossy(&b[24..total]).into_owned();
                self.fb = Some(Framebuffer::new(w, h, self.cfg.max_fb_bytes)?);
                self.send_set_pixel_format();
                self.send_set_encodings();
                self.request_update(false, Rect::new(0, 0, w, h));
                self.events.push_back(Event::Connected {
                    width: w,
                    height: h,
                    name,
                    version: self.version,
                    security: self.security,
                });
                Ok((State::MessageType, Some(total)))
            }
            State::MessageType => {
                if !self.need(b, 1) {
                    wait!(State::MessageType);
                }
                match b[0] {
                    0 => Ok((State::UpdateHeader, Some(1))),
                    1 => Ok((State::ColourMap, Some(1))),
                    2 => {
                        self.events.push_back(Event::Bell);
                        Ok((State::MessageType, Some(1)))
                    }
                    3 => Ok((State::CutText, Some(1))),
                    t => Err(Error::Protocol(format!(
                        "mensagem de servidor desconhecida {t}"
                    ))),
                }
            }
            State::UpdateHeader => {
                if !self.need(b, 3) {
                    wait!(State::UpdateHeader);
                }
                let n = be16(&b[1..]);
                if n == 0 {
                    self.events.push_back(Event::UpdateComplete);
                    return Ok((State::MessageType, Some(3)));
                }
                Ok((State::RectHeader { remaining: n }, Some(3)))
            }
            State::RectHeader { remaining } => {
                if !self.need(b, 12) {
                    wait!(State::RectHeader { remaining });
                }
                let r = Rect::new(be16(b), be16(&b[2..]), be16(&b[4..]), be16(&b[6..]));
                let enc = be32(&b[8..]) as i32;
                tracing::trace!(?r, enc, "retangulo");
                if !ANNOUNCED_ENCODINGS.contains(&enc) {
                    return Err(Error::Protocol(format!("encoding nao anunciado {enc}")));
                }
                if enc < 0 {
                    return Ok((
                        State::Pseudo {
                            remaining,
                            rect: r,
                            enc,
                        },
                        Some(12),
                    ));
                }
                let fb = self.fb.as_ref().expect("fb existe apos ServerInit");
                if r.clip_to(fb.width(), fb.height()) != r {
                    return Err(Error::Protocol(format!("retangulo fora da tela {r:?}")));
                }
                let dec = RectDecoder::new(r, enc)?;
                Ok((State::RectData { remaining, dec }, Some(12)))
            }
            State::Pseudo {
                remaining,
                rect,
                enc,
            } => {
                let used = match enc {
                    encoding::CURSOR => {
                        let Some(n) = self.cursor(rect, b)? else {
                            wait!(State::Pseudo {
                                remaining,
                                rect,
                                enc
                            });
                        };
                        n
                    }
                    encoding::DESKTOP_SIZE => {
                        self.resize(rect.width, rect.height)?;
                        0
                    }
                    _ => {
                        // ExtendedDesktopSize: n telas, 3 de padding, 16*n
                        if !self.need(b, 4) {
                            wait!(State::Pseudo {
                                remaining,
                                rect,
                                enc
                            });
                        }
                        let total = 4 + 16 * usize::from(b[0]);
                        if !self.need(b, total) {
                            wait!(State::Pseudo {
                                remaining,
                                rect,
                                enc
                            });
                        }
                        // y = codigo de status; != 0 e recusa de um pedido nosso
                        if rect.y == 0 {
                            self.resize(rect.width, rect.height)?;
                        } else {
                            tracing::debug!(status = rect.y, "ExtendedDesktopSize recusado");
                        }
                        total
                    }
                };
                Ok((self.rect_done(remaining), Some(used)))
            }
            State::RectData { remaining, mut dec } => {
                let fb = self.fb.as_mut().expect("fb existe apos ServerInit");
                let p = dec.decode(b, &self.pf, fb, &mut self.codecs)?;
                if !p.done {
                    let used = (p.consumed > 0).then_some(p.consumed);
                    return Ok((State::RectData { remaining, dec }, used));
                }
                Ok((self.rect_done(remaining), Some(p.consumed)))
            }
            State::ColourMap => {
                if !self.need(b, 5) {
                    wait!(State::ColourMap);
                }
                let total = 5 + usize::from(be16(&b[3..])) * 6;
                if !self.need(b, total) {
                    wait!(State::ColourMap);
                }
                // Pedimos true-colour; o mapa e lido e ignorado.
                Ok((State::MessageType, Some(total)))
            }
            State::CutText => {
                if !self.need(b, 7) {
                    wait!(State::CutText);
                }
                let len = be32(&b[3..]);
                check_limit("cut text", u64::from(len), u64::from(self.cfg.max_cut_text))?;
                let total = 7 + len as usize;
                if !self.need(b, total) {
                    wait!(State::CutText);
                }
                self.events.push_back(Event::CutText(latin1(&b[7..total])));
                Ok((State::MessageType, Some(total)))
            }
            State::Failed => Err(Error::Protocol("estado de falha".into())),
        }
    }

    fn check_choice(&self, t: u8) -> Result<()> {
        if t == security_type::VNC_AUTH && self.cfg.password.is_none() {
            return Err(Error::Protocol("servidor exige senha (VNC Auth)".into()));
        }
        Ok(())
    }

    fn after_security_chosen(&mut self) -> State {
        if self.security == security_type::VENCRYPT {
            State::VeVersion
        } else if self.security == security_type::VNC_AUTH {
            State::VncChallenge
        } else if self.version == ProtocolVersion::V3_8 {
            State::SecurityResult
        } else {
            self.send_client_init();
            State::ServerInit
        }
    }

    fn send_client_init(&mut self) {
        self.out.push(u8::from(self.cfg.shared));
    }

    fn send_set_pixel_format(&mut self) {
        self.out.extend_from_slice(&[0, 0, 0, 0]);
        self.out.extend_from_slice(&self.pf.to_bytes());
    }

    fn rect_done(&mut self, remaining: u16) -> State {
        let left = remaining - 1;
        if left == 0 {
            self.events.push_back(Event::UpdateComplete);
            State::MessageType
        } else {
            State::RectHeader { remaining: left }
        }
    }

    fn resize(&mut self, w: u16, h: u16) -> Result<()> {
        let max = u64::from(self.cfg.max_dimension);
        check_limit("framebuffer width", u64::from(w), max)?;
        check_limit("framebuffer height", u64::from(h), max)?;
        if self
            .fb
            .as_ref()
            .is_some_and(|f| (f.width(), f.height()) == (w, h))
        {
            return Ok(());
        }
        self.fb = Some(Framebuffer::new(w, h, self.cfg.max_fb_bytes)?);
        self.events.push_back(Event::Resized {
            width: w,
            height: h,
        });
        self.request_update(false, Rect::new(0, 0, w, h));
        Ok(())
    }

    /// Decodifica o pseudo-retangulo Cursor; `None` se faltam bytes.
    fn cursor(&mut self, r: Rect, b: &[u8]) -> Result<Option<usize>> {
        check_limit("cursor width", u64::from(r.width), u64::from(MAX_CURSOR))?;
        check_limit("cursor height", u64::from(r.height), u64::from(MAX_CURSOR))?;
        let (w, h) = (usize::from(r.width), usize::from(r.height));
        let bpp = usize::from(self.pf.bits_per_pixel / 8);
        let mask_row = w.div_ceil(8);
        let total = w * h * bpp + mask_row * h;
        if !self.need(b, total) {
            return Ok(None);
        }
        let (px, mask) = b[..total].split_at(w * h * bpp);
        let mut rgba = Vec::with_capacity(w * h * 4);
        for y in 0..h {
            for x in 0..w {
                let i = (y * w + x) * bpp;
                let mut c = self.pf.to_rgba(self.pf.read_pixel(&px[i..i + bpp]));
                c[3] = if mask[y * mask_row + x / 8] & (0x80 >> (x % 8)) != 0 {
                    255
                } else {
                    0
                };
                rgba.extend(c);
            }
        }
        self.events.push_back(Event::Cursor {
            hot_x: r.x,
            hot_y: r.y,
            width: r.width,
            height: r.height,
            rgba,
        });
        Ok(Some(total))
    }

    fn send_set_encodings(&mut self) {
        self.out.extend_from_slice(&[2, 0]);
        self.out
            .extend_from_slice(&(ANNOUNCED_ENCODINGS.len() as u16).to_be_bytes());
        for e in ANNOUNCED_ENCODINGS {
            self.out.extend_from_slice(&e.to_be_bytes());
        }
    }

    /// FramebufferUpdateRequest.
    pub fn request_update(&mut self, incremental: bool, r: Rect) {
        self.out.extend_from_slice(&[3, u8::from(incremental)]);
        for v in [r.x, r.y, r.width, r.height] {
            self.out.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// Pedido incremental do framebuffer inteiro.
    pub fn request_incremental(&mut self) {
        if let Some(fb) = &self.fb {
            let r = Rect::new(0, 0, fb.width(), fb.height());
            self.request_update(true, r);
        }
    }

    /// KeyEvent.
    pub fn send_key(&mut self, k: KeyEvent) {
        self.out.extend_from_slice(&[4, u8::from(k.down), 0, 0]);
        self.out.extend_from_slice(&k.keysym.to_be_bytes());
    }

    /// PointerEvent.
    pub fn send_pointer(&mut self, p: PointerEvent) {
        self.out.extend_from_slice(&[5, p.buttons]);
        self.out.extend_from_slice(&p.x.to_be_bytes());
        self.out.extend_from_slice(&p.y.to_be_bytes());
    }

    /// ClientCutText (caracteres fora do Latin-1 viram '?').
    pub fn send_cut_text(&mut self, text: &str) {
        let bytes: Vec<u8> = text
            .chars()
            .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
            .collect();
        let len = bytes.len().min(self.cfg.max_cut_text as usize);
        self.out.extend_from_slice(&[6, 0, 0, 0]);
        self.out.extend_from_slice(&(len as u32).to_be_bytes());
        self.out.extend_from_slice(&bytes[..len]);
    }
}

#[cfg(test)]
mod tests;
