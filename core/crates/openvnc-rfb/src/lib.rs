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
}

/// Configuracao e limites do cliente.
#[derive(Debug, Clone)]
pub struct Config {
    /// Senha para VNC Auth.
    pub password: Option<Password>,
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
    /// Um FramebufferUpdate completo foi aplicado.
    UpdateComplete,
    /// Bell.
    Bell,
    /// Clipboard do servidor (Latin-1 convertido).
    CutText(String),
}

/// Encodings anunciados — apenas os implementados por completo.
pub const ANNOUNCED_ENCODINGS: [i32; 4] = [
    encoding::ZRLE,
    encoding::HEXTILE,
    encoding::COPY_RECT,
    encoding::RAW,
];

#[derive(Debug)]
enum State {
    Version,
    SecurityTypes33,
    SecurityTypes,
    FailureReason,
    VncChallenge,
    SecurityResult,
    ServerInit,
    MessageType,
    UpdateHeader,
    RectHeader { remaining: u16 },
    RectData { remaining: u16, dec: RectDecoder },
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
                let chosen = if types.contains(&security_type::NONE) {
                    security_type::NONE
                } else if types.contains(&security_type::VNC_AUTH) {
                    security_type::VNC_AUTH
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
                let dec = RectDecoder::new(r, enc)?;
                Ok((State::RectData { remaining, dec }, Some(12)))
            }
            State::RectData { remaining, mut dec } => {
                let fb = self.fb.as_mut().expect("fb existe apos ServerInit");
                let p = dec.decode(b, &self.pf, fb, &mut self.codecs)?;
                if !p.done {
                    let used = (p.consumed > 0).then_some(p.consumed);
                    return Ok((State::RectData { remaining, dec }, used));
                }
                let left = remaining - 1;
                let next = if left == 0 {
                    self.events.push_back(Event::UpdateComplete);
                    State::MessageType
                } else {
                    State::RectHeader { remaining: left }
                };
                Ok((next, Some(p.consumed)))
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
        if self.security == security_type::VNC_AUTH {
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
