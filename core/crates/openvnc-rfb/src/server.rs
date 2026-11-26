//! Lado servidor do RFB (RFC 6143) como maquina de estados *sans-IO*.
//!
//! O servidor anuncia RFB 3.8 e aceita clientes 3.3, 3.7 e 3.8. O desafio
//! do VNC Auth e fornecido pelo chamador (vindo de um CSPRNG), para manter
//! este modulo deterministico e testavel.

use std::collections::VecDeque;

use openvnc_codecs::{encode, encoding, EncoderState};
use openvnc_core::{check_limit, Error, KeyEvent, PixelFormat, PointerEvent, Rect, Result};
use openvnc_framebuffer::Framebuffer;
use openvnc_security::{vnc_auth_response, Password};

use crate::{be16, be32, latin1, security_type, vencrypt, ProtocolVersion};

/// Verificador de usuario/senha do VeNCrypt X509Plain
/// (`(usuario, senha) -> aceito`). No servidor de referencia consulta o
/// armazenamento de dispositivos pareados.
#[derive(Clone)]
pub struct PlainVerifier(pub std::sync::Arc<PlainFn>);

/// `(usuario, senha) -> aceito?`
pub type PlainFn = dyn Fn(&str, &[u8]) -> bool + Send + Sync;

impl std::fmt::Debug for PlainVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlainVerifier(..)")
    }
}

/// Limite de usuario/senha no X509Plain.
const MAX_PLAIN_FIELD: u32 = 1024;

/// Configuracao do servidor por conexao.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Senha (VNC Auth). `None` exige `allow_no_auth`.
    pub password: Option<Password>,
    /// Permitir conexao sem autenticacao (inseguro; desligado por padrao).
    pub allow_no_auth: bool,
    /// Nome do desktop.
    pub name: String,
    /// Desafio VNC Auth (16 bytes aleatorios do chamador).
    pub challenge: [u8; 16],
    /// Limite de texto de clipboard (bytes).
    pub max_cut_text: u32,
    /// Limite de encodings no SetEncodings.
    pub max_encodings: u16,
    /// Oferecer VeNCrypt (o driver precisa ter uma identidade TLS).
    pub vencrypt: bool,
    /// Oferecer **somente** VeNCrypt: tipos sem TLS nao sao anunciados.
    pub require_tls: bool,
    /// Habilita o sub-tipo X509Plain (usuario/senha dentro do TLS).
    pub plain: Option<PlainVerifier>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            password: None,
            allow_no_auth: false,
            name: "OpenVNC".into(),
            challenge: [0; 16],
            max_cut_text: 1024 * 1024,
            max_encodings: 1024,
            vencrypt: false,
            require_tls: false,
            plain: None,
        }
    }
}

/// Eventos recebidos do cliente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    /// Handshake concluido (ClientInit recebido).
    Initialized {
        /// Cliente pediu sessao compartilhada.
        shared: bool,
        /// Versao negociada.
        version: ProtocolVersion,
    },
    /// Autenticacao recusada (a conexao deve ser fechada apos enviar a saida).
    AuthFailed,
    /// VeNCrypt negociado: o driver envia `take_output`, faz o handshake
    /// TLS (lado servidor) e chama [`Server::tls_established`].
    StartTls,
    /// Tentativa de login X509Plain (para auditoria).
    PlainLogin {
        /// Usuario informado.
        username: String,
        /// Aceito pelo verificador.
        accepted: bool,
    },
    /// Novo formato de pixel.
    PixelFormatChanged(PixelFormat),
    /// Lista de encodings do cliente.
    Encodings(Vec<i32>),
    /// FramebufferUpdateRequest.
    UpdateRequest {
        /// Incremental.
        incremental: bool,
        /// Area pedida.
        rect: Rect,
    },
    /// Tecla.
    Key(KeyEvent),
    /// Ponteiro.
    Pointer(PointerEvent),
    /// Clipboard do cliente.
    CutText(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SState {
    Version,
    SecurityChoice,
    VncResponse,
    VeVersion,
    VeSubtype,
    TlsPending,
    PlainCreds,
    ClientInit,
    MessageType,
    Failed,
}

/// Servidor RFB sans-IO (uma instancia por conexao).
#[derive(Debug)]
pub struct Server {
    cfg: ServerConfig,
    state: SState,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    events: VecDeque<ServerEvent>,
    version: ProtocolVersion,
    pf: PixelFormat,
    encodings: Vec<i32>,
    width: u16,
    height: u16,
    enc: EncoderState,
    subtype: Option<u32>,
    /// Sessao sem autenticacao (None ou X509None).
    no_auth: bool,
}

impl Server {
    /// Cria o servidor e ja enfileira o banner `RFB 003.008`.
    /// Falha se nao houver senha nem `allow_no_auth`.
    pub fn new(cfg: ServerConfig, width: u16, height: u16) -> Result<Self> {
        if cfg.require_tls && !cfg.vencrypt {
            return Err(Error::Protocol("require_tls exige vencrypt".into()));
        }
        if cfg.plain.is_some() && !cfg.vencrypt {
            return Err(Error::Protocol(
                "X509Plain so existe dentro do VeNCrypt".into(),
            ));
        }
        if cfg.password.is_none() && !cfg.allow_no_auth && cfg.plain.is_none() {
            return Err(Error::Protocol(
                "servidor sem senha exige allow_no_auth".into(),
            ));
        }
        Ok(Server {
            cfg,
            state: SState::Version,
            inbuf: Vec::new(),
            out: ProtocolVersion::V3_8.banner().to_vec(),
            events: VecDeque::new(),
            version: ProtocolVersion::V3_8,
            pf: PixelFormat::RGBX8888,
            encodings: vec![encoding::RAW],
            width,
            height,
            enc: EncoderState::default(),
            subtype: None,
            no_auth: false,
        })
    }

    /// Bytes a enviar ao cliente.
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Ha bytes pendentes de envio?
    pub fn has_output(&self) -> bool {
        !self.out.is_empty()
    }

    /// Proximo evento.
    pub fn poll_event(&mut self) -> Option<ServerEvent> {
        self.events.pop_front()
    }

    /// Handshake concluido?
    pub fn is_ready(&self) -> bool {
        self.state == SState::MessageType
    }

    /// Formato de pixel atual do cliente.
    pub fn pixel_format(&self) -> &PixelFormat {
        &self.pf
    }

    /// Cliente aceita o encoding `e`?
    pub fn supports(&self, e: i32) -> bool {
        self.encodings.contains(&e)
    }

    /// Melhor encoding de pixels que este servidor sabe gerar, na ordem
    /// de preferencia do cliente.
    pub fn preferred_encoding(&self) -> i32 {
        self.encodings
            .iter()
            .copied()
            .find(|e| matches!(*e, encoding::ZRLE | encoding::HEXTILE | encoding::RAW))
            .unwrap_or(encoding::RAW)
    }

    /// Entrega bytes recebidos.
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        if self.state == SState::Failed {
            return Err(Error::Protocol("sessao encerrada".into()));
        }
        self.inbuf.extend_from_slice(data);
        let buf = std::mem::take(&mut self.inbuf);
        let mut pos = 0;
        let res = loop {
            match self.step(&buf[pos..]) {
                Ok(0) => break Ok(()),
                Ok(n) => pos += n,
                Err(e) => break Err(e),
            }
        };
        self.inbuf = buf;
        self.inbuf.drain(..pos);
        if res.is_err() {
            self.state = SState::Failed;
        }
        res
    }

    fn fail_auth(&mut self, reason: &str) -> usize {
        if self.version == ProtocolVersion::V3_8 {
            self.out.extend_from_slice(&1u32.to_be_bytes());
            self.out
                .extend_from_slice(&(reason.len() as u32).to_be_bytes());
            self.out.extend_from_slice(reason.as_bytes());
        } else {
            self.out.extend_from_slice(&1u32.to_be_bytes());
        }
        self.events.push_back(ServerEvent::AuthFailed);
        self.state = SState::Failed;
        0
    }

    /// Sub-tipo VeNCrypt em uso (`None` = sem TLS).
    pub fn tls_subtype(&self) -> Option<u32> {
        self.subtype
    }

    /// O cliente entrou sem credencial (tipo None ou X509None).
    pub fn unauthenticated(&self) -> bool {
        self.no_auth
    }

    /// Chamado pelo driver quando o handshake TLS terminou.
    pub fn tls_established(&mut self) -> Result<()> {
        if self.state != SState::TlsPending {
            return Err(Error::Protocol("tls_established fora de hora".into()));
        }
        self.state = match self.subtype {
            Some(vencrypt::X509_VNC) => {
                self.out.extend_from_slice(&self.cfg.challenge);
                SState::VncResponse
            }
            Some(vencrypt::X509_PLAIN) => SState::PlainCreds,
            _ => {
                self.no_auth = true;
                self.out.extend_from_slice(&0u32.to_be_bytes());
                SState::ClientInit
            }
        };
        self.feed(&[])
    }

    fn subtypes(&self) -> Vec<u32> {
        let mut v = Vec::new();
        if self.cfg.plain.is_some() {
            v.push(vencrypt::X509_PLAIN);
        }
        if self.cfg.password.is_some() {
            v.push(vencrypt::X509_VNC);
        }
        if self.cfg.allow_no_auth {
            v.push(vencrypt::X509_NONE);
        }
        v
    }

    fn offered(&self) -> Vec<u8> {
        let mut v = Vec::new();
        if self.cfg.vencrypt {
            v.push(security_type::VENCRYPT);
        }
        if self.cfg.require_tls {
            return v;
        }
        if self.cfg.password.is_some() {
            v.push(security_type::VNC_AUTH);
        }
        if self.cfg.allow_no_auth {
            v.push(security_type::NONE);
        }
        v
    }

    fn start_security(&mut self, t: u8) {
        if t == security_type::VENCRYPT {
            self.out.extend_from_slice(&[0, 2]);
            self.state = SState::VeVersion;
        } else if t == security_type::VNC_AUTH {
            self.out.extend_from_slice(&self.cfg.challenge);
            self.state = SState::VncResponse;
        } else {
            self.no_auth = true;
            if self.version == ProtocolVersion::V3_8 {
                self.out.extend_from_slice(&0u32.to_be_bytes());
            }
            self.state = SState::ClientInit;
        }
    }

    /// Processa um passo; retorna bytes consumidos (0 = faltam dados).
    fn step(&mut self, b: &[u8]) -> Result<usize> {
        match self.state {
            SState::Version => {
                if b.len() < 12 {
                    return Ok(0);
                }
                let banner: [u8; 12] = b[..12].try_into().unwrap_or([0; 12]);
                self.version = ProtocolVersion::negotiate(&banner)?;
                let offered = self.offered();
                if self.version == ProtocolVersion::V3_3 {
                    // 3.3: o servidor escolhe o tipo (u32); VeNCrypt nao
                    // existe no 3.3
                    let Some(&t) = offered.iter().find(|t| **t != security_type::VENCRYPT) else {
                        self.out.extend_from_slice(&0u32.to_be_bytes());
                        let r = "TLS obrigatorio; cliente RFB 3.3 recusado";
                        self.out.extend_from_slice(&(r.len() as u32).to_be_bytes());
                        self.out.extend_from_slice(r.as_bytes());
                        self.state = SState::Failed;
                        return Err(Error::Unsupported(r.into()));
                    };
                    self.out.extend_from_slice(&u32::from(t).to_be_bytes());
                    self.start_security(t);
                } else {
                    self.out.push(offered.len() as u8);
                    self.out.extend_from_slice(&offered);
                    self.state = SState::SecurityChoice;
                }
                Ok(12)
            }
            SState::SecurityChoice => {
                let Some(&t) = b.first() else { return Ok(0) };
                if !self.offered().contains(&t) {
                    self.fail_auth("tipo de seguranca nao oferecido");
                    return Err(Error::Protocol(format!("security type {t} recusado")));
                }
                self.start_security(t);
                Ok(1)
            }
            SState::VncResponse => {
                if b.len() < 16 {
                    return Ok(0);
                }
                let ok = match &self.cfg.password {
                    Some(p) => {
                        let expect = vnc_auth_response(p, &self.cfg.challenge);
                        // comparacao em tempo constante
                        expect
                            .iter()
                            .zip(&b[..16])
                            .fold(0u8, |a, (x, y)| a | (x ^ y))
                            == 0
                    }
                    None => false,
                };
                if !ok {
                    self.fail_auth("autenticacao falhou");
                    return Err(Error::Protocol("autenticacao falhou".into()));
                }
                self.out.extend_from_slice(&0u32.to_be_bytes());
                self.state = SState::ClientInit;
                Ok(16)
            }
            SState::VeVersion => {
                if b.len() < 2 {
                    return Ok(0);
                }
                if (b[0], b[1]) != (0, 2) {
                    self.out.push(255);
                    self.state = SState::Failed;
                    return Err(Error::Unsupported(format!(
                        "VeNCrypt {}.{} do cliente",
                        b[0], b[1]
                    )));
                }
                let subs = self.subtypes();
                self.out.push(0);
                self.out.push(subs.len() as u8);
                for t in subs {
                    self.out.extend_from_slice(&t.to_be_bytes());
                }
                self.state = SState::VeSubtype;
                Ok(2)
            }
            SState::VeSubtype => {
                if b.len() < 4 {
                    return Ok(0);
                }
                let t = be32(b);
                if !self.subtypes().contains(&t) {
                    self.out.push(0);
                    self.events.push_back(ServerEvent::AuthFailed);
                    self.state = SState::Failed;
                    return Err(Error::Protocol(format!("sub-tipo VeNCrypt {t} recusado")));
                }
                self.out.push(1);
                self.subtype = Some(t);
                self.events.push_back(ServerEvent::StartTls);
                self.state = SState::TlsPending;
                Ok(4)
            }
            SState::TlsPending => {
                if b.is_empty() {
                    Ok(0)
                } else {
                    Err(Error::Protocol("dados antes do handshake TLS".into()))
                }
            }
            SState::PlainCreds => {
                if b.len() < 8 {
                    return Ok(0);
                }
                let ulen = be32(b);
                let plen = be32(&b[4..]);
                check_limit("usuario", u64::from(ulen), u64::from(MAX_PLAIN_FIELD))?;
                check_limit("senha", u64::from(plen), u64::from(MAX_PLAIN_FIELD))?;
                let total = 8 + ulen as usize + plen as usize;
                if b.len() < total {
                    return Ok(0);
                }
                let user = String::from_utf8_lossy(&b[8..8 + ulen as usize]).into_owned();
                let pass = &b[8 + ulen as usize..total];
                let ok = self.cfg.plain.as_ref().is_some_and(|v| (v.0)(&user, pass));
                self.events.push_back(ServerEvent::PlainLogin {
                    username: user,
                    accepted: ok,
                });
                if !ok {
                    self.fail_auth("autenticacao falhou");
                    return Err(Error::Protocol("autenticacao falhou".into()));
                }
                self.out.extend_from_slice(&0u32.to_be_bytes());
                self.state = SState::ClientInit;
                Ok(total)
            }
            SState::ClientInit => {
                let Some(&shared) = b.first() else {
                    return Ok(0);
                };
                self.send_server_init();
                self.state = SState::MessageType;
                self.events.push_back(ServerEvent::Initialized {
                    shared: shared != 0,
                    version: self.version,
                });
                Ok(1)
            }
            SState::MessageType => self.message(b),
            SState::Failed => Err(Error::Protocol("estado de falha".into())),
        }
    }

    fn message(&mut self, b: &[u8]) -> Result<usize> {
        let Some(&t) = b.first() else { return Ok(0) };
        match t {
            0 => {
                if b.len() < 20 {
                    return Ok(0);
                }
                let raw: [u8; 16] = b[4..20].try_into().unwrap_or([0; 16]);
                let pf = PixelFormat::parse(&raw)?;
                if !pf.true_colour {
                    return Err(Error::Unsupported("colour map".into()));
                }
                self.pf = pf;
                self.events.push_back(ServerEvent::PixelFormatChanged(pf));
                Ok(20)
            }
            2 => {
                if b.len() < 4 {
                    return Ok(0);
                }
                let n = be16(&b[2..]);
                check_limit("encodings", u64::from(n), u64::from(self.cfg.max_encodings))?;
                let len = 4 + usize::from(n) * 4;
                if b.len() < len {
                    return Ok(0);
                }
                self.encodings = b[4..len].chunks_exact(4).map(|c| be32(c) as i32).collect();
                self.events
                    .push_back(ServerEvent::Encodings(self.encodings.clone()));
                Ok(len)
            }
            3 => {
                if b.len() < 10 {
                    return Ok(0);
                }
                let rect = Rect::new(be16(&b[2..]), be16(&b[4..]), be16(&b[6..]), be16(&b[8..]))
                    .clip_to(self.width, self.height);
                self.events.push_back(ServerEvent::UpdateRequest {
                    incremental: b[1] != 0,
                    rect,
                });
                Ok(10)
            }
            4 => {
                if b.len() < 8 {
                    return Ok(0);
                }
                self.events.push_back(ServerEvent::Key(KeyEvent {
                    keysym: be32(&b[4..]),
                    down: b[1] != 0,
                }));
                Ok(8)
            }
            5 => {
                if b.len() < 6 {
                    return Ok(0);
                }
                self.events.push_back(ServerEvent::Pointer(PointerEvent {
                    buttons: b[1],
                    x: be16(&b[2..]),
                    y: be16(&b[4..]),
                }));
                Ok(6)
            }
            6 => {
                if b.len() < 8 {
                    return Ok(0);
                }
                let n = be32(&b[4..]);
                check_limit("cut text", u64::from(n), u64::from(self.cfg.max_cut_text))?;
                let len = 8 + n as usize;
                if b.len() < len {
                    return Ok(0);
                }
                self.events
                    .push_back(ServerEvent::CutText(latin1(&b[8..len])));
                Ok(len)
            }
            other => Err(Error::Protocol(format!("mensagem de cliente {other}"))),
        }
    }

    fn send_server_init(&mut self) {
        self.out.extend_from_slice(&self.width.to_be_bytes());
        self.out.extend_from_slice(&self.height.to_be_bytes());
        self.out
            .extend_from_slice(&PixelFormat::RGBX8888.to_bytes());
        let name = self.cfg.name.as_bytes();
        self.out
            .extend_from_slice(&(name.len() as u32).to_be_bytes());
        self.out.extend_from_slice(name);
    }

    /// Envia um FramebufferUpdate com `copies` (CopyRect: destino, origem)
    /// seguidos de `rects` codificados no encoding preferido do cliente.
    pub fn send_update(
        &mut self,
        fb: &Framebuffer,
        copies: &[(Rect, u16, u16)],
        rects: &[Rect],
    ) -> Result<()> {
        let use_copy = self.supports(encoding::COPY_RECT);
        let copies: &[(Rect, u16, u16)] = if use_copy { copies } else { &[] };
        let n = copies.len() + rects.len();
        let n = u16::try_from(n).map_err(|_| Error::Protocol("retangulos demais".into()))?;
        self.out.extend_from_slice(&[0, 0]);
        self.out.extend_from_slice(&n.to_be_bytes());
        for (dst, sx, sy) in copies {
            encode::encode_copy_rect(*dst, *sx, *sy, &mut self.out);
        }
        let enc = self.preferred_encoding();
        let pf = self.pf;
        for r in rects {
            self.enc.encode_rect(fb, *r, enc, &pf, &mut self.out)?;
        }
        Ok(())
    }

    /// Envia DesktopSize (-223) se o cliente aceitar; retorna se enviou.
    pub fn send_desktop_size(&mut self, width: u16, height: u16) -> bool {
        if !self.supports(encoding::DESKTOP_SIZE) {
            return false;
        }
        self.width = width;
        self.height = height;
        self.out.extend_from_slice(&[0, 0, 0, 1]);
        encode::write_rect_header(
            Rect::new(0, 0, width, height),
            encoding::DESKTOP_SIZE,
            &mut self.out,
        );
        true
    }

    /// Bell.
    pub fn send_bell(&mut self) {
        self.out.push(2);
    }

    /// ServerCutText (caracteres fora do Latin-1 viram '?').
    pub fn send_cut_text(&mut self, text: &str) {
        let bytes: Vec<u8> = text
            .chars()
            .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
            .collect();
        let len = bytes.len().min(self.cfg.max_cut_text as usize);
        self.out.extend_from_slice(&[3, 0, 0, 0]);
        self.out.extend_from_slice(&(len as u32).to_be_bytes());
        self.out.extend_from_slice(&bytes[..len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Client, Config, Event};
    use openvnc_framebuffer::DEFAULT_MAX_BYTES;

    fn pump(c: &mut Client, s: &mut Server) {
        for _ in 0..20 {
            let a = s.take_output();
            if !a.is_empty() {
                c.feed(&a).unwrap();
            }
            let b = c.take_output();
            if !b.is_empty() {
                let _ = s.feed(&b);
            }
            if a.is_empty() && b.is_empty() {
                break;
            }
        }
    }

    fn scene() -> Framebuffer {
        let mut fb = Framebuffer::new(100, 60, DEFAULT_MAX_BYTES).unwrap();
        fb.fill_rect(Rect::new(0, 0, 100, 60), [0, 0, 80, 255]);
        fb.fill_rect(Rect::new(10, 10, 30, 20), [250, 250, 0, 255]);
        fb
    }

    fn session(pw: Option<&str>, client_pw: Option<&str>) -> (Client, Server) {
        let cfg = ServerConfig {
            password: pw.map(Password::new),
            allow_no_auth: pw.is_none(),
            challenge: *b"0123456789abcdef",
            ..Default::default()
        };
        let s = Server::new(cfg, 100, 60).unwrap();
        let c = Client::new(Config {
            password: client_pw.map(Password::new),
            ..Default::default()
        });
        (c, s)
    }

    /// Simula o TLS: bytes passam direto; nos eventos StartTls os dois lados
    /// sao "promovidos".
    fn pump_tls(c: &mut Client, s: &mut Server) -> Vec<ServerEvent> {
        let mut sev = Vec::new();
        let (mut ctls, mut stls) = (false, false);
        for _ in 0..40 {
            let a = s.take_output();
            if !a.is_empty() && c.feed(&a).is_err() {
                break;
            }
            while let Some(e) = c.poll_event() {
                if e == Event::StartTls {
                    ctls = true;
                }
            }
            let b = c.take_output();
            if !b.is_empty() {
                let _ = s.feed(&b);
            }
            while let Some(e) = s.poll_event() {
                if e == ServerEvent::StartTls {
                    stls = true;
                }
                sev.push(e);
            }
            if ctls && stls {
                ctls = false;
                stls = false;
                s.tls_established().unwrap();
                c.tls_established().unwrap();
                continue;
            }
            if a.is_empty() && b.is_empty() {
                break;
            }
        }
        sev
    }

    fn tls_server(pw: Option<&str>, plain: bool, require: bool) -> Server {
        let verifier = PlainVerifier(std::sync::Arc::new(|u: &str, p: &[u8]| {
            u == "dev1" && p == b"tok"
        }));
        Server::new(
            ServerConfig {
                password: pw.map(Password::new),
                vencrypt: true,
                require_tls: require,
                plain: plain.then_some(verifier),
                challenge: *b"0123456789abcdef",
                ..Default::default()
            },
            100,
            60,
        )
        .unwrap()
    }

    #[test]
    fn vencrypt_x509vnc() {
        let mut s = tls_server(Some("pw"), false, true);
        let mut c = Client::new(Config {
            password: Some(Password::new("pw")),
            require_tls: true,
            ..Default::default()
        });
        pump_tls(&mut c, &mut s);
        assert!(s.is_ready());
        assert!(c.is_connected());
        assert_eq!(c.tls_subtype(), Some(vencrypt::X509_VNC));
        assert_eq!(s.tls_subtype(), Some(vencrypt::X509_VNC));
    }

    #[test]
    fn vencrypt_x509plain_device() {
        let mut s = tls_server(None, true, true);
        let mut c = Client::new(Config {
            username: Some("dev1".into()),
            password: Some(Password::new("tok")),
            require_tls: true,
            ..Default::default()
        });
        let ev = pump_tls(&mut c, &mut s);
        assert!(s.is_ready() && c.is_connected());
        assert!(ev.contains(&ServerEvent::PlainLogin {
            username: "dev1".into(),
            accepted: true
        }));
        // token errado
        let mut s = tls_server(None, true, true);
        let mut c = Client::new(Config {
            username: Some("dev1".into()),
            password: Some(Password::new("x")),
            require_tls: true,
            ..Default::default()
        });
        let ev = pump_tls(&mut c, &mut s);
        assert!(!s.is_ready() && !c.is_connected());
        assert!(ev.contains(&ServerEvent::AuthFailed));
    }

    #[test]
    fn no_silent_downgrade() {
        // cliente exige TLS, servidor sem VeNCrypt -> erro
        let (_, mut s) = session(Some("pw"), None);
        let mut c = Client::new(Config {
            password: Some(Password::new("pw")),
            require_tls: true,
            ..Default::default()
        });
        let a = s.take_output();
        c.feed(&a).unwrap();
        s.feed(&c.take_output()).unwrap();
        let e = c.feed(&s.take_output()).unwrap_err();
        assert!(e.to_string().contains("sem downgrade"), "{e}");
        assert!(c.take_output().is_empty() || !c.is_connected());
        // servidor exige TLS: nao anuncia VNC Auth
        let mut s = tls_server(Some("pw"), false, true);
        assert_eq!(s.offered(), vec![security_type::VENCRYPT]);
        // cliente sem TLS contra servidor so-TLS -> erro claro
        let mut c = Client::new(Config {
            password: Some(Password::new("pw")),
            ..Default::default()
        });
        c.feed(&s.take_output()).unwrap();
        s.feed(&c.take_output()).unwrap();
        let e = c.feed(&s.take_output()).unwrap_err();
        assert!(e.to_string().contains("ative o TLS"), "{e}");
        // dados em claro durante TlsPending sao erro
        let mut s = tls_server(Some("pw"), false, true);
        let mut c = Client::new(Config {
            password: Some(Password::new("pw")),
            require_tls: true,
            ..Default::default()
        });
        for _ in 0..6 {
            let a = s.take_output();
            let _ = c.feed(&a);
            let b = c.take_output();
            let _ = s.feed(&b);
        }
        assert_eq!(s.state, SState::TlsPending);
        assert!(s.feed(b"x").is_err());
    }

    #[test]
    fn client_server_full_session() {
        let (mut c, mut s) = session(Some("segredo"), Some("segredo"));
        pump(&mut c, &mut s);
        assert!(s.is_ready());
        assert!(matches!(
            c.poll_event(),
            Some(Event::Connected { width: 100, .. })
        ));
        // o cliente envia SetPixelFormat/SetEncodings/Request no connect
        let mut got_req = false;
        while let Some(e) = s.poll_event() {
            if let ServerEvent::UpdateRequest { incremental, rect } = e {
                assert!(!incremental);
                assert_eq!(rect, Rect::new(0, 0, 100, 60));
                got_req = true;
            }
        }
        assert!(got_req);
        assert_eq!(s.preferred_encoding(), encoding::ZRLE);
        let fb = scene();
        s.send_update(&fb, &[], &[Rect::new(0, 0, 100, 60)])
            .unwrap();
        // CopyRect + ZRLE incremental no mesmo stream
        s.send_update(
            &fb,
            &[(Rect::new(50, 30, 30, 20), 10, 10)],
            &[Rect::new(0, 0, 8, 8)],
        )
        .unwrap();
        pump(&mut c, &mut s);
        let mut want = fb.clone();
        want.copy_rect(10, 10, Rect::new(50, 30, 30, 20));
        assert_eq!(c.framebuffer().unwrap().data(), want.data());
    }

    #[test]
    fn wrong_password_rejected_with_reason() {
        let (mut c, mut s) = session(Some("certa"), Some("errada"));
        let mut client_err = None;
        for _ in 0..10 {
            if let Err(e) = c.feed(&s.take_output()) {
                client_err = Some(e);
                break;
            }
            let _ = s.feed(&c.take_output());
        }
        assert_eq!(s.poll_event(), Some(ServerEvent::AuthFailed));
        let err = client_err.expect("cliente deveria falhar");
        assert!(err.to_string().contains("autenticacao falhou"), "{err}");
    }

    #[test]
    fn no_auth_requires_opt_in() {
        assert!(Server::new(ServerConfig::default(), 10, 10).is_err());
    }

    #[test]
    fn legacy_versions() {
        for banner in [b"RFB 003.003\n", b"RFB 003.007\n"] {
            let (_, mut s) = session(None, None);
            s.take_output();
            s.feed(banner).unwrap();
            let out = s.take_output();
            if banner[10] == b'3' {
                assert_eq!(out, 1u32.to_be_bytes()); // tipo None escolhido
            } else {
                assert_eq!(out, [1, 1]);
                s.feed(&[1]).unwrap();
                assert!(s.take_output().is_empty()); // 3.7: sem SecurityResult
            }
            s.feed(&[1]).unwrap();
            assert!(s.is_ready());
        }
    }

    #[test]
    fn input_messages_and_limits() {
        let (mut c, mut s) = session(None, None);
        pump(&mut c, &mut s);
        while s.poll_event().is_some() {}
        c.send_key(KeyEvent {
            keysym: 0x61,
            down: true,
        });
        c.send_pointer(PointerEvent {
            buttons: 1,
            x: 5,
            y: 6,
        });
        c.send_cut_text("olá");
        let bytes = c.take_output();
        // entrega byte a byte (retomavel)
        for b in &bytes {
            s.feed(&[*b]).unwrap();
        }
        assert_eq!(
            s.poll_event(),
            Some(ServerEvent::Key(KeyEvent {
                keysym: 0x61,
                down: true
            }))
        );
        assert!(matches!(s.poll_event(), Some(ServerEvent::Pointer(_))));
        assert_eq!(s.poll_event(), Some(ServerEvent::CutText("olá".into())));
        // cut text gigante
        assert!(s.feed(&[6, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]).is_err());
    }
}
