//! Cliente do protocolo nativo OpenVNC (RFC 0001).
//!
//! Tenta QUIC primeiro e, se falhar (UDP bloqueado, por exemplo), cai para
//! TCP+TLS na mesma porta. A verificacao do certificado e a mesma nos dois
//! transportes ([`ClientTls`]), entao o fallback nunca reduz a seguranca.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use crate::files::{self, Inbound};
use openvnc_core::{Error, Rect, Result};
use openvnc_framebuffer::{Framebuffer, DEFAULT_MAX_BYTES};
use openvnc_protocol::io::{read_message, write_message};
use openvnc_protocol::{
    auth_method, capability, close_code, encoding, FrameRect, Input, Message, DEFAULT_MAX_PAYLOAD,
    PROTOCOL_VERSION,
};
use openvnc_transport::tls::{host_of, ClientTls};
use openvnc_transport::{connect_tcp, quic};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// Transporte desejado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NativeTransport {
    /// QUIC, com fallback para TCP+TLS.
    #[default]
    Auto,
    /// Somente QUIC.
    Quic,
    /// Somente TCP+TLS.
    Tcp,
}

/// Credenciais.
#[derive(Clone, Default)]
pub enum NativeAuth {
    /// Sem autenticacao (o servidor precisa permitir).
    #[default]
    None,
    /// Senha.
    Password(String),
    /// Conta da empresa (o servidor confere com `auth_command`: LDAP, SSO...).
    User {
        /// Usuario.
        user: String,
        /// Senha.
        password: String,
    },
    /// SSO: ID token obtido com [`NativeClient::oidc_login`].
    OidcToken(String),
    /// Dispositivo pareado: id e token.
    Device {
        /// Id (`dev-...`).
        id: String,
        /// Token.
        token: String,
    },
}

impl std::fmt::Debug for NativeAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // nunca mostra segredos
        match self {
            NativeAuth::None => f.write_str("None"),
            NativeAuth::Password(_) => f.write_str("Password(***)"),
            NativeAuth::User { user, .. } => write!(f, "User({user}, ***)"),
            NativeAuth::Device { id, .. } => write!(f, "Device({id})"),
            NativeAuth::OidcToken(_) => f.write_str("OidcToken(***)"),
        }
    }
}

/// Opcoes de conexao nativa.
#[derive(Debug, Clone)]
pub struct NativeOptions {
    /// `host:porta`.
    pub address: String,
    /// Politica de confianca TLS.
    pub tls: ClientTls,
    /// Transporte.
    pub transport: NativeTransport,
    /// Credenciais.
    pub auth: NativeAuth,
    /// Timeout de cada tentativa de conexao.
    pub timeout: Duration,
}

/// Canal de saida (no TCP todos vao pelo mesmo stream).
#[derive(Debug, Clone, Copy)]
enum Chan {
    Control,
    Input,
    Graphics,
}

/// Envia entrada e clipboard para uma [`NativeClient`].
#[derive(Clone)]
pub struct NativeSender(mpsc::UnboundedSender<(Chan, Message)>);

impl NativeSender {
    /// Evento de entrada.
    pub fn input(&self, ev: Input) -> Result<()> {
        self.0
            .send((Chan::Input, Message::InputEvent(ev)))
            .map_err(|_| perr("conexao encerrada"))
    }

    /// Clipboard local para o servidor.
    pub fn clipboard(&self, text: String) -> Result<()> {
        self.0
            .send((Chan::Control, Message::Clipboard { text }))
            .map_err(|_| perr("conexao encerrada"))
    }

    /// Pedido ao explorador de arquivos; a resposta chega como
    /// [`NativeEvent::FsResponse`] com o mesmo `id`.
    pub fn fs(&self, id: u32, op: openvnc_protocol::FsOp) -> Result<()> {
        self.0
            .send((Chan::Control, Message::FsRequest { id, op }))
            .map_err(|_| perr("conexao encerrada"))
    }

    /// Liga ou desliga o bloqueio de mouse e teclado do computador remoto.
    /// Com o bloqueio ligado, mande [`Self::ping`] a cada poucos segundos:
    /// o servidor solta o bloqueio apos 10 s sem trafego.
    pub fn input_lock(&self, on: bool) -> Result<()> {
        self.0
            .send((Chan::Control, Message::InputLock { on }))
            .map_err(|_| perr("conexao encerrada"))
    }

    /// Pede para mostrar outro monitor do servidor (255 = o proximo).
    pub fn select_screen(&self, index: u8) -> Result<()> {
        self.0
            .send((Chan::Control, Message::ScreenSelect { index }))
            .map_err(|_| perr("conexao encerrada"))
    }

    /// Sinal de vida (PING).
    pub fn ping(&self, nonce: u64) -> Result<()> {
        self.0
            .send((Chan::Control, Message::Ping { nonce }))
            .map_err(|_| perr("conexao encerrada"))
    }
}

/// Sessao nativa estabelecida e autenticada.
pub struct NativeClient {
    fb: Framebuffer,
    display_name: String,
    transport: &'static str,
    inbox: mpsc::Receiver<Message>,
    out: mpsc::UnboundedSender<(Chan, Message)>,
    quic: Option<(quinn::Endpoint, quinn::Connection)>,
    #[cfg(feature = "h264")]
    video: Option<openvnc_codecs::video::H264Decoder>,
    xfer: Transfers,
    files_only: bool,
}

/// Estado da transferencia de arquivos da sessao.
struct Transfers {
    /// Pasta e limite de recebimento (`None`: recusa ofertas).
    inbound: Option<Inbound>,
    /// Ofertas do servidor aguardando decisao: id -> (nome, tamanho).
    offered: HashMap<u32, (String, u64)>,
    /// Nossas ofertas aguardando FILE_ACCEPT.
    pending: HashMap<u32, PathBuf>,
    next: u32,
    /// Eventos das tarefas de envio em segundo plano.
    ev_tx: mpsc::UnboundedSender<NativeEvent>,
    ev_rx: mpsc::UnboundedReceiver<NativeEvent>,
}

impl Transfers {
    fn new() -> Self {
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        Self {
            inbound: None,
            offered: HashMap::new(),
            pending: HashMap::new(),
            next: 0,
            ev_tx,
            ev_rx,
        }
    }
}

impl std::fmt::Debug for NativeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeClient")
            .field("transport", &self.transport)
            .field("fb", &self.fb)
            .finish()
    }
}

/// Atualizacao recebida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeEvent {
    /// Retangulos aplicados ao framebuffer.
    Frame(Vec<Rect>),
    /// Tela redimensionada (framebuffer recriado).
    Resized(u16, u16),
    /// Clipboard do servidor.
    Clipboard(String),
    /// O servidor oferece um arquivo: responda com
    /// [`NativeClient::accept_file`] ou [`NativeClient::reject_file`].
    FileOffer {
        /// Identificador da oferta.
        id: u32,
        /// Nome (ja saneado pelo protocolo).
        name: String,
        /// Tamanho anunciado em bytes.
        size: u64,
    },
    /// Progresso de um recebimento.
    FileProgress {
        /// Identificador da oferta.
        id: u32,
        /// Bytes recebidos ate agora.
        done: u64,
        /// Tamanho total.
        total: u64,
    },
    /// Arquivo recebido e conferido (SHA-256).
    FileReceived {
        /// Identificador da oferta.
        id: u32,
        /// Caminho final.
        path: PathBuf,
        /// Tamanho em bytes.
        size: u64,
    },
    /// Resposta do servidor a uma oferta nossa.
    FileAnswer {
        /// Identificador da nossa oferta.
        id: u32,
        /// Aceitou?
        accepted: bool,
    },
    /// Envio concluido.
    FileSent {
        /// Identificador da nossa oferta.
        id: u32,
        /// Bytes enviados.
        bytes: u64,
    },
    /// Falha em uma transferencia (em qualquer sentido).
    FileFailed {
        /// Identificador da oferta.
        id: u32,
        /// Motivo.
        reason: String,
    },
    /// Resposta do explorador de arquivos (ver [`NativeSender::fs`]).
    FsResponse {
        /// Id do pedido.
        id: u32,
        /// Resultado.
        reply: openvnc_protocol::FsReply,
    },
    /// Estado do bloqueio de mouse e teclado do computador remoto.
    InputLockState {
        /// Bloqueado?
        on: bool,
        /// Motivo (vazio quando tudo certo).
        reason: String,
    },
    /// Monitor mostrado e quantos o servidor tem.
    ScreenInfo {
        /// Indice do monitor atual.
        index: u8,
        /// Total de monitores.
        count: u8,
    },
}

fn perr(s: impl Into<String>) -> Error {
    Error::Protocol(s.into())
}

async fn reader<R: AsyncRead + Unpin>(mut r: R, tx: mpsc::Sender<Message>) {
    while let Ok(m) = read_message(&mut r, DEFAULT_MAX_PAYLOAD).await {
        if tx.send(m).await.is_err() {
            break;
        }
    }
}

async fn writer<W: AsyncWrite + Unpin>(mut w: W, mut rx: mpsc::UnboundedReceiver<Message>) {
    while let Some(m) = rx.recv().await {
        if write_message(&mut w, &m, DEFAULT_MAX_PAYLOAD)
            .await
            .is_err()
        {
            break;
        }
    }
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;
}

/// Roteia a saida para os escritores de cada canal.
fn router(
    mut rx: mpsc::UnboundedReceiver<(Chan, Message)>,
    ctrl: mpsc::UnboundedSender<Message>,
    input: mpsc::UnboundedSender<Message>,
    gfx: mpsc::UnboundedSender<Message>,
) {
    tokio::spawn(async move {
        while let Some((c, m)) = rx.recv().await {
            let tx = match c {
                Chan::Control => &ctrl,
                Chan::Input => &input,
                Chan::Graphics => &gfx,
            };
            if tx.send(m).is_err() {
                break;
            }
        }
    });
}

type Link = (
    mpsc::Receiver<Message>,
    mpsc::UnboundedSender<(Chan, Message)>,
    Option<(quinn::Endpoint, quinn::Connection)>,
);

async fn link_quic(o: &NativeOptions) -> Result<Link> {
    let addr = tokio::net::lookup_host(&o.address)
        .await?
        .next()
        .ok_or_else(|| perr(format!("endereco sem IP: {}", o.address)))?;
    let (ep, s) = tokio::time::timeout(
        o.timeout,
        quic::connect(addr, host_of(&o.address), &o.address, &o.tls),
    )
    .await
    .map_err(|_| perr("quic: timeout"))??;
    let (in_tx, in_rx) = mpsc::channel(64);
    tokio::spawn(reader(s.control.recv, in_tx.clone()));
    tokio::spawn(reader(s.graphics.recv, in_tx));
    let (c_tx, c_rx) = mpsc::unbounded_channel();
    let (i_tx, i_rx) = mpsc::unbounded_channel();
    let (g_tx, g_rx) = mpsc::unbounded_channel();
    tokio::spawn(writer(s.control.send, c_rx));
    tokio::spawn(writer(s.input.send, i_rx));
    tokio::spawn(writer(s.graphics.send, g_rx));
    let (out, out_rx) = mpsc::unbounded_channel();
    router(out_rx, c_tx, i_tx, g_tx);
    Ok((in_rx, out, Some((ep, s.connection))))
}

async fn link_tcp(o: &NativeOptions) -> Result<Link> {
    let sock = connect_tcp(&o.address, o.timeout).await?;
    let tls = tokio::time::timeout(
        o.timeout,
        o.tls.connect(sock, host_of(&o.address), &o.address),
    )
    .await
    .map_err(|_| perr("tls: timeout"))??;
    let (r, w) = tokio::io::split(tls);
    let (in_tx, in_rx) = mpsc::channel(64);
    tokio::spawn(reader(r, in_tx));
    let (w_tx, w_rx) = mpsc::unbounded_channel();
    tokio::spawn(writer(w, w_rx));
    let (out, out_rx) = mpsc::unbounded_channel();
    router(out_rx, w_tx.clone(), w_tx.clone(), w_tx);
    Ok((in_rx, out, None))
}

/// Configuracao de SSO anunciada pelo servidor.
#[derive(Debug, Clone)]
pub struct OidcInfo {
    /// Emissor.
    pub issuer: String,
    /// Client id.
    pub client_id: String,
    /// Escopos.
    pub scope: String,
}

async fn open_link(o: &NativeOptions) -> Result<(Link, &'static str)> {
    Ok(match o.transport {
        NativeTransport::Quic => (link_quic(o).await?, "quic"),
        NativeTransport::Tcp => (link_tcp(o).await?, "tcp-tls"),
        NativeTransport::Auto => match link_quic(o).await {
            Ok(l) => (l, "quic"),
            Err(e) => {
                tracing::info!("QUIC indisponivel ({e}); tentando TCP+TLS");
                (link_tcp(o).await?, "tcp-tls")
            }
        },
    })
}

impl NativeClient {
    /// Pergunta ao servidor como fazer SSO (abre e fecha uma conexao).
    pub async fn oidc_info(o: &NativeOptions) -> Result<OidcInfo> {
        let ((mut inbox, out, _quic), _) = open_link(o).await?;
        let send = |m: Message| {
            out.send((Chan::Control, m))
                .map_err(|_| perr("conexao encerrada"))
        };
        send(Message::ClientHello {
            min_version: PROTOCOL_VERSION,
            max_version: PROTOCOL_VERSION,
            capabilities: vec![capability::AUTH_OIDC],
            name: format!("openvnc-client {}", crate::VERSION),
        })?;
        let mut info = None;
        for _ in 0..2 {
            match next(&mut inbox, o.timeout).await? {
                Some(Message::ServerHello { auth_methods, .. })
                    if !auth_methods.contains(&auth_method::OIDC) =>
                {
                    break;
                }
                Some(Message::ServerHello { .. }) => {}
                Some(Message::OidcConfig {
                    issuer,
                    client_id,
                    scope,
                }) => {
                    info = Some(OidcInfo {
                        issuer,
                        client_id,
                        scope,
                    });
                    break;
                }
                _ => break,
            }
        }
        let _ = send(Message::Close {
            code: close_code::NORMAL,
            reason: String::new(),
        });
        info.ok_or_else(|| perr("o servidor nao oferece SSO"))
    }

    /// SSO completo: descobre o provedor pelo servidor e faz o login por
    /// codigo de dispositivo. `show` exibe o codigo ao usuario. Devolve
    /// opcoes com [`NativeAuth::OidcToken`] prontas para [`Self::connect`].
    pub async fn oidc_login(
        o: &NativeOptions,
        show: impl FnMut(&openvnc_security::oidc::DeviceCode) + Send + 'static,
        cancel: impl Fn() -> bool + Send + 'static,
        ca_pem: Option<Vec<u8>>,
    ) -> Result<NativeOptions> {
        let info = Self::oidc_info(o).await?;
        let mut show = show;
        let token = tokio::task::spawn_blocking(move || {
            openvnc_security::oidc::device_login(
                &info.issuer,
                &info.client_id,
                &info.scope,
                ca_pem.as_deref(),
                &mut show,
                &cancel,
            )
        })
        .await
        .map_err(|e| perr(e.to_string()))?
        .map_err(|e| perr(format!("SSO: {e}")))?;
        let mut o = o.clone();
        o.auth = NativeAuth::OidcToken(token);
        Ok(o)
    }

    /// Conecta, autentica e espera o DISPLAY_INFO.
    pub async fn connect(o: &NativeOptions) -> Result<Self> {
        let (link, transport) = open_link(o).await?;
        let (mut inbox, out, quic) = link;
        let send = |m: Message| {
            out.send((Chan::Control, m))
                .map_err(|_| perr("conexao encerrada"))
        };
        send(Message::ClientHello {
            min_version: PROTOCOL_VERSION,
            max_version: PROTOCOL_VERSION,
            capabilities: if cfg!(feature = "h264") {
                vec![
                    capability::TILE_RAW,
                    capability::TILE_ZLIB,
                    capability::VIDEO_H264,
                    capability::FILE_TRANSFER,
                    capability::FS_EXPLORER,
                    capability::INPUT_LOCK,
                    capability::SCREEN_SELECT,
                ]
            } else {
                vec![
                    capability::TILE_RAW,
                    capability::TILE_ZLIB,
                    capability::FILE_TRANSFER,
                    capability::FS_EXPLORER,
                    capability::INPUT_LOCK,
                    capability::SCREEN_SELECT,
                ]
            },
            name: format!("openvnc-client {}", crate::VERSION),
        })?;
        let recv = |m: Option<Message>| -> Result<Message> {
            match m {
                Some(Message::Close { code, reason }) => {
                    Err(perr(format!("servidor fechou ({code}): {reason}")))
                }
                Some(m) => Ok(m),
                None => Err(perr("conexao encerrada")),
            }
        };
        let deadline = o.timeout;
        let Message::ServerHello { auth_methods, .. } = recv(next(&mut inbox, deadline).await?)?
        else {
            return Err(perr("esperava SERVER_HELLO"));
        };
        let (method, user, secret) = match &o.auth {
            NativeAuth::None => (auth_method::NONE, String::new(), Vec::new()),
            NativeAuth::Password(p) => {
                (auth_method::PASSWORD, String::new(), p.as_bytes().to_vec())
            }
            NativeAuth::User { user, password } => (
                auth_method::PASSWORD,
                user.clone(),
                password.as_bytes().to_vec(),
            ),
            NativeAuth::Device { id, token } => {
                (auth_method::DEVICE, id.clone(), token.as_bytes().to_vec())
            }
            NativeAuth::OidcToken(t) => (auth_method::OIDC, String::new(), t.as_bytes().to_vec()),
        };
        if !auth_methods.contains(&method) {
            return Err(perr(format!(
                "servidor nao aceita este metodo de autenticacao (aceita {auth_methods:?})"
            )));
        }
        send(Message::AuthRequest {
            method,
            user,
            secret,
        })?;
        match recv(next(&mut inbox, deadline).await?)? {
            Message::AuthResult { ok: true, .. } => {}
            Message::AuthResult { reason, .. } => {
                return Err(perr(format!("autenticacao recusada: {reason}")))
            }
            _ => return Err(perr("esperava AUTH_RESULT")),
        }
        let Message::DisplayInfo {
            width,
            height,
            name,
        } = recv(next(&mut inbox, deadline).await?)?
        else {
            return Err(perr("esperava DISPLAY_INFO"));
        };
        Ok(NativeClient {
            fb: Framebuffer::new(width, height, DEFAULT_MAX_BYTES)?,
            display_name: name,
            transport,
            inbox,
            out,
            quic,
            #[cfg(feature = "h264")]
            video: None,
            xfer: Transfers::new(),
            files_only: false,
        })
    }

    /// Framebuffer atual (RGBA8).
    pub fn framebuffer(&self) -> &Framebuffer {
        &self.fb
    }

    /// Nome do display.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Transporte em uso: `"quic"` ou `"tcp-tls"`.
    pub fn transport(&self) -> &'static str {
        self.transport
    }

    /// RTT estimado (so QUIC).
    pub fn rtt(&self) -> Option<Duration> {
        self.quic.as_ref().map(|(_, c)| c.rtt())
    }

    /// Espera a proxima atualizacao, aplica e confirma.
    pub async fn next_event(&mut self) -> Result<NativeEvent> {
        loop {
            let m = tokio::select! {
                m = self.inbox.recv() => m.ok_or_else(|| perr("conexao encerrada"))?,
                Some(ev) = self.xfer.ev_rx.recv() => return Ok(ev),
            };
            match m {
                Message::FileOffer { id, name, size } => {
                    if self.xfer.inbound.is_none() || self.xfer.offered.len() >= 16 {
                        self.send(Chan::Control, Message::FileAccept { id, accept: false })?;
                        continue;
                    }
                    self.xfer.offered.insert(id, (name.clone(), size));
                    return Ok(NativeEvent::FileOffer { id, name, size });
                }
                Message::FileChunk { id, offset, data } => {
                    let Some(inb) = self.xfer.inbound.as_mut() else {
                        continue;
                    };
                    match inb.chunk(id, offset, &data) {
                        Ok(()) => {
                            let done = offset + data.len() as u64;
                            let total = inb.size_of(id).unwrap_or(done);
                            return Ok(NativeEvent::FileProgress { id, done, total });
                        }
                        Err(reason) => return Ok(NativeEvent::FileFailed { id, reason }),
                    }
                }
                Message::FileEnd { id, sha256 } => {
                    let Some(inb) = self.xfer.inbound.as_mut() else {
                        continue;
                    };
                    return Ok(match inb.end(id, &sha256) {
                        Ok(r) => NativeEvent::FileReceived {
                            id,
                            path: r.path,
                            size: r.size,
                        },
                        Err(reason) => NativeEvent::FileFailed { id, reason },
                    });
                }
                Message::FileAccept { id, accept } => {
                    let Some(path) = self.xfer.pending.remove(&id) else {
                        continue;
                    };
                    if accept {
                        self.spawn_stream(id, path);
                    }
                    return Ok(NativeEvent::FileAnswer {
                        id,
                        accepted: accept,
                    });
                }
                Message::FrameUpdate { .. } if self.files_only => {}
                Message::FrameUpdate { seq, rects } => {
                    let mut out = Vec::with_capacity(rects.len());
                    for r in &rects {
                        out.push(self.apply_rect(r)?);
                    }
                    self.send(Chan::Graphics, Message::FrameAck { seq })?;
                    return Ok(NativeEvent::Frame(out));
                }
                Message::DisplayInfo { width, height, .. } => {
                    self.fb = Framebuffer::new(width, height, DEFAULT_MAX_BYTES)?;
                    #[cfg(feature = "h264")]
                    {
                        self.video = None;
                    }
                    return Ok(NativeEvent::Resized(width, height));
                }
                Message::Clipboard { text } => return Ok(NativeEvent::Clipboard(text)),
                Message::FsResponse { id, reply } => {
                    return Ok(NativeEvent::FsResponse { id, reply })
                }
                Message::InputLockState { on, reason } => {
                    return Ok(NativeEvent::InputLockState { on, reason })
                }
                Message::ScreenInfo { index, count } => {
                    return Ok(NativeEvent::ScreenInfo { index, count })
                }
                Message::Ping { nonce } => self.send(Chan::Control, Message::Pong { nonce })?,
                Message::Close { code, reason } => {
                    return Err(perr(format!("servidor fechou ({code}): {reason}")))
                }
                _ => {}
            }
        }
    }

    fn apply_rect(&mut self, r: &FrameRect) -> Result<Rect> {
        if r.encoding != encoding::H264 {
            return apply(&mut self.fb, r);
        }
        #[cfg(feature = "h264")]
        {
            let (w, h) = (self.fb.width(), self.fb.height());
            if (r.x, r.y, r.width, r.height) != (0, 0, w, h) {
                return Err(perr("quadro H.264 precisa cobrir a tela inteira"));
            }
            let dec = match &mut self.video {
                Some(d) => d,
                slot => slot.insert(openvnc_codecs::video::H264Decoder::new()?),
            };
            let mut px = vec![0u8; usize::from(w) * usize::from(h) * 4];
            if dec.decode(&r.data, w, h, &mut px)? {
                put(&mut self.fb, r, &px);
            }
            Ok(Rect::new(0, 0, w, h))
        }
        #[cfg(not(feature = "h264"))]
        Err(perr("H.264 nao habilitado neste build"))
    }

    fn send(&self, c: Chan, m: Message) -> Result<()> {
        self.out.send((c, m)).map_err(|_| perr("conexao encerrada"))
    }

    /// Sessao usada so para arquivos: quadros sao descartados sem
    /// FRAME_ACK, e o servidor para de enviar video apos a janela inicial.
    pub fn set_files_only(&mut self, on: bool) {
        self.files_only = on;
    }

    /// Habilita o recebimento de arquivos em `dir`, com limite por arquivo.
    /// Sem isso, ofertas do servidor sao recusadas automaticamente.
    pub fn set_download_dir(&mut self, dir: PathBuf, max_bytes: u64) {
        self.xfer.inbound = Some(Inbound::new(dir, max_bytes));
    }

    /// Aceita uma oferta recebida em [`NativeEvent::FileOffer`]. Retorna o
    /// caminho temporario onde os blocos serao gravados.
    pub fn accept_file(&mut self, id: u32) -> Result<PathBuf> {
        let (name, size) = self
            .xfer
            .offered
            .remove(&id)
            .ok_or_else(|| perr("oferta desconhecida"))?;
        let inb = self
            .xfer
            .inbound
            .as_mut()
            .ok_or_else(|| perr("recebimento desabilitado"))?;
        match inb.offer(id, &name, size) {
            Ok(p) => {
                self.send(Chan::Control, Message::FileAccept { id, accept: true })?;
                Ok(p)
            }
            Err(e) => {
                self.send(Chan::Control, Message::FileAccept { id, accept: false })?;
                Err(perr(e))
            }
        }
    }

    /// Recusa uma oferta recebida.
    pub fn reject_file(&mut self, id: u32) -> Result<()> {
        self.xfer.offered.remove(&id);
        self.send(Chan::Control, Message::FileAccept { id, accept: false })
    }

    /// Oferece um arquivo ao servidor. A resposta chega como
    /// [`NativeEvent::FileAnswer`] e, se aceito, o envio segue em segundo
    /// plano ate [`NativeEvent::FileSent`] ou [`NativeEvent::FileFailed`].
    pub fn offer_file(&mut self, path: PathBuf) -> Result<u32> {
        let meta = std::fs::metadata(&path)?;
        if !meta.is_file() {
            return Err(perr("nao e um arquivo"));
        }
        if self.xfer.pending.len() >= 16 {
            return Err(perr("ofertas demais aguardando resposta"));
        }
        let name = path
            .file_name()
            .ok_or_else(|| perr("caminho sem nome"))?
            .to_string_lossy()
            .into_owned();
        let name = openvnc_protocol::sanitize_file_name(&name).map_err(|e| perr(e.to_string()))?;
        self.xfer.next = self.xfer.next.wrapping_add(1);
        let id = self.xfer.next;
        self.send(
            Chan::Control,
            Message::FileOffer {
                id,
                name,
                size: meta.len(),
            },
        )?;
        self.xfer.pending.insert(id, path);
        Ok(id)
    }

    fn spawn_stream(&self, id: u32, path: PathBuf) {
        let out = self.out.clone();
        let ev = self.xfer.ev_tx.clone();
        let (tx, mut rx) = mpsc::channel::<Message>(4);
        // ponte: canal limitado (contrapressao na leitura) -> canal de controle
        tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                if out.send((Chan::Control, m)).is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let r = files::stream(id, &path, &tx).await;
            let _ = ev.send(match r {
                Ok(bytes) => NativeEvent::FileSent { id, bytes },
                Err(reason) => NativeEvent::FileFailed { id, reason },
            });
        });
    }

    /// Canal de envio independente do `&mut self` de [`Self::next_event`]
    /// (para mandar entrada e clipboard enquanto espera quadros).
    pub fn sender(&self) -> NativeSender {
        NativeSender(self.out.clone())
    }

    /// Envia um evento de entrada.
    pub fn send_input(&self, ev: Input) -> Result<()> {
        self.send(Chan::Input, Message::InputEvent(ev))
    }

    /// Encerra a sessao.
    pub async fn close(self) {
        let _ = self.send(
            Chan::Control,
            Message::Close {
                code: 0,
                reason: String::new(),
            },
        );
        drop(self.out);
        if let Some((ep, conn)) = self.quic {
            // da tempo do CLOSE sair antes de fechar a conexao
            tokio::time::sleep(Duration::from_millis(50)).await;
            conn.close(0u32.into(), b"fim");
            let _ = tokio::time::timeout(Duration::from_secs(1), ep.wait_idle()).await;
        }
    }
}

async fn next(inbox: &mut mpsc::Receiver<Message>, d: Duration) -> Result<Option<Message>> {
    tokio::time::timeout(d, inbox.recv())
        .await
        .map_err(|_| perr("timeout no handshake"))
}

/// Decodifica e aplica um retangulo, validando limites.
fn apply(fb: &mut Framebuffer, r: &FrameRect) -> Result<Rect> {
    let (x1, y1) = (
        u32::from(r.x) + u32::from(r.width),
        u32::from(r.y) + u32::from(r.height),
    );
    if x1 > u32::from(fb.width()) || y1 > u32::from(fb.height()) {
        return Err(perr("retangulo fora da tela"));
    }
    let need = usize::from(r.width) * usize::from(r.height) * 4;
    let px = match r.encoding {
        encoding::RAW => r.data.clone(),
        encoding::ZLIB => {
            let mut v = Vec::with_capacity(need);
            flate2::read::ZlibDecoder::new(&r.data[..])
                .take(need as u64 + 1)
                .read_to_end(&mut v)
                .map_err(|e| perr(format!("zlib: {e}")))?;
            v
        }
        e => return Err(perr(format!("encoding {e} nao suportado"))),
    };
    if px.len() != need {
        return Err(perr("tamanho de pixels incorreto"));
    }
    put(fb, r, &px);
    Ok(Rect::new(r.x, r.y, r.width, r.height))
}

fn put(fb: &mut Framebuffer, r: &FrameRect, px: &[u8]) {
    let w = usize::from(r.width) * 4;
    if w > 0 {
        for (i, row) in px.chunks_exact(w).enumerate() {
            let rgba: Vec<[u8; 4]> = row
                .chunks_exact(4)
                .map(|c| [c[0], c[1], c[2], c[3]])
                .collect();
            fb.put_rgba_row(r.x, r.y + i as u16, &rgba);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aplica_raw_e_zlib_e_recusa_fora_da_tela() {
        use std::io::Write as _;
        let mut fb = Framebuffer::new(4, 4, DEFAULT_MAX_BYTES).unwrap();
        let px = vec![7u8; 2 * 2 * 4];
        let raw = FrameRect {
            x: 1,
            y: 1,
            width: 2,
            height: 2,
            encoding: encoding::RAW,
            data: px.clone(),
        };
        apply(&mut fb, &raw).unwrap();
        assert_eq!(fb.pixel(2, 2), Some([7, 7, 7, 7]));
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(&[9u8; 16]).unwrap();
        let zr = FrameRect {
            x: 0,
            y: 0,
            encoding: encoding::ZLIB,
            data: z.finish().unwrap(),
            ..raw.clone()
        };
        apply(&mut fb, &zr).unwrap();
        assert_eq!(fb.pixel(0, 0), Some([9, 9, 9, 9]));
        let fora = FrameRect {
            x: 3,
            ..raw.clone()
        };
        assert!(apply(&mut fb, &fora).is_err());
        let curto = FrameRect {
            data: vec![0; 3],
            ..raw
        };
        assert!(apply(&mut fb, &curto).is_err());
    }
}
