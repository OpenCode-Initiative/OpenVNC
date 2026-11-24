//! Sessao de cliente VNC assincrona.
//!
//! Roda a maquina de estados [`openvnc_rfb::Client`] numa task tokio
//! separada, de modo que a UI nunca bloqueia em rede. A UI envia
//! [`Command`]s, recebe [`SessionEvent`]s e le o quadro compartilhado
//! ([`SharedFrame`]) quando notificada.

use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use openvnc_core::{Error, KeyEvent, PointerEvent, Rect, Result};
use openvnc_framebuffer::Framebuffer;
use openvnc_rfb::{Client, Config, Event, ProtocolVersion};
use openvnc_transport::tls::{host_of, ClientTls};
use openvnc_transport::{connect_tcp, Backoff, BoxStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc as tmpsc;

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Opcoes de conexao.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Endereco `host:porta` (ver `openvnc_transport::parse_address`).
    pub address: String,
    /// Configuracao RFB (senha, shared, limites).
    pub config: Config,
    /// Timeout de conexao TCP.
    pub connect_timeout: Duration,
    /// Timeout do handshake RFB.
    pub handshake_timeout: Duration,
    /// Reconectar apos queda de uma sessao estabelecida.
    pub reconnect: bool,
    /// Politica de backoff.
    pub backoff: Backoff,
    /// TLS (VeNCrypt). `Some` implica `config.require_tls`: sem fallback
    /// para conexao em claro.
    pub tls: Option<ClientTls>,
}

impl ConnectOptions {
    /// Opcoes padrao para um endereco.
    pub fn new(address: impl Into<String>) -> Self {
        ConnectOptions {
            address: address.into(),
            config: Config::default(),
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            reconnect: true,
            backoff: Backoff::default(),
            tls: None,
        }
    }
}

/// Comandos da UI para a sessao.
#[derive(Debug, Clone)]
pub enum Command {
    /// Tecla.
    Key(KeyEvent),
    /// Mouse.
    Pointer(PointerEvent),
    /// Clipboard local -> servidor.
    CutText(String),
    /// Encerrar.
    Close,
}

/// Eventos da sessao para a UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Conectado (ou reconectado).
    Connected {
        /// Largura.
        width: u16,
        /// Altura.
        height: u16,
        /// Nome do desktop.
        name: String,
        /// Versao RFB.
        version: ProtocolVersion,
        /// Transporte criptografado (VeNCrypt/TLS 1.3)?
        encrypted: bool,
        /// Autenticacao legada VNC Auth (DES) foi usada.
        legacy_auth: bool,
    },
    /// Quadro atualizado (ver [`SharedFrame::damage`]).
    Updated,
    /// Bell.
    Bell,
    /// Clipboard remoto.
    CutText(String),
    /// A tela remota mudou de tamanho (o quadro compartilhado foi recriado).
    Resized {
        /// Largura.
        width: u16,
        /// Altura.
        height: u16,
    },
    /// Novo formato de cursor (RGBA, `width * height * 4` bytes).
    Cursor {
        /// Ponto quente x.
        hot_x: u16,
        /// Ponto quente y.
        hot_y: u16,
        /// Largura.
        width: u16,
        /// Altura.
        height: u16,
        /// Pixels.
        rgba: Vec<u8>,
    },
    /// Conexao perdida/encerrada.
    Disconnected {
        /// Motivo legivel.
        reason: String,
        /// Uma reconexao sera tentada.
        retrying: bool,
    },
}

/// Quadro compartilhado entre a task de rede e a UI.
#[derive(Debug, Default)]
pub struct SharedFrame {
    /// Framebuffer atual (None antes da conexao).
    pub fb: Option<Framebuffer>,
    /// Regioes alteradas ainda nao consumidas pela UI.
    pub damage: Vec<Rect>,
    /// Incrementado a cada reinicializacao do framebuffer (novo tamanho).
    pub generation: u64,
}

/// Handle de uma sessao em execucao.
pub struct Session {
    cmd: tmpsc::UnboundedSender<Command>,
    events: mpsc::Receiver<SessionEvent>,
    frame: Arc<Mutex<SharedFrame>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session")
    }
}

impl Session {
    /// Inicia a sessao no runtime `rt`. `notify` e chamado (da task de
    /// rede) sempre que ha evento novo, para acordar a UI.
    pub fn spawn(
        rt: &tokio::runtime::Handle,
        opts: ConnectOptions,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Session {
        let (cmd_tx, cmd_rx) = tmpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::channel();
        let frame = Arc::new(Mutex::new(SharedFrame::default()));
        let ctx = Ctx {
            ev: ev_tx,
            notify,
            frame: frame.clone(),
        };
        rt.spawn(run(opts, cmd_rx, ctx));
        Session {
            cmd: cmd_tx,
            events: ev_rx,
            frame,
        }
    }

    /// Envia um comando (ignorado se a sessao ja terminou).
    pub fn send(&self, c: Command) {
        let _ = self.cmd.send(c);
    }

    /// Proximo evento sem bloquear.
    pub fn try_event(&self) -> Option<SessionEvent> {
        self.events.try_recv().ok()
    }

    /// Proximo evento, bloqueando ate `timeout`.
    pub fn wait_event(&self, timeout: Duration) -> Option<SessionEvent> {
        self.events.recv_timeout(timeout).ok()
    }

    /// Quadro compartilhado.
    pub fn frame(&self) -> &Arc<Mutex<SharedFrame>> {
        &self.frame
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.cmd.send(Command::Close);
    }
}

struct Ctx {
    ev: mpsc::Sender<SessionEvent>,
    notify: Arc<dyn Fn() + Send + Sync>,
    frame: Arc<Mutex<SharedFrame>>,
}

impl Ctx {
    fn emit(&self, e: SessionEvent) {
        let _ = self.ev.send(e);
        (self.notify)();
    }
}

enum Outcome {
    Closed,
    Lost { was_connected: bool, err: Error },
}

async fn run(mut opts: ConnectOptions, mut cmds: tmpsc::UnboundedReceiver<Command>, ctx: Ctx) {
    // So reconecta apos perder uma sessao que chegou a ser estabelecida;
    // falhas na primeira conexao (senha errada, host inexistente) sao finais.
    let mut in_retry = false;
    loop {
        match session_once(&opts, &mut cmds, &ctx).await {
            Outcome::Closed => {
                ctx.emit(SessionEvent::Disconnected {
                    reason: "encerrada".into(),
                    retrying: false,
                });
                return;
            }
            Outcome::Lost { was_connected, err } => {
                if was_connected {
                    opts.backoff.reset();
                    in_retry = true;
                }
                let delay = if opts.reconnect && in_retry {
                    opts.backoff.next_delay()
                } else {
                    None
                };
                tracing::warn!(error = %err, retrying = delay.is_some(), "sessao perdida");
                ctx.emit(SessionEvent::Disconnected {
                    reason: err.to_string(),
                    retrying: delay.is_some(),
                });
                let Some(d) = delay else { return };
                let sleep = tokio::time::sleep(d);
                tokio::pin!(sleep);
                loop {
                    tokio::select! {
                        _ = &mut sleep => break,
                        c = cmds.recv() => match c {
                            None | Some(Command::Close) => return,
                            Some(_) => {}
                        }
                    }
                }
            }
        }
    }
}

async fn session_once(
    opts: &ConnectOptions,
    cmds: &mut tmpsc::UnboundedReceiver<Command>,
    ctx: &Ctx,
) -> Outcome {
    let mut connected = false;
    let res = drive(opts, cmds, ctx, &mut connected).await;
    match res {
        Ok(()) => Outcome::Closed,
        Err(err) => Outcome::Lost {
            was_connected: connected,
            err,
        },
    }
}

async fn drive(
    opts: &ConnectOptions,
    cmds: &mut tmpsc::UnboundedReceiver<Command>,
    ctx: &Ctx,
    connected: &mut bool,
) -> Result<()> {
    let mut stream: BoxStream = Box::new(connect_tcp(&opts.address, opts.connect_timeout).await?);
    let mut cfg = opts.config.clone();
    if opts.tls.is_some() {
        cfg.require_tls = true;
    }
    if cfg.require_tls && opts.tls.is_none() {
        return Err(Error::Protocol("require_tls sem configuracao TLS".into()));
    }
    let mut client = Client::new(cfg);
    let mut start_tls = false;
    let mut buf = vec![0u8; 64 * 1024];
    let deadline = tokio::time::Instant::now() + opts.handshake_timeout;
    loop {
        tokio::select! {
            r = stream.read(&mut buf) => {
                let n = r?;
                if n == 0 {
                    return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
                }
                client.feed(&buf[..n])?;
                while let Some(e) = client.poll_event() {
                    if e == Event::StartTls {
                        start_tls = true;
                    } else {
                        handle_event(e, &mut client, ctx, connected);
                    }
                }
            }
            c = cmds.recv() => match c {
                None | Some(Command::Close) => return Ok(()),
                Some(_) if !*connected => {}
                Some(Command::Key(k)) => client.send_key(k),
                Some(Command::Pointer(p)) => client.send_pointer(p),
                Some(Command::CutText(t)) => client.send_cut_text(&t),
            },
            _ = tokio::time::sleep_until(deadline), if !*connected => {
                return Err(Error::Protocol("timeout no handshake".into()));
            }
        }
        let out = client.take_output();
        if !out.is_empty() {
            stream.write_all(&out).await?;
        }
        if std::mem::take(&mut start_tls) {
            let tls = opts.tls.as_ref().expect("checado acima");
            stream.flush().await?;
            let host = host_of(&opts.address).to_string();
            let fut = tls.connect(stream, &host, &opts.address);
            stream = Box::new(
                tokio::time::timeout_at(deadline, fut)
                    .await
                    .map_err(|_| Error::Protocol("timeout no handshake TLS".into()))??,
            );
            tracing::info!(subtype = ?client.tls_subtype(), "TLS 1.3 estabelecido");
            client.tls_established()?;
            while let Some(e) = client.poll_event() {
                handle_event(e, &mut client, ctx, connected);
            }
            let out = client.take_output();
            if !out.is_empty() {
                stream.write_all(&out).await?;
            }
        }
    }
}

fn handle_event(e: Event, client: &mut Client, ctx: &Ctx, connected: &mut bool) {
    match e {
        Event::Connected {
            width,
            height,
            name,
            version,
            security,
        } => {
            *connected = true;
            {
                let mut f = ctx.frame.lock().expect("mutex");
                f.fb = client.framebuffer().cloned();
                f.damage = vec![Rect::new(0, 0, width, height)];
                f.generation += 1;
            }
            if let Some(fb) = client.framebuffer_mut() {
                fb.take_damage();
            }
            tracing::info!(width, height, ?version, "sessao estabelecida");
            ctx.emit(SessionEvent::Connected {
                width,
                height,
                name,
                version,
                encrypted: client.tls_subtype().is_some(),
                legacy_auth: security == openvnc_rfb::security_type::VNC_AUTH
                    || client.tls_subtype() == Some(openvnc_rfb::vencrypt::X509_VNC),
            });
        }
        Event::UpdateComplete => {
            let mut changed = false;
            if let Some(src) = client.framebuffer_mut() {
                let damage = src.take_damage();
                changed = !damage.is_empty();
                let mut f = ctx.frame.lock().expect("mutex");
                if let Some(dst) = f.fb.as_mut() {
                    for r in &damage {
                        dst.copy_from(src, *r);
                    }
                    dst.take_damage();
                }
                f.damage.extend(damage);
                if f.damage.len() > 256 {
                    let bb = f.damage.iter().fold(Rect::default(), |a, d| a.union(d));
                    f.damage = vec![bb];
                }
            }
            client.request_incremental();
            // updates so com pseudo-encodings (cursor, tamanho) nao mudam pixels
            if changed {
                ctx.emit(SessionEvent::Updated);
            }
        }
        Event::StartTls => {} // tratado em drive
        Event::Bell => ctx.emit(SessionEvent::Bell),
        Event::CutText(t) => ctx.emit(SessionEvent::CutText(t)),
        Event::Resized { width, height } => {
            {
                let mut f = ctx.frame.lock().expect("mutex");
                f.fb = client.framebuffer().cloned();
                f.damage = vec![Rect::new(0, 0, width, height)];
                f.generation += 1;
            }
            if let Some(fb) = client.framebuffer_mut() {
                fb.take_damage();
            }
            tracing::info!(width, height, "tela remota redimensionada");
            ctx.emit(SessionEvent::Resized { width, height });
        }
        Event::Cursor {
            hot_x,
            hot_y,
            width,
            height,
            rgba,
        } => ctx.emit(SessionEvent::Cursor {
            hot_x,
            hot_y,
            width,
            height,
            rgba,
        }),
    }
}

#[cfg(test)]
mod tests;
