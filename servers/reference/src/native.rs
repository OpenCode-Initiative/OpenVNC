//! Protocolo nativo OpenVNC (RFC 0001) sobre QUIC, com fallback TCP+TLS
//! na mesma porta.
//!
//! No QUIC cada canal logico e um stream proprio (controle, entrada,
//! graficos); no TCP+TLS todas as mensagens compartilham o stream. Os dois
//! transportes alimentam a mesma sessao: leitores empurram mensagens numa
//! fila de entrada e escritores drenam as filas de saida.

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{bail, Context as _};
use openvnc_core::{KeyEvent, PointerEvent, Rect};
use openvnc_framebuffer::Framebuffer;
use openvnc_protocol::io::{read_message, write_message};
use openvnc_protocol::{
    auth_method, capability, close_code, encoding, FrameRect, Input as NInput, Message,
    DEFAULT_MAX_PAYLOAD, MAX_RECTS, PROTOCOL_VERSION,
};
use openvnc_security::pairing::Verdict;
use openvnc_transport::quic;
use openvnc_transport::tls::TlsAcceptor;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::{diff, Frame, Input, Shared};

/// Quadros enviados sem confirmacao (controle de fluxo).
const WINDOW: u64 = 2;
/// Lado dos tiles do quadro completo.
const TILE: u16 = 64;
/// Tempo maximo para hello + autenticacao.
/// Sem mudancas por este tempo apos video, a tela e reenviada sem perdas.
const REFINE_AFTER: std::time::Duration = std::time::Duration::from_millis(300);
/// Percentual da tela que precisa mudar para usar video.
#[cfg(feature = "h264")]
const VIDEO_THRESHOLD_PCT: u64 = 25;
/// Taxa alvo do H.264 em bit/s.
#[cfg(feature = "h264")]
const VIDEO_BITRATE: u32 = 8_000_000;

/// Estado de video H.264 de uma sessao.
struct Video {
    #[cfg_attr(not(feature = "h264"), allow(dead_code))]
    enabled: bool,
    /// O cliente tem uma imagem com perdas ainda nao refinada.
    lossy: bool,
    #[cfg(feature = "h264")]
    enc: Option<openvnc_codecs::video::H264Encoder>,
}

impl Video {
    fn new(enabled: bool) -> Self {
        Video {
            enabled: enabled && cfg!(feature = "h264"),
            lossy: false,
            #[cfg(feature = "h264")]
            enc: None,
        }
    }

    /// Decide se a mudanca vai como video. Retorna o retangulo H.264 de tela
    /// inteira, ou `None` para seguir com tiles sem perdas.
    #[cfg(feature = "h264")]
    fn frame(
        &mut self,
        fb: &Framebuffer,
        rects: &[Rect],
        resized: bool,
    ) -> anyhow::Result<Option<FrameRect>> {
        use openvnc_codecs::video::{supported, H264Encoder};
        if resized {
            self.enc = None;
        }
        if !self.enabled || resized || rects.is_empty() {
            return Ok(None);
        }
        let (w, h) = (fb.width(), fb.height());
        let dirty: u64 = rects
            .iter()
            .map(|r| u64::from(r.width) * u64::from(r.height))
            .sum();
        let total = u64::from(w) * u64::from(h);
        if !supported(w, h) || dirty * 100 < total * VIDEO_THRESHOLD_PCT {
            return Ok(None);
        }
        let enc = match &mut self.enc {
            Some(e) if e.size() == (w, h) => e,
            slot => slot.insert(H264Encoder::new(w, h, VIDEO_BITRATE)?),
        };
        let (data, _key) = enc.encode(&extract(fb, Rect::new(0, 0, w, h)))?;
        self.lossy = true;
        Ok(Some(FrameRect {
            x: 0,
            y: 0,
            width: w,
            height: h,
            encoding: encoding::H264,
            data,
        }))
    }

    #[cfg(not(feature = "h264"))]
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn frame(&mut self, _: &Framebuffer, _: &[Rect], _: bool) -> anyhow::Result<Option<FrameRect>> {
        Ok(None)
    }
}

/// Payload maximo aceito antes da autenticacao (limita memoria de
/// clientes anonimos).
const PREAUTH_MAX_PAYLOAD: u32 = 64 * 1024;

/// Liga o limite normal de payload depois da autenticacao.
type AuthFlag = Arc<std::sync::atomic::AtomicBool>;

/// Listeners nativos ja ligados.
pub struct Listeners {
    endpoint: quinn::Endpoint,
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl Listeners {
    /// Endereco efetivo (UDP e TCP usam a mesma porta).
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}

/// Liga QUIC (UDP) em `addr` e TCP+TLS na mesma porta.
pub async fn bind(addr: SocketAddr, cfg: &crate::Config) -> anyhow::Result<Listeners> {
    let id = crate::identity(cfg)?;
    let endpoint = quic::server_endpoint(addr, &id).context("ligando QUIC")?;
    let real = endpoint.local_addr()?;
    let tcp = TcpListener::bind(real)
        .await
        .with_context(|| format!("ligando TCP+TLS nativo em {real}"))?;
    tracing::info!(addr = %real, fingerprint = %id.fingerprint(), "protocolo nativo (QUIC + TCP/TLS)");
    Ok(Listeners {
        endpoint,
        tcp,
        acceptor: id.acceptor()?,
    })
}

/// Aceita conexoes nos dois transportes ate o endpoint fechar.
pub async fn serve(l: Listeners, sh: Arc<Shared>) {
    let Listeners {
        endpoint,
        tcp,
        acceptor,
    } = l;
    let sh2 = sh.clone();
    let tcp_task = tokio::spawn(async move {
        loop {
            let Ok((sock, peer)) = tcp.accept().await else {
                continue;
            };
            if !sh2.cfg.peer_allowed(peer.ip()) {
                tracing::warn!(%peer, "fora da rede local; recusado (nativo)");
                sh2.audit.record(
                    "rejected",
                    &[("peer", &peer.to_string()), ("reason", "lan_only")],
                );
                continue;
            }
            if sh2
                .lockout
                .blocked(peer.ip(), std::time::Instant::now())
                .is_some()
            {
                sh2.audit.record(
                    "rejected",
                    &[("peer", &peer.to_string()), ("reason", "lockout")],
                );
                continue;
            }
            let _ = sock.set_nodelay(true);
            let acc = acceptor.clone();
            let sh = sh2.clone();
            tokio::spawn(async move {
                // prazo unico: TLS + handshake + autenticacao
                let deadline = tokio::time::Instant::now() + crate::AUTH_TIMEOUT;
                let Some(_slot) = Slot::take(&sh, &peer.to_string(), peer.ip()) else {
                    return;
                };
                let tls = match tokio::time::timeout_at(deadline, acc.accept(sock)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        tracing::info!(%peer, "TLS nativo falhou: {e}");
                        return;
                    }
                    Err(_) => {
                        tracing::info!(%peer, "TLS nativo: timeout");
                        return;
                    }
                };
                let (r, w) = tokio::io::split(tls);
                let (in_tx, in_rx) = mpsc::channel(256);
                let (out_tx, out_rx) = mpsc::channel(64);
                let authed = AuthFlag::default();
                tokio::spawn(reader(r, in_tx, authed.clone()));
                let wt = tokio::spawn(writer(w, out_rx));
                run_session(
                    &sh,
                    &peer.to_string(),
                    "tcp-tls",
                    deadline,
                    &authed,
                    in_rx,
                    out_tx.clone(),
                    out_tx,
                )
                .await;
                let _ = wt.await;
            });
        }
    });
    loop {
        let s = match quic::accept(&endpoint).await {
            Ok(Some(s)) => s,
            Ok(None) => break,
            Err(e) => {
                tracing::info!("QUIC: conexao recusada: {e}");
                continue;
            }
        };
        let sh = sh.clone();
        tokio::spawn(async move {
            let addr = s.connection.remote_address();
            let peer = addr.to_string();
            if !sh.cfg.peer_allowed(addr.ip()) {
                tracing::warn!(%peer, "fora da rede local; recusado (quic)");
                sh.audit
                    .record("rejected", &[("peer", &peer), ("reason", "lan_only")]);
                s.connection.close(5u32.into(), b"fora da rede local");
                return;
            }
            if sh
                .lockout
                .blocked(addr.ip(), std::time::Instant::now())
                .is_some()
            {
                sh.audit
                    .record("rejected", &[("peer", &peer), ("reason", "lockout")]);
                s.connection
                    .close(5u32.into(), b"bloqueado temporariamente");
                return;
            }
            let deadline = tokio::time::Instant::now() + crate::AUTH_TIMEOUT;
            let Some(_slot) = Slot::take(&sh, &peer, addr.ip()) else {
                s.connection.close(4u32.into(), b"limite de clientes");
                return;
            };
            let (in_tx, in_rx) = mpsc::channel(256);
            let (ctrl_tx, ctrl_rx) = mpsc::channel(16);
            let (gfx_tx, gfx_rx) = mpsc::channel(8);
            let authed = AuthFlag::default();
            tokio::spawn(reader(s.control.recv, in_tx.clone(), authed.clone()));
            tokio::spawn(reader(s.input.recv, in_tx.clone(), authed.clone()));
            tokio::spawn(reader(s.graphics.recv, in_tx, authed.clone()));
            let wc = tokio::spawn(writer(s.control.send, ctrl_rx));
            let wg = tokio::spawn(writer(s.graphics.send, gfx_rx));
            run_session(
                &sh, &peer, "quic", deadline, &authed, in_rx, ctrl_tx, gfx_tx,
            )
            .await;
            let _ = wc.await;
            let _ = wg.await;
            s.connection.close(0u32.into(), b"fim");
        });
    }
    tcp_task.abort();
}

/// Reserva uma vaga no limite de clientes e no limite por IP; libera no
/// drop.
struct Slot<'a>(&'a Shared, #[allow(dead_code)] crate::IpSlot);

impl<'a> Slot<'a> {
    fn take(sh: &'a Shared, peer: &str, ip: std::net::IpAddr) -> Option<Self> {
        let Some(ip_slot) = sh.per_ip.take(ip) else {
            tracing::warn!(%peer, "limite de conexoes por IP; recusado (nativo)");
            sh.audit
                .record("rejected", &[("peer", peer), ("reason", "max_per_ip")]);
            return None;
        };
        if sh.clients.fetch_add(1, Ordering::SeqCst) >= sh.cfg.max_clients {
            sh.clients.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!(%peer, "limite de clientes; recusado (nativo)");
            sh.audit
                .record("rejected", &[("peer", peer), ("reason", "max_clients")]);
            return None;
        }
        crate::tray::CLIENTS.fetch_add(1, Ordering::Relaxed);
        Some(Slot(sh, ip_slot))
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.clients.fetch_sub(1, Ordering::SeqCst);
        crate::tray::CLIENTS.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn reader<R: AsyncRead + Unpin>(r: R, tx: mpsc::Sender<Message>, authed: AuthFlag) {
    use tokio::io::AsyncBufReadExt as _;
    let mut r = tokio::io::BufReader::new(r);
    loop {
        // espera chegar dado antes de escolher o limite: o quadro que vem
        // logo apos o AuthResult ja usa o limite normal
        match r.fill_buf().await {
            Ok([]) | Err(_) => break,
            Ok(_) => {}
        }
        // antes de autenticar so aceita quadros pequenos
        let max = if authed.load(Ordering::Acquire) {
            DEFAULT_MAX_PAYLOAD
        } else {
            PREAUTH_MAX_PAYLOAD
        };
        let Ok(m) = read_message(&mut r, max).await else {
            break;
        };
        if tx.send(m).await.is_err() {
            break;
        }
    }
}

async fn writer<W: AsyncWrite + Unpin>(mut w: W, mut rx: mpsc::Receiver<Message>) {
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

#[allow(clippy::too_many_arguments)]
async fn run_session(
    sh: &Shared,
    peer: &str,
    transport: &str,
    deadline: tokio::time::Instant,
    authed: &AuthFlag,
    inbox: mpsc::Receiver<Message>,
    ctrl: mpsc::Sender<Message>,
    gfx: mpsc::Sender<Message>,
) {
    tracing::info!(%peer, transport, "nativo: conectado");
    sh.audit
        .record("connect", &[("peer", peer), ("transport", transport)]);
    match session(sh, peer, deadline, authed, inbox, &ctrl, &gfx).await {
        Ok(()) => {
            tracing::info!(%peer, "nativo: desconectado");
            sh.audit.record("disconnect", &[("peer", peer)]);
        }
        Err(e) => {
            tracing::info!(%peer, "nativo: desconectado: {e:#}");
            sh.audit.record(
                "disconnect",
                &[("peer", peer), ("error", &format!("{e:#}"))],
            );
        }
    }
}

/// Metodos de autenticacao oferecidos pela configuracao.
fn methods(sh: &Shared) -> Vec<u8> {
    let mut m = Vec::new();
    if sh.password.is_some() || sh.cfg.password_hash.is_some() || sh.cfg.ext_auth().is_some() {
        m.push(auth_method::PASSWORD);
    }
    if sh.devices.is_some() {
        m.push(auth_method::DEVICE);
    }
    if sh.oidc.is_some() {
        m.push(auth_method::OIDC);
    }
    if sh.cfg.allow_no_auth || sh.cfg.allow_attended {
        m.push(auth_method::NONE);
    }
    m
}

/// Comparacao em tempo constante para o tamanho dado.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Permissoes da sessao vindas do ticket do servidor central. Sem
/// ticket do central (`perms: None`) vale tudo o que a configuracao
/// local permite.
#[derive(Debug, Clone, Default)]
struct SessionPerms {
    perms: Option<Vec<String>>,
    ask: Option<bool>,
}

impl SessionPerms {
    fn has(&self, p: &str) -> bool {
        self.perms.as_ref().is_none_or(|v| v.iter().any(|x| x == p))
    }

    fn label(&self) -> String {
        match &self.perms {
            Some(v) => v.join(","),
            None => "local".into(),
        }
    }
}

/// Confere as credenciais e devolve o usuario efetivo. `Err` traz o motivo
/// (sem o segredo).
fn check_auth(
    sh: &Shared,
    peer: &str,
    method: u8,
    user: &str,
    secret: &[u8],
) -> Result<(String, SessionPerms), String> {
    if !methods(sh).contains(&method) {
        return Err("metodo nao permitido".into());
    }
    if method == auth_method::OIDC {
        let Some(v) = &sh.oidc else {
            return Err("SSO desligado".into());
        };
        return match v.verify(secret) {
            Ok(id) => {
                sh.audit
                    .record("oidc_auth", &[("peer", peer), ("user", &id.user)]);
                // com central_machine_id o ticket precisa trazer permissoes
                let perms = match (&sh.cfg.central_machine_id, id.perms) {
                    (Some(_), None) => return Err("ticket sem permissoes".into()),
                    (_, p) => p,
                };
                Ok((id.user, SessionPerms { perms, ask: id.ask }))
            }
            Err(e) => {
                let why = e.to_string();
                sh.audit
                    .record("oidc_auth_failed", &[("peer", peer), ("reason", &why)]);
                Err(format!("SSO recusado: {why}"))
            }
        };
    }
    check_local(sh, peer, method, user, secret).map(|()| (user.to_owned(), SessionPerms::default()))
}

fn check_local(
    sh: &Shared,
    peer: &str,
    method: u8,
    user: &str,
    secret: &[u8],
) -> Result<(), String> {
    match method {
        auth_method::NONE => Ok(()),
        auth_method::PASSWORD if !user.is_empty() && user != crate::config::REMOTE_USER => {
            let Some(cmd) = sh.cfg.ext_auth() else {
                return Err("contas de usuario desligadas (sem auth_command)".into());
            };
            let t = std::time::Duration::from_secs(sh.cfg.auth_timeout_secs);
            let r = crate::extauth::check(cmd, t, user, peer, secret);
            match &r {
                Ok(()) => sh
                    .audit
                    .record("user_auth", &[("peer", peer), ("user", user)]),
                Err(why) => sh.audit.record(
                    "user_auth_failed",
                    &[("peer", peer), ("user", user), ("reason", why)],
                ),
            }
            r
        }
        auth_method::PASSWORD => {
            let ok = match (&sh.cfg.password_hash, &sh.password) {
                (Some(h), _) => openvnc_security::passhash::verify(secret, h),
                (None, Some(pw)) => ct_eq(pw.as_bytes(), secret),
                (None, None) => false,
            };
            if ok {
                Ok(())
            } else {
                Err("senha incorreta".into())
            }
        }
        auth_method::DEVICE => {
            let Some(st) = &sh.devices else {
                return Err("pareamento desligado".into());
            };
            match st.verify(user, secret) {
                Verdict::Ok => Ok(()),
                v => {
                    sh.audit.record(
                        "device_auth_failed",
                        &[("peer", peer), ("device", user), ("reason", v.as_str())],
                    );
                    Err(format!("dispositivo recusado: {}", v.as_str()))
                }
            }
        }
        _ => Err("metodo desconhecido".into()),
    }
}

async fn close(ctrl: &mpsc::Sender<Message>, code: u16, reason: &str) {
    let _ = ctrl
        .send(Message::Close {
            code,
            reason: reason.into(),
        })
        .await;
}

/// Hello + autenticacao. Devolve se o cliente aceita ZLIB.
async fn handshake(
    sh: &Shared,
    peer: &str,
    inbox: &mut mpsc::Receiver<Message>,
    ctrl: &mpsc::Sender<Message>,
    authed: &AuthFlag,
) -> anyhow::Result<(Vec<u32>, bool, String, SessionPerms)> {
    let Some(Message::ClientHello {
        min_version,
        max_version,
        capabilities,
        name,
    }) = inbox.recv().await
    else {
        close(ctrl, close_code::PROTOCOL_ERROR, "esperava CLIENT_HELLO").await;
        bail!("esperava CLIENT_HELLO");
    };
    if !(min_version..=max_version).contains(&PROTOCOL_VERSION) {
        close(
            ctrl,
            close_code::UNSUPPORTED_VERSION,
            "versao nao suportada",
        )
        .await;
        bail!("versao {min_version}..={max_version} nao suportada");
    }
    let mut ours = vec![capability::TILE_RAW, capability::TILE_ZLIB];
    if cfg!(feature = "h264") {
        ours.push(capability::VIDEO_H264);
    }
    if sh.cfg.files_send || sh.cfg.files_receive {
        ours.push(capability::FILE_TRANSFER);
    }
    if sh.oidc.is_some() {
        ours.push(capability::AUTH_OIDC);
    }
    if sh.cfg.files_send || sh.cfg.files_receive {
        ours.push(capability::FS_EXPLORER);
    }
    if sh.input.is_some() {
        ours.push(capability::INPUT_LOCK);
        ours.push(capability::SCREEN_SELECT);
    }
    let caps: Vec<u32> = capabilities
        .iter()
        .copied()
        .filter(|c| ours.contains(c))
        .collect();
    tracing::debug!(%peer, client = %name, ?caps, "CLIENT_HELLO");
    ctrl.send(Message::ServerHello {
        version: PROTOCOL_VERSION,
        capabilities: caps.clone(),
        auth_methods: methods(sh),
        name: sh.cfg.name.clone(),
    })
    .await?;
    if caps.contains(&capability::AUTH_OIDC) {
        if let (Some(issuer), Some(client_id)) = (&sh.cfg.oidc_issuer, &sh.cfg.oidc_client_id) {
            ctrl.send(Message::OidcConfig {
                issuer: issuer.clone(),
                client_id: client_id.clone(),
                scope: match &sh.cfg.central_machine_id {
                    Some(m) => format!(
                        "{} {}{m}",
                        sh.cfg.oidc_scope,
                        openvnc_security::oidc::SCOPE_MACHINE
                    ),
                    None => sh.cfg.oidc_scope.clone(),
                },
            })
            .await?;
        }
    }
    let Some(Message::AuthRequest {
        method,
        user,
        secret,
    }) = inbox.recv().await
    else {
        close(ctrl, close_code::PROTOCOL_ERROR, "esperava AUTH_REQUEST").await;
        bail!("esperava AUTH_REQUEST");
    };
    let checked = if method == auth_method::OIDC || sh.cfg.ext_auth().is_some() {
        // pode fazer rede ou rodar programa: fora das threads do runtime
        tokio::task::block_in_place(|| check_auth(sh, peer, method, &user, &secret))
    } else {
        check_auth(sh, peer, method, &user, &secret)
    };
    let (user, perms) = match checked {
        Ok(u) => u,
        Err(reason) => {
            sh.audit
                .record("auth_failed", &[("peer", peer), ("reason", &reason)]);
            crate::lock_fail(sh, peer);
            ctrl.send(Message::AuthResult {
                ok: false,
                reason: reason.clone(),
            })
            .await?;
            close(ctrl, close_code::AUTH_FAILED, &reason).await;
            bail!("autenticacao: {reason}");
        }
    };
    sh.audit
        .record("auth_ok", &[("peer", peer), ("user", &user)]);
    // libera quadros grandes antes de o cliente saber do sucesso
    authed.store(true, Ordering::Release);
    if let Some(ip) = crate::lockout::peer_ip(peer) {
        sh.lockout.success(ip);
    }
    ctrl.send(Message::AuthResult {
        ok: true,
        reason: String::new(),
    })
    .await?;
    Ok((caps, method == auth_method::NONE, user, perms))
}

async fn session(
    sh: &Shared,
    peer: &str,
    deadline: tokio::time::Instant,
    authed: &AuthFlag,
    mut inbox: mpsc::Receiver<Message>,
    ctrl: &mpsc::Sender<Message>,
    gfx: &mpsc::Sender<Message>,
) -> anyhow::Result<()> {
    let (caps, no_auth, user, perms) =
        tokio::time::timeout_at(deadline, handshake(sh, peer, &mut inbox, ctrl, authed))
            .await
            .map_err(|_| anyhow::anyhow!("timeout no handshake"))??;
    // sem credencial, so com autorizacao local (allow_attended)
    if !perms.has("view") {
        sh.audit.record(
            "rejected",
            &[("peer", peer), ("reason", "sem_permissao_view")],
        );
        close(ctrl, close_code::AUTH_FAILED, "sem permissao de ver a tela").await;
        bail!("ticket sem permissao view");
    }
    let control = perms.has("control");
    let mut input_denied = false;
    sh.audit.record(
        "session_perms",
        &[("peer", peer), ("user", &user), ("perms", &perms.label())],
    );
    // o central pode exigir ou dispensar a aprovacao local
    let ask = match perms.ask {
        Some(a) => a,
        None => sh.cfg.ask_before_accept,
    } || (no_auth && !sh.cfg.allow_no_auth);
    let approval = if ask {
        crate::tray::ask_once(&user, peer, !no_auth).await
    } else {
        None
    };
    if ask && approval.is_none() {
        sh.audit
            .record("rejected", &[("peer", peer), ("reason", "local_user")]);
        close(ctrl, close_code::AUTH_FAILED, "recusado pelo usuario local").await;
        bail!("recusado pelo usuario local");
    }
    let files_ok = caps.contains(&capability::FILE_TRANSFER) && perms.has("files");
    let mut inbound = (files_ok && sh.cfg.files_receive).then(|| {
        openvnc_client::files::Inbound::new(
            sh.cfg.files_dir(),
            sh.cfg.files_max_mb.saturating_mul(1024 * 1024),
        )
    });
    let mut outbound = crate::files::Outbound::default();
    let mut offers = (files_ok && sh.cfg.files_send).then(crate::files::subscribe);
    let fsx = crate::fsexplorer::Explorer::new(
        &sh.cfg,
        caps.contains(&capability::FS_EXPLORER) && perms.has("files"),
    );
    let lock_ok = control && sh.input.is_some() && caps.contains(&capability::INPUT_LOCK);
    let mut lock: Option<Locked> = None;
    let mut last_seen = std::time::Instant::now();
    let mut idle = crate::idle::Idle::new(peer, sh.cfg.idle_timeout_secs);
    let mut screens = caps
        .contains(&capability::SCREEN_SELECT)
        .then(|| sh.screens.info.clone());
    if let Some(rx) = &mut screens {
        let (index, count) = *rx.borrow_and_update();
        ctrl.send(Message::ScreenInfo { index, count }).await?;
    }
    let zlib = caps.contains(&capability::TILE_ZLIB);
    let mut video = Video::new(caps.contains(&capability::VIDEO_H264));
    let mut frames = sh.frames.clone();
    let mut sent: Option<Frame> = None;
    let (mut seq, mut acked) = (0u64, 0u64);
    loop {
        if seq - acked < WINDOW {
            let cur = frames.borrow_and_update().clone();
            if sent.as_ref().map(|s| s.gen) != Some(cur.gen) {
                let size = (cur.fb.width(), cur.fb.height());
                let resized = sent
                    .as_ref()
                    .is_none_or(|s| (s.fb.width(), s.fb.height()) != size);
                if resized {
                    ctrl.send(Message::DisplayInfo {
                        width: size.0,
                        height: size.1,
                        name: sh.cfg.name.clone(),
                    })
                    .await?;
                }
                let rects = match (&sent, resized) {
                    (Some(old), false) => diff::dirty_tiles(&old.fb, &cur.fb),
                    _ => grid(size.0, size.1),
                };
                if let Some(r) = video.frame(&cur.fb, &rects, resized)? {
                    seq += 1;
                    gfx.send(Message::FrameUpdate {
                        seq,
                        rects: vec![r],
                    })
                    .await?;
                } else if !rects.is_empty() {
                    for chunk in rects.chunks(MAX_RECTS) {
                        seq += 1;
                        let rects = chunk
                            .iter()
                            .map(|r| encode_rect(&cur.fb, *r, zlib))
                            .collect::<anyhow::Result<_>>()?;
                        gfx.send(Message::FrameUpdate { seq, rects }).await?;
                    }
                }
                sent = Some(cur);
            }
        }
        tokio::select! {
            m = inbox.recv() => { last_seen = std::time::Instant::now();
                // acao do usuario (nao conta confirmacao de quadro nem keepalive)
                if !matches!(
                    m,
                    None | Some(Message::FrameAck { .. } | Message::Ping { .. } | Message::Pong { .. })
                ) {
                    idle.touch();
                }
                match m {
                None => return Ok(()),
                Some(Message::FrameAck { seq: s }) => {
                    if s > seq {
                        bail!("FRAME_ACK de quadro nao enviado");
                    }
                    acked = acked.max(s);
                }
                Some(Message::InputEvent(ev)) => {
                    // sem permissao de controle: so assiste
                    if control {
                        forward(sh, ev);
                    } else if !input_denied {
                        input_denied = true;
                        sh.audit.record("input_denied", &[("peer", peer), ("user", &user)]);
                    }
                }
                Some(Message::Ping { nonce }) => ctrl.send(Message::Pong { nonce }).await?,
                Some(Message::Pong { .. }) => {}
                Some(Message::Close { .. }) => return Ok(()),
                Some(Message::FileOffer { id, name, size }) => {
                    let r = match &mut inbound {
                        Some(i) => i.offer(id, &name, size),
                        None => Err("recebimento de arquivos desabilitado".into()),
                    };
                    match &r {
                        Ok(dest) => tracing::info!(%peer, "recebendo {name} ({size} bytes) em {}", dest.display()),
                        Err(e) => tracing::info!(%peer, "recusado {name}: {e}"),
                    }
                    ctrl.send(Message::FileAccept { id, accept: r.is_ok() }).await?;
                }
                Some(Message::FileChunk { id, offset, data }) => {
                    let Some(i) = &mut inbound else { bail!("FILE_CHUNK sem transferencia") };
                    if let Err(e) = i.chunk(id, offset, &data) {
                        tracing::warn!(%peer, "arquivo {id} descartado: {e}");
                    }
                }
                Some(Message::FileEnd { id, sha256 }) => {
                    let Some(i) = &mut inbound else { bail!("FILE_END sem transferencia") };
                    match i.end(id, &sha256) {
                        Ok(f) => {
                            let path = f.path.display().to_string();
                            tracing::info!(%peer, "arquivo recebido: {path}");
                            sh.audit.record("file_received", &[("peer", peer), ("path", &path), ("size", &f.size.to_string())]);
                        }
                        Err(e) => tracing::warn!(%peer, "arquivo {id} descartado: {e}"),
                    }
                }
                Some(Message::FileAccept { id, accept }) => outbound.answer(id, accept, ctrl.clone()),
                Some(Message::FsRequest { id, op }) => {
                    let reply = tokio::task::block_in_place(|| fsx.handle(&op));
                    crate::fsexplorer::audit(&sh.audit, peer, &user, &op, &reply);
                    ctrl.send(Message::FsResponse { id, reply }).await?;
                }
                Some(Message::ScreenSelect { index }) => {
                    if control {
                        sh.screens.select(index);
                    }
                }
                Some(Message::InputLock { on }) => {
                    let reason = if !on {
                        if let Some(mut l) = lock.take() {
                            l.reason = "cliente";
                        }
                        String::new()
                    } else if !lock_ok {
                        "sem permissao de controle".to_string()
                    } else if lock.is_some() {
                        String::new()
                    } else {
                        match crate::inputlock::Manager::acquire(crate::inputlock::global()) {
                            Ok(h) => {
                                lock = Some(Locked {
                                    _hold: h,
                                    audit: sh.audit.clone(),
                                    peer: peer.to_string(),
                                    user: user.clone(),
                                    reason: "sessao encerrada",
                                });
                                sh.audit.record("input_lock", &[("peer", peer), ("user", &user)]);
                                String::new()
                            }
                            Err(e) => e,
                        }
                    };
                    ctrl.send(Message::InputLockState { on: lock.is_some(), reason }).await?;
                }
                Some(other) => {
                    close(ctrl, close_code::PROTOCOL_ERROR, "mensagem inesperada").await;
                    bail!("mensagem inesperada: tipo {:#06x}", other.type_code());
                }
            }},
            p = async { offers.as_mut().expect("guardado").recv().await }, if offers.is_some() => {
                match p {
                    Ok(path) => {
                        if let Some(m) = outbound.offer(path.clone()) {
                            sh.audit.record("file_offered", &[("peer", peer), ("path", &path.display().to_string())]);
                            ctrl.send(m).await?;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => offers = None,
                }
            }
            _ = tokio::time::sleep(REFINE_AFTER), if video.lossy && seq - acked < WINDOW => {
                // movimento parou: reenvia a tela sem perdas
                video.lossy = false;
                if let Some(s) = &sent {
                    for chunk in grid(s.fb.width(), s.fb.height()).chunks(MAX_RECTS) {
                        seq += 1;
                        let rects = chunk
                            .iter()
                            .map(|r| encode_rect(&s.fb, *r, zlib))
                            .collect::<anyhow::Result<_>>()?;
                        gfx.send(Message::FrameUpdate { seq, rects }).await?;
                    }
                }
            }
            _ = tokio::time::sleep_until(crate::inputlock::idle_deadline(last_seen).into()), if lock.is_some() => {
                // conexao parada: solta mouse e teclado do usuario local
                if let Some(mut l) = lock.take() {
                    l.reason = "inatividade";
                }
                let _ = ctrl.try_send(Message::InputLockState { on: false, reason: "liberado por inatividade".into() });
            }
            r = async { screens.as_mut().expect("guardado").changed().await }, if screens.is_some() => {
                if r.is_err() {
                    screens = None;
                } else if let Some(rx) = &mut screens {
                    let (index, count) = *rx.borrow_and_update();
                    ctrl.send(Message::ScreenInfo { index, count }).await?;
                }
            }
            r = frames.changed(), if seq - acked < WINDOW => {
                if r.is_err() {
                    close(ctrl, close_code::SERVER_SHUTDOWN, "captura encerrada").await;
                    return Ok(());
                }
            }
            _ = tokio::time::sleep_until(idle.deadline().into()) => {
                if !idle.expired() {
                    continue;
                }
                sh.audit.record("idle_timeout", &[("peer", peer)]);
                close(ctrl, close_code::SERVER_SHUTDOWN, "encerrada por inatividade").await;
                return Ok(());
            }
        }
    }
}

/// Bloqueio ativo da sessao. Ao ser solto (pelo cliente, por inatividade ou
/// porque a sessao terminou de qualquer jeito) registra `input_unlock`.
struct Locked {
    _hold: crate::inputlock::Hold,
    audit: Arc<openvnc_security::audit::AuditLog>,
    peer: String,
    user: String,
    reason: &'static str,
}

impl Drop for Locked {
    fn drop(&mut self) {
        self.audit.record(
            "input_unlock",
            &[
                ("peer", &self.peer),
                ("user", &self.user),
                ("reason", self.reason),
            ],
        );
    }
}

fn forward(sh: &Shared, ev: NInput) {
    let Some(tx) = &sh.input else { return };
    let ev = match ev {
        NInput::Pointer { x, y, buttons } => Input::Pointer(PointerEvent { buttons, x, y }),
        NInput::Key { keysym, down } => Input::Key(KeyEvent { down, keysym }),
    };
    let _ = tx.send(ev);
}

/// Tiles cobrindo a tela inteira.
fn grid(w: u16, h: u16) -> Vec<Rect> {
    let mut v = Vec::new();
    let mut y = 0u16;
    while y < h {
        let th = TILE.min(h - y);
        let mut x = 0u16;
        while x < w {
            let tw = TILE.min(w - x);
            v.push(Rect::new(x, y, tw, th));
            x += tw;
        }
        y += th;
    }
    v
}

/// Extrai o retangulo como RGBA8 e codifica.
fn extract(fb: &Framebuffer, r: Rect) -> Vec<u8> {
    let stride = fb.stride();
    let mut raw = Vec::with_capacity(usize::from(r.width) * usize::from(r.height) * 4);
    for row in r.y..r.y + r.height {
        let off = usize::from(row) * stride + usize::from(r.x) * 4;
        raw.extend_from_slice(&fb.data()[off..off + usize::from(r.width) * 4]);
    }
    raw
}

fn encode_rect(fb: &Framebuffer, r: Rect, zlib: bool) -> anyhow::Result<FrameRect> {
    let raw = extract(fb, r);
    let (enc, data) = if zlib {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(&raw)?;
        (encoding::ZLIB, z.finish()?)
    } else {
        (encoding::RAW, raw)
    };
    Ok(FrameRect {
        x: r.x,
        y: r.y,
        width: r.width,
        height: r.height,
        encoding: enc,
        data,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "h264")]
    #[test]
    fn video_so_com_mudanca_grande() {
        use openvnc_codecs::video::H264Decoder;
        let mut fb = Framebuffer::new(64, 48, 1 << 20).unwrap();
        let mut v = super::Video::new(true);
        let small = [Rect::new(0, 0, 8, 8)];
        assert!(v.frame(&fb, &small, false).unwrap().is_none());
        assert!(v.frame(&fb, &super::grid(64, 48), true).unwrap().is_none());
        for y in 0..48 {
            fb.put_rgba_row(0, y, &[[200, 10, 10, 255]; 64]);
        }
        let r = v.frame(&fb, &super::grid(64, 48), false).unwrap().unwrap();
        assert_eq!((r.encoding, r.width, r.height), (encoding::H264, 64, 48));
        assert!(v.lossy);
        let mut out = vec![0u8; 64 * 48 * 4];
        assert!(H264Decoder::new()
            .unwrap()
            .decode(&r.data, 64, 48, &mut out)
            .unwrap());
        assert!(out[0].abs_diff(200) < 12 && out[1] < 24);
    }

    use super::*;

    #[test]
    fn grid_cobre_a_tela() {
        let g = grid(130, 70);
        assert_eq!(g.len(), 3 * 2);
        let area: u32 = g
            .iter()
            .map(|r| u32::from(r.width) * u32::from(r.height))
            .sum();
        assert_eq!(area, 130 * 70);
    }

    #[test]
    fn comparacao_constante() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
