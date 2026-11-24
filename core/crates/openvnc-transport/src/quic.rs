//! QUIC (quinn) com streams separados por funcao.
//!
//! **So transporte**, sem logica de aplicacao (o protocolo nativo e a
//! fase 4). A conexao usa TLS 1.3 com as mesmas politicas de confianca de
//! [`crate::tls`] e ALPN [`ALPN`]. Logo apos o handshake o cliente abre
//! quatro streams bidirecionais e escreve no primeiro byte de cada um o
//! [`Channel`] que ele representa; o servidor aceita exatamente esses
//! quatro, sem repeticao, antes de entregar a [`QuicSession`]. Assim uma
//! rajada no canal de graficos nao atrasa entrada nem controle
//! (sem head-of-line blocking entre canais).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use openvnc_core::{Error, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
pub use quinn::{Connection, Endpoint, RecvStream, SendStream};

use crate::tls::{server_name_of, ClientTls, ServerIdentity};

/// ALPN do transporte QUIC do OpenVNC (versao 0, instavel).
pub const ALPN: &[u8] = b"openvnc-quic/0";

/// Tempo maximo para o par abrir os quatro canais.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Canais logicos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Channel {
    /// Controle (negociacao, keepalive, encerramento).
    Control = 1,
    /// Entrada (teclado, mouse): baixa latencia.
    Input = 2,
    /// Graficos (atualizacoes de tela): alto volume.
    Graphics = 3,
    /// Metadados (clipboard, cursor, tamanho de tela).
    Metadata = 4,
}

impl Channel {
    /// Todos, na ordem de abertura.
    pub const ALL: [Channel; 4] = [
        Channel::Control,
        Channel::Input,
        Channel::Graphics,
        Channel::Metadata,
    ];

    fn from_tag(t: u8) -> Option<Channel> {
        Channel::ALL.into_iter().find(|c| *c as u8 == t)
    }
}

/// Um stream bidirecional.
#[derive(Debug)]
pub struct ChannelStream {
    /// Envio.
    pub send: SendStream,
    /// Recebimento.
    pub recv: RecvStream,
}

/// Conexao QUIC estabelecida com os quatro canais abertos.
#[derive(Debug)]
pub struct QuicSession {
    /// Conexao (estatisticas, encerramento, RTT).
    pub connection: Connection,
    /// Canal de controle.
    pub control: ChannelStream,
    /// Canal de entrada.
    pub input: ChannelStream,
    /// Canal de graficos.
    pub graphics: ChannelStream,
    /// Canal de metadados.
    pub metadata: ChannelStream,
}

fn qerr(e: impl std::fmt::Display) -> Error {
    Error::Protocol(format!("quic: {e}"))
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // so os quatro canais; o par nao pode abrir mais streams
    t.max_concurrent_bidi_streams(4u32.into());
    t.max_concurrent_uni_streams(0u32.into());
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    t.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("30s cabe"),
    ));
    Arc::new(t)
}

/// Cria um endpoint servidor em `addr`.
pub fn server_endpoint(addr: SocketAddr, id: &ServerIdentity) -> Result<Endpoint> {
    let tls = id.rustls_config(&[ALPN])?;
    let crypto = QuicServerConfig::try_from((*tls).clone()).map_err(qerr)?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport_config());
    Ok(Endpoint::server(cfg, addr)?)
}

/// Aceita a proxima conexao e seus quatro canais. `Ok(None)` quando o
/// endpoint foi fechado.
pub async fn accept(endpoint: &Endpoint) -> Result<Option<QuicSession>> {
    let Some(incoming) = endpoint.accept().await else {
        return Ok(None);
    };
    let conn = incoming.await.map_err(qerr)?;
    let res = tokio::time::timeout(OPEN_TIMEOUT, accept_channels(&conn)).await;
    match res {
        Ok(Ok(s)) => Ok(Some(s)),
        Ok(Err(e)) => {
            conn.close(1u32.into(), b"canais invalidos");
            Err(e)
        }
        Err(_) => {
            conn.close(2u32.into(), b"timeout");
            Err(qerr("timeout esperando os canais"))
        }
    }
}

async fn accept_channels(conn: &Connection) -> Result<QuicSession> {
    let mut slots: [Option<ChannelStream>; 4] = [None, None, None, None];
    for _ in 0..4 {
        let (send, mut recv) = conn.accept_bi().await.map_err(qerr)?;
        let mut tag = [0u8; 1];
        recv.read_exact(&mut tag).await.map_err(qerr)?;
        let ch = Channel::from_tag(tag[0]).ok_or_else(|| qerr("canal desconhecido"))?;
        let slot = &mut slots[ch as usize - 1];
        if slot.is_some() {
            return Err(qerr(format!("canal {ch:?} repetido")));
        }
        *slot = Some(ChannelStream { send, recv });
    }
    let [Some(control), Some(input), Some(graphics), Some(metadata)] = slots else {
        unreachable!("4 canais distintos de 4 possiveis");
    };
    Ok(QuicSession {
        connection: conn.clone(),
        control,
        input,
        graphics,
        metadata,
    })
}

/// Conecta a `addr`. `server_name` e validado conforme `tls.trust`;
/// `host_key` identifica o servidor no `known_hosts` (TOFU).
pub async fn connect(
    addr: SocketAddr,
    server_name: &str,
    host_key: &str,
    tls: &ClientTls,
) -> Result<(Endpoint, QuicSession)> {
    let (rcfg, observed) = tls.rustls_config(host_key, &[ALPN])?;
    let crypto = QuicClientConfig::try_from((*rcfg).clone()).map_err(qerr)?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(transport_config());
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().expect("fixo")
    } else {
        "0.0.0.0:0".parse().expect("fixo")
    };
    let mut ep = Endpoint::client(bind)?;
    ep.set_default_client_config(cfg);
    // valida o nome antes (mensagem melhor que a do quinn)
    server_name_of(server_name)?;
    let name = server_name.trim_start_matches('[').trim_end_matches(']');
    let conn = ep
        .connect(addr, name)
        .map_err(qerr)?
        .await
        .map_err(|e| qerr(format!("handshake falhou: {e}")))?;
    tls.commit(host_key, &observed)?;
    let mut streams = Vec::with_capacity(4);
    for ch in Channel::ALL {
        let (mut send, recv) = conn.open_bi().await.map_err(qerr)?;
        send.write_all(&[ch as u8]).await.map_err(qerr)?;
        streams.push(ChannelStream { send, recv });
    }
    let mut it = streams.into_iter();
    let mut next = || it.next().expect("4 streams");
    let session = QuicSession {
        connection: conn,
        control: next(),
        input: next(),
        graphics: next(),
        metadata: next(),
    };
    Ok((ep, session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::Trust;

    fn ident() -> ServerIdentity {
        ServerIdentity::self_signed(&["localhost".into()]).unwrap()
    }

    #[tokio::test]
    async fn four_channels_echo_independently() {
        let id = ident();
        let ep = server_endpoint("127.0.0.1:0".parse().unwrap(), &id).unwrap();
        let addr = ep.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let mut s = accept(&ep).await.unwrap().unwrap();
            // ecoa cada canal com o seu proprio prefixo
            for (tag, ch) in [
                (b'c', &mut s.control),
                (b'i', &mut s.input),
                (b'g', &mut s.graphics),
                (b'm', &mut s.metadata),
            ] {
                let mut b = [0u8; 4];
                ch.recv.read_exact(&mut b).await.unwrap();
                ch.send.write_all(&[tag]).await.unwrap();
                ch.send.write_all(&b).await.unwrap();
            }
            s.connection.closed().await;
        });
        let tls = ClientTls {
            trust: Trust::Pinned(id.fingerprint()),
        };
        let (ep, mut s) = connect(addr, "localhost", "x", &tls).await.unwrap();
        for (tag, ch) in [
            (b'c', &mut s.control),
            (b'i', &mut s.input),
            (b'g', &mut s.graphics),
            (b'm', &mut s.metadata),
        ] {
            ch.send.write_all(b"ping").await.unwrap();
            let mut b = [0u8; 5];
            ch.recv.read_exact(&mut b).await.unwrap();
            assert_eq!(b[0], tag);
            assert_eq!(&b[1..], b"ping");
        }
        s.connection.close(0u32.into(), b"fim");
        ep.wait_idle().await;
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_pin_fails_handshake() {
        let id = ident();
        let ep = server_endpoint("127.0.0.1:0".parse().unwrap(), &id).unwrap();
        let addr = ep.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = accept(&ep).await;
        });
        let tls = ClientTls {
            trust: Trust::Pinned(ident().fingerprint()),
        };
        let e = connect(addr, "localhost", "x", &tls).await.unwrap_err();
        assert!(e.to_string().contains("handshake"), "{e}");
    }

    #[tokio::test]
    async fn duplicate_channel_is_rejected() {
        let id = ident();
        let ep = server_endpoint("127.0.0.1:0".parse().unwrap(), &id).unwrap();
        let addr = ep.local_addr().unwrap();
        let srv = tokio::spawn(async move { accept(&ep).await.map(|_| ()) });
        // cliente "manual" que abre o canal de controle duas vezes
        let (rcfg, _) = ClientTls {
            trust: Trust::Pinned(id.fingerprint()),
        }
        .rustls_config("x", &[ALPN])
        .unwrap();
        let mut cep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        cep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from((*rcfg).clone()).unwrap(),
        )));
        let conn = cep.connect(addr, "localhost").unwrap().await.unwrap();
        let mut keep = Vec::new();
        for _ in 0..2 {
            let (mut s, r) = conn.open_bi().await.unwrap();
            s.write_all(&[Channel::Control as u8]).await.unwrap();
            keep.push((s, r));
        }
        let e = srv.await.unwrap().unwrap_err();
        assert!(e.to_string().contains("repetido"), "{e}");
    }
}
