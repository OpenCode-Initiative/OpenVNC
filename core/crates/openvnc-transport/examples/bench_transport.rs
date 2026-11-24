//! Compara TCP, TCP+TLS 1.3 e QUIC em loopback.
//!
//! `cargo run --release -p openvnc-transport --example bench_transport [MiB] [pings]`
//!
//! Mede: vazao de um envio em massa (cliente -> servidor) e RTT de
//! ping-pong de 64 bytes ocioso. No QUIC mede tambem o RTT do canal de
//! entrada enquanto o canal de graficos esta saturado (o caso que motiva
//! streams separados). Loopback nao tem perda nem latencia: os numeros
//! mostram so o custo de CPU de cada pilha, nao o comportamento em rede
//! real (onde o QUIC evita head-of-line blocking entre canais).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use openvnc_transport::quic;
use openvnc_transport::tls::{ClientTls, ServerIdentity, Trust};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CHUNK: usize = 64 * 1024;
const PING: usize = 64;

async fn sink<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(r: &mut R, w: &mut W, total: u64) {
    let mut buf = vec![0u8; CHUNK];
    let mut got = 0u64;
    while got < total {
        let n = r.read(&mut buf).await.unwrap();
        assert!(n > 0);
        got += n as u64;
    }
    w.write_all(b"k").await.unwrap();
    w.flush().await.unwrap();
}

async fn bulk<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    total: u64,
) -> f64 {
    let buf = vec![0xa5u8; CHUNK];
    let t = Instant::now();
    let mut sent = 0u64;
    while sent < total {
        w.write_all(&buf).await.unwrap();
        sent += CHUNK as u64;
    }
    w.flush().await.unwrap();
    let mut k = [0u8; 1];
    r.read_exact(&mut k).await.unwrap();
    total as f64 * 8.0 / t.elapsed().as_secs_f64() / 1e9
}

async fn echo<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(r: &mut R, w: &mut W, n: usize) {
    let mut b = [0u8; PING];
    for _ in 0..n {
        r.read_exact(&mut b).await.unwrap();
        w.write_all(&b).await.unwrap();
        w.flush().await.unwrap();
    }
}

/// Devolve (mediana, p99) em microssegundos.
async fn pings<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    n: usize,
) -> (f64, f64) {
    let mut b = [7u8; PING];
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        w.write_all(&b).await.unwrap();
        w.flush().await.unwrap();
        r.read_exact(&mut b).await.unwrap();
        v.push(t.elapsed());
    }
    v.sort();
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    (us(v[n / 2]), us(v[n * 99 / 100]))
}

fn report(name: &str, gbps: f64, (p50, p99): (f64, f64)) {
    println!("{name:<10} {gbps:>8.2} Gbit/s   RTT p50 {p50:>7.1} us   p99 {p99:>7.1} us");
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let mib: u64 = args.next().map_or(512, |a| a.parse().expect("MiB"));
    let n: usize = args.next().map_or(5000, |a| a.parse().expect("pings"));
    let total = mib * 1024 * 1024;
    println!("loopback, {mib} MiB em massa, {n} pings de {PING} B");
    let id = ServerIdentity::self_signed(&["localhost".into()]).unwrap();
    let tls = ClientTls {
        trust: Trust::Pinned(id.fingerprint()),
    };

    // TCP
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            s.set_nodelay(true).unwrap();
            let (mut r, mut w) = tokio::io::split(s);
            sink(&mut r, &mut w, total).await;
            echo(&mut r, &mut w, n).await;
        });
        let s = TcpStream::connect(addr).await.unwrap();
        s.set_nodelay(true).unwrap();
        let (mut r, mut w) = tokio::io::split(s);
        let g = bulk(&mut r, &mut w, total).await;
        let p = pings(&mut r, &mut w, n).await;
        srv.await.unwrap();
        report("TCP", g, p);
    }

    // TCP + TLS 1.3
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let acc = id.acceptor().unwrap();
        let srv = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            s.set_nodelay(true).unwrap();
            let s = acc.accept(s).await.unwrap();
            let (mut r, mut w) = tokio::io::split(s);
            sink(&mut r, &mut w, total).await;
            echo(&mut r, &mut w, n).await;
        });
        let s = TcpStream::connect(addr).await.unwrap();
        s.set_nodelay(true).unwrap();
        let s = tls.connect(s, "localhost", "bench").await.unwrap();
        let (mut r, mut w) = tokio::io::split(s);
        let g = bulk(&mut r, &mut w, total).await;
        let p = pings(&mut r, &mut w, n).await;
        srv.await.unwrap();
        report("TLS 1.3", g, p);
    }

    // QUIC: massa no canal de graficos, pings no de entrada
    {
        let ep = quic::server_endpoint("127.0.0.1:0".parse().unwrap(), &id).unwrap();
        let addr: SocketAddr = ep.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let mut s = quic::accept(&ep).await.unwrap().unwrap();
            let g = &mut s.graphics;
            sink(&mut g.recv, &mut g.send, total).await;
            let i = &mut s.input;
            echo(&mut i.recv, &mut i.send, n).await;
            // RTT sob carga: graficos e entrada ao mesmo tempo
            let (g, i) = (&mut s.graphics, &mut s.input);
            tokio::join!(
                sink(&mut g.recv, &mut g.send, total),
                echo(&mut i.recv, &mut i.send, n)
            );
            s.connection.closed().await;
        });
        let (cep, mut s) = quic::connect(addr, "localhost", "bench", &tls)
            .await
            .unwrap();
        let g = &mut s.graphics;
        let gb = bulk(&mut g.recv, &mut g.send, total).await;
        let i = &mut s.input;
        let p = pings(&mut i.recv, &mut i.send, n).await;
        report("QUIC", gb, p);
        let (g, i) = (&mut s.graphics, &mut s.input);
        let (_, loaded) = tokio::join!(
            bulk(&mut g.recv, &mut g.send, total),
            pings(&mut i.recv, &mut i.send, n)
        );
        println!(
            "QUIC: RTT do canal de entrada com graficos saturados: p50 {:.1} us  p99 {:.1} us",
            loaded.0, loaded.1
        );
        s.connection.close(0u32.into(), b"fim");
        cep.wait_idle().await;
        srv.await.unwrap();
    }
}
