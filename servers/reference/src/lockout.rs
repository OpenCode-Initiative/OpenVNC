//! Protecao contra forca bruta: depois de [`FREE_FAILS`] falhas de
//! autenticacao seguidas, o IP fica bloqueado por um tempo que dobra a cada
//! nova falha (30 s, 60 s, 120 s... ate [`MAX_BLOCK`]). Um login bem
//! sucedido zera o contador. Vale para o RFB e para o protocolo nativo.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Falhas toleradas antes do primeiro bloqueio.
pub const FREE_FAILS: u32 = 5;
/// Primeiro bloqueio.
const BASE_BLOCK: Duration = Duration::from_secs(30);
/// Bloqueio maximo.
pub const MAX_BLOCK: Duration = Duration::from_secs(15 * 60);
/// Entradas sem falha ha mais que isto sao esquecidas.
const FORGET: Duration = Duration::from_secs(60 * 60);
/// Limite de IPs lembrados (memoria limitada mesmo sob varredura).
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Entry {
    fails: u32,
    last: Instant,
    until: Option<Instant>,
}

/// Tabela de falhas por IP.
#[derive(Debug, Default)]
pub struct Lockout {
    map: Mutex<HashMap<IpAddr, Entry>>,
}

impl Lockout {
    /// Tempo restante de bloqueio de `ip` (`None` = livre).
    pub fn blocked(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let m = self.map.lock().ok()?;
        let until = m.get(&norm(ip))?.until?;
        (until > now).then(|| until - now)
    }

    /// Registra uma falha; devolve o bloqueio aplicado, se houver.
    pub fn fail(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let mut m = self.map.lock().ok()?;
        if m.len() >= MAX_ENTRIES {
            m.retain(|_, e| now.duration_since(e.last) < FORGET);
            if m.len() >= MAX_ENTRIES {
                // sob varredura macica: descarta tudo que nao esta bloqueado
                m.retain(|_, e| e.until.is_some_and(|u| u > now));
            }
        }
        let e = m.entry(norm(ip)).or_insert(Entry {
            fails: 0,
            last: now,
            until: None,
        });
        if now.duration_since(e.last) >= FORGET {
            e.fails = 0;
        }
        e.fails = e.fails.saturating_add(1);
        e.last = now;
        if e.fails < FREE_FAILS {
            return None;
        }
        let exp = (e.fails - FREE_FAILS).min(16);
        let d = BASE_BLOCK.saturating_mul(1 << exp).min(MAX_BLOCK);
        e.until = Some(now + d);
        Some(d)
    }

    /// Login aceito: esquece as falhas.
    pub fn success(&self, ip: IpAddr) {
        if let Ok(mut m) = self.map.lock() {
            m.remove(&norm(ip));
        }
    }
}

/// IPv4 mapeado em IPv6 conta como o IPv4.
fn norm(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(IpAddr::V6(v), IpAddr::V4),
        v => v,
    }
}

/// IP de um `peer` no formato `ip:porta` (ou `[ipv6]:porta`).
pub fn peer_ip(peer: &str) -> Option<IpAddr> {
    peer.parse::<std::net::SocketAddr>()
        .map(|s| s.ip())
        .ok()
        .or_else(|| peer.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloqueia_depois_de_cinco_e_dobra() {
        let l = Lockout::default();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let t = Instant::now();
        for _ in 0..FREE_FAILS - 1 {
            assert_eq!(l.fail(ip, t), None);
        }
        assert!(l.blocked(ip, t).is_none());
        assert_eq!(l.fail(ip, t), Some(Duration::from_secs(30)));
        assert!(l.blocked(ip, t).is_some());
        assert_eq!(l.fail(ip, t), Some(Duration::from_secs(60)));
        // depois do prazo, livre de novo (mas a proxima falha bloqueia mais)
        assert!(l.blocked(ip, t + Duration::from_secs(61)).is_none());
        for _ in 0..30 {
            l.fail(ip, t);
        }
        assert_eq!(l.fail(ip, t), Some(MAX_BLOCK));
    }

    #[test]
    fn sucesso_zera_e_ips_sao_independentes() {
        let l = Lockout::default();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "::ffff:10.0.0.2".parse().unwrap();
        let t = Instant::now();
        for _ in 0..FREE_FAILS {
            l.fail(a, t);
        }
        assert!(l.blocked(a, t).is_some());
        assert!(l.blocked(b, t).is_none());
        l.success(a);
        assert!(l.blocked(a, t).is_none());
        // mapeado = mesmo IP
        for _ in 0..FREE_FAILS {
            l.fail(b, t);
        }
        assert!(l.blocked("10.0.0.2".parse().unwrap(), t).is_some());
    }

    #[test]
    fn peer_com_porta() {
        assert_eq!(peer_ip("1.2.3.4:5900"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(peer_ip("[::1]:5900"), Some("::1".parse().unwrap()));
        assert_eq!(peer_ip("lixo"), None);
    }
}
