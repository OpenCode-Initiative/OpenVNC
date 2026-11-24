//! Transportes. Fase 1: TCP com timeout e backoff exponencial.
//!
//! TCP puro nao tem criptografia: a UI deve avisar o usuario e recomendar
//! tunel SSH (ver `docs/security.md`).

use std::time::Duration;

use openvnc_core::{Error, Result};
use tokio::net::TcpStream;

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Porta VNC padrao (display :0).
pub const DEFAULT_PORT: u16 = 5900;

/// Conecta via TCP com timeout; desativa Nagle (latencia de entrada).
pub async fn connect_tcp(addr: &str, timeout: Duration) -> Result<TcpStream> {
    let s = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timeout de conexao",
            ))
        })??;
    s.set_nodelay(true)?;
    Ok(s)
}

/// Normaliza `host`, `host:porta` ou `host::porta-display` (convencao VNC `host:1` = 5901).
pub fn parse_address(input: &str) -> Result<String> {
    let input = input.trim();
    if input.is_empty() {
        return Err(Error::Protocol("endereco vazio".into()));
    }
    if input.starts_with('[') {
        // IPv6 literal: [::1]:5900 ou [::1]
        return Ok(if input.ends_with(']') {
            format!("{input}:{DEFAULT_PORT}")
        } else {
            input.to_string()
        });
    }
    if input.matches(':').count() > 2 || input.starts_with("::") {
        // IPv6 literal sem colchetes: sem porta
        return Ok(format!("[{input}]:{DEFAULT_PORT}"));
    }
    if let Some((host, port)) = input.split_once("::") {
        let p: u16 = port
            .parse()
            .map_err(|_| Error::Protocol("porta invalida".into()))?;
        return Ok(format!("{host}:{p}"));
    }
    match input.rsplit_once(':') {
        Some((host, n)) if !host.contains(':') => {
            let v: u16 = n
                .parse()
                .map_err(|_| Error::Protocol("porta invalida".into()))?;
            // numeros pequenos sao displays VNC
            let port = if v < 100 { DEFAULT_PORT + v } else { v };
            Ok(format!("{host}:{port}"))
        }
        Some(_) => Ok(format!("[{input}]:{DEFAULT_PORT}")),
        None => Ok(format!("{input}:{DEFAULT_PORT}")),
    }
}

/// Backoff exponencial com teto e limite de tentativas.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    max_attempts: u32,
    attempt: u32,
}

impl Backoff {
    /// Novo backoff.
    pub fn new(base: Duration, max: Duration, max_attempts: u32) -> Self {
        Backoff {
            base,
            max,
            max_attempts,
            attempt: 0,
        }
    }

    /// Proximo atraso, ou `None` se as tentativas acabaram.
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.attempt >= self.max_attempts {
            return None;
        }
        let d = self
            .base
            .saturating_mul(1u32 << self.attempt.min(16))
            .min(self.max);
        self.attempt += 1;
        Some(d)
    }

    /// Zera apos conexao bem-sucedida.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff::new(Duration::from_millis(500), Duration::from_secs(30), 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(parse_address("host").unwrap(), "host:5900");
        assert_eq!(parse_address("host:1").unwrap(), "host:5901");
        assert_eq!(parse_address("host:5905").unwrap(), "host:5905");
        assert_eq!(parse_address("host::22").unwrap(), "host:22");
        assert_eq!(parse_address("[::1]").unwrap(), "[::1]:5900");
        assert_eq!(parse_address("::1").unwrap(), "[::1]:5900");
        assert!(parse_address("h:x").is_err());
        assert!(parse_address("").is_err());
    }

    #[test]
    fn backoff_grows_caps_and_ends() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(5), 4);
        let v: Vec<_> = std::iter::from_fn(|| b.next_delay())
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(v, vec![1, 2, 4, 5]);
        b.reset();
        assert!(b.next_delay().is_some());
    }

    #[tokio::test]
    async fn connect_refused_or_timeout_is_error() {
        assert!(connect_tcp("127.0.0.1:1", Duration::from_millis(500))
            .await
            .is_err());
    }
}
