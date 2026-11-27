//! Encerramento por inatividade: sem acao do cliente (tecla, mouse,
//! arquivos) por `idle_timeout_secs`, a sessao fecha.
//!
//! O cliente abre duas conexoes (RFB para a imagem e nativa para arquivos);
//! a ultima acao e compartilhada por IP para uma nao derrubar a outra.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static LAST: Mutex<Option<HashMap<IpAddr, Instant>>> = Mutex::new(None);

/// Relogio de inatividade de uma sessao.
pub struct Idle {
    ip: Option<IpAddr>,
    limit: Duration,
    own: Instant,
}

impl Idle {
    /// Comeca a contar agora.
    pub fn new(peer: &str, secs: u64) -> Self {
        let mut i = Idle {
            ip: crate::lockout::peer_ip(peer),
            limit: Duration::from_secs(secs),
            own: Instant::now(),
        };
        i.touch();
        i
    }

    /// Registra uma acao do cliente.
    pub fn touch(&mut self) {
        self.own = Instant::now();
        if let (Some(ip), Ok(mut m)) = (self.ip, LAST.lock()) {
            m.get_or_insert_with(HashMap::new).insert(ip, self.own);
        }
    }

    /// Quando a sessao expira, se nada mais acontecer.
    pub fn deadline(&self) -> Instant {
        let shared = self
            .ip
            .and_then(|ip| LAST.lock().ok()?.as_ref()?.get(&ip).copied());
        shared.map_or(self.own, |s| s.max(self.own)) + self.limit
    }

    /// Ja passou do limite.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline()
    }
}
