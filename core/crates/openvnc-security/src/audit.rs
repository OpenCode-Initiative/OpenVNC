//! Log de auditoria em JSON lines (um objeto por linha, so acrescentado).
//!
//! Campos fixos: `ts` (segundos UNIX) e `event`; o resto sao pares
//! texto. Segredos (senhas, tokens) nunca devem ser passados aqui.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use openvnc_core::Result;

/// Destino do log.
#[derive(Debug)]
pub struct AuditLog {
    out: Mutex<Option<File>>,
}

/// Escapa `s` como string JSON (sem as aspas).
pub fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// Monta uma linha (sem `\n`).
pub fn format_line(ts: u64, event: &str, fields: &[(&str, &str)]) -> String {
    let mut s = format!("{{\"ts\":{ts},\"event\":\"{}\"", json_escape(event));
    for (k, v) in fields {
        s.push_str(&format!(",\"{}\":\"{}\"", json_escape(k), json_escape(v)));
    }
    s.push('}');
    s
}

impl AuditLog {
    /// Log desligado (descarta tudo).
    pub fn disabled() -> Self {
        AuditLog {
            out: Mutex::new(None),
        }
    }

    /// Abre `path` para acrescentar (cria se preciso).
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        Ok(AuditLog {
            out: Mutex::new(Some(o.open(path)?)),
        })
    }

    /// Registra um evento. Falha de escrita vai para o `tracing` mas nao
    /// derruba o servidor.
    pub fn record(&self, event: &str, fields: &[(&str, &str)]) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut line = format_line(ts, event, fields);
        line.push('\n');
        let Ok(mut g) = self.out.lock() else { return };
        if let Some(f) = g.as_mut() {
            if let Err(e) = f.write_all(line.as_bytes()).and_then(|_| f.flush()) {
                eprintln!("auditoria: falha ao gravar: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_appends() {
        assert_eq!(
            format_line(5, "login", &[("user", "a\"b\\c\n\u{1}")]),
            r#"{"ts":5,"event":"login","user":"a\"b\\c\n\u0001"}"#
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.log");
        {
            let a = AuditLog::open(&p).unwrap();
            a.record("x", &[]);
        }
        AuditLog::open(&p).unwrap().record("y", &[("k", "v")]);
        let t = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<_> = t.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].ends_with(r#""event":"y","k":"v"}"#));
        AuditLog::disabled().record("z", &[]);
    }
}
