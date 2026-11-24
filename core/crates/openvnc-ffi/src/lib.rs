//! C ABI estavel do OpenVNC.
//!
//! Status: esqueleto da Fase 0. Implementacao planejada em `PLANO.md`.

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
