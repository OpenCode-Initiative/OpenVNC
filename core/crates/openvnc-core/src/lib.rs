//! Tipos centrais do OpenVNC: PixelFormat, Rect, eventos e erros comuns.
//!
//! Convencoes do projeto definidas aqui:
//! - Erros com [`thiserror`], expostos via [`Error`] e [`Result`].
//! - Logs com `tracing`; nunca registrar senhas nem conteudo de tela.

pub mod input;
pub mod pixel;
pub mod rect;

pub use input::{KeyEvent, PointerEvent};
pub use pixel::PixelFormat;
pub use rect::Rect;

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Erro comum do OpenVNC.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Mensagem malformada ou invalida recebida do par remoto.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// Um limite configurado (tamanho, contagem) foi excedido.
    #[error("limit exceeded: {what} ({got} > {max})")]
    LimitExceeded {
        /// O que excedeu o limite.
        what: &'static str,
        /// Valor recebido.
        got: u64,
        /// Valor maximo permitido.
        max: u64,
    },
    /// Funcionalidade ainda nao suportada.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Erro de E/S.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Alias de resultado do OpenVNC.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Verifica `got <= max`, retornando [`Error::LimitExceeded`] caso contrario.
pub fn check_limit(what: &'static str, got: u64, max: u64) -> Result<()> {
    if got > max {
        tracing::warn!(what, got, max, "limit exceeded");
        return Err(Error::LimitExceeded { what, got, max });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_ok_and_exceeded() {
        assert!(check_limit("payload", 10, 10).is_ok());
        let e = check_limit("payload", 11, 10).unwrap_err();
        assert_eq!(e.to_string(), "limit exceeded: payload (11 > 10)");
    }
}
