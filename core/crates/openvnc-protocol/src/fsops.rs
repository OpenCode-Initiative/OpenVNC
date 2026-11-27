//! Explorador de arquivos remoto e bloqueio de entrada (mensagens 0x005x e
//! 0x006x).
//!
//! O explorador e um protocolo de pedido e resposta: o cliente manda
//! [`super::Message::FsRequest`] com um id e uma [`FsOp`]; o servidor
//! responde [`super::Message::FsResponse`] com o mesmo id e um [`FsReply`].
//! Transferencias recursivas sao conduzidas pelo cliente (lista, cria
//! pastas, le e escreve blocos), entao o servidor so precisa validar cada
//! caminho isoladamente.

use super::{check_limit, Error, Result, MAX_FILE_CHUNK, R, W};

/// Numero maximo de entradas numa listagem.
pub const MAX_FS_ENTRIES: usize = 10_000;

/// Numero maximo de raizes (unidades) numa resposta.
pub const MAX_FS_ROOTS: usize = 64;

/// Operacao pedida pelo cliente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsOp {
    /// Lista as raizes navegaveis (unidades no Windows, `/` ou a raiz
    /// configurada).
    Roots,
    /// Lista um diretorio.
    List {
        /// Caminho absoluto no servidor.
        path: String,
    },
    /// Cria um diretorio (o pai precisa existir).
    Mkdir {
        /// Caminho do novo diretorio.
        path: String,
    },
    /// Renomeia ou move dentro da area permitida.
    Rename {
        /// Origem.
        from: String,
        /// Destino (nao pode existir).
        to: String,
    },
    /// Apaga arquivo ou diretorio (recursivo).
    Delete {
        /// Caminho.
        path: String,
    },
    /// Le um bloco de um arquivo.
    Read {
        /// Caminho.
        path: String,
        /// Posicao.
        offset: u64,
        /// Tamanho maximo (limitado a [`MAX_FILE_CHUNK`]).
        len: u32,
    },
    /// Escreve um bloco. Com `offset == 0` o arquivo e criado (ou truncado
    /// se `overwrite`); depois, os blocos devem vir em ordem.
    Write {
        /// Caminho.
        path: String,
        /// Posicao.
        offset: u64,
        /// Pode substituir um arquivo existente.
        overwrite: bool,
        /// Dados.
        data: Vec<u8>,
    },
}

impl FsOp {
    /// Nome curto (auditoria e logs).
    pub fn name(&self) -> &'static str {
        match self {
            FsOp::Roots => "roots",
            FsOp::List { .. } => "list",
            FsOp::Mkdir { .. } => "mkdir",
            FsOp::Rename { .. } => "rename",
            FsOp::Delete { .. } => "delete",
            FsOp::Read { .. } => "read",
            FsOp::Write { .. } => "write",
        }
    }
}

/// Entrada de diretorio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEntry {
    /// Nome (sem diretorio).
    pub name: String,
    /// E diretorio.
    pub is_dir: bool,
    /// Tamanho em bytes (0 para diretorios).
    pub size: u64,
    /// Modificacao em segundos Unix (0 = desconhecido).
    pub modified: u64,
}

/// Resposta do servidor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsReply {
    /// Sucesso sem dados.
    Ok,
    /// Falha (permissao, caminho fora da area, inexistente...).
    Error {
        /// Motivo legivel.
        message: String,
    },
    /// Raizes navegaveis.
    Roots {
        /// Caminhos absolutos.
        roots: Vec<String>,
    },
    /// Conteudo de um diretorio.
    Entries {
        /// Caminho canonico listado.
        path: String,
        /// Entradas.
        entries: Vec<FsEntry>,
    },
    /// Bloco lido.
    Data {
        /// Dados.
        data: Vec<u8>,
        /// Fim do arquivo.
        eof: bool,
    },
}

pub(super) fn encode_op(w: &mut W, op: &FsOp) -> Result<()> {
    match op {
        FsOp::Roots => w.u8(0),
        FsOp::List { path } => {
            w.u8(1);
            w.str(path)?;
        }
        FsOp::Mkdir { path } => {
            w.u8(2);
            w.str(path)?;
        }
        FsOp::Rename { from, to } => {
            w.u8(3);
            w.str(from)?;
            w.str(to)?;
        }
        FsOp::Delete { path } => {
            w.u8(4);
            w.str(path)?;
        }
        FsOp::Read { path, offset, len } => {
            w.u8(5);
            w.str(path)?;
            w.u64(*offset);
            w.u32(*len);
        }
        FsOp::Write {
            path,
            offset,
            overwrite,
            data,
        } => {
            check_limit("fs write", data.len() as u64, MAX_FILE_CHUNK as u64)?;
            w.u8(6);
            w.str(path)?;
            w.u64(*offset);
            w.u8(u8::from(*overwrite));
            w.bytes32(data);
        }
    }
    Ok(())
}

pub(super) fn decode_op(r: &mut R<'_>) -> Result<FsOp> {
    Ok(match r.u8()? {
        0 => FsOp::Roots,
        1 => FsOp::List { path: r.str()? },
        2 => FsOp::Mkdir { path: r.str()? },
        3 => FsOp::Rename {
            from: r.str()?,
            to: r.str()?,
        },
        4 => FsOp::Delete { path: r.str()? },
        5 => FsOp::Read {
            path: r.str()?,
            offset: r.u64()?,
            len: r.u32()?,
        },
        6 => FsOp::Write {
            path: r.str()?,
            offset: r.u64()?,
            overwrite: r.bool()?,
            data: r.bytes32(MAX_FILE_CHUNK)?,
        },
        k => return Err(Error::Protocol(format!("operacao fs desconhecida: {k}"))),
    })
}

pub(super) fn encode_reply(w: &mut W, rep: &FsReply) -> Result<()> {
    match rep {
        FsReply::Ok => w.u8(0),
        FsReply::Error { message } => {
            w.u8(1);
            w.str(message)?;
        }
        FsReply::Roots { roots } => {
            check_limit("fs roots", roots.len() as u64, MAX_FS_ROOTS as u64)?;
            w.u8(2);
            w.u16(roots.len() as u16);
            for r in roots {
                w.str(r)?;
            }
        }
        FsReply::Entries { path, entries } => {
            check_limit("fs entries", entries.len() as u64, MAX_FS_ENTRIES as u64)?;
            w.u8(3);
            w.str(path)?;
            w.u32(entries.len() as u32);
            for e in entries {
                w.str(&e.name)?;
                w.u8(u8::from(e.is_dir));
                w.u64(e.size);
                w.u64(e.modified);
            }
        }
        FsReply::Data { data, eof } => {
            check_limit("fs data", data.len() as u64, MAX_FILE_CHUNK as u64)?;
            w.u8(4);
            w.u8(u8::from(*eof));
            w.bytes32(data);
        }
    }
    Ok(())
}

pub(super) fn decode_reply(r: &mut R<'_>) -> Result<FsReply> {
    Ok(match r.u8()? {
        0 => FsReply::Ok,
        1 => FsReply::Error { message: r.str()? },
        2 => {
            let n = usize::from(r.u16()?);
            check_limit("fs roots", n as u64, MAX_FS_ROOTS as u64)?;
            let mut roots = Vec::with_capacity(n);
            for _ in 0..n {
                roots.push(r.str()?);
            }
            FsReply::Roots { roots }
        }
        3 => {
            let path = r.str()?;
            let n = r.u32()? as usize;
            check_limit("fs entries", n as u64, MAX_FS_ENTRIES as u64)?;
            let mut entries = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let name = r.str()?;
                if name.is_empty()
                    || name == "."
                    || name == ".."
                    || name.contains(['/', '\\'])
                    || name.chars().any(char::is_control)
                {
                    return Err(Error::Protocol("nome de entrada invalido".into()));
                }
                entries.push(FsEntry {
                    name,
                    is_dir: r.bool()?,
                    size: r.u64()?,
                    modified: r.u64()?,
                });
            }
            FsReply::Entries { path, entries }
        }
        4 => {
            let eof = r.bool()?;
            FsReply::Data {
                data: r.bytes32(MAX_FILE_CHUNK)?,
                eof,
            }
        }
        k => return Err(Error::Protocol(format!("resposta fs desconhecida: {k}"))),
    })
}
