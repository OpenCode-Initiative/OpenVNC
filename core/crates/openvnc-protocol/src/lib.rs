//! Protocolo nativo OpenVNC: framing, mensagens e capabilities.
//!
//! Implementa a especificacao `docs/RFC/0001-protocolo-nativo.md`
//! (rascunho 0). O nucleo e **sans-IO**: [`encode`] serializa uma
//! [`Message`] e o [`Decoder`] recebe bytes em qualquer quantidade e
//! devolve mensagens completas, sempre validando limites antes de alocar.
//! Os helpers de E/S assincrona ficam em [`io`].
//!
//! Formato de cada quadro (big-endian):
//!
//! ```text
//! Version u16 | Type u16 | Flags u16 | Length u32 | Payload[Length]
//! ```

pub mod io;

mod fsops;
pub use fsops::{FsEntry, FsOp, FsReply, MAX_FS_ENTRIES, MAX_FS_ROOTS};

use openvnc_core::{check_limit, Error, Result};

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Versao do protocolo implementada (rascunho 0, instavel).
pub const PROTOCOL_VERSION: u16 = 0;

/// Tamanho do cabecalho em bytes.
pub const HEADER_LEN: usize = 10;

/// Tamanho maximo padrao de payload (16 MiB).
pub const DEFAULT_MAX_PAYLOAD: u32 = 16 * 1024 * 1024;

/// Tamanho maximo de qualquer string do protocolo (bytes UTF-8).
pub const MAX_STRING: usize = 4096;

/// Tamanho maximo do segredo de autenticacao (ID tokens OIDC com grupos
/// passam de 4 KiB).
pub const MAX_SECRET: usize = 32 * 1024;

/// Numero maximo de capabilities numa mensagem HELLO.
pub const MAX_CAPABILITIES: usize = 64;

/// Numero maximo de retangulos num FRAME_UPDATE.
pub const MAX_RECTS: usize = 4096;

/// Tamanho maximo de texto de clipboard (1 MiB).
pub const MAX_CLIPBOARD: usize = 1024 * 1024;

/// Tamanho maximo de um bloco de arquivo (1 MiB).
pub const MAX_FILE_CHUNK: usize = 1024 * 1024;

/// Flag: o payload foi comprimido com zlib (reservado, nao usado no v0).
pub const FLAG_RESERVED_MASK: u16 = 0xffff;

/// Codigos de tipo de mensagem.
pub mod msg_type {
    #![allow(missing_docs)]
    pub const CLIENT_HELLO: u16 = 0x0001;
    pub const SERVER_HELLO: u16 = 0x0002;
    pub const AUTH_REQUEST: u16 = 0x0003;
    pub const AUTH_RESULT: u16 = 0x0004;
    pub const OIDC_CONFIG: u16 = 0x0005;
    pub const DISPLAY_INFO: u16 = 0x0010;
    pub const FRAME_UPDATE: u16 = 0x0011;
    pub const FRAME_ACK: u16 = 0x0012;
    pub const INPUT_EVENT: u16 = 0x0020;
    pub const CURSOR_UPDATE: u16 = 0x0021;
    pub const CLIPBOARD: u16 = 0x0030;
    pub const FILE_OFFER: u16 = 0x0040;
    pub const FILE_ACCEPT: u16 = 0x0041;
    pub const FILE_CHUNK: u16 = 0x0042;
    pub const FILE_END: u16 = 0x0043;
    // explorador de arquivos e bloqueio de entrada (modulo fsops)
    pub const FS_REQUEST: u16 = 0x0050;
    pub const FS_RESPONSE: u16 = 0x0051;
    pub const INPUT_LOCK: u16 = 0x0060;
    pub const INPUT_LOCK_STATE: u16 = 0x0061;
    // varios monitores no servidor
    pub const SCREEN_SELECT: u16 = 0x0070;
    pub const SCREEN_INFO: u16 = 0x0071;
    pub const PING: u16 = 0x00F0;
    pub const PONG: u16 = 0x00F1;
    pub const CLOSE: u16 = 0x00FF;
}

/// Capabilities negociaveis. O servidor responde com a intersecao.
pub mod capability {
    #![allow(missing_docs)]
    /// Tiles sem compressao (obrigatoria).
    pub const TILE_RAW: u32 = 0x0001;
    /// Tiles comprimidos com zlib (lossless, bom para texto).
    pub const TILE_ZLIB: u32 = 0x0002;
    /// Cursor separado da imagem.
    pub const CURSOR: u32 = 0x0010;
    /// Clipboard de texto.
    pub const CLIPBOARD_TEXT: u32 = 0x0020;
    /// Transferencia de arquivos basica.
    pub const FILE_TRANSFER: u32 = 0x0030;
    /// Explorador de arquivos remoto (FS_REQUEST/FS_RESPONSE).
    pub const FS_EXPLORER: u32 = 0x0031;
    /// Bloqueio do mouse e teclado locais do servidor (INPUT_LOCK).
    pub const INPUT_LOCK: u32 = 0x0040;
    /// Escolha do monitor capturado (SCREEN_SELECT/SCREEN_INFO).
    pub const SCREEN_SELECT: u32 = 0x0050;
    /// Video H.264: retangulos `encoding::H264` de tela inteira, fluxo continuo.
    pub const VIDEO_H264: u32 = 0x0100;
    /// Video AV1 (reservado; ainda nao implementado).
    pub const VIDEO_AV1: u32 = 0x0101;
    /// Login SSO por OIDC: o servidor manda [`super::Message::OidcConfig`]
    /// logo depois do `ServerHello`.
    pub const AUTH_OIDC: u32 = 0x0200;
}

/// Metodos de autenticacao.
pub mod auth_method {
    #![allow(missing_docs)]
    /// Sem autenticacao (so com permissao explicita no servidor).
    pub const NONE: u8 = 0;
    /// Senha compartilhada.
    pub const PASSWORD: u8 = 1;
    /// Dispositivo pareado (id + token).
    pub const DEVICE: u8 = 2;
    /// SSO: `secret` e o ID token (JWT) emitido pelo provedor OIDC.
    pub const OIDC: u8 = 3;
}

/// Encodings de retangulo em FRAME_UPDATE.
pub mod encoding {
    #![allow(missing_docs)]
    pub const RAW: u16 = 0;
    pub const ZLIB: u16 = 1;
    /// Quadro H.264 (Annex B) de tela inteira; exige `capability::VIDEO_H264`.
    pub const H264: u16 = 2;
}

/// Codigos de CLOSE.
pub mod close_code {
    #![allow(missing_docs)]
    pub const NORMAL: u16 = 0;
    pub const PROTOCOL_ERROR: u16 = 1;
    pub const AUTH_FAILED: u16 = 2;
    pub const UNSUPPORTED_VERSION: u16 = 3;
    pub const LIMIT_EXCEEDED: u16 = 4;
    pub const SERVER_SHUTDOWN: u16 = 5;
}

/// Um retangulo de imagem em FRAME_UPDATE. `data` esta no encoding
/// indicado; pixels sempre RGBA8 depois de decodificados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRect {
    /// X.
    pub x: u16,
    /// Y.
    pub y: u16,
    /// Largura.
    pub width: u16,
    /// Altura.
    pub height: u16,
    /// Encoding ([`encoding`]).
    pub encoding: u16,
    /// Dados codificados.
    pub data: Vec<u8>,
}

/// Evento de entrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// Ponteiro: posicao e mascara de botoes.
    Pointer {
        /// X.
        x: u16,
        /// Y.
        y: u16,
        /// Mascara de botoes (mesma convencao do RFB).
        buttons: u8,
    },
    /// Tecla (keysym X11).
    Key {
        /// Keysym.
        keysym: u32,
        /// Pressionada.
        down: bool,
    },
}

/// Mensagens do protocolo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Cliente inicia: faixa de versoes, capabilities e nome.
    ClientHello {
        /// Menor versao aceita.
        min_version: u16,
        /// Maior versao aceita.
        max_version: u16,
        /// Capabilities oferecidas.
        capabilities: Vec<u32>,
        /// Nome do cliente (informativo).
        name: String,
    },
    /// Servidor responde: versao escolhida, capabilities aceitas e metodos
    /// de autenticacao permitidos.
    ServerHello {
        /// Versao escolhida.
        version: u16,
        /// Intersecao de capabilities.
        capabilities: Vec<u32>,
        /// Metodos de autenticacao aceitos.
        auth_methods: Vec<u8>,
        /// Nome do servidor.
        name: String,
    },
    /// Credenciais.
    AuthRequest {
        /// Metodo ([`auth_method`]).
        method: u8,
        /// Usuario ou id do dispositivo (vazio para senha).
        user: String,
        /// Segredo (senha ou token). Nunca registrar em log.
        secret: Vec<u8>,
    },
    /// Dados do provedor OIDC para o cliente fazer o login por codigo de
    /// dispositivo (RFC 8628). So enviado se `capability::AUTH_OIDC` foi
    /// negociada.
    OidcConfig {
        /// Emissor (`iss`), base da descoberta `.well-known/openid-configuration`.
        issuer: String,
        /// Client id publico registrado no provedor.
        client_id: String,
        /// Escopos pedidos (separados por espaco).
        scope: String,
    },
    /// Resultado da autenticacao.
    AuthResult {
        /// Aceito.
        ok: bool,
        /// Motivo em caso de falha.
        reason: String,
    },
    /// Tamanho do display remoto (enviado no inicio e a cada mudanca).
    DisplayInfo {
        /// Largura.
        width: u16,
        /// Altura.
        height: u16,
        /// Nome do display.
        name: String,
    },
    /// Atualizacao de tela.
    FrameUpdate {
        /// Sequencia crescente.
        seq: u64,
        /// Retangulos.
        rects: Vec<FrameRect>,
    },
    /// Confirmacao do cliente (controle de fluxo).
    FrameAck {
        /// Ultima sequencia aplicada.
        seq: u64,
    },
    /// Entrada do cliente.
    InputEvent(Input),
    /// Cursor RGBA com hotspot.
    CursorUpdate {
        /// Hotspot X.
        hot_x: u16,
        /// Hotspot Y.
        hot_y: u16,
        /// Largura.
        width: u16,
        /// Altura.
        height: u16,
        /// Pixels RGBA8 (`width * height * 4`).
        rgba: Vec<u8>,
    },
    /// Clipboard de texto (ambos os sentidos).
    Clipboard {
        /// Texto UTF-8.
        text: String,
    },
    /// Oferta de arquivo.
    FileOffer {
        /// Id da transferencia, escolhido por quem envia.
        id: u32,
        /// Nome (sem diretorios).
        name: String,
        /// Tamanho total.
        size: u64,
    },
    /// Aceite ou recusa da oferta.
    FileAccept {
        /// Id.
        id: u32,
        /// Aceito.
        accept: bool,
    },
    /// Bloco de arquivo.
    FileChunk {
        /// Id.
        id: u32,
        /// Deslocamento.
        offset: u64,
        /// Dados.
        data: Vec<u8>,
    },
    /// Fim do arquivo com SHA-256 do conteudo.
    FileEnd {
        /// Id.
        id: u32,
        /// SHA-256.
        sha256: [u8; 32],
    },
    /// Pedido ao explorador de arquivos.
    FsRequest {
        /// Id ecoado na resposta.
        id: u32,
        /// Operacao.
        op: FsOp,
    },
    /// Resposta do explorador de arquivos.
    FsResponse {
        /// Id do pedido.
        id: u32,
        /// Resultado.
        reply: FsReply,
    },
    /// Cliente pede para bloquear (ou liberar) o mouse e teclado fisicos
    /// do computador remoto.
    InputLock {
        /// Ligar o bloqueio.
        on: bool,
    },
    /// Estado do bloqueio informado pelo servidor.
    InputLockState {
        /// Bloqueio ativo.
        on: bool,
        /// Motivo (erro ou observacao); vazio se nada a dizer.
        reason: String,
    },
    /// Cliente pede outro monitor do servidor. `index` 255 = o proximo.
    ScreenSelect {
        /// Monitor pedido (0 = primeiro) ou 255 para o proximo.
        index: u8,
    },
    /// Monitor atual e quantos o servidor tem.
    ScreenInfo {
        /// Monitor capturado agora.
        index: u8,
        /// Total de monitores.
        count: u8,
    },
    /// Keepalive.
    Ping {
        /// Valor ecoado.
        nonce: u64,
    },
    /// Resposta ao keepalive.
    Pong {
        /// Valor recebido.
        nonce: u64,
    },
    /// Encerramento.
    Close {
        /// Codigo ([`close_code`]).
        code: u16,
        /// Motivo.
        reason: String,
    },
}

impl Message {
    /// Codigo de tipo.
    pub fn type_code(&self) -> u16 {
        use msg_type::*;
        match self {
            Message::ClientHello { .. } => CLIENT_HELLO,
            Message::ServerHello { .. } => SERVER_HELLO,
            Message::AuthRequest { .. } => AUTH_REQUEST,
            Message::AuthResult { .. } => AUTH_RESULT,
            Message::OidcConfig { .. } => OIDC_CONFIG,
            Message::DisplayInfo { .. } => DISPLAY_INFO,
            Message::FrameUpdate { .. } => FRAME_UPDATE,
            Message::FrameAck { .. } => FRAME_ACK,
            Message::InputEvent(_) => INPUT_EVENT,
            Message::CursorUpdate { .. } => CURSOR_UPDATE,
            Message::Clipboard { .. } => CLIPBOARD,
            Message::FileOffer { .. } => FILE_OFFER,
            Message::FileAccept { .. } => FILE_ACCEPT,
            Message::FileChunk { .. } => FILE_CHUNK,
            Message::FileEnd { .. } => FILE_END,
            Message::FsRequest { .. } => FS_REQUEST,
            Message::FsResponse { .. } => FS_RESPONSE,
            Message::InputLock { .. } => INPUT_LOCK,
            Message::InputLockState { .. } => INPUT_LOCK_STATE,
            Message::ScreenSelect { .. } => SCREEN_SELECT,
            Message::ScreenInfo { .. } => SCREEN_INFO,
            Message::Ping { .. } => PING,
            Message::Pong { .. } => PONG,
            Message::Close { .. } => CLOSE,
        }
    }
}

// ---------------------------------------------------------------- escrita

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes16(&mut self, b: &[u8]) -> Result<()> {
        self.bytes16_max(b, MAX_STRING)
    }
    fn bytes16_max(&mut self, b: &[u8], max: usize) -> Result<()> {
        check_limit("string", b.len() as u64, max as u64)?;
        self.u16(b.len() as u16);
        self.0.extend_from_slice(b);
        Ok(())
    }
    fn str(&mut self, s: &str) -> Result<()> {
        self.bytes16(s.as_bytes())
    }
    fn bytes32(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
}

fn encode_payload(m: &Message) -> Result<Vec<u8>> {
    let mut w = W(Vec::new());
    match m {
        Message::ClientHello {
            min_version,
            max_version,
            capabilities,
            name,
        } => {
            w.u16(*min_version);
            w.u16(*max_version);
            check_limit(
                "capabilities",
                capabilities.len() as u64,
                MAX_CAPABILITIES as u64,
            )?;
            w.u16(capabilities.len() as u16);
            for c in capabilities {
                w.u32(*c);
            }
            w.str(name)?;
        }
        Message::ServerHello {
            version,
            capabilities,
            auth_methods,
            name,
        } => {
            w.u16(*version);
            check_limit(
                "capabilities",
                capabilities.len() as u64,
                MAX_CAPABILITIES as u64,
            )?;
            w.u16(capabilities.len() as u16);
            for c in capabilities {
                w.u32(*c);
            }
            check_limit("auth methods", auth_methods.len() as u64, 16)?;
            w.u8(auth_methods.len() as u8);
            for a in auth_methods {
                w.u8(*a);
            }
            w.str(name)?;
        }
        Message::AuthRequest {
            method,
            user,
            secret,
        } => {
            w.u8(*method);
            w.str(user)?;
            w.bytes16_max(secret, MAX_SECRET)?;
        }
        Message::AuthResult { ok, reason } => {
            w.u8(u8::from(*ok));
            w.str(reason)?;
        }
        Message::OidcConfig {
            issuer,
            client_id,
            scope,
        } => {
            w.str(issuer)?;
            w.str(client_id)?;
            w.str(scope)?;
        }
        Message::DisplayInfo {
            width,
            height,
            name,
        } => {
            w.u16(*width);
            w.u16(*height);
            w.str(name)?;
        }
        Message::FrameUpdate { seq, rects } => {
            w.u64(*seq);
            check_limit("rects", rects.len() as u64, MAX_RECTS as u64)?;
            w.u16(rects.len() as u16);
            for r in rects {
                w.u16(r.x);
                w.u16(r.y);
                w.u16(r.width);
                w.u16(r.height);
                w.u16(r.encoding);
                w.bytes32(&r.data);
            }
        }
        Message::FrameAck { seq } => w.u64(*seq),
        Message::InputEvent(Input::Pointer { x, y, buttons }) => {
            w.u8(0);
            w.u16(*x);
            w.u16(*y);
            w.u8(*buttons);
        }
        Message::InputEvent(Input::Key { keysym, down }) => {
            w.u8(1);
            w.u32(*keysym);
            w.u8(u8::from(*down));
        }
        Message::CursorUpdate {
            hot_x,
            hot_y,
            width,
            height,
            rgba,
        } => {
            let need = u64::from(*width) * u64::from(*height) * 4;
            if rgba.len() as u64 != need {
                return Err(Error::Protocol("cursor: tamanho do rgba".into()));
            }
            w.u16(*hot_x);
            w.u16(*hot_y);
            w.u16(*width);
            w.u16(*height);
            w.0.extend_from_slice(rgba);
        }
        Message::Clipboard { text } => {
            check_limit("clipboard", text.len() as u64, MAX_CLIPBOARD as u64)?;
            w.bytes32(text.as_bytes());
        }
        Message::FileOffer { id, name, size } => {
            w.u32(*id);
            w.str(name)?;
            w.u64(*size);
        }
        Message::FileAccept { id, accept } => {
            w.u32(*id);
            w.u8(u8::from(*accept));
        }
        Message::FileChunk { id, offset, data } => {
            check_limit("file chunk", data.len() as u64, MAX_FILE_CHUNK as u64)?;
            w.u32(*id);
            w.u64(*offset);
            w.bytes32(data);
        }
        Message::FileEnd { id, sha256 } => {
            w.u32(*id);
            w.0.extend_from_slice(sha256);
        }
        Message::FsRequest { id, op } => {
            w.u32(*id);
            fsops::encode_op(&mut w, op)?;
        }
        Message::FsResponse { id, reply } => {
            w.u32(*id);
            fsops::encode_reply(&mut w, reply)?;
        }
        Message::InputLock { on } => w.u8(u8::from(*on)),
        Message::ScreenSelect { index } => w.u8(*index),
        Message::ScreenInfo { index, count } => {
            w.u8(*index);
            w.u8(*count);
        }
        Message::InputLockState { on, reason } => {
            w.u8(u8::from(*on));
            w.str(reason)?;
        }
        Message::Ping { nonce } | Message::Pong { nonce } => w.u64(*nonce),
        Message::Close { code, reason } => {
            w.u16(*code);
            w.str(reason)?;
        }
    }
    Ok(w.0)
}

/// Serializa uma mensagem com cabecalho, respeitando `max_payload`.
pub fn encode_with_limit(m: &Message, max_payload: u32) -> Result<Vec<u8>> {
    let payload = encode_payload(m)?;
    check_limit("payload", payload.len() as u64, u64::from(max_payload))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(&m.type_code().to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Serializa uma mensagem com o limite padrao.
pub fn encode(m: &Message) -> Result<Vec<u8>> {
    encode_with_limit(m, DEFAULT_MAX_PAYLOAD)
}

// ---------------------------------------------------------------- leitura

struct R<'a> {
    b: &'a [u8],
}

fn short() -> Error {
    Error::Protocol("payload curto".into())
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.b.len() < n {
            return Err(short());
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(Error::Protocol(format!("booleano invalido: {v}"))),
        }
    }
    fn bytes16(&mut self) -> Result<Vec<u8>> {
        self.bytes16_max(MAX_STRING)
    }
    fn bytes16_max(&mut self, max: usize) -> Result<Vec<u8>> {
        let n = usize::from(self.u16()?);
        check_limit("string", n as u64, max as u64)?;
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> Result<String> {
        String::from_utf8(self.bytes16()?).map_err(|_| Error::Protocol("UTF-8 invalido".into()))
    }
    fn bytes32(&mut self, max: usize) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        check_limit("bytes", n as u64, max as u64)?;
        Ok(self.take(n)?.to_vec())
    }
    fn done(&self) -> Result<()> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol("bytes sobrando no payload".into()))
        }
    }
}

/// Decodifica um payload ja separado do cabecalho.
pub fn decode_payload(ty: u16, payload: &[u8]) -> Result<Message> {
    use msg_type::*;
    let mut r = R { b: payload };
    let m = match ty {
        CLIENT_HELLO => {
            let min_version = r.u16()?;
            let max_version = r.u16()?;
            let n = usize::from(r.u16()?);
            check_limit("capabilities", n as u64, MAX_CAPABILITIES as u64)?;
            let mut capabilities = Vec::with_capacity(n);
            for _ in 0..n {
                capabilities.push(r.u32()?);
            }
            let name = r.str()?;
            if min_version > max_version {
                return Err(Error::Protocol("faixa de versao invertida".into()));
            }
            Message::ClientHello {
                min_version,
                max_version,
                capabilities,
                name,
            }
        }
        SERVER_HELLO => {
            let version = r.u16()?;
            let n = usize::from(r.u16()?);
            check_limit("capabilities", n as u64, MAX_CAPABILITIES as u64)?;
            let mut capabilities = Vec::with_capacity(n);
            for _ in 0..n {
                capabilities.push(r.u32()?);
            }
            let na = usize::from(r.u8()?);
            check_limit("auth methods", na as u64, 16)?;
            let auth_methods = r.take(na)?.to_vec();
            let name = r.str()?;
            Message::ServerHello {
                version,
                capabilities,
                auth_methods,
                name,
            }
        }
        AUTH_REQUEST => Message::AuthRequest {
            method: r.u8()?,
            user: r.str()?,
            secret: r.bytes16_max(MAX_SECRET)?,
        },
        AUTH_RESULT => Message::AuthResult {
            ok: r.bool()?,
            reason: r.str()?,
        },
        OIDC_CONFIG => Message::OidcConfig {
            issuer: r.str()?,
            client_id: r.str()?,
            scope: r.str()?,
        },
        DISPLAY_INFO => Message::DisplayInfo {
            width: r.u16()?,
            height: r.u16()?,
            name: r.str()?,
        },
        FRAME_UPDATE => {
            let seq = r.u64()?;
            let n = usize::from(r.u16()?);
            check_limit("rects", n as u64, MAX_RECTS as u64)?;
            let mut rects = Vec::with_capacity(n.min(256));
            for _ in 0..n {
                let x = r.u16()?;
                let y = r.u16()?;
                let width = r.u16()?;
                let height = r.u16()?;
                let encoding = r.u16()?;
                let data = r.bytes32(DEFAULT_MAX_PAYLOAD as usize)?;
                rects.push(FrameRect {
                    x,
                    y,
                    width,
                    height,
                    encoding,
                    data,
                });
            }
            Message::FrameUpdate { seq, rects }
        }
        FRAME_ACK => Message::FrameAck { seq: r.u64()? },
        INPUT_EVENT => match r.u8()? {
            0 => Message::InputEvent(Input::Pointer {
                x: r.u16()?,
                y: r.u16()?,
                buttons: r.u8()?,
            }),
            1 => Message::InputEvent(Input::Key {
                keysym: r.u32()?,
                down: r.bool()?,
            }),
            k => {
                return Err(Error::Protocol(format!(
                    "tipo de entrada desconhecido: {k}"
                )))
            }
        },
        CURSOR_UPDATE => {
            let hot_x = r.u16()?;
            let hot_y = r.u16()?;
            let width = r.u16()?;
            let height = r.u16()?;
            check_limit("cursor", u64::from(width.max(height)), 256)?;
            let n = usize::from(width) * usize::from(height) * 4;
            Message::CursorUpdate {
                hot_x,
                hot_y,
                width,
                height,
                rgba: r.take(n)?.to_vec(),
            }
        }
        CLIPBOARD => {
            let b = r.bytes32(MAX_CLIPBOARD)?;
            Message::Clipboard {
                text: String::from_utf8(b)
                    .map_err(|_| Error::Protocol("clipboard: UTF-8 invalido".into()))?,
            }
        }
        FILE_OFFER => {
            let id = r.u32()?;
            let name = r.str()?;
            let size = r.u64()?;
            Message::FileOffer {
                id,
                name: sanitize_file_name(&name)?,
                size,
            }
        }
        FILE_ACCEPT => Message::FileAccept {
            id: r.u32()?,
            accept: r.bool()?,
        },
        FILE_CHUNK => Message::FileChunk {
            id: r.u32()?,
            offset: r.u64()?,
            data: r.bytes32(MAX_FILE_CHUNK)?,
        },
        FILE_END => {
            let id = r.u32()?;
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(r.take(32)?);
            Message::FileEnd { id, sha256 }
        }
        FS_REQUEST => Message::FsRequest {
            id: r.u32()?,
            op: fsops::decode_op(&mut r)?,
        },
        FS_RESPONSE => Message::FsResponse {
            id: r.u32()?,
            reply: fsops::decode_reply(&mut r)?,
        },
        INPUT_LOCK => Message::InputLock { on: r.bool()? },
        SCREEN_SELECT => Message::ScreenSelect { index: r.u8()? },
        SCREEN_INFO => Message::ScreenInfo {
            index: r.u8()?,
            count: r.u8()?,
        },
        INPUT_LOCK_STATE => Message::InputLockState {
            on: r.bool()?,
            reason: r.str()?,
        },
        PING => Message::Ping { nonce: r.u64()? },
        PONG => Message::Pong { nonce: r.u64()? },
        CLOSE => Message::Close {
            code: r.u16()?,
            reason: r.str()?,
        },
        t => {
            return Err(Error::Protocol(format!(
                "tipo de mensagem desconhecido: {t:#06x}"
            )))
        }
    };
    r.done()?;
    Ok(m)
}

/// Recusa nomes de arquivo com diretorios, `..`, vazios ou com controle.
pub fn sanitize_file_name(name: &str) -> Result<String> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', ':'])
        || name.chars().any(char::is_control);
    if bad {
        return Err(Error::Protocol("nome de arquivo invalido".into()));
    }
    Ok(name.to_string())
}

/// Decodificador incremental (sans-IO).
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    max_payload: u32,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder::new(DEFAULT_MAX_PAYLOAD)
    }
}

/// Cabecalho decodificado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Versao.
    pub version: u16,
    /// Tipo.
    pub ty: u16,
    /// Flags (devem ser zero no v0).
    pub flags: u16,
    /// Tamanho do payload.
    pub length: u32,
}

/// Le e valida um cabecalho.
pub fn parse_header(b: &[u8; HEADER_LEN], max_payload: u32) -> Result<Header> {
    let h = Header {
        version: u16::from_be_bytes([b[0], b[1]]),
        ty: u16::from_be_bytes([b[2], b[3]]),
        flags: u16::from_be_bytes([b[4], b[5]]),
        length: u32::from_be_bytes([b[6], b[7], b[8], b[9]]),
    };
    if h.version != PROTOCOL_VERSION {
        return Err(Error::Unsupported(format!(
            "versao de protocolo {} (esperada {PROTOCOL_VERSION})",
            h.version
        )));
    }
    if h.flags & FLAG_RESERVED_MASK != 0 {
        return Err(Error::Protocol(format!(
            "flags reservadas: {:#06x}",
            h.flags
        )));
    }
    check_limit("payload", u64::from(h.length), u64::from(max_payload))?;
    Ok(h)
}

impl Decoder {
    /// Cria com limite de payload.
    pub fn new(max_payload: u32) -> Self {
        Decoder {
            buf: Vec::new(),
            max_payload,
        }
    }

    /// Acrescenta bytes recebidos.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Bytes ainda nao consumidos.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Proxima mensagem completa, se houver. Erros sao fatais para a
    /// conexao: o chamador deve enviar CLOSE e desconectar.
    pub fn next_message(&mut self) -> Result<Option<Message>> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let mut hb = [0u8; HEADER_LEN];
        hb.copy_from_slice(&self.buf[..HEADER_LEN]);
        let h = parse_header(&hb, self.max_payload)?;
        let total = HEADER_LEN + h.length as usize;
        if self.buf.len() < total {
            return Ok(None);
        }
        let m = decode_payload(h.ty, &self.buf[HEADER_LEN..total]);
        self.buf.drain(..total);
        m.map(Some)
    }
}

/// Intersecao de capabilities preservando a ordem do cliente.
pub fn negotiate_capabilities(client: &[u32], server: &[u32]) -> Vec<u32> {
    let mut out: Vec<u32> = client
        .iter()
        .copied()
        .filter(|c| server.contains(c))
        .collect();
    out.dedup();
    out
}

/// Escolhe a versao: a maior comum, ou `None`.
pub fn negotiate_version(min: u16, max: u16) -> Option<u16> {
    (min..=max)
        .contains(&PROTOCOL_VERSION)
        .then_some(PROTOCOL_VERSION)
}

#[cfg(test)]
mod tests;
