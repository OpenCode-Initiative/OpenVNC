//! Servidor HTTP/1.1 minimo sobre TLS: uma requisicao por conexao
//! (`Connection: close`), limites de cabecalho, corpo e tempo.

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Limite do cabecalho.
pub const MAX_HEAD: usize = 16 * 1024;
/// Limite do corpo.
pub const MAX_BODY: usize = 256 * 1024;

/// Requisicao recebida.
#[derive(Debug)]
pub struct Request {
    /// Metodo.
    pub method: String,
    /// Caminho sem a query.
    pub path: String,
    /// Query (sem `?`).
    pub query: String,
    /// Cabecalhos (nome em minusculas).
    pub headers: Vec<(String, String)>,
    /// Corpo.
    pub body: Vec<u8>,
    /// IP do cliente.
    pub peer: IpAddr,
}

impl Request {
    /// Valor de um cabecalho.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Campos `application/x-www-form-urlencoded` do corpo.
    pub fn form(&self) -> Vec<(String, String)> {
        parse_form(&String::from_utf8_lossy(&self.body))
    }

    /// Campo da query.
    pub fn query_get(&self, k: &str) -> Option<String> {
        parse_form(&self.query)
            .into_iter()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v)
    }
}

/// Resposta.
pub struct Response {
    /// Codigo.
    pub status: u16,
    /// Content-Type.
    pub ctype: &'static str,
    /// Corpo.
    pub body: Vec<u8>,
}

impl Response {
    /// JSON.
    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self {
            status,
            ctype: "application/json",
            body: v.to_string().into_bytes(),
        }
    }

    /// Erro JSON `{"error": msg}`.
    pub fn error(status: u16, msg: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": msg }))
    }

    /// Pagina HTML.
    pub fn html(status: u16, body: String) -> Self {
        Self {
            status,
            ctype: "text/html; charset=utf-8",
            body: body.into_bytes(),
        }
    }

    /// Texto.
    pub fn text(status: u16, ctype: &'static str, body: String) -> Self {
        Self {
            status,
            ctype,
            body: body.into_bytes(),
        }
    }
}

fn reason(s: u16) -> &'static str {
    match s {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

fn unhex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// Decodifica `%XX` e `+`.
pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match (unhex(b[i + 1]), unhex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push(h << 4 | l);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Codifica para URL.
#[cfg(test)]
pub fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|c| match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (c as char).to_string()
            }
            c => format!("%{c:02X}"),
        })
        .collect()
}

/// Interpreta `a=1&b=2`.
pub fn parse_form(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (url_decode(k), url_decode(v))
        })
        .collect()
}

/// Escapa texto para HTML.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Le uma requisicao. `Err(status)` para requisicao ruim.
pub async fn read_request<S: AsyncRead + Unpin>(s: &mut S, peer: IpAddr) -> Result<Request, u16> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEAD {
            return Err(431);
        }
        let n = s.read(&mut tmp).await.map_err(|_| 400u16)?;
        if n == 0 {
            return Err(400);
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    if head_end > MAX_HEAD {
        return Err(431);
    }
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or(400u16)?;
    let mut it = first.split(' ');
    let (Some(method), Some(target), Some(ver)) = (it.next(), it.next(), it.next()) else {
        return Err(400);
    };
    if !ver.starts_with("HTTP/1.") {
        return Err(400);
    }
    let mut headers = Vec::new();
    for l in lines {
        let (k, v) = l.split_once(':').ok_or(400u16)?;
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
    }
    if headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && !v.eq_ignore_ascii_case("identity"))
    {
        return Err(400);
    }
    let len: usize = match headers.iter().find(|(k, _)| k == "content-length") {
        Some((_, v)) => v.parse().map_err(|_| 400u16)?,
        None => 0,
    };
    if len > MAX_BODY {
        return Err(413);
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).await.map_err(|_| 400u16)?;
        if n == 0 {
            return Err(400);
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Ok(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        body,
        peer,
    })
}

/// Escreve a resposta com cabecalhos de seguranca e fecha.
pub async fn write_response<S: AsyncWrite + Unpin>(s: &mut S, r: &Response) -> std::io::Result<()> {
    let mut h = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\nStrict-Transport-Security: max-age=31536000\r\n",
        r.status,
        reason(r.status),
        r.ctype,
        r.body.len()
    );
    if r.ctype.starts_with("text/html") {
        h.push_str(
            "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n",
        );
    }
    h.push_str("\r\n");
    s.write_all(h.as_bytes()).await?;
    s.write_all(&r.body).await?;
    s.flush().await?;
    let _ = s.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodifica_form_e_escapa_html() {
        let f = parse_form("user_code=AB%2DCD&user=a+b&x=%zz&y=%4");
        assert_eq!(f[0], ("user_code".into(), "AB-CD".into()));
        assert_eq!(f[1].1, "a b");
        assert_eq!(f[2].1, "%zz");
        assert_eq!(f[3].1, "%4");
        assert_eq!(url_decode(&url_encode("a b/c&d")), "a b/c&d");
        assert_eq!(html_escape("<a href='x'>&"), "&lt;a href=&#39;x&#39;&gt;&amp;");
    }

    #[tokio::test]
    async fn le_requisicao_e_aplica_limites() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let raw = b"POST /api/login?a=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcdEXTRA";
        let r = read_request(&mut &raw[..], ip).await.unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/api/login"));
        assert_eq!(r.query_get("a").as_deref(), Some("1"));
        assert_eq!(r.body, b"abcd");
        let big = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert_eq!(read_request(&mut big.as_bytes(), ip).await.unwrap_err(), 413);
        let chunked = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(read_request(&mut &chunked[..], ip).await.unwrap_err(), 400);
        let huge = vec![b'a'; MAX_HEAD + 10];
        assert_eq!(read_request(&mut &huge[..], ip).await.unwrap_err(), 431);
    }
}
