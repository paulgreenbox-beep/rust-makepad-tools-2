//! Deliberately small HTTP/1.1 subset: one Content-Length request per connection.
//! No proxying, chunked bodies, pipelining, browser CORS or legacy SSE endpoint.
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

const MAX_HEAD: usize = 8192;
const MAX_BODY: usize = 262_144;
pub(super) struct Request {
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

pub(super) fn read(stream: &mut TcpStream, port: u16, token: &str) -> Result<Request, u16> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut bytes = Vec::new();
    let head_end = loop {
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            if index + 4 > MAX_HEAD {
                return Err(413);
            }
            break index + 4;
        }
        if bytes.len() >= MAX_HEAD {
            return Err(413);
        }
        read_more(stream, &mut bytes, deadline)?;
    };
    let (method, headers) = parse_head(&bytes[..head_end], port, token)?;
    let length = match headers.get("content-length") {
        Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
            value.parse::<usize>().map_err(|_| 413u16)?
        }
        None if method != "POST" => 0,
        _ => return Err(400),
    };
    if length > MAX_BODY {
        return Err(413);
    }
    if method != "POST" && length != 0 {
        return Err(400);
    }
    while bytes.len() < head_end + length {
        read_more(stream, &mut bytes, deadline)?;
    }
    if bytes.len() != head_end + length {
        return Err(400);
    }
    Ok(Request {
        method,
        headers,
        body: bytes.split_off(head_end),
    })
}

fn read_more(stream: &mut TcpStream, bytes: &mut Vec<u8>, deadline: Instant) -> Result<(), u16> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(408);
    }
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| 400u16)?;
    let mut buffer = [0u8; 1024];
    let count = stream.read(&mut buffer).map_err(|_| 408u16)?;
    if count == 0 {
        return Err(400);
    }
    bytes.extend_from_slice(&buffer[..count]);
    Ok(())
}

fn parse_head(
    head: &[u8],
    port: u16,
    token: &str,
) -> Result<(String, BTreeMap<String, String>), u16> {
    if !head.is_ascii() {
        return Err(400);
    }
    let text = std::str::from_utf8(head).map_err(|_| 400u16)?;
    let mut lines = text.split("\r\n");
    let parts: Vec<_> = lines.next().unwrap_or_default().split(' ').collect();
    if parts.len() != 3 || parts[1] != "/mcp" || parts[2] != "HTTP/1.1" {
        return Err(400);
    }
    if !matches!(parts[0], "POST" | "GET" | "DELETE") {
        return Err(405);
    }
    let mut headers = BTreeMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        {
            return Err(400);
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err(400);
        }
    }
    let host = format!("127.0.0.1:{port}");
    if headers.get("host") != Some(&host) {
        return Err(403);
    }
    if headers
        .get("origin")
        .is_some_and(|v| v != &format!("http://{host}"))
    {
        return Err(403);
    }
    let expected = format!("Bearer {token}");
    if !constant_time_equal(
        headers
            .get("authorization")
            .map(String::as_bytes)
            .unwrap_or_default(),
        expected.as_bytes(),
    ) {
        return Err(401);
    }
    if headers.contains_key("transfer-encoding") || headers.contains_key("expect") {
        return Err(400);
    }
    if parts[0] == "POST" {
        if headers
            .get("content-type")
            .map(|v| v.split(';').next().unwrap_or_default().trim())
            != Some("application/json")
        {
            return Err(400);
        }
        let accepts: Vec<_> = headers
            .get("accept")
            .map(String::as_str)
            .unwrap_or_default()
            .split(',')
            .map(|s| s.split(';').next().unwrap_or_default().trim())
            .collect();
        if !accepts.contains(&"application/json") || !accepts.contains(&"text/event-stream") {
            return Err(400);
        }
    }
    Ok((parts[0].to_owned(), headers))
}

fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b)
        .fold(0u8, |different, (x, y)| different | (x ^ y))
        == 0
}

pub(super) fn write(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    session: Option<&str>,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Internal Server Error",
    };
    let mut header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
        body.len()
    );
    if status == 405 {
        header.push_str("Allow: POST, DELETE\r\n");
    }
    if status == 429 {
        header.push_str("Retry-After: 1\r\n");
    }
    if let Some(session) = session {
        header.push_str(&format!("Mcp-Session-Id: {session}\r\n"));
    }
    header.push_str("\r\n");
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)
}

pub(super) fn finish(stream: &mut TcpStream) {
    // An early auth/framing refusal can leave a body in the socket. Closing a
    // Windows socket with unread bytes can reset it and hide the HTTP error.
    // Send FIN after the response, then drain only a bounded amount/time. This
    // neither dispatches the rejected body nor trusts an unauthenticated peer.
    let _ = stream.shutdown(Shutdown::Write);
    let deadline = Instant::now() + Duration::from_millis(200);
    let mut remaining = MAX_BODY + MAX_HEAD;
    let mut buffer = [0u8; 4096];
    while remaining > 0 {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            break;
        }
        if stream.set_read_timeout(Some(timeout)).is_err() {
            break;
        }
        match stream.read(&mut buffer[..remaining.min(4096)]) {
            Ok(0) | Err(_) => break,
            Ok(count) => remaining -= count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auth_refusal_survives_body_arriving_after_headers() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (body_sent, body_ready) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read(&mut stream, port, "expected").err(), Some(401));
            write(&mut stream, 401, b"{}", None).unwrap();
            body_ready.recv_timeout(Duration::from_secs(2)).unwrap();
            finish(&mut stream);
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(format!("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer wrong\r\nContent-Length: 4\r\n\r\n").as_bytes()).unwrap();
        // Observe the status before sending the late body, not a fixed sleep.
        let mut first = [0u8; 1];
        client.read_exact(&mut first).unwrap();
        client.write_all(b"null").unwrap();
        body_sent.send(()).unwrap();
        let mut response = vec![first[0]];
        client.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
        assert!(response.ends_with(b"{}"));
        drop(client);
        worker.join().unwrap();
    }
    fn head(extra: &str) -> Vec<u8> {
        format!("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:18761\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n{extra}\r\n").into_bytes()
    }
    #[test]
    fn authenticated_loopback_only_and_no_browser_origin() {
        assert!(parse_head(&head(""), 18761, "secret").is_ok());
        assert_eq!(
            parse_head(&head("Origin: https://evil.example\r\n"), 18761, "secret").unwrap_err(),
            403
        );
        assert_eq!(parse_head(&head(""), 18762, "secret").unwrap_err(), 403);
        assert_eq!(parse_head(&head(""), 18761, "wrong").unwrap_err(), 401);
    }
    #[test]
    fn rejects_ambiguous_framing_and_duplicate_security_headers() {
        assert_eq!(
            parse_head(&head("Transfer-Encoding: chunked\r\n"), 18761, "secret").unwrap_err(),
            400
        );
        assert_eq!(
            parse_head(
                &head("Content-Length: 1\r\nContent-Length: 2\r\n"),
                18761,
                "secret"
            )
            .unwrap_err(),
            400
        );
        assert_eq!(
            parse_head(&head("Host: evil.example\r\n"), 18761, "secret").unwrap_err(),
            400
        );
    }
}
