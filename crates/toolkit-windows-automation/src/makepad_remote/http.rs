//! Bounded framing for the pinned runtime's Content-Length replies. A complete
//! message does not require a second read/EOF after an app has begun quitting.
//! No socket, dispatch, retry, or normal-exit inference lives here.
use super::protocol::{RemoteError, Result};
use serde_json::json;
use std::io;

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 4 * 1024 * 1024;

pub(super) fn read_response(
    mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> Result<(u16, Vec<u8>)> {
    let mut packet = Vec::new();
    let mut framing: Option<(u16, usize, usize)> = None;
    let failure = |code: &str, received: usize, expected: Option<usize>| {
        let mut error = RemoteError::unknown(code);
        // Retain counts, never response headers/body or OS error strings.
        error.details["http_response_bytes"] = json!(received);
        error.details["http_expected_bytes"] = json!(expected);
        error
    };
    loop {
        if framing.is_none() {
            if let Some(split) = packet.windows(4).position(|v| v == b"\r\n\r\n") {
                let invalid = || failure("REMOTE_HTTP_INVALID", packet.len(), None);
                if split + 4 > MAX_HEADER {
                    return Err(invalid());
                }
                let header = std::str::from_utf8(&packet[..split]).map_err(|_| invalid())?;
                let mut lines = header.split("\r\n");
                let mut status = lines.next().ok_or_else(invalid)?.split_whitespace();
                if status.next() != Some("HTTP/1.1") {
                    return Err(invalid());
                }
                let code = status.next().ok_or_else(invalid)?;
                if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                let code: u16 = code.parse().map_err(|_| invalid())?;
                if !(200..=599).contains(&code) {
                    return Err(invalid());
                }
                let mut length = None;
                for line in lines {
                    let (name, value) = line.split_once(':').ok_or_else(invalid)?;
                    if name.is_empty()
                        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        || !value.bytes().all(|b| (32..=126).contains(&b) || b == b'\t')
                        || name.eq_ignore_ascii_case("transfer-encoding")
                    {
                        return Err(invalid());
                    }
                    if name.eq_ignore_ascii_case("content-length") {
                        let value = value.trim_matches([' ', '\t']);
                        if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                            return Err(invalid());
                        }
                        let size: usize = value.parse().map_err(|_| invalid())?;
                        if size > MAX_BODY {
                            return Err(failure("REMOTE_REPLY_BUDGET_EXCEEDED", packet.len(), None));
                        }
                        length = Some(size);
                    }
                }
                // Pinned respond() always sends exactly one Content-Length;
                // close-delimited/chunked/ambiguous replies fail closed.
                let body = split + 4;
                let total = body + length.ok_or_else(invalid)?;
                framing = Some((code, body, total));
            } else if packet.len() >= MAX_HEADER {
                return Err(failure("REMOTE_HTTP_HEADER_BUDGET_EXCEEDED", packet.len(), None));
            }
        }
        if let Some((status, body, total)) = framing {
            if packet.len() > total {
                return Err(failure("REMOTE_HTTP_TRAILING_BYTES", packet.len(), Some(total)));
            }
            if packet.len() == total {
                return Ok((status, packet[body..].to_vec()));
            }
        }
        let expected = framing.map(|(_, _, total)| total);
        let remaining = expected.unwrap_or(MAX_HEADER) - packet.len();
        let mut buffer = [0u8; 16384];
        let capacity = remaining.min(buffer.len());
        let n = read(&mut buffer[..capacity]).map_err(|error| {
            let code = if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
                "REMOTE_RESPONSE_TIMEOUT"
            } else {
                "REMOTE_CONNECTION_LOST"
            };
            failure(code, packet.len(), expected)
        })?;
        if n == 0 || n > capacity {
            return Err(failure("REMOTE_RESPONSE_TRUNCATED", packet.len(), expected));
        }
        packet.extend_from_slice(&buffer[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn packet(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
    }

    #[test]
    fn complete_ack_never_reads_eof_or_later_connection_reset() {
        let data = packet(r#"{"ok":1}"#);
        let mut calls = 0;
        let reply = read_response(|buffer| {
            calls += 1;
            assert_eq!(calls, 1, "complete reply must not wait for process/socket teardown");
            buffer[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        }).unwrap();
        assert_eq!(reply, (200, br#"{"ok":1}"#.to_vec()));
        assert_eq!(calls, 1);
    }

    #[test]
    fn fragmented_header_and_body_stop_at_declared_length() {
        let data = packet("hello");
        let mut offset = 0;
        let reply = read_response(|buffer| {
            assert!(offset < data.len(), "no EOF read");
            let n = 3.min(buffer.len()).min(data.len() - offset);
            buffer[..n].copy_from_slice(&data[offset..offset+n]);
            offset += n;
            Ok(n)
        }).unwrap();
        assert_eq!(reply, (200, b"hello".to_vec()));
        assert_eq!(offset, data.len());
    }

    #[test]
    fn incomplete_ack_is_unknown_on_eof_reset_or_timeout_without_retry() {
        for kind in [None, Some(io::ErrorKind::ConnectionReset), Some(io::ErrorKind::TimedOut)] {
            let data = packet(r#"{"ok":1}"#);
            let mut calls = 0;
            let error = read_response(|buffer| {
                calls += 1;
                if calls == 1 {
                    let n = data.len()-1;
                    buffer[..n].copy_from_slice(&data[..n]);
                    Ok(n)
                } else if let Some(kind) = kind {
                    Err(io::Error::new(kind, "secret OS diagnostic"))
                } else { Ok(0) }
            }).unwrap_err();
            assert_eq!(calls, 2);
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
            assert!(!error.retry_safe);
            assert_eq!(error.details["http_response_bytes"], data.len()-1);
            assert_eq!(error.details["http_expected_bytes"], data.len());
            assert!(!serde_json::to_string(&error).unwrap().contains("secret"));
        }
    }

    #[test]
    fn invalid_ambiguous_or_unbounded_framing_is_never_success() {
        for header in [
            "HTTP/1.1 200 OK\r\n", // missing Content-Length
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: +1\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4194305\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999\r\n",
            "HTTP/1.1 200 OK\r\n Content-Length: 0\r\n",
            "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n",
            "HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n",
        ] {
            let data = format!("{header}\r\n").into_bytes();
            let mut input = data.as_slice();
            let error = read_response(|b| input.read(b)).unwrap_err();
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
            assert!(!error.retry_safe);
        }
        let data = vec![b'x';MAX_HEADER];
        let mut input = data.as_slice();
        assert_eq!(read_response(|b| input.read(b)).unwrap_err().code, "REMOTE_HTTP_HEADER_BUDGET_EXCEEDED");
    }

    #[test]
    fn conflict_body_and_trailing_bytes_are_not_silently_discarded() {
        let data = b"HTTP/1.1 409 Conflict\r\ncontent-length: 17\r\n\r\n{\"applied\":false}";
        let mut input = data.as_slice();
        let (status, body) = read_response(|b| input.read(b)).unwrap();
        assert_eq!(super::super::protocol::classify_reply(status,&body,true).unwrap_err().outcome, "NOT_DISPATCHED");
        let mut data = packet("hello"); data.push(b'x');
        let mut input = data.as_slice();
        assert_eq!(read_response(|b| input.read(b)).unwrap_err().code, "REMOTE_HTTP_TRAILING_BYTES");
    }
}
