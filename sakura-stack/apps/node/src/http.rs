//! Management plane (§21.1: изолированная плоскость, non-control):
//! минимальный HTTP/1.1 read-only — /health, /status, /metrics, /audit/head.
//! Управление через HTTP ЗАПРЕЩЕНО (no direct external access к control
//! plane, §13.19.4).

use std::io::{Read, Write};
use std::net::TcpStream;

pub struct HttpConn {
    pub stream: TcpStream,
    pub buf: Vec<u8>,
}

impl HttpConn {
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_read_timeout(Some(std::time::Duration::from_millis(2)))?;
        stream.set_nodelay(true)?;
        Ok(HttpConn { stream, buf: Vec::new() })
    }

    /// Возвращает Some(path) при получении полного запроса.
    pub fn poll(&mut self) -> Option<String> {
        let mut chunk = [0u8; 2048];
        match self.stream.read(&mut chunk) {
            Ok(0) => return Some(String::new()), // eof — закрыть
            Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return Some(String::new()),
        }
        if let Some(pos) = find_headers_end(&self.buf) {
            let head = String::from_utf8_lossy(&self.buf[..pos]).to_string();
            let path = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            Some(path)
        } else if self.buf.len() > 16384 {
            Some(String::new())
        } else {
            None
        }
    }

    pub fn respond(&mut self, status: u16, body: &str, content_type: &str) {
        let reason = match status {
            200 => "OK",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "Error",
        };
        let resp = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}",
            body.len()
        );
        let _ = self.stream.write_all(resp.as_bytes());
        let _ = self.stream.flush();
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn http_request_response() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut c = HttpConn::new(s).unwrap();
            // дождаться запроса
            for _ in 0..200 {
                if let Some(path) = c.poll() {
                    assert_eq!(path, "/health");
                    c.respond(200, "{\"state\":\"RUNTIME_READY\"}", "application/json");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            panic!("no request");
        });
        let mut cli = TcpStream::connect(addr).unwrap();
        cli.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut resp = String::new();
        cli.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("RUNTIME_READY"));
        t.join().unwrap();
    }
}
