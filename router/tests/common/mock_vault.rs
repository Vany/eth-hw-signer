//! A mock Vault for the router's tests (F6: one mock, shared by
//! `vault_mock.rs`, `record_no_echo.rs` and `vault.rs`'s unit tests): an
//! HTTP/1.1 server on 127.0.0.1, one request per connection, answered by a
//! handler. Every request it answers is recorded in `seen`, so a test can
//! prove its client reached the mock (a pass that never got here is
//! vacuous). A malformed request or a failed accept is skipped, never the
//! end of the server thread; dropping the [`Mock`] stops it.
//!
//! Test-only, std only. Each test crate uses part of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// One request as the mock saw it.
#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    /// Path and query, as sent.
    pub path: String,
    /// The `X-Vault-Token` header, if any.
    pub token: Option<String>,
    pub body: String,
}

type Handler = dyn Fn(&Req) -> (u16, String) + Send + Sync;

/// A running mock: its base address (`http://127.0.0.1:port`) and the
/// requests answered so far.
pub struct Mock {
    pub addr: String,
    pub seen: Arc<Mutex<Vec<Req>>>,
    stop: Arc<AtomicBool>,
}

impl Mock {
    /// The requests answered so far, removed from `seen`.
    pub fn take_seen(&self) -> Vec<Req> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so the thread sees `stop` and ends.
        let _ = TcpStream::connect(self.addr.trim_start_matches("http://"));
    }
}

/// Serve `handler`'s `(status, body)` for every request. A 3xx answer
/// carries `Location: /v1/elsewhere`, back at this server, so a redirect
/// that is followed shows up as a second request in `seen`.
pub fn mock(handler: impl Fn(&Req) -> (u16, String) + Send + Sync + 'static) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (seen2, stop2) = (Arc::clone(&seen), Arc::clone(&stop));
    let handler: Arc<Handler> = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            if stop2.load(Ordering::SeqCst) {
                return;
            }
            let Ok(stream) = stream else { continue };
            let Some(req) = read_request(&stream) else {
                continue;
            };
            let (status, resp) = handler(&req);
            seen2.lock().unwrap().push(req);
            let extra = if (300..400).contains(&status) {
                "Location: /v1/elsewhere\r\n"
            } else {
                ""
            };
            let _ = write!(
                &stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{resp}",
                resp.len()
            );
        }
    });
    Mock { addr, seen, stop }
}

fn read_request(stream: &TcpStream) -> Option<Req> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let (mut len, mut token) = (0usize, None);
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':')?;
        match k.to_ascii_lowercase().as_str() {
            "content-length" => len = v.trim().parse().ok()?,
            "x-vault-token" => token = Some(v.trim().to_string()),
            _ => {}
        }
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body).ok()?;
    Some(Req {
        method,
        path,
        token,
        body: String::from_utf8(body).ok()?,
    })
}
