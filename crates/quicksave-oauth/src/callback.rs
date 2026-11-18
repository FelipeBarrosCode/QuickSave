// SPDX-License-Identifier: GPL-3.0-only
//! Small, strict HTTP callback parser. No request material is logged or reflected.

use std::net::IpAddr;
use subtle::{Choice, ConstantTimeEq};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::Zeroizing;

pub(crate) const MAX_HEADERS: usize = 8 * 1024;
const MAX_PARAMETERS: usize = 16;
const MAX_CODE: usize = 4096;
pub(crate) const STATE_LENGTH: usize = 43;

pub(crate) struct Expected<'a> {
    pub(crate) path: &'a str,
    pub(crate) host: &'a str,
    pub(crate) state: &'a str,
}

pub(crate) enum Callback {
    Code(Zeroizing<String>),
    Denied,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    Peer,
    Size,
    Syntax,
    Target,
    Host,
    Body,
    Parameters,
    State,
    Io,
}

/// Always compares the same number of state bytes, even for a wrong input length.
fn matches_state(actual: &str, expected: &str) -> bool {
    let mut left = Zeroizing::new([0_u8; STATE_LENGTH]);
    let mut right = Zeroizing::new([0_u8; STATE_LENGTH]);
    let left_length = actual.len() == STATE_LENGTH;
    let right_length = expected.len() == STATE_LENGTH;
    if left_length {
        left.copy_from_slice(actual.as_bytes());
    }
    if right_length {
        right.copy_from_slice(expected.as_bytes());
    }
    bool::from(
        left.as_slice().ct_eq(right.as_slice())
            & Choice::from(left_length as u8)
            & Choice::from(right_length as u8),
    )
}

fn decode(value: &str) -> Result<Zeroizing<String>, Rejection> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len()));
    let encoded = value.as_bytes();
    let mut offset = 0;
    while offset < encoded.len() {
        match encoded[offset] {
            b'+' => bytes.push(b' '),
            b'%' => {
                if offset + 2 >= encoded.len() {
                    return Err(Rejection::Parameters);
                }
                let hex = |byte: u8| match byte {
                    b'0'..=b'9' => Some(byte - b'0'),
                    b'a'..=b'f' => Some(byte - b'a' + 10),
                    b'A'..=b'F' => Some(byte - b'A' + 10),
                    _ => None,
                };
                let hi = hex(encoded[offset + 1]).ok_or(Rejection::Parameters)?;
                let lo = hex(encoded[offset + 2]).ok_or(Rejection::Parameters)?;
                bytes.push(hi * 16 + lo);
                offset += 2;
            }
            byte => bytes.push(byte),
        }
        offset += 1;
    }
    let decoded = std::str::from_utf8(&bytes).map_err(|_| Rejection::Parameters)?;
    if decoded.chars().any(char::is_control) {
        return Err(Rejection::Parameters);
    }
    Ok(Zeroizing::new(decoded.to_owned()))
}

fn parse_parameters(query: &str, expected: &Expected<'_>) -> Result<Callback, Rejection> {
    let mut parameters: Vec<(Zeroizing<String>, Zeroizing<String>)> = Vec::new();
    for pair in query.split('&') {
        if parameters.len() == MAX_PARAMETERS {
            return Err(Rejection::Parameters);
        }
        let (key, value) = pair.split_once('=').ok_or(Rejection::Parameters)?;
        let key = decode(key)?;
        let value = decode(value)?;
        if key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            || parameters
                .iter()
                .any(|(previous, _)| previous.as_str() == key.as_str())
        {
            return Err(Rejection::Parameters);
        }
        // An implicit/hybrid response is never a substitute for a PKCE code.
        if ["access_token", "refresh_token", "id_token", "token_type"].contains(&key.as_str()) {
            return Err(Rejection::Parameters);
        }
        parameters.push((key, value));
    }
    let state = parameters
        .iter()
        .find(|(key, _)| key.as_str() == "state")
        .map(|(_, value)| value.as_str())
        .ok_or(Rejection::State)?;
    if !matches_state(state, expected.state) {
        return Err(Rejection::State);
    }
    let code = parameters
        .iter()
        .position(|(key, _)| key.as_str() == "code");
    let error = parameters
        .iter()
        .position(|(key, _)| key.as_str() == "error");
    match (code, error) {
        (Some(index), None) => {
            let (_, code) = parameters.swap_remove(index);
            if code.is_empty() || code.len() > MAX_CODE {
                return Err(Rejection::Parameters);
            }
            Ok(Callback::Code(code))
        }
        (None, Some(index)) if !parameters[index].1.is_empty() => Ok(Callback::Denied),
        _ => Err(Rejection::Parameters),
    }
}

fn header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

pub(crate) fn parse(
    input: &[u8],
    peer: IpAddr,
    expected: &Expected<'_>,
) -> Result<Callback, Rejection> {
    if !peer.is_loopback() {
        return Err(Rejection::Peer);
    }
    if input.len() > MAX_HEADERS {
        return Err(Rejection::Size);
    }
    let input = std::str::from_utf8(input).map_err(|_| Rejection::Syntax)?;
    if !input.is_ascii() || !input.ends_with("\r\n\r\n") {
        return Err(Rejection::Syntax);
    }
    let mut lines = input[..input.len() - 4].split("\r\n");
    let request = lines.next().ok_or(Rejection::Syntax)?;
    let mut parts = request.split(' ');
    if parts.next() != Some("GET") {
        return Err(Rejection::Syntax);
    }
    let target = parts.next().ok_or(Rejection::Syntax)?;
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(Rejection::Syntax);
    }
    if target.contains('#') {
        return Err(Rejection::Target);
    }
    let (path, query) = target.split_once('?').ok_or(Rejection::Target)?;
    // No URL normalization or prefix/percent-decoded-path matching.
    if path != expected.path {
        return Err(Rejection::Target);
    }
    let mut seen_host = false;
    let mut count = 0;
    for line in lines {
        count += 1;
        if count > 64 || line.starts_with([' ', '\t']) {
            return Err(Rejection::Syntax);
        }
        let (name, value) = line.split_once(':').ok_or(Rejection::Syntax)?;
        if !header_name(name)
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(Rejection::Syntax);
        }
        if name.eq_ignore_ascii_case("host") {
            if seen_host || value.trim_matches([' ', '\t']) != expected.host {
                return Err(Rejection::Host);
            }
            seen_host = true;
        } else if ["content-length", "transfer-encoding", "expect", "upgrade"]
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
        {
            return Err(Rejection::Body);
        }
    }
    if !seen_host {
        return Err(Rejection::Host);
    }
    parse_parameters(query, expected)
}

pub(crate) async fn read(
    stream: &mut TcpStream,
    expected: &Expected<'_>,
) -> Result<Callback, Rejection> {
    let peer = stream.peer_addr().map_err(|_| Rejection::Io)?.ip();
    if !peer.is_loopback() {
        return Err(Rejection::Peer);
    }
    let mut input = Zeroizing::new(Vec::with_capacity(MAX_HEADERS));
    let mut chunk = Zeroizing::new([0_u8; 1024]);
    loop {
        let remaining = MAX_HEADERS - input.len();
        if remaining == 0 {
            return Err(Rejection::Size);
        }
        let read = stream
            .read(&mut chunk[..remaining.min(1024)])
            .await
            .map_err(|_| Rejection::Io)?;
        if read == 0 {
            return Err(Rejection::Syntax);
        }
        input.extend_from_slice(&chunk[..read]);
        if let Some(end) = input.windows(4).position(|window| window == b"\r\n\r\n") {
            if end + 4 != input.len() {
                return Err(Rejection::Body);
            }
            return parse(&input, peer, expected);
        }
    }
}

pub(crate) enum Page {
    Received,
    Denied,
    Rejected,
}

pub(crate) fn response(page: Page) -> String {
    let (status, message) = match page {
        Page::Received => ("200 OK", "Authorization received. Return to QuickSave."),
        Page::Denied => (
            "403 Forbidden",
            "Authorization was not granted. Return to QuickSave.",
        ),
        Page::Rejected => (
            "400 Bad Request",
            "Authorization callback rejected. Return to QuickSave.",
        ),
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>QuickSave authorization</title><body><p>{message}</p></body></html>"
    );
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub(crate) async fn write(stream: &mut TcpStream, page: Page) {
    // This fixed response contains no untrusted request/provider data. A browser
    // disconnecting after a valid callback does not invalidate the received code.
    let _ = stream.write_all(response(page).as_bytes()).await;
    let _ = stream.shutdown().await;
}
