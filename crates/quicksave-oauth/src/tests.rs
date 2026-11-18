// SPDX-License-Identifier: GPL-3.0-only
// Synthetic credentials only. No public network, browser, vault or real account.

use super::*;
use callback::{Callback, Expected, Rejection};
use std::{
    collections::BTreeMap,
    future::Future,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
    task::JoinHandle,
};

static_assertions::assert_not_impl_any!(OAuthRequest: std::fmt::Debug, serde::Serialize, Clone);
static_assertions::assert_not_impl_any!(OAuthTokens: std::fmt::Debug, serde::Serialize, Clone);
static_assertions::assert_not_impl_any!(FlowSecrets: std::fmt::Debug, serde::Serialize, Clone);
static_assertions::assert_not_impl_any!(TokenReply: std::fmt::Debug, serde::Serialize, Clone);

const STATE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const CALLBACK_PATH: &str = "/oauth/callback/test-only-unpredictable-path";
const HOST: &str = "127.0.0.1:49152";
const CODE: &str = "test-only-authorization-code-private";
const ACCESS: &str = "test-only-access-token-private";
const REFRESH: &str = "test-only-refresh-token-private";
const CLIENT_SECRET: &str = "test-only-client-secret-private";
const VERIFIER: &str = "test-only-verifier-never-placed-in-browser-url";

// A fixed registered port must never be made dynamic just for a test. Serialize
// this crate's owned loopback listeners so ephemeral tests cannot coincidentally
// reserve 53682 while a registered-redirect test is running.
static LOOPBACK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn expected() -> Expected<'static> {
    Expected {
        path: CALLBACK_PATH,
        host: HOST,
        state: STATE,
    }
}
fn request_line(target: &str, headers: &str) -> String {
    format!("GET {target} HTTP/1.1\r\n{headers}\r\n\r\n")
}
fn valid_callback() -> String {
    request_line(
        &format!("{CALLBACK_PATH}?code={CODE}&state={STATE}"),
        &format!("Host: {HOST}"),
    )
}
fn parsed(input: &str) -> std::result::Result<Callback, Rejection> {
    callback::parse(
        input.as_bytes(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &expected(),
    )
}
fn rejection(input: &str) -> Rejection {
    parsed(input)
        .err()
        .expect("malformed callback was accepted")
}
fn client(kind: &str) -> OAuthRequest {
    OAuthRequest {
        kind: kind.to_owned(),
        client_id: "test-only-registered-client".to_owned(),
        client_secret: None,
    }
}
fn token_reply(provider: Provider) -> TokenReply {
    TokenReply {
        status: 200,
        body: Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({
                "access_token": ACCESS,
                "refresh_token": REFRESH,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": provider.required_scopes().join(" "),
            }))
            .expect("synthetic JSON"),
        ),
    }
}
fn error_message(result: Result<OAuthTokens>) -> String {
    let error = result.err().expect("expected a redacted error, not tokens");
    let error = format!("{error:#} {error:?}");
    for private in [CODE, ACCESS, REFRESH, CLIENT_SECRET, VERIFIER] {
        assert!(
            !error.contains(private),
            "private input appeared in an error"
        );
    }
    error
}

#[test]
fn private_structs_zeroize_all_owned_fields_without_debug_or_serialize() {
    let mut input = client("google_drive");
    input.client_secret = Some(CLIENT_SECRET.to_owned());
    input.zeroize();
    assert!(input.kind.is_empty());
    assert!(input.client_id.is_empty());
    assert!(input
        .client_secret
        .as_deref()
        .unwrap_or_default()
        .is_empty());
    let mut tokens = OAuthTokens {
        access_token: ACCESS.to_owned(),
        refresh_token: Some(REFRESH.to_owned()),
        expires_at: 12345,
    };
    tokens.zeroize();
    assert!(tokens.access_token.is_empty());
    assert!(tokens
        .refresh_token
        .as_deref()
        .unwrap_or_default()
        .is_empty());
    assert_eq!(tokens.expires_at, 0);
    assert!(std::mem::needs_drop::<OAuthRequest>());
    assert!(std::mem::needs_drop::<OAuthTokens>());
}

#[test]
fn production_timeouts_and_rejection_limit_are_fixed_and_bounded() {
    let limits = Limits::default();
    assert_eq!(limits.total, Duration::from_secs(300));
    assert_eq!(limits.connection, Duration::from_secs(10));
    assert_eq!(limits.token, Duration::from_secs(30));
    assert_eq!(MAX_UNEXPECTED_CALLBACKS, 16);
    assert_eq!(callback::MAX_HEADERS, 8192);
    assert_eq!(MAX_TOKEN_BODY, 256 * 1024);
}

#[test]
fn pkce_s256_matches_the_public_rfc7636_appendix_b_vector() {
    let secrets = FlowSecrets {
        verifier: Zeroizing::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned()),
        state: Zeroizing::new(STATE.to_owned()),
        callback_path: Zeroizing::new(CALLBACK_PATH.to_owned()),
    };
    assert_eq!(
        secrets.challenge(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn three_independent_os_random_secrets_are_url_safe_and_have_256_bits_of_input() {
    let first = FlowSecrets::new(Provider::GoogleDrive).expect("OS randomness");
    let second = FlowSecrets::new(Provider::GoogleDrive).expect("OS randomness");
    for text in [
        first.verifier.as_str(),
        first.state.as_str(),
        first.callback_path.rsplit('/').next().unwrap(),
    ] {
        assert_eq!(text.len(), 43);
        assert_eq!(URL_SAFE_NO_PAD.decode(text).expect("base64url").len(), 32);
    }
    assert_ne!(first.verifier.as_str(), first.state.as_str());
    assert_ne!(
        first.state.as_str(),
        first.callback_path.rsplit('/').next().unwrap()
    );
    assert_ne!(first.state.as_str(), second.state.as_str());
    assert_ne!(first.callback_path.as_str(), second.callback_path.as_str());
}

#[test]
fn provider_endpoints_and_scope_sets_are_static_and_do_not_include_identity_or_admin() {
    let definitions = [
        (
            "google_drive",
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
        ),
        (
            "microsoft_onedrive",
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        ),
        (
            "dropbox",
            "https://www.dropbox.com/oauth2/authorize",
            "https://api.dropboxapi.com/oauth2/token",
        ),
    ];
    for (kind, authorization, token) in definitions {
        let provider = Provider::from_kind(kind).expect("supported definition");
        assert_eq!(provider.authorization_endpoint(), authorization);
        assert_eq!(provider.token_endpoint(), token);
        assert!(Provider::is_static_token_endpoint(token));
        assert!(!provider.scope().contains("openid"));
        assert!(!provider.scope().contains("profile"));
        assert!(!provider.scope().contains("Sites."));
    }
    for endpoint in [
        "http://oauth2.googleapis.com/token",
        "https://oauth2.googleapis.com/token?redirect=evil",
        "https://oauth2.googleapis.com.evil.invalid/token",
        "https://127.0.0.1/token",
        "https://evil.invalid/",
    ] {
        assert!(!Provider::is_static_token_endpoint(endpoint));
    }
}

#[test]
fn service_protocol_support_includes_explicit_box_confidential_flow() {
    for kind in ["google_drive", "microsoft_onedrive", "dropbox", "box"] {
        assert!(supports(kind));
    }
    for kind in ["s3", "GoogleDrive", "", "https://evil.invalid"] {
        assert!(!supports(kind));
    }
}

#[test]
fn registered_redirect_policy_is_fixed_while_google_retains_ephemeral_random_paths() {
    for provider in [Provider::MicrosoftOneDrive, Provider::Dropbox] {
        assert_eq!(provider.listener_port(), 53682);
        assert_eq!(
            provider.registered_path(),
            Some("/quicksave/oauth/callback")
        );
        assert_eq!(
            provider.registered_redirect(),
            Some("http://127.0.0.1:53682/quicksave/oauth/callback"),
        );
        let first = FlowSecrets::new(provider).unwrap();
        let second = FlowSecrets::new(provider).unwrap();
        assert_eq!(first.callback_path.as_str(), "/quicksave/oauth/callback");
        assert_eq!(first.callback_path.as_str(), second.callback_path.as_str());
        assert_ne!(first.state.as_str(), second.state.as_str());
        assert_ne!(first.verifier.as_str(), second.verifier.as_str());
        assert_ne!(first.challenge(), second.challenge());
    }
    assert_eq!(Provider::GoogleDrive.listener_port(), 0);
    assert!(Provider::GoogleDrive.registered_redirect().is_none());
    let first = FlowSecrets::new(Provider::GoogleDrive).unwrap();
    let second = FlowSecrets::new(Provider::GoogleDrive).unwrap();
    assert!(first.callback_path.starts_with("/oauth/callback/"));
    assert_ne!(first.callback_path.as_str(), second.callback_path.as_str());
}

#[test]
fn authorization_urls_encode_only_allowed_public_parameters_not_secrets_or_verifiers() {
    for kind in ["google_drive", "microsoft_onedrive", "dropbox"] {
        let mut input = client(kind);
        if kind == "google_drive" {
            input.client_secret = Some(CLIENT_SECRET.to_owned());
        }
        // Even malicious-looking public ID text cannot append a query parameter.
        input.client_id = "test-client&untrusted=https://evil.invalid/".to_owned();
        let provider = validate_request(&input).expect("encoded public ID");
        let secrets = FlowSecrets {
            verifier: Zeroizing::new(VERIFIER.to_owned()),
            state: Zeroizing::new(STATE.to_owned()),
            callback_path: Zeroizing::new(CALLBACK_PATH.to_owned()),
        };
        let redirect = provider
            .registered_redirect()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("http://{HOST}{CALLBACK_PATH}"));
        let url = authorization_url(provider, &input, &redirect, &secrets).expect("native URL");
        assert!(!url.contains(CLIENT_SECRET));
        assert!(!url.contains(VERIFIER));
        let url = Url::parse(&url).expect("generated URL");
        let values = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
        assert_eq!(values.get("client_id").unwrap(), &input.client_id);
        assert_eq!(values.get("redirect_uri").unwrap(), &redirect);
        assert_eq!(values.get("state").unwrap(), STATE);
        assert_eq!(values.get("code_challenge_method").unwrap(), "S256");
        assert!(!values.contains_key("code_verifier"));
        assert!(!values.contains_key("client_secret"));
        assert!(!values.contains_key("untrusted"));
        assert_eq!(url.scheme(), "https");
        assert_eq!(
            url.origin(),
            Url::parse(provider.authorization_endpoint())
                .unwrap()
                .origin()
        );
    }
}

#[test]
fn google_and_dropbox_request_offline_tokens_microsoft_uses_query_callback() {
    for (kind, key, value) in [
        ("google_drive", "access_type", "offline"),
        ("dropbox", "token_access_type", "offline"),
        ("microsoft_onedrive", "response_mode", "query"),
    ] {
        let input = client(kind);
        let provider = validate_request(&input).unwrap();
        let secrets = FlowSecrets::new(provider).unwrap();
        let redirect = provider
            .registered_redirect()
            .unwrap_or("http://127.0.0.1:49152/test");
        let url = authorization_url(provider, &input, redirect, &secrets).unwrap();
        assert!(Url::parse(&url)
            .unwrap()
            .query_pairs()
            .any(|pair| pair.0 == key && pair.1 == value));
    }
}

#[test]
fn public_fixed_callback_path_still_rejects_forged_state_path_and_host() {
    let expected = Expected {
        path: providers::REGISTERED_PATH,
        host: "127.0.0.1:53682",
        state: STATE,
    };
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let valid = request_line(
        &format!("{}?code={CODE}&state={STATE}", expected.path),
        &format!("Host: {}", expected.host),
    );
    assert!(matches!(
        callback::parse(valid.as_bytes(), peer, &expected),
        Ok(Callback::Code(_))
    ));
    for (input, reason) in [
        (
            valid.replace(
                &format!("state={STATE}"),
                &format!("state=Z{}", &STATE[1..]),
            ),
            Rejection::State,
        ),
        (
            valid.replace("/quicksave/oauth/callback?", "/quicksave/oauth/other?"),
            Rejection::Target,
        ),
        (
            valid.replace("Host: 127.0.0.1:53682", "Host: localhost:53682"),
            Rejection::Host,
        ),
        (
            valid.replace("Host: 127.0.0.1:53682", "Host: 127.0.0.1:53683"),
            Rejection::Host,
        ),
    ] {
        assert_eq!(
            callback::parse(input.as_bytes(), peer, &expected).err(),
            Some(reason)
        );
    }
}

#[test]
fn native_public_provider_registrations_reject_confidential_client_fallback() {
    for kind in ["microsoft_onedrive", "dropbox"] {
        let mut input = client(kind);
        input.client_secret = Some(CLIENT_SECRET.to_owned());
        let error = validate_request(&input)
            .err()
            .expect("secret must be rejected");
        assert!(error.to_string().contains("public-client PKCE"));
        assert!(!error.to_string().contains(CLIENT_SECRET));
    }
    for id in ["", "bad\nclient", "bad client"] {
        let mut input = client("google_drive");
        input.client_id = id.to_owned();
        assert!(validate_request(&input).is_err());
    }
}

#[test]
fn token_code_verifier_and_optional_google_secret_only_appear_in_encoded_post_body() {
    let mut input = client("google_drive");
    input.client_secret = Some(CLIENT_SECRET.to_owned());
    let form = token_form(
        Provider::GoogleDrive,
        &input,
        &format!("http://{HOST}{CALLBACK_PATH}"),
        VERIFIER,
        "test code & encoded",
    );
    let values = url::form_urlencoded::parse(form.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(values.get("code").unwrap(), "test code & encoded");
    assert_eq!(values.get("code_verifier").unwrap(), VERIFIER);
    assert_eq!(values.get("client_secret").unwrap(), CLIENT_SECRET);
    assert_eq!(values.get("grant_type").unwrap(), "authorization_code");
}

#[test]
fn callback_accepts_only_exact_path_host_loopback_and_matching_state() {
    let result = parsed(&valid_callback()).expect("valid callback");
    match result {
        Callback::Code(code) => assert_eq!(code.as_str(), CODE),
        Callback::Denied => panic!("success turned into denial"),
    }
    let mut wrong_peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    assert_eq!(
        callback::parse(valid_callback().as_bytes(), wrong_peer, &expected()).err(),
        Some(Rejection::Peer),
    );
    wrong_peer = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    assert!(callback::parse(valid_callback().as_bytes(), wrong_peer, &expected()).is_ok());
}

#[test]
fn callback_decodes_code_once_and_allows_bounded_provider_metadata() {
    let request = request_line(
        &format!(
            "{CALLBACK_PATH}?code=a%2Bb%2Fc%3D&state={STATE}&scope=drive&authuser=0&prompt=consent"
        ),
        &format!("hOsT: {HOST}\r\nAccept: text/html"),
    );
    match parsed(&request).unwrap() {
        Callback::Code(code) => assert_eq!(code.as_str(), "a+b/c="),
        Callback::Denied => panic!("unexpected denial"),
    }
}

#[test]
fn wrong_missing_short_long_or_duplicate_state_is_not_an_authorized_denial() {
    for parameters in [
        format!("code={CODE}"),
        format!("code={CODE}&state=wrong"),
        format!("code={CODE}&state={STATE}x"),
        format!("code={CODE}&state={STATE}&state={STATE}"),
        format!("code={CODE}&state={STATE}&%73tate={STATE}"),
        "error=access_denied&state=wrong".to_owned(),
    ] {
        assert!(parsed(&request_line(
            &format!("{CALLBACK_PATH}?{parameters}"),
            &format!("Host: {HOST}"),
        ))
        .is_err());
    }
}

#[test]
fn code_error_implicit_response_duplicates_and_bad_percent_encoding_are_rejected() {
    for parameters in [
        format!("state={STATE}"),
        format!("state={STATE}&code="),
        format!("state={STATE}&code={CODE}&error=access_denied"),
        format!("state={STATE}&code={CODE}&code=other"),
        format!("state={STATE}&code={CODE}&authuser=0&authuser=1"),
        format!("state={STATE}&access_token={ACCESS}"),
        format!("state={STATE}&code={CODE}&id_token=unexpected"),
        format!("state={STATE}&code=%"),
        format!("state={STATE}&code=%GG"),
        format!("state={STATE}&code=%ff"),
        format!("state={STATE}&code=%00"),
        format!("state={STATE}&code=%0a"),
        format!("state={STATE}&code={CODE}&badkey"),
        format!("state={STATE}&code={CODE}&=emptykey"),
    ] {
        assert!(parsed(&request_line(
            &format!("{CALLBACK_PATH}?{parameters}"),
            &format!("Host: {HOST}"),
        ))
        .is_err());
    }
}

#[test]
fn genuine_state_bound_provider_error_is_denied_without_reflecting_description() {
    let input = request_line(
        &format!("{CALLBACK_PATH}?state={STATE}&error=access_denied&error_description={ACCESS}"),
        &format!("Host: {HOST}"),
    );
    assert!(matches!(parsed(&input), Ok(Callback::Denied)));
}

#[test]
fn callback_requires_get_origin_form_http11_exact_raw_path_and_no_fragment() {
    for target in [
        "/oauth/callback/another",
        "/oauth/callback/test-only-unpredictable-path/extra",
        "/oauth/callback/%74est-only-unpredictable-path",
        "http://127.0.0.1:49152/oauth/callback/test-only-unpredictable-path",
        "//127.0.0.1:49152/oauth/callback/test-only-unpredictable-path",
    ] {
        assert_eq!(
            rejection(&request_line(
                &format!("{target}?code={CODE}&state={STATE}"),
                &format!("Host: {HOST}"),
            )),
            Rejection::Target
        );
    }
    assert_eq!(
        rejection(&valid_callback().replace("GET ", "POST ")),
        Rejection::Syntax
    );
    assert_eq!(
        rejection(&valid_callback().replace("HTTP/1.1", "HTTP/1.0")),
        Rejection::Syntax
    );
    assert_eq!(
        rejection(&valid_callback().replace("?code=", "#code=")),
        Rejection::Target
    );
    assert_eq!(
        rejection(&valid_callback().replace("GET ", "GET  ")),
        Rejection::Syntax
    );
}

#[test]
fn callback_rejects_host_confusion_and_duplicate_headers() {
    for host in [
        "localhost:49152",
        "127.0.0.1",
        "127.0.0.1:49153",
        "127.0.0.1:49152.evil.invalid",
        "127.0.0.1:49152@evil.invalid",
        "127.0.0.1.:49152",
    ] {
        assert_eq!(
            rejection(&valid_callback().replace(HOST, host)),
            Rejection::Host
        );
    }
    assert_eq!(
        rejection(&valid_callback().replace(
            &format!("Host: {HOST}"),
            &format!("Host: {HOST}\r\nHost: {HOST}"),
        )),
        Rejection::Host
    );
    assert_eq!(
        rejection(&valid_callback().replace("Host:", "Missing-Host:")),
        Rejection::Host
    );
}

#[test]
fn callback_rejects_body_smuggling_obsolete_folding_and_trailing_pipeline() {
    for header in [
        "Content-Length: 0",
        "Content-Length: 10",
        "Transfer-Encoding: chunked",
        "Expect: 100-continue",
        "Upgrade: websocket",
    ] {
        let input = valid_callback().replace("\r\n\r\n", &format!("\r\n{header}\r\n\r\n"));
        assert_eq!(rejection(&input), Rejection::Body);
    }
    assert_eq!(
        rejection(&valid_callback().replace("Host:", " Host:")),
        Rejection::Syntax
    );
    assert_eq!(
        rejection(&valid_callback().replace("Host:", "Host :")),
        Rejection::Syntax
    );
    assert!(parsed(&(valid_callback() + "GET /other HTTP/1.1\r\n\r\n")).is_err());
}

#[test]
fn callback_header_and_parameter_sizes_are_bounded_including_exact_boundary() {
    let base = valid_callback().replace("\r\n\r\n", "\r\nX-Pad: \r\n\r\n");
    let padding = "x".repeat(callback::MAX_HEADERS - base.len());
    let exact = base.replace("X-Pad: ", &format!("X-Pad: {padding}"));
    assert_eq!(exact.len(), callback::MAX_HEADERS);
    assert!(parsed(&exact).is_ok());
    assert_eq!(
        rejection(&exact.replace("X-Pad: ", "X-Pad: x")),
        Rejection::Size
    );
    let extras = (0..15)
        .map(|index| format!("&extra{index}=x"))
        .collect::<String>();
    assert_eq!(
        rejection(
            &valid_callback()
                .replace(&format!("state={STATE}"), &format!("state={STATE}{extras}"),)
        ),
        Rejection::Parameters
    );
}

#[test]
fn callback_responses_are_static_hardened_and_never_claim_provider_health() {
    for page in [
        callback::Page::Received,
        callback::Page::Denied,
        callback::Page::Rejected,
    ] {
        let response = callback::response(page);
        assert!(response.contains("Cache-Control: no-store"));
        assert!(response.contains("Pragma: no-cache"));
        assert!(response.contains("Referrer-Policy: no-referrer"));
        assert!(response.contains("Content-Security-Policy: default-src 'none'"));
        assert!(response.contains("frame-ancestors 'none'"));
        assert!(response.contains("X-Content-Type-Options: nosniff"));
        assert!(response.contains("Connection: close"));
        assert!(!response.contains("<script"));
        assert!(!response.contains("<img"));
        assert!(!response.to_lowercase().contains("connected"));
        for secret in [CODE, ACCESS, REFRESH, CLIENT_SECRET, VERIFIER, STATE] {
            assert!(!response.contains(secret));
        }
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(headers.contains(&format!("Content-Length: {}", body.len())));
    }
    assert!(callback::response(callback::Page::Received)
        .contains("Authorization received. Return to QuickSave."));
}

#[test]
fn token_parser_preserves_actual_lifetime_and_refresh_token_without_fabrication() {
    for provider in [
        Provider::GoogleDrive,
        Provider::MicrosoftOneDrive,
        Provider::Dropbox,
    ] {
        let tokens = parse_tokens(provider, token_reply(provider), 1_700_000_000).unwrap();
        assert_eq!(tokens.access_token, ACCESS);
        assert_eq!(tokens.refresh_token.as_deref(), Some(REFRESH));
        assert_eq!(tokens.expires_at, 1_700_003_600);
    }
    let reply = TokenReply {
        status: 200,
        body: Zeroizing::new(
            format!("{{\"access_token\":\"{ACCESS}\",\"token_type\":\"bearer\",\"expires_in\":1}}")
                .into_bytes(),
        ),
    };
    let tokens = parse_tokens(Provider::Dropbox, reply, 100).unwrap();
    assert!(tokens.refresh_token.is_none());
    assert_eq!(tokens.expires_at, 101);
}

#[test]
fn token_parser_rejects_error_status_oversized_body_duplicates_and_invalid_tokens_redacted() {
    let bad_json = [
        format!("{{\"error\":\"{ACCESS}\",\"error_description\":\"{CLIENT_SECRET}\"}}"),
        format!("{{\"access_token\":\"{ACCESS}\",\"access_token\":\"other\",\"expires_in\":1,\"token_type\":\"Bearer\"}}"),
        format!("{{\"access_token\":\"{ACCESS}\",\"expires_in\":0,\"token_type\":\"Bearer\"}}"),
        format!("{{\"access_token\":\"{ACCESS}\",\"expires_in\":-1,\"token_type\":\"Bearer\"}}"),
        format!("{{\"access_token\":\"{ACCESS}\",\"expires_in\":999999999999,\"token_type\":\"Bearer\"}}"),
        format!("{{\"access_token\":\"{ACCESS}\",\"expires_in\":\"3600\",\"token_type\":\"Bearer\"}}"),
        format!("{{\"access_token\":\"{ACCESS}\",\"expires_in\":3600,\"token_type\":\"DPoP\"}}"),
        format!("{{\"access_token\":\"{ACCESS}\",\"expires_in\":3600}}"),
        "{\"access_token\":\"bad token\",\"expires_in\":3600,\"token_type\":\"Bearer\"}".to_owned(),
        format!("{{\"access_token\":\"{ACCESS}\",\"refresh_token\":\"bad\\nrefresh\",\"expires_in\":3600,\"token_type\":\"Bearer\"}}"),
        format!("not JSON {CODE} {CLIENT_SECRET}"),
    ];
    for body in bad_json {
        let error = error_message(parse_tokens(
            Provider::GoogleDrive,
            TokenReply {
                status: 200,
                body: Zeroizing::new(body.into_bytes()),
            },
            1_700_000_000,
        ));
        assert!(error.contains("OAuth"));
    }
    for status in [302, 400, 401, 429, 500] {
        let mut reply = token_reply(Provider::GoogleDrive);
        reply.status = status;
        assert!(
            error_message(parse_tokens(Provider::GoogleDrive, reply, 100)).contains("rejected")
        );
    }
    let reply = TokenReply {
        status: 200,
        body: Zeroizing::new(vec![b'x'; MAX_TOKEN_BODY + 1]),
    };
    assert!(error_message(parse_tokens(Provider::GoogleDrive, reply, 100)).contains("size limit"));
    assert!(error_message(parse_tokens(
        Provider::GoogleDrive,
        token_reply(Provider::GoogleDrive),
        i64::MAX
    ))
    .contains("expiry"));
}

#[test]
fn partial_scopes_are_not_treated_as_approved_file_permissions() {
    for provider in [
        Provider::GoogleDrive,
        Provider::MicrosoftOneDrive,
        Provider::Dropbox,
    ] {
        let reply = TokenReply {
            status: 200,
            body: Zeroizing::new(format!(
                "{{\"access_token\":\"{ACCESS}\",\"expires_in\":3600,\"token_type\":\"Bearer\",\"scope\":\"unrelated.read\"}}"
            ).into_bytes()),
        };
        assert!(
            error_message(parse_tokens(provider, reply, 100)).contains("required file permissions")
        );
    }
}

enum FakeResult {
    Reply(TokenReply),
    Error,
    Pending,
}
struct FakeTransport {
    result: Mutex<Option<FakeResult>>,
    calls: AtomicUsize,
    endpoint: Mutex<Option<&'static str>>,
    form: Mutex<Option<Zeroizing<String>>>,
}
impl FakeTransport {
    fn new(result: FakeResult) -> Arc<Self> {
        Arc::new(Self {
            result: Mutex::new(Some(result)),
            calls: AtomicUsize::new(0),
            endpoint: Mutex::new(None),
            form: Mutex::new(None),
        })
    }
}
impl HttpTransport for FakeTransport {
    fn exchange<'a>(
        &'a self,
        endpoint: &'static str,
        body: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<TokenReply>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.endpoint.lock().unwrap() = Some(endpoint);
            *self.form.lock().unwrap() = Some(Zeroizing::new(body.to_owned()));
            let result = self
                .result
                .lock()
                .unwrap()
                .take()
                .expect("exchange must not retry");
            match result {
                FakeResult::Reply(reply) => Ok(reply),
                FakeResult::Error => bail!("{CODE} {ACCESS} {CLIENT_SECRET} {VERIFIER}"),
                FakeResult::Pending => std::future::pending().await,
            }
        })
    }
}

fn start(
    input: OAuthRequest,
    transport: Arc<FakeTransport>,
    limits: Limits,
) -> (JoinHandle<Result<OAuthTokens>>, oneshot::Receiver<String>) {
    let (sender, receiver) = oneshot::channel();
    let sender = Mutex::new(Some(sender));
    let open: Opener = Arc::new(move |url| {
        sender
            .lock()
            .unwrap()
            .take()
            .expect("browser must only open once")
            .send(url.to_owned())
            .map_err(|_| anyhow!("test opener receiver closed"))?;
        Ok(())
    });
    (
        tokio::spawn(async move {
            let _owned_sockets = LOOPBACK_TEST_LOCK.lock().await;
            authorize_with_transport(input, open, transport.as_ref(), limits).await
        }),
        receiver,
    )
}

fn redirect_data(url: &str) -> (Url, String) {
    let url = Url::parse(url).expect("synthetic authorization URL");
    let values = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
    (
        Url::parse(values.get("redirect_uri").unwrap()).unwrap(),
        values.get("state").unwrap().to_owned(),
    )
}
async fn send_request(redirect: &Url, request: String) -> String {
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, redirect.port().unwrap()))
        .await
        .expect("own loopback listener");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("local callback write");
    let mut response = Vec::new();
    stream
        .take(4096)
        .read_to_end(&mut response)
        .await
        .expect("bounded fixed callback response");
    String::from_utf8(response).expect("fixed response is ASCII")
}
async fn send_callback(url: &str, code: Option<&str>, error: Option<&str>) -> String {
    let (mut redirect, state) = redirect_data(url);
    {
        let mut query = redirect.query_pairs_mut();
        query.append_pair("state", &state);
        if let Some(code) = code {
            query.append_pair("code", code);
        }
        if let Some(error) = error {
            query
                .append_pair("error", error)
                .append_pair("error_description", CLIENT_SECRET);
        }
    }
    let request = request_line(
        &format!("{}?{}", redirect.path(), redirect.query().unwrap()),
        &format!("Host: 127.0.0.1:{}", redirect.port().unwrap()),
    );
    send_request(&redirect, request).await
}

#[tokio::test]
async fn injected_end_to_end_loopback_flow_binds_before_open_and_exchanges_once() {
    // Full real-socket callback/exchange coverage uses the ephemeral Google
    // listener. Fixed-port setup is tested below without accepting a TCP peer,
    // avoiding platform TIME_WAIT and touching no preexisting local service.
    let kind = "google_drive";
    let provider = Provider::GoogleDrive;
    let transport = FakeTransport::new(FakeResult::Reply(token_reply(provider)));
    let (task, opening) = start(client(kind), Arc::clone(&transport), Limits::default());
    let url = opening.await.expect("injected native opener");
    let (redirect, _) = redirect_data(&url);
    let response = send_callback(&url, Some(CODE), None).await;
    assert!(response.contains("Authorization received."));
    assert!(!response.contains("connected"));
    let tokens = task.await.unwrap().expect("synthetic successful exchange");
    assert_eq!(tokens.access_token, ACCESS);
    assert!(tokens.expires_at > unix_seconds().unwrap());
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *transport.endpoint.lock().unwrap(),
        Some(provider.token_endpoint())
    );
    let values = {
        let form = transport.form.lock().unwrap();
        url::form_urlencoded::parse(form.as_ref().unwrap().as_bytes())
            .into_owned()
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(values.get("code").unwrap(), CODE);
    assert_eq!(values.get("redirect_uri").unwrap(), redirect.as_str());
    let verifier = values.get("code_verifier").unwrap();
    let expected_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let authorization = Url::parse(&url).unwrap();
    assert!(authorization
        .query_pairs()
        .any(|pair| pair.0 == "code_challenge" && pair.1 == expected_challenge));
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, redirect.port().unwrap()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn fixed_registered_listener_is_bound_before_open_and_each_attempt_has_fresh_proofs() {
    let _owned_sockets = LOOPBACK_TEST_LOCK.lock().await;
    for kind in ["microsoft_onedrive", "dropbox"] {
        let mut previous: Option<(String, String)> = None;
        for _ in 0..2 {
            let transport = FakeTransport::new(FakeResult::Error);
            let opened = Arc::new(Mutex::new(None::<String>));
            let captured = Arc::clone(&opened);
            let open: Opener = Arc::new(move |url| {
                // This bind must already be unavailable before the OS opener.
                assert!(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 53682)).is_err());
                *captured.lock().unwrap() = Some(url.to_owned());
                // No browser or TCP client is started by this test. Closing an
                // unused listener avoids TIME_WAIT while testing real binding.
                bail!("synthetic opener deliberately stopped after native bind")
            });
            let error = error_message(
                authorize_with_transport(client(kind), open, transport.as_ref(), Limits::default())
                    .await,
            );
            assert!(error.contains("browser could not be opened"));
            let authorization = {
                let opened = opened.lock().unwrap();
                Url::parse(opened.as_ref().expect("native opener was not called")).unwrap()
            };
            let values = authorization
                .query_pairs()
                .into_owned()
                .collect::<BTreeMap<_, _>>();
            assert_eq!(
                values.get("redirect_uri").unwrap(),
                providers::REGISTERED_URI
            );
            assert_eq!(values.get("code_challenge_method").unwrap(), "S256");
            let current = (
                values.get("state").unwrap().to_owned(),
                values.get("code_challenge").unwrap().to_owned(),
            );
            if let Some(previous) = previous {
                assert_ne!(current.0, previous.0);
                assert_ne!(current.1, previous.1);
            }
            previous = Some(current);
            assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
            let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 53682))
                .expect("unused owned listener must close on opener failure");
            drop(probe);
        }
    }
}

#[tokio::test]
async fn occupied_registered_port_fails_closed_without_opener_or_alternate_redirect() {
    let _owned_sockets = LOOPBACK_TEST_LOCK.lock().await;
    let occupied = bind_loopback(Provider::MicrosoftOneDrive)
        .expect("test must own the reserved loopback listener before exercising collisions");
    assert_eq!(occupied.local_addr().unwrap().port(), 53682);
    for kind in ["microsoft_onedrive", "dropbox"] {
        let transport = FakeTransport::new(FakeResult::Error);
        let opened = Arc::new(AtomicBool::new(false));
        let captured = Arc::clone(&opened);
        let open: Opener = Arc::new(move |_| {
            captured.store(true, Ordering::SeqCst);
            Ok(())
        });
        let error = error_message(
            authorize_with_transport(client(kind), open, transport.as_ref(), Limits::default())
                .await,
        );
        assert!(error.contains("port 53682 is unavailable"));
        assert!(error.contains("no alternate redirect"));
        assert!(!opened.load(Ordering::SeqCst));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }
    drop(occupied);
}

#[tokio::test]
async fn denied_authorization_never_reaches_token_transport_and_reflects_no_error_details() {
    let transport = FakeTransport::new(FakeResult::Error);
    let (task, opening) = start(
        client("google_drive"),
        Arc::clone(&transport),
        Limits::default(),
    );
    let url = opening.await.unwrap();
    let response = send_callback(&url, None, Some("access_denied")).await;
    assert!(response.starts_with("HTTP/1.1 403"));
    assert!(!response.contains(CLIENT_SECRET));
    assert!(error_message(task.await.unwrap()).contains("denied"));
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_host_and_duplicate_state_are_rejected_before_a_valid_callback_succeeds() {
    let transport = FakeTransport::new(FakeResult::Reply(token_reply(Provider::GoogleDrive)));
    let (task, opening) = start(
        client("google_drive"),
        Arc::clone(&transport),
        Limits::default(),
    );
    let url = opening.await.unwrap();
    let (redirect, state) = redirect_data(&url);
    for (host, query) in [
        (
            "evil.invalid".to_owned(),
            format!("code={CODE}&state={state}"),
        ),
        (
            format!("127.0.0.1:{}", redirect.port().unwrap()),
            format!("code={CODE}&state={state}&state={state}"),
        ),
    ] {
        let response = send_request(
            &redirect,
            request_line(
                &format!("{}?{query}", redirect.path()),
                &format!("Host: {host}"),
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }
    send_callback(&url, Some(CODE), None).await;
    assert!(task.await.unwrap().is_ok());
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sixteen_unexpected_callbacks_stop_the_flow_without_a_token_request() {
    let transport = FakeTransport::new(FakeResult::Error);
    let (task, opening) = start(
        client("google_drive"),
        Arc::clone(&transport),
        Limits::default(),
    );
    let url = opening.await.unwrap();
    let (redirect, state) = redirect_data(&url);
    for _ in 0..16 {
        let response = send_request(
            &redirect,
            request_line(
                &format!("/wrong-path?code={CODE}&state={state}"),
                &format!("Host: 127.0.0.1:{}", redirect.port().unwrap()),
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"));
    }
    assert!(error_message(task.await.unwrap()).contains("too many"));
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_opener_failure_is_redacted_and_releases_the_already_bound_listener() {
    let _owned_sockets = LOOPBACK_TEST_LOCK.lock().await;
    let transport = FakeTransport::new(FakeResult::Error);
    let opened = Arc::new(Mutex::new(None::<String>));
    let captured = Arc::clone(&opened);
    let open: Opener = Arc::new(move |url| {
        *captured.lock().unwrap() = Some(url.to_owned());
        bail!("{CODE} {CLIENT_SECRET}")
    });
    let result = authorize_with_transport(
        client("google_drive"),
        open,
        transport.as_ref(),
        Limits::default(),
    )
    .await;
    assert!(error_message(result).contains("browser could not be opened"));
    let (redirect, _) = redirect_data(opened.lock().unwrap().as_ref().unwrap());
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, redirect.port().unwrap()))
            .await
            .is_err()
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn box_and_unknown_kinds_fail_before_opener_or_http_without_weaker_fallback() {
    for kind in ["box", "https://evil.invalid/", "unknown"] {
        let opened = Arc::new(AtomicBool::new(false));
        let count = Arc::clone(&opened);
        let open: Opener = Arc::new(move |_| {
            count.store(true, Ordering::SeqCst);
            Ok(())
        });
        let error = error_message(authorize(client(kind), open).await);
        if kind == "box" {
            assert!(error.contains("confidential"));
        }
        assert!(!opened.load(Ordering::SeqCst));
    }
}

#[test]
fn box_requires_explicit_secret_and_does_not_claim_undocumented_public_pkce() {
    assert!(validate_request(&client("box")).is_err());
    let mut request = client("box");
    request.client_secret = Some(CLIENT_SECRET.into());
    let provider = validate_request(&request).unwrap();
    assert!(provider == Provider::Box);
    let secrets = FlowSecrets::new(provider).unwrap();
    let url = authorization_url(provider, &request, providers::REGISTERED_URI, &secrets).unwrap();
    assert!(url.starts_with("https://account.box.com/api/oauth2/authorize?"));
    let parsed = Url::parse(&url).unwrap();
    let params = parsed
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert!(params.contains_key("state"));
    assert!(!params.contains_key("code_challenge"));
    assert!(!params.contains_key("code_challenge_method"));
    assert!(!params.contains_key("client_secret"));
    let form = token_form(
        provider,
        &request,
        providers::REGISTERED_URI,
        VERIFIER,
        CODE,
    );
    let params = url::form_urlencoded::parse(form.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(params["client_secret"], CLIENT_SECRET);
    assert_eq!(params["code"], CODE);
    assert!(!params.contains_key("code_verifier"));
    assert_eq!(
        provider.token_endpoint(),
        "https://api.box.com/oauth2/token"
    );
}

#[tokio::test]
async fn box_never_silently_falls_back_from_normal_pkce_entrypoint() {
    let mut request = client("box");
    request.client_secret = Some(CLIENT_SECRET.into());
    let opened = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&opened);
    let error = error_message(
        authorize(
            request,
            Arc::new(move |_| {
                seen.store(true, Ordering::SeqCst);
                Ok(())
            }),
        )
        .await,
    );
    assert!(error.contains("authorize_box_confidential"));
    assert!(!opened.load(Ordering::SeqCst));
}

#[tokio::test]
async fn native_refresh_all_four_providers_uses_one_private_post_and_preserves_actual_rotation() {
    for kind in ["google_drive", "microsoft_onedrive", "dropbox", "box"] {
        let mut request = client(kind);
        if kind == "box" {
            request.client_secret = Some(CLIENT_SECRET.into());
        }
        let provider = validate_request(&request).unwrap();
        let transport = FakeTransport::new(FakeResult::Reply(token_reply(provider)));
        let tokens = refresh_with_transport(
            &request,
            "old-synthetic-refresh",
            transport.as_ref(),
            TOKEN_TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(tokens.refresh_token.as_deref(), Some(REFRESH));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        let form = transport.form.lock().unwrap();
        let params = url::form_urlencoded::parse(form.as_ref().unwrap().as_bytes())
            .into_owned()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(params["grant_type"], "refresh_token");
        assert_eq!(params["refresh_token"], "old-synthetic-refresh");
        assert!(!params.contains_key("code_verifier"));
        assert!(!params.contains_key("redirect_uri"));
        if kind == "box" {
            assert_eq!(params["client_secret"], CLIENT_SECRET);
        }
    }
}

#[tokio::test]
async fn refresh_omitted_refresh_token_preserves_old_and_errors_never_return_stale_success() {
    let request = client("google_drive");
    let reply = TokenReply {
        status: 200,
        body: Zeroizing::new(
            format!(r#"{{"access_token":"{ACCESS}","token_type":"Bearer","expires_in":3600}}"#)
                .into_bytes(),
        ),
    };
    let transport = FakeTransport::new(FakeResult::Reply(reply));
    let tokens = refresh_with_transport(&request, REFRESH, transport.as_ref(), TOKEN_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(tokens.refresh_token.as_deref(), Some(REFRESH));
    for result in [
        FakeResult::Error,
        FakeResult::Pending,
        FakeResult::Reply(TokenReply {
            status: 401,
            body: Zeroizing::new(format!(r#"{{"error":"{CLIENT_SECRET}"}}"#).into_bytes()),
        }),
    ] {
        let transport = FakeTransport::new(result);
        let result = refresh_with_transport(
            &request,
            REFRESH,
            transport.as_ref(),
            Duration::from_millis(1),
        )
        .await;
        assert!(error_message(result).contains("OAuth"));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn injected_transport_error_and_oversized_reply_are_redacted_without_retry() {
    for result in [
        FakeResult::Error,
        FakeResult::Reply(TokenReply {
            status: 200,
            body: Zeroizing::new(vec![b'x'; MAX_TOKEN_BODY + 1]),
        }),
    ] {
        let transport = FakeTransport::new(result);
        let (task, opening) = start(
            client("google_drive"),
            Arc::clone(&transport),
            Limits::default(),
        );
        let url = opening.await.unwrap();
        send_callback(&url, Some(CODE), None).await;
        assert!(error_message(task.await.unwrap()).contains("OAuth"));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn total_deadline_closes_an_unused_callback_listener_without_network_exchange() {
    let transport = FakeTransport::new(FakeResult::Error);
    let limits = Limits {
        total: Duration::from_millis(250),
        ..Limits::default()
    };
    let (task, opening) = start(client("google_drive"), Arc::clone(&transport), limits);
    let url = opening.await.unwrap();
    let (redirect, _) = redirect_data(&url);
    assert!(error_message(task.await.unwrap()).contains("timed out"));
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, redirect.port().unwrap()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_stalled_connection_uses_its_own_deadline_and_does_not_block_a_valid_callback() {
    let transport = FakeTransport::new(FakeResult::Reply(token_reply(Provider::GoogleDrive)));
    let limits = Limits {
        total: Duration::from_secs(5),
        connection: Duration::from_millis(40),
        token: TOKEN_TIMEOUT,
    };
    let (task, opening) = start(client("google_drive"), Arc::clone(&transport), limits);
    let url = opening.await.unwrap();
    let (redirect, _) = redirect_data(&url);
    let mut stalled = TcpStream::connect((Ipv4Addr::LOCALHOST, redirect.port().unwrap()))
        .await
        .unwrap();
    stalled.write_all(b"GET /partial").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    send_callback(&url, Some(CODE), None).await;
    assert!(task.await.unwrap().is_ok());
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn token_exchange_has_a_separate_deadline_and_no_retry() {
    let transport = FakeTransport::new(FakeResult::Pending);
    let limits = Limits {
        total: Duration::from_secs(5),
        token: Duration::from_millis(40),
        ..Limits::default()
    };
    let (task, opening) = start(client("google_drive"), Arc::clone(&transport), limits);
    let url = opening.await.unwrap();
    send_callback(&url, Some(CODE), None).await;
    assert!(error_message(task.await.unwrap()).contains("token exchange timed out"));
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropping_authorization_before_callback_closes_listener_and_never_requests_tokens() {
    let transport = FakeTransport::new(FakeResult::Error);
    let (task, opening) = start(
        client("google_drive"),
        Arc::clone(&transport),
        Limits::default(),
    );
    let url = opening.await.unwrap();
    let (redirect, _) = redirect_data(&url);
    task.abort();
    assert!(task
        .await
        .err()
        .expect("authorization task should be cancelled")
        .is_cancelled());
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, redirect.port().unwrap()))
            .await
            .is_err()
    );
}
