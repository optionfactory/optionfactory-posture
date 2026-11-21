pub(crate) mod pages;

use crate::collect::Client;
use crate::machines;
use axum::Router;
use axum::extract::{Extension, Path as UrlPath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{AppendHeaders, Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{SignedDuration, Timestamp};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const SESSION: SignedDuration = SignedDuration::from_hours(12);
const SESSION_COOKIE: &str = "posture_session";
const LOGIN_COOKIE: &str = "posture_login";
const STYLE: &str = include_str!("web/posture.css");
const ADMINS_ONLY: &str = "Only the admins see this page.";

/// The Google OAuth client the pages sign in with, and who may read them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub client_id: String,
    pub client_secret: String,
    /// `https://<host>`, where Google sends the browser back after the login.
    pub public_url: String,
    /// One email per line, read again at every request: taking someone off revokes their session.
    pub admins: PathBuf,
    /// Google Workspace domain: Google offers only its accounts (`hd`), and only its ID tokens are accepted.
    pub domain: Option<String>,
}

/// Who is signed in: an admin reads every page, an owner of machines on the list only the pages of those machines.
pub(crate) struct Viewer {
    pub email: String,
    pub admin: bool,
}

struct Web {
    reports: PathBuf,
    machines: PathBuf,
    login: Login,
    /// Signs the session cookies; new at every start, which signs everyone out.
    key: ring::hmac::Key,
}

/// The pages of the reports, read-only: all of them for the admins on the list, those of their own machines for the
/// owners.
pub fn pages(reports: PathBuf, machines: PathBuf, login: Login) -> Result<Router, String> {
    let rng = ring::rand::SystemRandom::new();
    let key = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).map_err(|_| "no randomness".to_string())?;
    let web = Arc::new(Web {
        reports,
        machines,
        login,
        key,
    });
    Ok(Router::new()
        .route("/", get(overview))
        .route("/machines/{name}", get(machine))
        .route("/people", get(people))
        .route("/people/{owner}", get(person))
        .route("/types", get(kinds))
        .route("/types/{kind}", get(kind))
        .route(
            "/posture.css",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/css; charset=utf-8"),
                        (header::CACHE_CONTROL, "max-age=3600"),
                    ],
                    STYLE,
                )
            }),
        )
        .route("/login", get(sign_in))
        .route("/oidc/callback", get(callback))
        .route("/logout", get(sign_out))
        .with_state(web))
}

async fn overview(State(web): State<Arc<Web>>, headers: HeaderMap) -> Response {
    signed_in_page(web, headers, "", pages::render_overview).await
}

async fn machine(State(web): State<Arc<Web>>, headers: HeaderMap, UrlPath(name): UrlPath<String>) -> Response {
    signed_in_page(web, headers, "Not on the list of machines.", move |web, viewer| {
        pages::render_machine(web, viewer, &name)
    })
    .await
}

async fn people(State(web): State<Arc<Web>>, headers: HeaderMap) -> Response {
    signed_in_page(web, headers, ADMINS_ONLY, pages::render_people).await
}

async fn person(State(web): State<Arc<Web>>, headers: HeaderMap, UrlPath(owner): UrlPath<String>) -> Response {
    signed_in_page(web, headers, "Owns no machine on the list.", move |web, viewer| {
        pages::render_person(web, viewer, &owner)
    })
    .await
}

async fn kinds(State(web): State<Arc<Web>>, headers: HeaderMap) -> Response {
    signed_in_page(web, headers, ADMINS_ONLY, pages::render_types).await
}

async fn kind(State(web): State<Arc<Web>>, headers: HeaderMap, UrlPath(kind): UrlPath<String>) -> Response {
    signed_in_page(web, headers, "No such type of machine.", move |web, viewer| {
        pages::render_kind(web, viewer, &kind)
    })
    .await
}

/// `missing` is the message when the page has nothing to show, for a name not on the list.
async fn signed_in_page(
    web: Arc<Web>,
    headers: HeaderMap,
    missing: &'static str,
    render: impl FnOnce(&Web, &Viewer) -> Result<Option<String>, String> + Send + 'static,
) -> Response {
    let session = cookie(&headers, SESSION_COOKIE).map(str::to_string);
    let rendered = tokio::task::spawn_blocking(move || {
        let Some(viewer) = session.and_then(|session| signed_in(&web, &session)) else {
            return Ok(None);
        };
        render(&web, &viewer).map(|page| Some(page.ok_or(())))
    })
    .await;
    match rendered {
        Ok(Ok(Some(Ok(page)))) => html(StatusCode::OK, page),
        Ok(Ok(Some(Err(())))) => message(StatusCode::NOT_FOUND, missing),
        Ok(Ok(None)) => Redirect::to("/login").into_response(),
        Ok(Err(e)) => {
            eprintln!("optionfactory-posture: {e}");
            message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The reports cannot be read: see the log of the collector.",
            )
        }
        Err(e) => {
            eprintln!("optionfactory-posture: {e}");
            message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong: see the log of the collector.",
            )
        }
    }
}

/// The email and the expiry, signed with the key of this run.
fn session(key: &ring::hmac::Key, email: &str, expiry: Timestamp) -> String {
    let payload = URL_SAFE_NO_PAD.encode(format!("{email} {}", expiry.as_second()));
    let tag = URL_SAFE_NO_PAD.encode(ring::hmac::sign(key, payload.as_bytes()));
    format!("{payload}.{tag}")
}

/// Who a valid session cookie is for, while they are still an admin or own a machine on the list.
fn signed_in(web: &Web, session: &str) -> Option<Viewer> {
    let (payload, tag) = session.split_once('.')?;
    ring::hmac::verify(&web.key, payload.as_bytes(), &URL_SAFE_NO_PAD.decode(tag).ok()?).ok()?;
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    let (email, expiry) = payload.split_once(' ')?;
    let valid = expiry.parse::<i64>().ok()? > Timestamp::now().as_second();
    valid.then(|| viewer(web, email))?
}

/// Read again at every request: who is taken off the admins, or whose last machine leaves the list, is signed out.
fn viewer(web: &Web, email: &str) -> Option<Viewer> {
    let admin = is_admin(&web.login.admins, email);
    let owner = || match machines::read(&web.machines) {
        Ok(machines) => machines.iter().any(|machine| machine.owner.eq_ignore_ascii_case(email)),
        Err(e) => {
            eprintln!("optionfactory-posture: {e}");
            false
        }
    };
    (admin || owner()).then(|| Viewer {
        email: email.to_string(),
        admin,
    })
}

fn is_admin(admins: &Path, email: &str) -> bool {
    match std::fs::read_to_string(admins) {
        Ok(text) => text
            .lines()
            .map(str::trim)
            .any(|line| !line.starts_with('#') && !line.is_empty() && line.eq_ignore_ascii_case(email)),
        Err(e) => {
            eprintln!("optionfactory-posture: {}: {e}", admins.display());
            false
        }
    }
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(name)?.strip_prefix('='))
}

fn redirect_uri(login: &Login) -> String {
    format!("{}/oidc/callback", login.public_url.trim_end_matches('/'))
}

/// Google's authorization code flow with PKCE; the state and the verifier wait in a short cookie.
async fn sign_in(State(web): State<Arc<Web>>) -> Response {
    let rng = ring::rand::SystemRandom::new();
    let random = |len: usize| {
        let mut bytes = vec![0u8; len];
        ring::rand::SecureRandom::fill(&rng, &mut bytes).map(|()| URL_SAFE_NO_PAD.encode(bytes))
    };
    let (Ok(state), Ok(verifier)) = (random(16), random(32)) else {
        return message(StatusCode::INTERNAL_SERVER_ERROR, "No randomness for the login.");
    };
    let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()));
    let mut url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&scope=openid%20email&client_id={}\
         &redirect_uri={}&state={state}&code_challenge={challenge}&code_challenge_method=S256&prompt=select_account",
        url_encode(&web.login.client_id),
        url_encode(&redirect_uri(&web.login)),
    );
    if let Some(domain) = &web.login.domain {
        url.push_str(&format!("&hd={}", url_encode(domain)));
    }
    (
        AppendHeaders([(
            header::SET_COOKIE,
            format!("{LOGIN_COOKIE}={state}.{verifier}; Path=/oidc; Max-Age=600; HttpOnly; Secure; SameSite=Lax"),
        )]),
        Redirect::to(&url),
    )
        .into_response()
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
}

async fn callback(
    State(web): State<Arc<Web>>,
    Extension(Client(client)): Extension<Client>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    let Some((state, verifier)) = cookie(&headers, LOGIN_COOKIE).and_then(|value| value.split_once('.')) else {
        return message(StatusCode::BAD_REQUEST, "The login took too long: sign in again.");
    };
    let (Some(code), true) = (query.code, query.state.as_deref() == Some(state)) else {
        return message(
            StatusCode::BAD_REQUEST,
            "The login was refused or did not start here: sign in again.",
        );
    };
    let verifier = verifier.to_string();
    let signed = {
        let web = web.clone();
        tokio::task::spawn_blocking(move || {
            let email = google_email(&web.login, &code, &verifier)?;
            Ok::<_, String>((viewer(&web, &email).is_some(), email))
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|signed| signed)
    };
    let email = match signed {
        Ok((true, email)) => email,
        Ok((false, email)) => {
            eprintln!("optionfactory-posture: {email} signed in from {client} but is no admin and owns no machine");
            return message(
                StatusCode::FORBIDDEN,
                &format!("{email} is not an admin and owns no machine on the list."),
            );
        }
        Err(e) => {
            eprintln!("optionfactory-posture: login from {client}: {e}");
            return message(
                StatusCode::BAD_GATEWAY,
                "Google did not confirm the login: sign in again.",
            );
        }
    };
    (
        AppendHeaders([
            (
                header::SET_COOKIE,
                format!(
                    "{SESSION_COOKIE}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
                    session(&web.key, &email, Timestamp::now() + SESSION),
                    SESSION.as_secs()
                ),
            ),
            (
                header::SET_COOKIE,
                format!("{LOGIN_COOKIE}=; Path=/oidc; Max-Age=0; HttpOnly; Secure; SameSite=Lax"),
            ),
        ]),
        Redirect::to("/"),
    )
        .into_response()
}

/// Exchanges the code for the ID token and returns its verified email. The token comes straight from Google over TLS,
/// so its signature need not be checked (OpenID Connect Core 1.0, 3.1.3.7); its claims still are.
fn google_email(login: &Login, code: &str, verifier: &str) -> Result<String, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .into();
    let redirect_uri = redirect_uri(login);
    let body = agent
        .post("https://oauth2.googleapis.com/token")
        .send_form([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &login.client_id),
            ("client_secret", &login.client_secret),
            ("redirect_uri", &redirect_uri),
            ("code_verifier", verifier),
        ])
        .and_then(|mut response| response.body_mut().read_to_string())
        .map_err(|e| e.to_string())?;
    #[derive(Deserialize)]
    struct Tokens {
        id_token: String,
    }
    let tokens: Tokens = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    id_token_email(login, &tokens.id_token)
}

/// The verified email of an ID token whose issuer, audience, expiry and domain are the expected ones.
fn id_token_email(login: &Login, id_token: &str) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        aud: String,
        exp: i64,
        email: String,
        #[serde(default)]
        email_verified: bool,
        hd: Option<String>,
    }
    let claims = id_token.split('.').nth(1).ok_or("ID token without claims")?;
    let claims = URL_SAFE_NO_PAD.decode(claims).map_err(|e| e.to_string())?;
    let claims: Claims = serde_json::from_slice(&claims).map_err(|e| e.to_string())?;
    if !matches!(
        claims.iss.as_str(),
        "https://accounts.google.com" | "accounts.google.com"
    ) {
        return Err(format!("ID token from {}", claims.iss));
    }
    if claims.aud != login.client_id {
        return Err(format!("ID token for {}", claims.aud));
    }
    if claims.exp <= Timestamp::now().as_second() {
        return Err("expired ID token".to_string());
    }
    if !claims.email_verified {
        return Err(format!("{} is not verified", claims.email));
    }
    if let Some(domain) = &login.domain
        && claims.hd.as_ref() != Some(domain)
    {
        return Err(format!("{} is not an account of {domain}", claims.email));
    }
    Ok(claims.email.to_ascii_lowercase())
}

async fn sign_out() -> Response {
    (
        AppendHeaders([(
            header::SET_COOKIE,
            format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"),
        )]),
        message(StatusCode::OK, "Signed out."),
    )
        .into_response()
}

fn url_encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (byte as char).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn html(status: StatusCode, page: String) -> Response {
    (
        status,
        [
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'",
            ),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(page),
    )
        .into_response()
}

fn message(status: StatusCode, text: &str) -> Response {
    let body = format!(
        "<div class=\"message\"><p>{}</p><p><a href=\"/login\">Sign in</a></p></div>",
        pages::escape(text)
    );
    html(status, pages::page("Sign in", "", &[], None, &body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn web(dir: &Path) -> Web {
        std::fs::create_dir_all(dir.join("reports")).unwrap();
        std::fs::write(dir.join("admins"), "# domain-admins\nmario.rossi@optionfactory.net\n").unwrap();
        std::fs::write(
            dir.join("machines"),
            format!("kup luigi.verdi@optionfactory.net {}\n", "0".repeat(64)),
        )
        .unwrap();
        Web {
            reports: dir.join("reports"),
            machines: dir.join("machines"),
            login: Login {
                client_id: String::new(),
                client_secret: String::new(),
                public_url: String::new(),
                admins: dir.join("admins"),
                domain: None,
            },
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test"),
        }
    }

    #[test]
    fn a_session_counts_only_signed_unexpired_and_for_an_admin_or_an_owner() {
        let dir = std::env::temp_dir().join(format!("optionfactory-posture-web-{}", std::process::id()));
        let web = web(&dir);
        let later = Timestamp::now() + SESSION;
        let admin = session(&web.key, "mario.rossi@optionfactory.net", later);
        let (payload, _) = admin.split_once('.').unwrap();
        let forged = format!("{payload}.{}", URL_SAFE_NO_PAD.encode([0u8; 32]));
        let expired = session(&web.key, "mario.rossi@optionfactory.net", Timestamp::now() - SESSION);
        let owner = session(&web.key, "luigi.verdi@optionfactory.net", later);
        let other = session(&web.key, "anna.bianchi@optionfactory.net", later);

        let valid = [&admin, &forged, &expired, &owner, &other]
            .map(|cookie| signed_in(&web, cookie).map(|viewer| (viewer.email, viewer.admin)));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            valid,
            [
                Some(("mario.rossi@optionfactory.net".to_string(), true)),
                None,
                None,
                Some(("luigi.verdi@optionfactory.net".to_string(), false)),
                None
            ]
        );
    }

    #[test]
    fn only_id_tokens_of_the_domain_sign_in() {
        let login = Login {
            client_id: "client".to_string(),
            client_secret: String::new(),
            public_url: String::new(),
            admins: PathBuf::new(),
            domain: Some("optionfactory.net".to_string()),
        };
        let id_token = |email: &str, hd: Option<&str>| {
            let claims = serde_json::json!({
                "iss": "https://accounts.google.com",
                "aud": "client",
                "exp": Timestamp::now().as_second() + 60,
                "email": email,
                "email_verified": true,
                "hd": hd,
            });
            format!("header.{}.signature", URL_SAFE_NO_PAD.encode(claims.to_string()))
        };

        let emails = [
            id_token("Mario.Rossi@optionfactory.net", Some("optionfactory.net")),
            id_token("mario.rossi@gmail.com", None),
            id_token("mario.rossi@guests.opfa.net", Some("guests.opfa.net")),
        ]
        .map(|token| id_token_email(&login, &token).ok());
        assert_eq!(emails, [Some("mario.rossi@optionfactory.net".to_string()), None, None]);
    }
}
