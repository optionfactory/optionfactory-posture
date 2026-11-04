use crate::collect::Summary;
use crate::machines;
use crate::report::{Report, Status};
use crate::review;
use axum::Router;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{AppendHeaders, Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{SignedDuration, Timestamp};
use serde::Deserialize;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const SESSION: SignedDuration = SignedDuration::from_hours(12);
const SESSION_COOKIE: &str = "posture_session";
const LOGIN_COOKIE: &str = "posture_login";

/// The Google OAuth client the pages sign in with, and who may read them.
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

struct Web {
    reports: PathBuf,
    machines: PathBuf,
    login: Login,
    /// Signs the session cookies; new at every start, which signs everyone out.
    key: ring::hmac::Key,
}

/// The pages of the reports, read-only, for the admins on the list.
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
        .route("/login", get(sign_in))
        .route("/oidc/callback", get(callback))
        .route("/logout", get(sign_out))
        .with_state(web))
}

async fn overview(State(web): State<Arc<Web>>, headers: HeaderMap) -> Response {
    signed_in_page(web, headers, render_overview).await
}

async fn machine(State(web): State<Arc<Web>>, headers: HeaderMap, UrlPath(name): UrlPath<String>) -> Response {
    signed_in_page(web, headers, move |web, email| render_machine(web, email, &name)).await
}

async fn signed_in_page(
    web: Arc<Web>,
    headers: HeaderMap,
    render: impl FnOnce(&Web, &str) -> Result<Option<String>, String> + Send + 'static,
) -> Response {
    let session = cookie(&headers, SESSION_COOKIE).map(str::to_string);
    let rendered = tokio::task::spawn_blocking(move || {
        let Some(email) = session.and_then(|session| signed_in(&web, &session)) else {
            return Ok(None);
        };
        render(&web, &email).map(|page| Some(page.ok_or(())))
    })
    .await;
    match rendered {
        Ok(Ok(Some(Ok(page)))) => html(StatusCode::OK, page),
        Ok(Ok(Some(Err(())))) => message(StatusCode::NOT_FOUND, "Not on the list of machines."),
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

/// The email of a valid session cookie, while it is still on the list of admins.
fn signed_in(web: &Web, session: &str) -> Option<String> {
    let (payload, tag) = session.split_once('.')?;
    ring::hmac::verify(&web.key, payload.as_bytes(), &URL_SAFE_NO_PAD.decode(tag).ok()?).ok()?;
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    let (email, expiry) = payload.split_once(' ')?;
    let valid = expiry.parse::<i64>().ok()? > Timestamp::now().as_second();
    (valid && is_admin(&web.login.admins, email)).then(|| email.to_string())
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

async fn callback(State(web): State<Arc<Web>>, headers: HeaderMap, Query(query): Query<Callback>) -> Response {
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
            Ok::<_, String>((is_admin(&web.login.admins, &email), email))
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|signed| signed)
    };
    let email = match signed {
        Ok((true, email)) => email,
        Ok((false, email)) => {
            eprintln!("optionfactory-posture: {email} signed in but is not on the list of admins");
            return message(StatusCode::FORBIDDEN, &format!("{email} may not read the reports."));
        }
        Err(e) => {
            eprintln!("optionfactory-posture: login: {e}");
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

fn render_overview(web: &Web, email: &str) -> Result<Option<String>, String> {
    let machines = machines::read(&web.machines)?;
    let pending = machines::pending(&web.reports, &machines)?;
    let now = Timestamp::now();
    let mut rows = Vec::new();
    // one machine at a time: only its latest report is kept
    for machine in &machines {
        let (reports, findings) = review::reviewed(&web.reports, machine, now);
        rows.push((machine, reports.into_iter().next(), findings));
    }
    // the ones needing attention first
    rows.sort_by_key(|(machine, _, findings)| (findings.is_empty(), machine.name.clone()));

    let attention = rows.iter().filter(|(_, _, findings)| !findings.is_empty()).count();
    let mut body = String::from("<h1>Workstations</h1><p class=\"counts\">");
    let _ = write!(
        body,
        "<span>{} approved</span><span class=\"{}\">{attention} needing attention</span><span>{} waiting for \
         approval</span></p>",
        machines.len(),
        if attention > 0 { "fail" } else { "pass" },
        pending.len()
    );
    body.push_str(
        "<div class=\"scroll\"><table class=\"machines stack\"><thead><tr><th>Machine</th><th>Last report</th>\
         <th>State</th></tr></thead><tbody>",
    );
    for (machine, latest, findings) in &rows {
        let _ = write!(
            body,
            "<tr><td><a href=\"/machines/{name}\">{name}</a><div class=\"owner\">{}</div></td><td class=\"time\">{}</td><td>",
            escape(&machine.owner),
            latest
                .as_ref()
                .map(|latest| ago(latest.taken_at, now))
                .unwrap_or_else(|| "never".to_string()),
            name = escape(&machine.name),
        );
        if let Some(latest) = latest {
            body.push_str(&not_passing(
                latest.checks.iter().map(|check| (&check.name, check.status)),
            ));
        }
        if !findings.is_empty() {
            body.push_str("<ul class=\"attention\">");
            for finding in findings {
                let _ = write!(body, "<li>{}</li>", escape(finding));
            }
            body.push_str("</ul>");
        }
        body.push_str("</td></tr>");
    }
    body.push_str("</tbody></table></div>");

    body.push_str("<h2>Waiting for approval</h2>");
    if pending.is_empty() {
        body.push_str("<p>None.</p>");
    } else {
        body.push_str(
            "<p>Before approving, the hash must match what <code>optionfactory-posture id</code> prints on the \
             machine itself: anyone can send a report under any hostname.</p>\
             <div class=\"scroll\"><table class=\"stack\"><thead><tr><th>Hostname</th><th>Machine id</th><th>First seen</th>\
             <th>Last seen</th><th>Hash of the token</th></tr></thead><tbody>",
        );
        for (hash, machine, last_seen) in &pending {
            let _ = write!(
                body,
                "<tr><td>{}</td><td><code>{}</code></td><td class=\"time\">{}</td><td class=\"time\">{}</td>\
                 <td><code>{}</code></td></tr>",
                escape(&machine.hostname),
                escape(&machine.machine_id),
                minutes(machine.first_seen),
                minutes(*last_seen),
                escape(hash)
            );
        }
        body.push_str("</tbody></table></div>");
    }
    Ok(Some(page("Workstations", email, &body)))
}

fn render_machine(web: &Web, email: &str, name: &str) -> Result<Option<String>, String> {
    let machines = machines::read(&web.machines)?;
    let Some(machine) = machines.iter().find(|machine| machine.name == name) else {
        return Ok(None);
    };
    let now = Timestamp::now();
    let (reports, findings) = review::reviewed(&web.reports, machine, now);

    let mut body = String::new();
    let _ = write!(
        body,
        "<p class=\"back\"><a href=\"/\">All workstations</a></p><h1>{}</h1><p class=\"lead\">{}</p>",
        escape(&machine.name),
        escape(&machine.owner)
    );
    if findings.is_empty() {
        body.push_str("<p>Nothing needs attention.</p>");
    } else {
        body.push_str("<ul class=\"attention\">");
        for finding in &findings {
            let _ = write!(body, "<li>{}</li>", escape(finding));
        }
        body.push_str("</ul>");
    }

    if let Some(latest) = reports.first() {
        let _ = write!(
            body,
            "<h2>Latest report</h2><dl><dt>Taken</dt><dd>{} ({})</dd><dt>Hostname</dt><dd>{}</dd><dt>System</dt>\
             <dd>{}</dd><dt>Kernel</dt><dd>{}</dd><dt>Agent</dt><dd>{}</dd></dl>",
            minutes(latest.taken_at),
            ago(latest.taken_at, now),
            escape(&latest.hostname),
            escape(&latest.os.pretty_name),
            escape(&latest.kernel),
            escape(&latest.agent)
        );
        body.push_str(
            "<div class=\"scroll\"><table><thead><tr><th>Check</th><th>Outcome</th><th>Detail</th></tr></thead><tbody>",
        );
        for check in &latest.checks {
            let _ = write!(
                body,
                "<tr><td>{}</td><td><span class=\"chip {}\">{}</span></td><td class=\"detail\">{}</td></tr>",
                escape(&check.name),
                status_class(check.status),
                status_class(check.status),
                escape(&check.detail)
            );
        }
        body.push_str("</tbody></table></div>");
    }

    body.push_str("<h2>Last thirty days</h2>");
    if reports.is_empty() {
        body.push_str("<p>No reports.</p>");
    } else {
        body.push_str(
            "<div class=\"scroll\"><table><thead><tr><th>From</th><th>To</th><th>Reports</th><th>State</th></tr>\
             </thead><tbody>",
        );
        // consecutive reports with the same outcomes make one row
        let state = |report: &Report| not_passing(report.checks.iter().map(|check| (&check.name, check.status)));
        let mut runs: Vec<(Timestamp, Timestamp, usize, String)> = Vec::new();
        for report in &reports {
            let current = state(report);
            match runs.last_mut() {
                Some((oldest, _, count, last)) if *last == current => {
                    *oldest = report.taken_at;
                    *count += 1;
                }
                _ => runs.push((report.taken_at, report.taken_at, 1, current)),
            }
        }
        for (oldest, newest, count, state) in &runs {
            let _ = write!(
                body,
                "<tr><td class=\"time\">{}</td><td class=\"time\">{}</td><td class=\"number\">{count}</td><td>{state}</td></tr>",
                minutes(*oldest),
                minutes(*newest)
            );
        }
        body.push_str("</tbody></table></div>");
    }

    let mut summaries: Vec<Summary> = std::fs::read_dir(web.reports.join(&machine.name).join("daily"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        .filter_map(|entry| serde_json::from_slice(&std::fs::read(entry.path()).ok()?).ok())
        .collect();
    summaries.sort_by_key(|summary| std::cmp::Reverse(summary.date));
    body.push_str("<h2>Daily summaries</h2><p>Older than thirty days: the worst outcome of each check in the day.</p>");
    if summaries.is_empty() {
        body.push_str("<p>None yet.</p>");
    } else {
        body.push_str("<div class=\"scroll\"><table><thead><tr><th>Day</th><th>Not passing</th></tr></thead><tbody>");
        for summary in &summaries {
            let _ = write!(
                body,
                "<tr><td class=\"time\">{}</td><td>{}</td></tr>",
                summary.date,
                not_passing(summary.checks.iter().map(|(name, status)| (name, *status)))
            );
        }
        body.push_str("</tbody></table></div>");
    }
    Ok(Some(page(&machine.name, email, &body)))
}

/// A time to the minute, in UTC.
fn minutes(at: Timestamp) -> String {
    at.strftime("%Y-%m-%d %H:%M").to_string()
}

fn not_passing<'a>(checks: impl Iterator<Item = (&'a String, Status)>) -> String {
    let failing: Vec<String> = checks
        .filter(|(_, status)| *status != Status::Pass)
        .map(|(name, status)| format!("<span class=\"chip {}\">{}</span>", status_class(status), escape(name)))
        .collect();
    if failing.is_empty() {
        "<span class=\"chip pass\">all pass</span>".to_string()
    } else {
        failing.join(" ")
    }
}

fn status_class(status: Status) -> &'static str {
    match status {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Unknown => "unknown",
    }
}

fn ago(then: Timestamp, now: Timestamp) -> String {
    let minutes = now.duration_since(then).as_secs() / 60;
    match minutes {
        ..1 => "just now".to_string(),
        1..60 => format!("{minutes} min ago"),
        60..2880 => format!("{} h ago", minutes / 60),
        _ => format!("{} days ago", minutes / 1440),
    }
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            c => escaped.push(c),
        }
    }
    escaped
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
                "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'",
            ),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(page),
    )
        .into_response()
}

fn message(status: StatusCode, text: &str) -> Response {
    let body = format!("<p>{}</p><p><a href=\"/login\">Sign in</a></p>", escape(text));
    html(status, page("Posture", "", &body))
}

fn page(title: &str, email: &str, body: &str) -> String {
    let account = if email.is_empty() {
        String::new()
    } else {
        format!("<span>{} · <a href=\"/logout\">sign out</a></span>", escape(email))
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{} · Posture</title>\
         <link rel=\"icon\" href=\"/favicon.ico\"><style>{STYLE}</style></head><body><header><a href=\"/\">Posture</a>\
         {account}</header><main>{body}<p class=\"lead\">Times are UTC.</p></main></body></html>",
        escape(title)
    )
}

const STYLE: &str = "
:root { --bg: #f6f7f9; --fg: #1c2230; --muted: #5f6878; --line: #e1e4ea; --surface: #ffffff; --head: #f0f2f5;
  --pass: #1d7348; --pass-bg: #e2f3e9; --fail: #a8222b; --fail-bg: #fbe5e6; --unknown: #855600; --unknown-bg: #faefd6;
  --link: #2758ad; color-scheme: light }
@media (prefers-color-scheme: dark) { :root { --bg: #13161c; --fg: #e3e6ed; --muted: #98a1b2; --line: #2a303a;
  --surface: #1a1e26; --head: #20252e; --pass: #72d39f; --pass-bg: #16301f; --fail: #ff9097; --fail-bg: #3b1b1f;
  --unknown: #f0c46e; --unknown-bg: #382c13; --link: #91b5ff; color-scheme: dark } }
* { box-sizing: border-box }
body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, -apple-system, 'Segoe UI', sans-serif }
header { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; flex-wrap: wrap;
  padding: 0.8rem max(1rem, calc((100% - 64rem) / 2)); border-bottom: 1px solid var(--line); background: var(--surface) }
header > a { font-weight: 650; color: var(--fg); text-decoration: none; letter-spacing: 0.01em }
header span { color: var(--muted); font-size: 0.9rem }
main { padding: 1.5rem 1rem 3rem; max-width: 66rem; margin: 0 auto }
a { color: var(--link); text-decoration: none } a:hover { text-decoration: underline }
h1 { font-size: 1.6rem; margin: 0 0 0.5rem; text-wrap: balance }
h2 { font-size: 1.1rem; margin: 2.25rem 0 0.6rem }
p { max-width: 65ch }
.lead, .back { color: var(--muted); margin-top: 0 }
.counts { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0 0 1.25rem }
.counts span { padding: 0.2rem 0.65rem; border-radius: 999px; background: var(--surface); border: 1px solid var(--line);
  font-size: 0.85rem; color: var(--muted) }
.counts span.fail { color: var(--fail); background: var(--fail-bg); border-color: transparent }
.counts span.pass { color: var(--pass); background: var(--pass-bg); border-color: transparent }
.scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; background: var(--surface) }
table { border-collapse: collapse; width: 100% }
th, td { padding: 0.55rem 0.8rem; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top }
th { font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted);
  background: var(--head); white-space: nowrap }
tbody tr:last-child td { border-bottom: 0 }
table.machines td:first-child { width: 16rem } table.machines td:nth-child(2) { width: 9rem }
td.time { white-space: nowrap; font-variant-numeric: tabular-nums; color: var(--muted) }
td.number { text-align: right; font-variant-numeric: tabular-nums }
td.detail { color: var(--muted); word-break: break-word; font-size: 0.9rem }
.owner { color: var(--muted); font-size: 0.85rem }
.chip { display: inline-block; margin: 0 0.25rem 0.25rem 0; padding: 0.05rem 0.5rem; border-radius: 4px;
  font-size: 0.8rem; font-weight: 550; white-space: nowrap }
.pass { color: var(--pass) } .chip.pass { background: var(--pass-bg) }
.fail { color: var(--fail) } .chip.fail { background: var(--fail-bg) }
.unknown { color: var(--unknown) } .chip.unknown { background: var(--unknown-bg) }
ul.attention { margin: 0.35rem 0 0; padding-left: 1.1rem; color: var(--fail); font-size: 0.9rem }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1.25rem; margin: 0 0 1rem }
dt { color: var(--muted) } dd { margin: 0; min-width: 0; overflow-wrap: anywhere }
code { font-size: 0.85em; word-break: break-all }
@media (max-width: 40rem) {
  table.stack thead { display: none }
  table.stack tr { display: block; padding: 0.6rem 0; border-bottom: 1px solid var(--line) }
  table.stack tbody tr:last-child { border-bottom: 0 }
  table.stack td { display: block; width: auto !important; border: 0; padding: 0.15rem 0.8rem }
}
";

#[cfg(test)]
mod tests {
    use super::*;

    fn web(dir: &Path) -> Web {
        std::fs::create_dir_all(dir.join("reports")).unwrap();
        std::fs::write(dir.join("admins"), "# domain-admins\nmario.rossi@optionfactory.net\n").unwrap();
        std::fs::write(dir.join("machines"), "").unwrap();
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
    fn a_session_counts_only_signed_unexpired_and_for_an_admin() {
        let dir = std::env::temp_dir().join(format!("optionfactory-posture-web-{}", std::process::id()));
        let web = web(&dir);
        let later = Timestamp::now() + SESSION;
        let admin = session(&web.key, "mario.rossi@optionfactory.net", later);
        let (payload, _) = admin.split_once('.').unwrap();
        let forged = format!("{payload}.{}", URL_SAFE_NO_PAD.encode([0u8; 32]));
        let expired = session(&web.key, "mario.rossi@optionfactory.net", Timestamp::now() - SESSION);
        let other = session(&web.key, "luigi.verdi@optionfactory.net", later);

        let valid = [&admin, &forged, &expired, &other].map(|cookie| signed_in(&web, cookie));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            valid,
            [Some("mario.rossi@optionfactory.net".to_string()), None, None, None]
        );
    }

    #[test]
    fn a_pending_hostname_is_text_not_markup() {
        let dir = std::env::temp_dir().join(format!("optionfactory-posture-web-pending-{}", std::process::id()));
        let web = web(&dir);
        machines::record_pending(&web.reports, &"0".repeat(64), "<script>alert(1)</script>", "id").unwrap();

        let page = render_overview(&web, "mario.rossi@optionfactory.net").unwrap().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!page.contains("<script>"));
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
