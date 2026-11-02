use crate::collect::Summary;
use crate::machines;
use crate::report::Status;
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
    let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&scope=openid%20email&client_id={}\
         &redirect_uri={}&state={state}&code_challenge={challenge}&code_challenge_method=S256&prompt=select_account",
        url_encode(&web.login.client_id),
        url_encode(&redirect_uri(&web.login)),
    );
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
    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        aud: String,
        exp: i64,
        email: String,
        #[serde(default)]
        email_verified: bool,
    }
    let tokens: Tokens = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let claims = tokens.id_token.split('.').nth(1).ok_or("ID token without claims")?;
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
    let mut columns: Vec<String> = Vec::new();
    let mut rows = Vec::new();
    // one machine at a time: only its latest report is kept
    for machine in &machines {
        let (reports, findings) = review::reviewed(&web.reports, machine, now);
        let latest = reports.into_iter().next();
        for check in latest.iter().flat_map(|latest| &latest.checks) {
            if !columns.contains(&check.name) {
                columns.push(check.name.clone());
            }
        }
        rows.push((machine, latest, findings));
    }

    let mut body = String::from("<h1>Workstations</h1>");
    let attention = rows.iter().filter(|(_, _, findings)| !findings.is_empty()).count();
    let _ = write!(
        body,
        "<p class=\"lead\">{} approved, {attention} needing attention, {} waiting for approval.</p>",
        machines.len(),
        pending.len()
    );
    body.push_str("<div class=\"scroll\"><table><thead><tr><th>Machine</th><th>Owner</th><th>Last report</th>");
    for column in &columns {
        let _ = write!(body, "<th class=\"check\"><span>{}</span></th>", escape(column));
    }
    body.push_str("</tr></thead><tbody>");
    for (machine, latest, findings) in &rows {
        let _ = write!(
            body,
            "<tr><td><a href=\"/machines/{name}\">{name}</a></td><td>{}</td><td class=\"time\">{}</td>",
            escape(&machine.owner),
            latest
                .as_ref()
                .map(|latest| ago(latest.taken_at, now))
                .unwrap_or_else(|| "never".to_string()),
            name = escape(&machine.name),
        );
        for column in &columns {
            let check = latest
                .iter()
                .flat_map(|latest| &latest.checks)
                .find(|check| &check.name == column);
            match check {
                Some(check) => {
                    let _ = write!(
                        body,
                        "<td class=\"check {}\" title=\"{}\">{}</td>",
                        status_class(check.status),
                        escape(&check.detail),
                        status_class(check.status)
                    );
                }
                None => body.push_str("<td class=\"check\"></td>"),
            }
        }
        body.push_str("</tr>");
        if !findings.is_empty() {
            let _ = write!(
                body,
                "<tr class=\"findings\"><td colspan=\"{}\"><ul>",
                columns.len() + 3
            );
            for finding in findings {
                let _ = write!(body, "<li>{}</li>", escape(finding));
            }
            body.push_str("</ul></td></tr>");
        }
    }
    body.push_str("</tbody></table></div>");

    body.push_str("<h2>Waiting for approval</h2>");
    if pending.is_empty() {
        body.push_str("<p>None.</p>");
    } else {
        body.push_str(
            "<p>Before approving, the hash must match what <code>optionfactory-posture id</code> prints on the \
             machine itself: anyone can send a report under any hostname.</p>\
             <div class=\"scroll\"><table><thead><tr><th>Hostname</th><th>Machine id</th><th>First seen</th>\
             <th>Last seen</th><th>Hash of the token</th></tr></thead><tbody>",
        );
        for (hash, machine, last_seen) in &pending {
            let _ = write!(
                body,
                "<tr><td>{}</td><td><code>{}</code></td><td class=\"time\">{}</td><td class=\"time\">{}</td>\
                 <td><code>{}</code></td></tr>",
                escape(&machine.hostname),
                escape(&machine.machine_id),
                machine.first_seen,
                last_seen,
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
            latest.taken_at,
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
                "<tr><td>{}</td><td class=\"check {}\">{}</td><td class=\"detail\">{}</td></tr>",
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
        body.push_str("<div class=\"scroll\"><table><thead><tr><th>Taken</th><th>Not passing</th></tr></thead><tbody>");
        for report in &reports {
            let _ = write!(
                body,
                "<tr><td class=\"time\">{}</td><td>{}</td></tr>",
                report.taken_at,
                not_passing(report.checks.iter().map(|check| (&check.name, check.status)))
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

fn not_passing<'a>(checks: impl Iterator<Item = (&'a String, Status)>) -> String {
    let failing: Vec<String> = checks
        .filter(|(_, status)| *status != Status::Pass)
        .map(|(name, status)| format!("<span class=\"{}\">{}</span>", status_class(status), escape(name)))
        .collect();
    if failing.is_empty() {
        "<span class=\"pass\">all pass</span>".to_string()
    } else {
        failing.join(", ")
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
         {account}</header><main>{body}</main></body></html>",
        escape(title)
    )
}

const STYLE: &str = "
:root { --bg: #f7f8fa; --fg: #1d2330; --muted: #5d6677; --line: #dde1e8; --surface: #ffffff;
  --pass: #1f7a4a; --pass-bg: #e3f4ea; --fail: #b4232c; --fail-bg: #fbe6e7; --unknown: #8a5a00; --unknown-bg: #fbf0d9;
  --link: #2b5fb8; color-scheme: light }
@media (prefers-color-scheme: dark) { :root { --bg: #14171d; --fg: #e4e7ee; --muted: #9aa3b4; --line: #2c323d;
  --surface: #1b1f27; --pass: #6fd39c; --pass-bg: #173326; --fail: #ff8f95; --fail-bg: #3d1c20; --unknown: #f2c26b;
  --unknown-bg: #3a2e14; --link: #8fb4ff; color-scheme: dark } }
body { margin: 0; background: var(--bg); color: var(--fg); font: 14px/1.5 system-ui, sans-serif }
header { display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--line); background: var(--surface) }
header > a { font-weight: 600; color: var(--fg); text-decoration: none }
header span { color: var(--muted) }
main { padding: 1rem; max-width: 80rem; margin: 0 auto }
a { color: var(--link) }
h1 { font-size: 1.5rem; margin: 0.5rem 0 0.25rem }
h2 { font-size: 1.1rem; margin: 2rem 0 0.5rem }
.lead, .back { color: var(--muted); margin-top: 0 }
.scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 6px; background: var(--surface) }
table { border-collapse: collapse; width: 100% }
th, td { padding: 0.35rem 0.6rem; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top }
th { font-weight: 600; font-size: 0.8rem; color: var(--muted); white-space: nowrap }
tbody tr:last-child td { border-bottom: 0 }
td.time { white-space: nowrap; font-variant-numeric: tabular-nums }
td.check { text-align: center; white-space: nowrap; font-size: 0.8rem }
td.detail { color: var(--muted); word-break: break-word }
td.pass, span.pass { color: var(--pass) } td.pass { background: var(--pass-bg) }
td.fail, span.fail { color: var(--fail); font-weight: 600 } td.fail { background: var(--fail-bg) }
td.unknown, span.unknown { color: var(--unknown); font-weight: 600 } td.unknown { background: var(--unknown-bg) }
tr.findings td { color: var(--fail); background: var(--surface) }
tr.findings ul, ul.attention { margin: 0; padding-left: 1.25rem }
ul.attention { color: var(--fail) }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem }
dt { color: var(--muted) } dd { margin: 0 }
code { font-size: 0.85em; word-break: break-all }
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
}
