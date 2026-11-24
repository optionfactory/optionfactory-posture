use crate::collect::Settings;
use crate::machines;
use crate::review::Review;
use jiff::Timestamp;
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::extension::ClientId;
use lettre::{Message, SmtpTransport, Transport};
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

/// The `[mail]` section of the settings: an SMTP relay with STARTTLS and no credentials, such as the one of Google
/// Workspace, which accepts the address of the server instead.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mail {
    pub relay: String,
    #[serde(default = "Mail::port")]
    pub port: u16,
    pub from: String,
    /// Where the review goes; each owner gets the reminder of their own machines.
    pub admins: String,
}

impl Mail {
    fn port() -> u16 {
        587
    }
}

/// The review to the admins, then to each owner the reminder of their own machines; nothing when nothing needs
/// attention. When the review cannot be made, the admins get the error instead.
pub fn send(config: &Path) -> Result<(), String> {
    let settings = Settings::read(config)?;
    let mail = settings
        .mail
        .as_ref()
        .ok_or_else(|| format!("{}: no [mail] section", config.display()))?;
    let from: Mailbox = format!("OptionFactory Posture <{}>", mail.from)
        .parse()
        .map_err(|e| format!("from {}: {e}", mail.from))?;
    let domain = mail.from.rsplit_once('@').map(|(_, domain)| domain).unwrap_or_default();
    let relay = SmtpTransport::starttls_relay(&mail.relay)
        .map_err(|e| format!("{}: {e}", mail.relay))?
        .port(mail.port)
        // the relay refuses a name outside the domain
        .hello_name(ClientId::Domain(domain.to_string()))
        .timeout(Some(Duration::from_secs(30)))
        .build();
    let deliver = |to: &str, subject: String, text: String, html: Option<String>| {
        let to: Mailbox = to.parse().map_err(|e| format!("{to}: {e}"))?;
        let message = Message::builder().from(from.clone()).to(to.clone()).subject(subject);
        let message = match html {
            Some(html) => message.multipart(MultiPart::alternative_plain_html(text, html)),
            None => message.header(ContentType::TEXT_PLAIN).body(text),
        };
        message
            .map_err(|e| format!("mail to {to}: {e}"))
            .and_then(|message| relay.send(&message).map_err(|e| format!("mail to {to}: {e}")))
            .map(|_| ())
    };
    let pages_url = settings.login.as_ref().map(|login| login.public_url.as_str());
    let with_link = |text: String, review: &Review| match pages_url {
        Some(url) => format!("{text}\n{}\n", review.link(url)),
        None => text,
    };

    let machines = match machines::read(&settings.machines) {
        Ok(machines) => machines,
        Err(e) => return Err(tell_admins(&deliver, mail, e)),
    };
    let review = match Review::read(&settings.reports, &machines, Timestamp::now()) {
        Ok(review) => review,
        Err(e) => return Err(tell_admins(&deliver, mail, e)),
    };
    if review.is_empty() {
        return Ok(());
    }
    deliver(
        &mail.admins,
        format!("Posture: {} to look at", review.count()),
        with_link(review.text(), &review),
        Some(review.html(pages_url)),
    )?;
    let mut unsent = Vec::new();
    for owner in review.owners() {
        let reminder = review.of_owner(&owner);
        if reminder.is_empty() {
            continue;
        }
        let sent = deliver(
            &owner,
            format!("Posture: {} to look at on your machines", reminder.count()),
            with_link(reminder.text(), &reminder),
            Some(reminder.html(pages_url)),
        );
        if let Err(e) = sent {
            eprintln!("optionfactory-posture: {e}");
            unsent.push(owner);
        }
    }
    match unsent.is_empty() {
        true => Ok(()),
        false => Err(format!("reminders not sent to {}", unsent.join(", "))),
    }
}

/// Mails the error of a review that could not be made, and returns it for the log.
fn tell_admins(
    deliver: &impl Fn(&str, String, String, Option<String>) -> Result<(), String>,
    mail: &Mail,
    error: String,
) -> String {
    let text = format!("The posture review could not be made:\n\n{error}\n");
    match deliver(&mail.admins, "Posture: the review failed".to_string(), text, None) {
        Ok(()) => error,
        Err(e) => format!("{error}; {e}"),
    }
}
