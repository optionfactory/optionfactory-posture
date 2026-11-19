use super::{Web, url_encode};
use crate::collect::Summary;
use crate::machines::{self, Machine};
use crate::report::{Report, Status};
use crate::review;
use jiff::Timestamp;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt::Write;

/// What a machine is, from the SMBIOS chassis type of its latest report.
#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Laptop,
    Workstation,
    /// An agent from before the chassis type was reported, or a chassis that is neither (a virtual machine).
    Unknown,
}

impl Kind {
    const ALL: [Kind; 3] = [Kind::Laptop, Kind::Workstation, Kind::Unknown];

    fn of(latest: Option<&Report>) -> Kind {
        match latest.and_then(|latest| latest.chassis_type) {
            // portable, laptop, notebook, sub notebook, tablet, convertible, detachable
            Some(8 | 9 | 10 | 14 | 30 | 31 | 32) => Kind::Laptop,
            // desktop, low profile desktop, pizza box, mini tower, tower, all in one, space-saving, lunch box,
            // sealed-case PC, mini PC, stick PC
            Some(3..=7 | 13 | 15 | 16 | 24 | 35 | 36) => Kind::Workstation,
            _ => Kind::Unknown,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Kind::Laptop => "laptop",
            Kind::Workstation => "workstation",
            Kind::Unknown => "unknown",
        }
    }

    fn plural(self) -> &'static str {
        match self {
            Kind::Laptop => "Laptops",
            Kind::Workstation => "Workstations",
            Kind::Unknown => "Unknown type",
        }
    }
}

/// A machine of the list with its latest report and what the review finds about it.
struct Row<'a> {
    machine: &'a Machine,
    latest: Option<Report>,
    findings: Vec<String>,
    kind: Kind,
}

impl Row<'_> {
    fn passing(&self) -> bool {
        self.latest
            .as_ref()
            .is_some_and(|latest| latest.checks.iter().all(|check| check.status == Status::Pass))
    }
}

/// The machines needing attention first, then by name.
fn rows<'a>(web: &Web, machines: impl Iterator<Item = &'a Machine>, now: Timestamp) -> Vec<Row<'a>> {
    let mut rows: Vec<Row> = machines
        .map(|machine| {
            // one machine at a time: only its latest report is kept
            let (reports, findings) = review::reviewed(&web.reports, machine, now);
            let latest = reports.into_iter().next();
            Row {
                kind: Kind::of(latest.as_ref()),
                machine,
                latest,
                findings,
            }
        })
        .collect();
    rows.sort_by(|a, b| (a.findings.is_empty(), &a.machine.name).cmp(&(b.findings.is_empty(), &b.machine.name)));
    rows
}

struct Card<'a> {
    label: &'a str,
    value: usize,
    class: &'a str,
    href: Option<&'a str>,
}

fn metrics(body: &mut String, cards: &[Card]) {
    body.push_str("<div class=\"metrics\">");
    for card in cards {
        let (open, close) = match card.href {
            Some(href) => (format!("<a href=\"{href}\""), "</a>"),
            None => ("<div".to_string(), "</div>"),
        };
        let _ = write!(
            body,
            "{open} class=\"{}\"><span>{}</span><strong>{}</strong>{close}",
            card.class, card.label, card.value
        );
    }
    body.push_str("</div>");
}

/// Machines, needing attention, passing every check: the cards of every page about a set of machines.
fn machine_cards<'a>(rows: &[Row]) -> Vec<Card<'a>> {
    let attention = rows.iter().filter(|row| !row.findings.is_empty()).count();
    vec![
        Card {
            label: "Machines",
            value: rows.len(),
            class: "all",
            href: None,
        },
        Card {
            label: "Needing attention",
            value: attention,
            class: if attention > 0 { "fail" } else { "pass" },
            href: None,
        },
        Card {
            label: "Passing every check",
            value: rows.iter().filter(|row| row.passing()).count(),
            class: "pass",
            href: None,
        },
    ]
}

fn section(body: &mut String, id: &str, title: &str, intro: &str) {
    let _ = write!(
        body,
        "<section id=\"{id}\"><h2>{title}</h2><p class=\"intro\">{intro}</p>"
    );
}

fn machines_table(body: &mut String, rows: &[Row], now: Timestamp) {
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">None.</p>");
        return;
    }
    body.push_str(
        "<div class=\"table\"><table><thead><tr><th>Machine</th><th>Type</th><th>Last report</th><th>State</th></tr>\
         </thead><tbody>",
    );
    for row in rows {
        let _ = write!(
            body,
            "<tr class=\"{}\"><td><a href=\"/machines/{name}\">{name}</a><a class=\"owner\" href=\"/people/{}\">{}</a></td>\
             <td data-label=\"Type\"><a href=\"/types/{kind}\">{kind}</a></td>\
             <td class=\"time\" data-label=\"Last report\">{}</td><td data-label=\"State\">",
            if row.findings.is_empty() { "ok" } else { "attention" },
            url_encode(&row.machine.owner),
            escape(&row.machine.owner),
            row.latest
                .as_ref()
                .map(|latest| ago(latest.taken_at, now))
                .unwrap_or_else(|| "never".to_string()),
            name = escape(&row.machine.name),
            kind = row.kind.slug(),
        );
        if let Some(latest) = &row.latest {
            body.push_str(&not_passing(
                latest.checks.iter().map(|check| (&check.name, check.status)),
            ));
        }
        attention(body, &row.findings);
        body.push_str("</td></tr>");
    }
    body.push_str("</tbody></table></div>");
}

/// How many machines pass, fail or cannot run each check in their latest report, the most failed first.
fn checks_table(body: &mut String, rows: &[Row]) {
    let mut counts: BTreeMap<&str, [usize; 3]> = BTreeMap::new();
    for check in rows
        .iter()
        .filter_map(|row| row.latest.as_ref())
        .flat_map(|latest| &latest.checks)
    {
        let count = counts.entry(&check.name).or_default();
        count[match check.status {
            Status::Pass => 0,
            Status::Fail => 1,
            Status::Unknown => 2,
        }] += 1;
    }
    if counts.is_empty() {
        body.push_str("<p class=\"empty\">No reports.</p>");
        return;
    }
    let mut counts: Vec<_> = counts.into_iter().collect();
    counts.sort_by_key(|(_, [_, fail, unknown])| Reverse(fail + unknown));
    body.push_str(
        "<div class=\"table\"><table><thead><tr><th>Check</th><th class=\"number\">Pass</th>\
         <th class=\"number\">Fail</th><th class=\"number\">Unknown</th></tr></thead><tbody>",
    );
    for (name, [pass, fail, unknown]) in counts {
        let _ = write!(
            body,
            "<tr class=\"{}\"><td>{}</td><td class=\"number\" data-label=\"Pass\">{pass}</td>\
             <td class=\"number\" data-label=\"Fail\">{}</td><td class=\"number\" data-label=\"Unknown\">{}</td></tr>",
            if fail + unknown == 0 { "ok" } else { "attention" },
            escape(name),
            count_chip(fail, "fail"),
            count_chip(unknown, "unknown"),
        );
    }
    body.push_str("</tbody></table></div>");
}

fn count_chip(count: usize, class: &str) -> String {
    if count == 0 {
        "0".to_string()
    } else {
        format!("<span class=\"chip {class}\">{count}</span>")
    }
}

fn attention(body: &mut String, findings: &[String]) {
    if findings.is_empty() {
        return;
    }
    body.push_str("<ul class=\"attention\">");
    for finding in findings {
        let _ = write!(body, "<li>{}</li>", escape(finding));
    }
    body.push_str("</ul>");
}

const MACHINES_INTRO: &str = "The machines needing attention come first, with what the review reports about them: a \
    check failing longer than its grace, no report for a week, a report that cannot be read. The chips are the checks \
    not passing in the latest report.";

const CHECKS_INTRO: &str = "The outcome of each check in the latest report of these machines. <em>Unknown</em> is a \
    check that could not run, and counts as failing.";

pub(super) fn render_overview(web: &Web, email: &str) -> Result<Option<String>, String> {
    let machines = machines::read(&web.machines)?;
    let pending = machines::pending(&web.reports, &machines)?;
    let now = Timestamp::now();
    let rows = rows(web, machines.iter(), now);

    let mut body = String::new();
    let mut cards = machine_cards(&rows);
    cards.push(Card {
        label: "Waiting for approval",
        value: pending.len(),
        class: if pending.is_empty() { "pass" } else { "wait" },
        href: Some("#pending"),
    });
    metrics(&mut body, &cards);
    section(&mut body, "machines", "Machines", MACHINES_INTRO);
    machines_table(&mut body, &rows, now);
    body.push_str("</section>");
    section(&mut body, "checks", "Checks", CHECKS_INTRO);
    checks_table(&mut body, &rows);
    body.push_str("</section>");

    section(
        &mut body,
        "pending",
        "Waiting for approval",
        "Machines whose token is not on the list. Before approving, the hash must match what \
         <code>optionfactory-posture id</code> prints on the machine itself: anyone can send a report under any \
         hostname.",
    );
    if pending.is_empty() {
        body.push_str("<p class=\"empty\">None.</p>");
    } else {
        body.push_str(
            "<div class=\"table\"><table><thead><tr><th>Hostname</th><th>Machine id</th><th>First seen</th>\
             <th>Last seen</th><th>Hash of the token</th></tr></thead><tbody>",
        );
        for (hash, machine, last_seen) in &pending {
            let _ = write!(
                body,
                "<tr><td>{}</td><td data-label=\"Machine id\"><code>{}</code></td>\
                 <td class=\"time\" data-label=\"First seen\">{}</td><td class=\"time\" data-label=\"Last seen\">{}</td>\
                 <td data-label=\"Hash of the token\"><code>{}</code></td></tr>",
                escape(&machine.hostname),
                escape(&machine.machine_id),
                minutes(machine.first_seen),
                minutes(*last_seen),
                escape(hash)
            );
        }
        body.push_str("</tbody></table></div>");
    }
    body.push_str("</section>");
    Ok(Some(page(
        "Machines",
        "/",
        &[
            ("machines", "Machines"),
            ("checks", "Checks"),
            ("pending", "Waiting for approval"),
        ],
        email,
        &body,
    )))
}

pub(super) fn render_people(web: &Web, email: &str) -> Result<Option<String>, String> {
    let machines = machines::read(&web.machines)?;
    let now = Timestamp::now();
    let rows = rows(web, machines.iter(), now);
    let mut people: BTreeMap<&str, Vec<&Row>> = BTreeMap::new();
    for row in &rows {
        people.entry(&row.machine.owner).or_default().push(row);
    }
    let mut people: Vec<_> = people.into_iter().collect();
    // the ones with a machine needing attention first
    people.sort_by_key(|(_, rows)| rows.iter().all(|row| row.findings.is_empty()));

    let attention = people
        .iter()
        .filter(|(_, rows)| rows.iter().any(|row| !row.findings.is_empty()))
        .count();
    let mut body = String::new();
    metrics(
        &mut body,
        &[
            Card {
                label: "People",
                value: people.len(),
                class: "all",
                href: None,
            },
            Card {
                label: "With a machine needing attention",
                value: attention,
                class: if attention > 0 { "fail" } else { "pass" },
                href: None,
            },
        ],
    );
    section(
        &mut body,
        "people",
        "People",
        "The owners on the list of machines, each with their machines: those in red need attention. The people with \
         one of them come first.",
    );
    if people.is_empty() {
        body.push_str("<p class=\"empty\">None.</p>");
    } else {
        body.push_str(
            "<div class=\"table\"><table><thead><tr><th>Person</th><th>Machines</th>\
             <th class=\"number\">Needing attention</th><th>Last report</th></tr></thead><tbody>",
        );
        for (owner, theirs) in &people {
            let attention = theirs.iter().filter(|row| !row.findings.is_empty()).count();
            let _ = write!(
                body,
                "<tr class=\"{}\"><td><a href=\"/people/{}\">{}</a></td><td data-label=\"Machines\">",
                if attention == 0 { "ok" } else { "attention" },
                url_encode(owner),
                escape(owner),
            );
            for row in theirs {
                let _ = write!(
                    body,
                    "<a href=\"/machines/{name}\"{}>{name}</a> ",
                    if row.findings.is_empty() {
                        ""
                    } else {
                        " class=\"danger\""
                    },
                    name = escape(&row.machine.name),
                );
            }
            let latest = theirs
                .iter()
                .filter_map(|row| row.latest.as_ref().map(|latest| latest.taken_at))
                .max();
            let _ = write!(
                body,
                "</td><td class=\"number\" data-label=\"Needing attention\">{}</td>\
                 <td class=\"time\" data-label=\"Last report\">{}</td></tr>",
                count_chip(attention, "fail"),
                latest
                    .map(|latest| ago(latest, now))
                    .unwrap_or_else(|| "never".to_string()),
            );
        }
        body.push_str("</tbody></table></div>");
    }
    body.push_str("</section>");
    Ok(Some(page("People", "/people", &[], email, &body)))
}

pub(super) fn render_person(web: &Web, email: &str, owner: &str) -> Result<Option<String>, String> {
    let machines = machines::read(&web.machines)?;
    let now = Timestamp::now();
    let rows = rows(web, machines.iter().filter(|machine| machine.owner == owner), now);
    if rows.is_empty() {
        return Ok(None);
    }
    let mut body = String::new();
    metrics(&mut body, &machine_cards(&rows));
    section(&mut body, "machines", "Machines", MACHINES_INTRO);
    machines_table(&mut body, &rows, now);
    body.push_str("</section>");
    section(&mut body, "checks", "Checks", CHECKS_INTRO);
    checks_table(&mut body, &rows);
    body.push_str("</section>");
    Ok(Some(page(
        owner,
        "/people",
        &[("machines", "Machines"), ("checks", "Checks")],
        email,
        &body,
    )))
}

const KIND_INTRO: &str = "The type comes from the chassis type the firmware gives (SMBIOS), in the latest report. \
    <em>Unknown</em> is a machine that never reported, one whose agent does not send the chassis type yet, or a \
    chassis that is neither a laptop nor a desktop, such as a virtual machine.";

pub(super) fn render_types(web: &Web, email: &str) -> Result<Option<String>, String> {
    let machines = machines::read(&web.machines)?;
    let now = Timestamp::now();
    let rows = rows(web, machines.iter(), now);

    let mut body = String::new();
    let count = |kind: Kind| rows.iter().filter(|row| row.kind == kind).count();
    let cards: Vec<Card> = Kind::ALL
        .into_iter()
        .filter(|kind| *kind != Kind::Unknown || count(*kind) > 0)
        .map(|kind| Card {
            label: kind.plural(),
            value: count(kind),
            class: "all",
            href: None,
        })
        .collect();
    metrics(&mut body, &cards);
    section(&mut body, "types", "Types", KIND_INTRO);
    body.push_str(
        "<div class=\"table\"><table><thead><tr><th>Type</th><th class=\"number\">Machines</th>\
         <th class=\"number\">Needing attention</th><th class=\"number\">Passing every check</th>\
         <th class=\"number\">People</th></tr></thead><tbody>",
    );
    for kind in Kind::ALL {
        let of_kind: Vec<&Row> = rows.iter().filter(|row| row.kind == kind).collect();
        if kind == Kind::Unknown && of_kind.is_empty() {
            continue;
        }
        let attention = of_kind.iter().filter(|row| !row.findings.is_empty()).count();
        let mut people: Vec<&str> = of_kind.iter().map(|row| row.machine.owner.as_str()).collect();
        people.sort_unstable();
        people.dedup();
        let _ = write!(
            body,
            "<tr class=\"{}\"><td><a href=\"/types/{}\">{}</a></td><td class=\"number\" data-label=\"Machines\">{}</td>\
             <td class=\"number\" data-label=\"Needing attention\">{}</td>\
             <td class=\"number\" data-label=\"Passing every check\">{}</td>\
             <td class=\"number\" data-label=\"People\">{}</td></tr>",
            if attention == 0 { "ok" } else { "attention" },
            kind.slug(),
            kind.plural(),
            of_kind.len(),
            count_chip(attention, "fail"),
            of_kind.iter().filter(|row| row.passing()).count(),
            people.len(),
        );
    }
    body.push_str("</tbody></table></div></section>");
    Ok(Some(page("Types", "/types", &[], email, &body)))
}

pub(super) fn render_kind(web: &Web, email: &str, slug: &str) -> Result<Option<String>, String> {
    let Some(kind) = Kind::ALL.into_iter().find(|kind| kind.slug() == slug) else {
        return Ok(None);
    };
    let machines = machines::read(&web.machines)?;
    let now = Timestamp::now();
    let rows: Vec<Row> = rows(web, machines.iter(), now)
        .into_iter()
        .filter(|row| row.kind == kind)
        .collect();

    let mut people: Vec<&str> = rows.iter().map(|row| row.machine.owner.as_str()).collect();
    people.sort_unstable();
    people.dedup();
    let mut body = String::new();
    let mut cards = machine_cards(&rows);
    cards.push(Card {
        label: "People",
        value: people.len(),
        class: "all",
        href: None,
    });
    metrics(&mut body, &cards);
    section(
        &mut body,
        "machines",
        "Machines",
        &format!("{MACHINES_INTRO} {KIND_INTRO}"),
    );
    machines_table(&mut body, &rows, now);
    body.push_str("</section>");
    section(&mut body, "checks", "Checks", CHECKS_INTRO);
    checks_table(&mut body, &rows);
    body.push_str("</section>");
    Ok(Some(page(
        kind.plural(),
        "/types",
        &[("machines", "Machines"), ("checks", "Checks")],
        email,
        &body,
    )))
}

pub(super) fn render_machine(web: &Web, email: &str, name: &str) -> Result<Option<String>, String> {
    let machines = machines::read(&web.machines)?;
    let Some(machine) = machines.iter().find(|machine| machine.name == name) else {
        return Ok(None);
    };
    let now = Timestamp::now();
    let (reports, findings) = review::reviewed(&web.reports, machine, now);
    let kind = Kind::of(reports.first());

    let mut body = String::new();
    let _ = write!(
        body,
        "<p class=\"lead\"><a href=\"/people/{}\">{}</a> · <a href=\"/types/{kind}\">{kind}</a></p>",
        url_encode(&machine.owner),
        escape(&machine.owner),
        kind = kind.slug(),
    );
    if findings.is_empty() {
        body.push_str("<p class=\"verdict pass\">Nothing needs attention.</p>");
    } else {
        body.push_str("<div class=\"verdict fail\">Needs attention");
        attention(&mut body, &findings);
        body.push_str("</div>");
    }

    section(
        &mut body,
        "latest",
        "Latest report",
        "Every check of the latest report, with what the agent found.",
    );
    match reports.first() {
        None => body.push_str("<p class=\"empty\">No reports.</p>"),
        Some(latest) => {
            let chassis = latest
                .chassis_type
                .map(|chassis| format!(" (chassis type {chassis})"))
                .unwrap_or_default();
            let _ = write!(
                body,
                "<dl class=\"facts\"><div><dt>Taken</dt><dd>{} ({})</dd></div><div><dt>Hostname</dt><dd>{}</dd></div>\
                 <div><dt>System</dt><dd>{}</dd></div><div><dt>Kernel</dt><dd>{}</dd></div>\
                 <div><dt>Agent</dt><dd>{}</dd></div><div><dt>Type</dt><dd>{}{chassis}</dd></div></dl>",
                minutes(latest.taken_at),
                ago(latest.taken_at, now),
                escape(&latest.hostname),
                escape(&latest.os.pretty_name),
                escape(&latest.kernel),
                escape(&latest.agent),
                kind.slug(),
            );
            body.push_str(
                "<div class=\"table\"><table><thead><tr><th>Check</th><th>Outcome</th><th>Detail</th></tr></thead>\
                 <tbody>",
            );
            for check in &latest.checks {
                let _ = write!(
                    body,
                    "<tr class=\"{}\"><td>{}</td><td data-label=\"Outcome\"><span class=\"chip {status}\">{status}</span>\
                     </td><td class=\"detail\" data-label=\"Detail\">{}</td></tr>",
                    if check.status == Status::Pass {
                        "ok"
                    } else {
                        "attention"
                    },
                    escape(&check.name),
                    escape(&check.detail),
                    status = status_class(check.status),
                );
            }
            body.push_str("</tbody></table></div>");
        }
    }
    body.push_str("</section>");

    section(
        &mut body,
        "hardware",
        "Hardware",
        "What the latest report says the machine is made of, as the firmware, the kernel and the drivers describe it.",
    );
    match reports.first() {
        None => body.push_str("<p class=\"empty\">No reports.</p>"),
        Some(latest) if latest.hardware.cpu.is_empty() => {
            body.push_str("<p class=\"empty\">The agent of the latest report does not send the hardware.</p>")
        }
        Some(latest) => hardware(&mut body, latest),
    }
    body.push_str("</section>");

    section(
        &mut body,
        "listening",
        "Listening ports",
        "The TCP ports open to the network on the machine itself in the latest report, without those on loopback: the \
         firewall decides who reaches them. <code>0.0.0.0</code> and <code>::</code> are every address of the machine.",
    );
    match reports.first().map(|latest| &latest.listening) {
        None => body.push_str("<p class=\"empty\">No reports.</p>"),
        Some(None) => body.push_str(
            "<p class=\"empty\">Not in the latest report: an agent older than them, or one that could not read \
                 <code>/proc/net/tcp</code>.</p>",
        ),
        Some(Some(listening)) if listening.is_empty() => body.push_str("<p class=\"empty\">None.</p>"),
        Some(Some(listening)) => {
            body.push_str("<p>");
            for socket in listening {
                let _ = write!(
                    body,
                    "<span class=\"chip\">{}</span>",
                    std::net::SocketAddr::new(socket.address, socket.port)
                );
            }
            body.push_str("</p>");
        }
    }
    body.push_str("</section>");

    section(
        &mut body,
        "history",
        "Last thirty days",
        "Consecutive reports with the same checks not passing make one row, newest first.",
    );
    if reports.is_empty() {
        body.push_str("<p class=\"empty\">No reports.</p>");
    } else {
        body.push_str(
            "<div class=\"table\"><table><thead><tr><th>From</th><th>To</th><th class=\"number\">Reports</th>\
             <th>Not passing</th></tr></thead><tbody>",
        );
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
                "<tr><td class=\"time\">{}</td><td class=\"time\" data-label=\"To\">{}</td>\
                 <td class=\"number\" data-label=\"Reports\">{count}</td><td data-label=\"Not passing\">{state}</td></tr>",
                minutes(*oldest),
                minutes(*newest)
            );
        }
        body.push_str("</tbody></table></div>");
    }
    body.push_str("</section>");

    let mut summaries: Vec<Summary> = std::fs::read_dir(web.reports.join(&machine.name).join("daily"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        .filter_map(|entry| serde_json::from_slice(&std::fs::read(entry.path()).ok()?).ok())
        .collect();
    summaries.sort_by_key(|summary| Reverse(summary.date));
    section(
        &mut body,
        "daily",
        "Daily summaries",
        "Older than thirty days: the worst outcome of each check in the day.",
    );
    if summaries.is_empty() {
        body.push_str("<p class=\"empty\">None yet.</p>");
    } else {
        body.push_str("<div class=\"table\"><table><thead><tr><th>Day</th><th>Not passing</th></tr></thead><tbody>");
        for summary in &summaries {
            let _ = write!(
                body,
                "<tr><td class=\"time\">{}</td><td data-label=\"Not passing\">{}</td></tr>",
                summary.date,
                not_passing(summary.checks.iter().map(|(name, status)| (name, *status)))
            );
        }
        body.push_str("</tbody></table></div>");
    }
    body.push_str("</section>");
    Ok(Some(page(
        &machine.name,
        "/",
        &[
            ("latest", "Latest report"),
            ("hardware", "Hardware"),
            ("listening", "Listening ports"),
            ("history", "Last thirty days"),
            ("daily", "Daily summaries"),
        ],
        email,
        &body,
    )))
}

fn hardware(body: &mut String, latest: &Report) {
    let hardware = &latest.hardware;
    let gib = |kib: u64| format!("{:.1} GiB", kib as f64 / (1024.0 * 1024.0));
    let model = [hardware.product.as_str(), hardware.product_version.as_str()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let bios = [hardware.bios_version.as_str(), hardware.bios_date.as_str()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    let cpu = format!("{}, {} threads", hardware.cpu, hardware.cpu_threads);
    body.push_str("<dl class=\"facts\">");
    for (label, value) in [
        ("Manufacturer", hardware.vendor.as_str()),
        ("Model", &model),
        ("Board", &hardware.board),
        ("BIOS", &bios),
        ("CPU", &cpu),
        ("Microcode", &hardware.microcode),
        ("Memory", &gib(hardware.memory_kib)),
    ] {
        if !value.is_empty() {
            let _ = write!(body, "<div><dt>{label}</dt><dd>{}</dd></div>", escape(value));
        }
    }
    body.push_str("</dl>");

    body.push_str("<h3>Graphics</h3>");
    if hardware.gpus.is_empty() {
        body.push_str("<p class=\"empty\">None.</p>");
    } else {
        body.push_str(
            "<div class=\"table\"><table><thead><tr><th>Model</th><th>Driver</th><th class=\"number\">Memory</th></tr>\
             </thead><tbody>",
        );
        for gpu in &hardware.gpus {
            let _ = write!(
                body,
                "<tr><td>{}</td><td data-label=\"Driver\">{}</td><td class=\"number\" data-label=\"Memory\">{}</td></tr>",
                escape(&gpu.name),
                escape(&gpu.driver),
                gpu.memory_mib
                    .map(|mib| gib(mib * 1024))
                    .unwrap_or_else(|| "shared or not told".to_string()),
            );
        }
        body.push_str("</tbody></table></div>");
    }

    body.push_str("<h3>Network cards</h3>");
    if hardware.nics.is_empty() {
        body.push_str("<p class=\"empty\">None.</p>");
    } else {
        body.push_str(
            "<div class=\"table\"><table><thead><tr><th>Interface</th><th>Model</th><th>Driver</th><th>MAC address</th>\
             <th>Link</th></tr></thead><tbody>",
        );
        for nic in &hardware.nics {
            let _ = write!(
                body,
                "<tr><td>{}</td><td data-label=\"Model\">{}</td><td data-label=\"Driver\">{}</td>\
                 <td data-label=\"MAC address\">{}</td><td data-label=\"Link\">{}</td></tr>",
                escape(&nic.interface),
                escape(&nic.name),
                escape(&nic.driver),
                escape(&nic.mac),
                if nic.wireless { "wireless" } else { "wired" },
            );
        }
        body.push_str("</tbody></table></div>");
    }

    let mut flaws: Vec<(&String, &String)> = hardware
        .cpu_vulnerabilities
        .iter()
        .filter(|(_, state)| state.as_str() != "Not affected")
        .collect();
    flaws.sort_by_key(|(_, state)| !state.starts_with("Vulnerable"));
    let _ = write!(
        body,
        "<h3>CPU flaws</h3><p class=\"empty\">{} of the {} flaws the kernel knows do not affect this CPU.</p>",
        hardware.cpu_vulnerabilities.len() - flaws.len(),
        hardware.cpu_vulnerabilities.len(),
    );
    if !flaws.is_empty() {
        body.push_str(
            "<div class=\"table\"><table><thead><tr><th>Flaw</th><th>State</th><th>Detail</th></tr></thead><tbody>",
        );
        for (name, state) in flaws {
            let vulnerable = state.starts_with("Vulnerable");
            let _ = write!(
                body,
                "<tr class=\"{}\"><td>{}</td><td data-label=\"State\"><span class=\"chip {}\">{}</span></td>\
                 <td class=\"detail\" data-label=\"Detail\">{}</td></tr>",
                if vulnerable { "attention" } else { "ok" },
                escape(name),
                if vulnerable { "fail" } else { "pass" },
                if vulnerable { "vulnerable" } else { "mitigated" },
                escape(state),
            );
        }
        body.push_str("</tbody></table></div>");
    }
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

pub(crate) fn escape(text: &str) -> String {
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

/// The page around a body: the views in the header for a signed-in admin, and links to the sections of the page.
pub(super) fn page(title: &str, view: &str, sections: &[(&str, &str)], email: &str, body: &str) -> String {
    let title = escape(title);
    let mut html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{title} · Posture</title>\
         <link rel=\"icon\" href=\"/favicon.ico\"><link rel=\"stylesheet\" href=\"/posture.css\"></head><body><header>\
         <h1><a href=\"/\"><img src=\"/favicon.ico\" alt=\"\">Posture</a><span class=\"page\">/ {title}</span></h1>"
    );
    if !email.is_empty() {
        html.push_str("<nav class=\"views\">");
        for (href, label) in [("/", "Machines"), ("/people", "People"), ("/types", "Types")] {
            let active = if href == view {
                " class=\"active\" aria-current=\"page\""
            } else {
                ""
            };
            let _ = write!(html, "<a href=\"{href}\"{active}>{label}</a>");
        }
        let _ = write!(
            html,
            "</nav><a class=\"sign-out\" href=\"/logout\" title=\"Sign out {}\" aria-label=\"Sign out\">\
             <svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4\"/>\
             <path d=\"m16 17 5-5-5-5M21 12H9\"/></svg></a>",
            escape(email)
        );
    }
    if !sections.is_empty() {
        html.push_str("<nav class=\"sections\">");
        for (id, label) in sections {
            let _ = write!(html, "<a href=\"#{id}\">{label}</a>");
        }
        html.push_str("</nav>");
    }
    let _ = write!(
        html,
        "</header><main>{body}<p class=\"note\">Times are UTC.</p></main></body></html>"
    );
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Check;
    use std::path::Path;

    fn web(dir: &Path, machines: &str) -> Web {
        std::fs::create_dir_all(dir.join("reports")).unwrap();
        std::fs::write(dir.join("machines"), machines).unwrap();
        Web {
            reports: dir.join("reports"),
            machines: dir.join("machines"),
            login: super::super::Login {
                client_id: String::new(),
                client_secret: String::new(),
                public_url: String::new(),
                admins: dir.join("admins"),
                domain: None,
            },
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test"),
        }
    }

    fn write_report(web: &Web, machine: &str, chassis_type: Option<u8>, firewall: Status) {
        let taken_at = Timestamp::now().round(jiff::Unit::Second).unwrap();
        let report = Report {
            agent: "posture test".to_string(),
            taken_at,
            hostname: machine.to_string(),
            machine_id: String::new(),
            os: Default::default(),
            kernel: String::new(),
            chassis_type,
            hardware: Default::default(),
            listening: None,
            checks: vec![Check::new("firewall", firewall, "inactive")],
        };
        let dir = web.reports.join(machine);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("{}.json", taken_at.strftime("%Y%m%dT%H%M%SZ"))),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn a_pending_hostname_is_text_not_markup() {
        let dir = std::env::temp_dir().join(format!("optionfactory-posture-web-pending-{}", std::process::id()));
        let web = web(&dir, "");
        machines::record_pending(&web.reports, &"0".repeat(64), "<script>alert(1)</script>", "id").unwrap();

        let page = render_overview(&web, "mario.rossi@optionfactory.net").unwrap().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!page.contains("<script>"));
    }

    #[test]
    fn a_person_sees_their_machines_and_a_type_its_machines() {
        let dir = std::env::temp_dir().join(format!("optionfactory-posture-web-views-{}", std::process::id()));
        let hash = "0".repeat(64);
        let web = web(
            &dir,
            &format!(
                "kup mario.rossi@optionfactory.net {hash}\nbox mario.rossi@optionfactory.net {hash}\n\
                 lap luigi.verdi@optionfactory.net {hash}\n"
            ),
        );
        write_report(&web, "kup", Some(10), Status::Pass);
        write_report(&web, "box", Some(3), Status::Fail);
        write_report(&web, "lap", Some(9), Status::Pass);
        let machines_on = |page: Option<String>| {
            let page = page.unwrap();
            ["kup", "box", "lap"]
                .into_iter()
                .filter(|name| page.contains(&format!("href=\"/machines/{name}\"")))
                .collect::<Vec<_>>()
        };

        let mario = render_person(&web, "", "mario.rossi@optionfactory.net").unwrap();
        let laptops = render_kind(&web, "", "laptop").unwrap();
        let workstations = render_kind(&web, "", "workstation").unwrap();
        let nobody = render_person(&web, "", "nobody@optionfactory.net").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(machines_on(mario), ["kup", "box"]);
        assert_eq!(machines_on(laptops), ["kup", "lap"]);
        assert_eq!(machines_on(workstations), ["box"]);
        assert!(nobody.is_none());
    }
}
