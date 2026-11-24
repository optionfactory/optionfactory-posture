use super::{Viewer, Web, url_encode};
use crate::checks;
use crate::collect::Summary;
use crate::machines::{self, Machine};
use crate::report::{Report, Status};
use crate::review::{self, Finding};
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
    findings: Vec<Finding>,
    within_grace: Vec<Finding>,
    kind: Kind,
}

impl Row<'_> {
    fn passing(&self) -> bool {
        self.latest
            .as_ref()
            .is_some_and(|latest| latest.checks.iter().all(|check| check.status == Status::Pass))
    }

    /// The finding about a check not passing, and whether it is past its grace.
    fn not_passing(&self, check: &str) -> Option<(&Finding, bool)> {
        not_passing(&self.findings, &self.within_grace, check)
    }
}

fn not_passing<'f>(findings: &'f [Finding], within_grace: &'f [Finding], check: &str) -> Option<(&'f Finding, bool)> {
    let about = |finding: &&Finding| matches!(finding, Finding::Check { name, .. } if name == check);
    findings
        .iter()
        .find(about)
        .map(|finding| (finding, true))
        .or_else(|| within_grace.iter().find(about).map(|finding| (finding, false)))
}

/// The machines needing attention first, then by name.
fn rows<'a>(web: &Web, machines: impl Iterator<Item = &'a Machine>, now: Timestamp) -> Vec<Row<'a>> {
    let mut rows: Vec<Row> = machines
        .map(|machine| {
            let review::Reviewed {
                reports,
                findings,
                within_grace,
            } = review::reviewed(&web.reports, machine, now);
            // one machine at a time: only its latest report is kept
            let latest = reports.into_iter().next();
            Row {
                kind: Kind::of(latest.as_ref()),
                machine,
                latest,
                findings,
                within_grace,
            }
        })
        .collect();
    rows.sort_by(|a, b| (a.findings.is_empty(), &a.machine.name).cmp(&(b.findings.is_empty(), &b.machine.name)));
    rows
}

/// The machines a summary card leads to: all of them, or `?show=attention`, `?show=passing`.
fn shown<'r, 'a>(rows: &'r [Row<'a>], show: Option<&str>) -> (Vec<&'r Row<'a>>, Option<&'static str>) {
    match show {
        Some("attention") => (
            rows.iter().filter(|row| !row.findings.is_empty()).collect(),
            Some("needing attention"),
        ),
        Some("passing") => (
            rows.iter().filter(|row| row.passing()).collect(),
            Some("passing every check"),
        ),
        _ => (rows.iter().collect(), None),
    }
}

struct Card<'a> {
    label: &'a str,
    value: usize,
    class: &'a str,
    href: Option<String>,
}

fn metrics(body: &mut String, cards: &[Card]) {
    body.push_str("<div class=\"metrics\">");
    for card in cards {
        let (open, close) = match &card.href {
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

/// Machines, needing attention, passing every check: the cards of every page about a set of machines, each leading to
/// the list at `base` showing those machines.
fn machine_cards<'a>(rows: &[Row], base: &str) -> Vec<Card<'a>> {
    let attention = rows.iter().filter(|row| !row.findings.is_empty()).count();
    vec![
        Card {
            label: "Machines",
            value: rows.len(),
            class: "all",
            href: Some(format!("{base}#machines")),
        },
        Card {
            label: "Needing attention",
            value: attention,
            class: if attention > 0 { "fail" } else { "pass" },
            href: Some(format!("{base}?show=attention#machines")),
        },
        Card {
            label: "Passing every check",
            value: rows.iter().filter(|row| row.passing()).count(),
            class: "pass",
            href: Some(format!("{base}?show=passing#machines")),
        },
    ]
}

fn section(body: &mut String, id: &str, title: &str, intro: &str) {
    let _ = write!(
        body,
        "<section id=\"{id}\"><h2>{title}</h2><p class=\"intro\">{intro}</p>"
    );
}

/// The machines of a page, narrowed to those of a summary card when it says so.
fn machines_section(body: &mut String, rows: &[Row], show: Option<&str>, base: &str, now: Timestamp, admin: bool) {
    section(body, "machines", "Machines", MACHINES_INTRO);
    let (shown, filter) = shown(rows, show);
    if let Some(filter) = filter {
        let _ = write!(
            body,
            "<p class=\"filter\">The {} machines {filter}, of {}. <a href=\"{base}#machines\">Show them all</a></p>",
            shown.len(),
            rows.len()
        );
    }
    machines_table(body, &shown, now, admin);
    body.push_str("</section>");
}

/// The types, the checks and the people are pages for the admins: an owner gets their names without links.
fn machines_table(body: &mut String, rows: &[&Row], now: Timestamp, admin: bool) {
    if rows.is_empty() {
        body.push_str("<p class=\"empty\">None.</p>");
        return;
    }
    body.push_str(
        "<div class=\"table\"><table><thead><tr><th>Machine</th><th>Type</th><th>Last report</th><th>State</th></tr>\
         </thead><tbody>",
    );
    for row in rows {
        let kind = match admin {
            true => format!("<a href=\"/types/{kind}\">{kind}</a>", kind = row.kind.slug()),
            false => row.kind.slug().to_string(),
        };
        let _ = write!(
            body,
            "<tr class=\"{}\"><td><a href=\"/machines/{name}\">{name}</a><a class=\"owner\" href=\"/people/{}\">{}</a></td>\
             <td data-label=\"Type\">{kind}</td><td class=\"time\" data-label=\"Last report\">{}</td>\
             <td data-label=\"State\">{}</td></tr>",
            if row.findings.is_empty() { "ok" } else { "attention" },
            url_encode(&row.machine.owner),
            escape(&row.machine.owner),
            row.latest
                .as_ref()
                .map(|latest| when(latest.taken_at, now))
                .unwrap_or_else(|| "never".to_string()),
            state(row, now, admin),
            name = escape(&row.machine.name),
        );
    }
    body.push_str("</tbody></table></div>");
}

/// One line per finding, then the checks still within their grace; `all pass` when there is nothing.
fn state(row: &Row, now: Timestamp, admin: bool) -> String {
    if row.findings.is_empty() && row.within_grace.is_empty() {
        return match row.latest {
            Some(_) => "<span class=\"chip pass\">all pass</span>".to_string(),
            None => String::new(),
        };
    }
    let mut html = String::from("<ul class=\"findings\">");
    for finding in &row.findings {
        let _ = write!(html, "<li>{}</li>", finding_html(finding, now, admin, true));
    }
    for finding in &row.within_grace {
        let _ = write!(html, "<li>{}</li>", finding_html(finding, now, admin, false));
    }
    html.push_str("</ul>");
    html
}

/// A finding as a chip, how long it has lasted and its detail. A check `due` is past its grace.
fn finding_html(finding: &Finding, now: Timestamp, admin: bool, due: bool) -> String {
    let lasting = |since: Timestamp| {
        format!(
            "<span class=\"since\" title=\"since {} UTC\">for {}</span>",
            minutes(since),
            for_how_long(since, now)
        )
    };
    match finding {
        Finding::Check {
            name,
            status,
            since,
            detail,
        } => {
            let (class, state) = match (due, status) {
                (false, _) => ("grace", " <span class=\"since\">within grace</span>"),
                (true, Status::Unknown) => ("unknown", " <span class=\"since\">could not run</span>"),
                (true, _) => ("fail", ""),
            };
            format!(
                "{} {}{state} <span class=\"detail\">{}</span>",
                check_chip(name, class, admin),
                lasting(*since),
                escape(detail)
            )
        }
        Finding::Silent { since } => format!("<span class=\"chip fail\">no report</span> {}", lasting(*since)),
        Finding::Never => "<span class=\"chip fail\">never reported</span>".to_string(),
        Finding::Future { at } => format!(
            "<span class=\"chip fail\">clock ahead</span> <span class=\"detail\">a report stamped {} UTC</span>",
            minutes(*at)
        ),
        Finding::Unreadable { path, error } => format!(
            "<span class=\"chip fail\">unreadable report</span> <span class=\"detail\">{}: {}</span>",
            escape(&path.display().to_string()),
            escape(error)
        ),
    }
}

/// A finding as a single chip, where a line would not fit.
fn finding_chip(finding: &Finding, admin: bool) -> String {
    match finding {
        Finding::Check {
            name,
            status: Status::Unknown,
            ..
        } => check_chip(name, "unknown", admin),
        Finding::Check { name, .. } => check_chip(name, "fail", admin),
        Finding::Silent { .. } => "<span class=\"chip fail\">no report</span>".to_string(),
        Finding::Never => "<span class=\"chip fail\">never reported</span>".to_string(),
        Finding::Future { .. } => "<span class=\"chip fail\">clock ahead</span>".to_string(),
        Finding::Unreadable { .. } => "<span class=\"chip fail\">unreadable report</span>".to_string(),
    }
}

/// A check name, the reports say which: escaped, and linked to its page for the admins.
fn check_chip(name: &str, class: &str, link: bool) -> String {
    match link {
        true => format!(
            "<a class=\"chip {class}\" href=\"/checks/{}\">{}</a>",
            url_encode(name),
            escape(name)
        ),
        false => format!("<span class=\"chip {class}\">{}</span>", escape(name)),
    }
}

fn remedy_html(remedy: Option<&str>) -> String {
    remedy
        .map(|remedy| format!("<div class=\"remedy\">To do: {}</div>", escape(remedy)))
        .unwrap_or_default()
}

fn machine_pill(row: &Row, class: &str) -> String {
    format!(
        "<a class=\"{class}\" href=\"/machines/{name}\">{name}</a>",
        name = escape(&row.machine.name)
    )
}

/// A check across machines: those whose latest report has it, by outcome.
struct CheckRows<'r> {
    name: &'r str,
    pass: Vec<&'r Row<'r>>,
    fail: Vec<&'r Row<'r>>,
    unknown: Vec<&'r Row<'r>>,
}

/// The most failed first.
fn by_check<'r>(rows: impl IntoIterator<Item = &'r Row<'r>>) -> Vec<CheckRows<'r>> {
    let mut by_name: BTreeMap<&'r str, CheckRows<'r>> = BTreeMap::new();
    for row in rows {
        let Some(latest) = &row.latest else {
            continue;
        };
        for check in &latest.checks {
            let rows = by_name.entry(&check.name).or_insert_with(|| CheckRows {
                name: &check.name,
                pass: Vec::new(),
                fail: Vec::new(),
                unknown: Vec::new(),
            });
            match check.status {
                Status::Pass => rows.pass.push(row),
                Status::Fail => rows.fail.push(row),
                Status::Unknown => rows.unknown.push(row),
            }
        }
    }
    let mut all: Vec<CheckRows> = by_name.into_values().collect();
    all.sort_by_key(|check| Reverse(check.fail.len() + check.unknown.len()));
    all
}

/// How many machines pass, fail or cannot run each check in their latest report, and which do not pass.
fn checks_table<'r>(body: &mut String, rows: impl IntoIterator<Item = &'r Row<'r>>, admin: bool) {
    let checks = by_check(rows);
    if checks.is_empty() {
        body.push_str("<p class=\"empty\">No reports.</p>");
        return;
    }
    body.push_str(
        "<div class=\"table\"><table><thead><tr><th>Check</th><th class=\"number\">Pass</th>\
         <th class=\"number\">Fail</th><th class=\"number\">Could not run</th><th>Not passing on</th></tr></thead>\
         <tbody>",
    );
    for check in &checks {
        let name = match admin {
            true => format!(
                "<a class=\"check\" href=\"/checks/{}\">{}</a>",
                url_encode(check.name),
                escape(check.name)
            ),
            false => escape(check.name),
        };
        let about = checks::about(check.name)
            .map(|about| format!("<div class=\"about\">{about}</div>"))
            .unwrap_or_default();
        let machines: Vec<String> = check
            .fail
            .iter()
            .map(|row| machine_pill(row, "danger"))
            .chain(check.unknown.iter().map(|row| machine_pill(row, "warning")))
            .collect();
        let _ = write!(
            body,
            "<tr class=\"{}\"><td>{name}{about}</td><td class=\"number\" data-label=\"Pass\">{}</td>\
             <td class=\"number\" data-label=\"Fail\">{}</td>\
             <td class=\"number\" data-label=\"Could not run\">{}</td><td data-label=\"Not passing on\">{}</td></tr>",
            if machines.is_empty() { "ok" } else { "attention" },
            check.pass.len(),
            count_chip(check.fail.len(), "fail"),
            count_chip(check.unknown.len(), "unknown"),
            machines.join(" "),
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

const MACHINES_INTRO: &str = "The machines needing attention come first, with what the review reports about them: a \
    check failing longer than its grace, no report for a week, a report that cannot be read. Checks failing for a \
    shorter time are shown <em>within grace</em>: not a finding yet.";

const CHECKS_INTRO: &str = "The outcome of each check in the latest report of these machines, and the machines where \
    it does not pass. <em>Could not run</em> counts as failing.";

/// An owner who is not an admin sees only their own machines.
pub(super) fn render_overview(web: &Web, viewer: &Viewer, show: Option<&str>) -> Result<Option<String>, String> {
    if !viewer.admin {
        return render_person(web, viewer, &viewer.email, show);
    }
    let machines = machines::read(&web.machines)?;
    let pending = machines::pending(&web.reports, &machines)?;
    let now = Timestamp::now();
    let rows = rows(web, machines.iter(), now);

    let mut body = String::new();
    let mut cards = machine_cards(&rows, "/");
    cards.push(Card {
        label: "Waiting for approval",
        value: pending.len(),
        class: if pending.is_empty() { "pass" } else { "wait" },
        href: Some("#pending".to_string()),
    });
    metrics(&mut body, &cards);
    machines_section(&mut body, &rows, show, "/", now, true);
    section(&mut body, "checks", "Checks", CHECKS_INTRO);
    checks_table(&mut body, &rows, true);
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
                when(machine.first_seen, now),
                when(*last_seen, now),
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
        Some(viewer),
        &body,
    )))
}

pub(super) fn render_people(web: &Web, viewer: &Viewer) -> Result<Option<String>, String> {
    if !viewer.admin {
        return Ok(None);
    }
    let machines = machines::read(&web.machines)?;
    let now = Timestamp::now();
    let rows = rows(web, machines.iter(), now);
    let mut people: BTreeMap<String, Vec<&Row>> = BTreeMap::new();
    for row in &rows {
        people
            .entry(row.machine.owner.to_ascii_lowercase())
            .or_default()
            .push(row);
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
        "The owners on the list of machines, each with their machines and what needs attention on them. The people \
         with something to do come first.",
    );
    if people.is_empty() {
        body.push_str("<p class=\"empty\">None.</p>");
    } else {
        body.push_str(
            "<div class=\"table\"><table><thead><tr><th>Person</th><th>Machines</th><th>Needs attention</th>\
             <th>Last report</th></tr></thead><tbody>",
        );
        for (owner, theirs) in &people {
            let needing: Vec<&&Row> = theirs.iter().filter(|row| !row.findings.is_empty()).collect();
            let _ = write!(
                body,
                "<tr class=\"{}\"><td><a href=\"/people/{}\">{}</a></td><td data-label=\"Machines\">",
                if needing.is_empty() { "ok" } else { "attention" },
                url_encode(owner),
                escape(owner),
            );
            for row in theirs {
                let class = if row.findings.is_empty() { "" } else { "danger" };
                body.push_str(&machine_pill(row, class));
                body.push(' ');
            }
            body.push_str("</td><td data-label=\"Needs attention\">");
            if needing.is_empty() {
                body.push_str("<span class=\"chip pass\">nothing</span>");
            }
            for row in &needing {
                let chips: Vec<String> = row.findings.iter().map(|finding| finding_chip(finding, true)).collect();
                let _ = write!(
                    body,
                    "<div class=\"needs\"><a href=\"/machines/{name}\">{name}</a> {}</div>",
                    chips.join(" "),
                    name = escape(&row.machine.name),
                );
            }
            let latest = theirs
                .iter()
                .filter_map(|row| row.latest.as_ref().map(|latest| latest.taken_at))
                .max();
            let _ = write!(
                body,
                "</td><td class=\"time\" data-label=\"Last report\">{}</td></tr>",
                latest
                    .map(|latest| when(latest, now))
                    .unwrap_or_else(|| "never".to_string()),
            );
        }
        body.push_str("</tbody></table></div>");
    }
    body.push_str("</section>");
    Ok(Some(page("People", "/people", &[], Some(viewer), &body)))
}

/// Owners are matched whatever the case of their address: the reminders link them in lower case.
pub(super) fn render_person(
    web: &Web,
    viewer: &Viewer,
    owner: &str,
    show: Option<&str>,
) -> Result<Option<String>, String> {
    if !viewer.admin && !owner.eq_ignore_ascii_case(&viewer.email) {
        return Ok(None);
    }
    let machines = machines::read(&web.machines)?;
    let now = Timestamp::now();
    let mut rows = rows(
        web,
        machines
            .iter()
            .filter(|machine| machine.owner.eq_ignore_ascii_case(owner)),
        now,
    );
    if rows.is_empty() {
        return Ok(None);
    }
    // what only the admins can deal with, as in the reminders
    if !viewer.admin {
        for row in &mut rows {
            row.findings.retain(Finding::for_owner);
        }
    }
    // an owner reaches their machines at the root
    let base = match viewer.admin {
        true => format!("/people/{}", url_encode(owner)),
        false => "/".to_string(),
    };
    let mut body = String::new();
    metrics(&mut body, &machine_cards(&rows, &base));
    machines_section(&mut body, &rows, show, &base, now, viewer.admin);
    section(&mut body, "checks", "Checks", CHECKS_INTRO);
    checks_table(&mut body, &rows, viewer.admin);
    body.push_str("</section>");
    Ok(Some(page(
        owner,
        if viewer.admin { "/people" } else { "/" },
        &[("machines", "Machines"), ("checks", "Checks")],
        Some(viewer),
        &body,
    )))
}

const KIND_INTRO: &str = "The type comes from the chassis type the firmware gives (SMBIOS), in the latest report. \
    <em>Unknown</em> is a machine that never reported, one whose agent does not send the chassis type yet, or a \
    chassis that is neither a laptop nor a desktop, such as a virtual machine.";

pub(super) fn render_types(web: &Web, viewer: &Viewer) -> Result<Option<String>, String> {
    if !viewer.admin {
        return Ok(None);
    }
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
            href: Some(format!("/types/{}", kind.slug())),
        })
        .collect();
    metrics(&mut body, &cards);
    section(&mut body, "types", "Types", KIND_INTRO);
    body.push_str(
        "<div class=\"table\"><table><thead><tr><th>Type</th><th class=\"number\">Machines</th>\
         <th class=\"number\">Needing attention</th><th class=\"number\">Passing every check</th>\
         <th class=\"number\">People</th><th>Most failed checks</th></tr></thead><tbody>",
    );
    for kind in Kind::ALL {
        let of_kind: Vec<&Row> = rows.iter().filter(|row| row.kind == kind).collect();
        if kind == Kind::Unknown && of_kind.is_empty() {
            continue;
        }
        let attention = of_kind.iter().filter(|row| !row.findings.is_empty()).count();
        let mut people: Vec<String> = of_kind
            .iter()
            .map(|row| row.machine.owner.to_ascii_lowercase())
            .collect();
        people.sort_unstable();
        people.dedup();
        let failed: Vec<String> = by_check(of_kind.iter().copied())
            .into_iter()
            .filter(|check| !check.fail.is_empty() || !check.unknown.is_empty())
            .take(5)
            .map(|check| {
                format!(
                    "<a class=\"chip fail\" href=\"/checks/{}\">{} · {}</a>",
                    url_encode(check.name),
                    escape(check.name),
                    check.fail.len() + check.unknown.len()
                )
            })
            .collect();
        let _ = write!(
            body,
            "<tr class=\"{}\"><td><a href=\"/types/{}\">{}</a></td><td class=\"number\" data-label=\"Machines\">{}</td>\
             <td class=\"number\" data-label=\"Needing attention\">{}</td>\
             <td class=\"number\" data-label=\"Passing every check\">{}</td>\
             <td class=\"number\" data-label=\"People\">{}</td><td data-label=\"Most failed checks\">{}</td></tr>",
            if attention == 0 { "ok" } else { "attention" },
            kind.slug(),
            kind.plural(),
            of_kind.len(),
            count_chip(attention, "fail"),
            of_kind.iter().filter(|row| row.passing()).count(),
            people.len(),
            failed.join(" "),
        );
    }
    body.push_str("</tbody></table></div></section>");
    Ok(Some(page("Types", "/types", &[], Some(viewer), &body)))
}

pub(super) fn render_kind(
    web: &Web,
    viewer: &Viewer,
    slug: &str,
    show: Option<&str>,
) -> Result<Option<String>, String> {
    if !viewer.admin {
        return Ok(None);
    }
    let Some(kind) = Kind::ALL.into_iter().find(|kind| kind.slug() == slug) else {
        return Ok(None);
    };
    let machines = machines::read(&web.machines)?;
    let now = Timestamp::now();
    let rows: Vec<Row> = rows(web, machines.iter(), now)
        .into_iter()
        .filter(|row| row.kind == kind)
        .collect();

    let mut people: Vec<String> = rows.iter().map(|row| row.machine.owner.to_ascii_lowercase()).collect();
    people.sort_unstable();
    people.dedup();
    let base = format!("/types/{}", kind.slug());
    let mut body = String::new();
    let mut cards = machine_cards(&rows, &base);
    cards.push(Card {
        label: "People",
        value: people.len(),
        class: "all",
        href: None,
    });
    metrics(&mut body, &cards);
    let _ = write!(body, "<p class=\"lead\">{KIND_INTRO}</p>");
    machines_section(&mut body, &rows, show, &base, now, true);
    section(&mut body, "checks", "Checks", CHECKS_INTRO);
    checks_table(&mut body, &rows, true);
    body.push_str("</section>");
    Ok(Some(page(
        kind.plural(),
        "/types",
        &[("machines", "Machines"), ("checks", "Checks")],
        Some(viewer),
        &body,
    )))
}

pub(super) fn render_checks(web: &Web, viewer: &Viewer) -> Result<Option<String>, String> {
    if !viewer.admin {
        return Ok(None);
    }
    let machines = machines::read(&web.machines)?;
    let now = Timestamp::now();
    let rows = rows(web, machines.iter(), now);
    let checks = by_check(&rows);
    let failing = checks
        .iter()
        .filter(|check| !check.fail.is_empty() || !check.unknown.is_empty())
        .count();
    let mut body = String::new();
    metrics(
        &mut body,
        &[
            Card {
                label: "Checks",
                value: checks.len(),
                class: "all",
                href: None,
            },
            Card {
                label: "Not passing somewhere",
                value: failing,
                class: if failing > 0 { "fail" } else { "pass" },
                href: None,
            },
            Card {
                label: "Machines reporting",
                value: rows.iter().filter(|row| row.latest.is_some()).count(),
                class: "all",
                href: Some("/".to_string()),
            },
        ],
    );
    section(&mut body, "checks", "Checks", CHECKS_INTRO);
    checks_table(&mut body, &rows, true);
    body.push_str("</section>");
    Ok(Some(page("Checks", "/checks", &[], Some(viewer), &body)))
}

/// One check across the machines: those not passing it, longest first, with what to do, then those passing it.
pub(super) fn render_check(web: &Web, viewer: &Viewer, name: &str) -> Result<Option<String>, String> {
    if !viewer.admin {
        return Ok(None);
    }
    let machines = machines::read(&web.machines)?;
    let now = Timestamp::now();
    let rows = rows(web, machines.iter(), now);
    let mut not_passing: Vec<(&Row, &Finding, bool)> = rows
        .iter()
        .filter_map(|row| row.not_passing(name).map(|(finding, due)| (row, finding, due)))
        .collect();
    let passing: Vec<&Row> = rows
        .iter()
        .filter(|row| {
            row.latest.as_ref().is_some_and(|latest| {
                latest
                    .checks
                    .iter()
                    .any(|check| check.name == name && check.status == Status::Pass)
            })
        })
        .collect();
    let about = checks::about(name);
    if not_passing.is_empty() && passing.is_empty() && about.is_none() {
        return Ok(None);
    }
    let since = |finding: &Finding| match finding {
        Finding::Check { since, .. } => Some(*since),
        _ => None,
    };
    not_passing.sort_by_key(|(_, finding, due)| (!due, since(finding)));
    let count = |due: bool, status: Status| {
        not_passing
            .iter()
            .filter(|(_, finding, is_due)| {
                *is_due == due && matches!(finding, Finding::Check { status: found, .. } if *found == status)
            })
            .count()
    };
    let within_grace = not_passing.iter().filter(|(_, _, due)| !due).count();

    let mut body = String::new();
    metrics(
        &mut body,
        &[
            Card {
                label: "Failing",
                value: count(true, Status::Fail),
                class: if count(true, Status::Fail) > 0 { "fail" } else { "pass" },
                href: None,
            },
            Card {
                label: "Could not run",
                value: count(true, Status::Unknown),
                class: if count(true, Status::Unknown) > 0 {
                    "wait"
                } else {
                    "pass"
                },
                href: None,
            },
            Card {
                label: "Within grace",
                value: within_grace,
                class: "all",
                href: None,
            },
            Card {
                label: "Passing",
                value: passing.len(),
                class: "pass",
                href: None,
            },
        ],
    );
    let mut intro = match about {
        Some(about) => format!("Passes when {about}."),
        None => "Not a check this version of the collector knows.".to_string(),
    };
    if let Some(remedy) = review::remedy(name) {
        let _ = write!(
            intro,
            " To do on a machine that does not pass it: <em>{}</em>.",
            escape(remedy)
        );
    }
    section(&mut body, "not-passing", "Not passing", &intro);
    if not_passing.is_empty() {
        body.push_str("<p class=\"empty\">None.</p>");
    } else {
        body.push_str("<div class=\"table\"><table><thead><tr><th>Machine</th><th>State</th></tr></thead><tbody>");
        for (row, finding, due) in &not_passing {
            // the name of the check is the page: the state takes its place
            let (class, state) = match (due, finding) {
                (false, _) => ("grace", "within grace"),
                (
                    true,
                    Finding::Check {
                        status: Status::Unknown,
                        ..
                    },
                ) => ("unknown", "could not run"),
                (true, _) => ("fail", "failing"),
            };
            let (since, detail) = match finding {
                Finding::Check { since, detail, .. } => (
                    format!(
                        "<span class=\"since\" title=\"since {} UTC\">for {}</span>",
                        minutes(*since),
                        for_how_long(*since, now)
                    ),
                    escape(detail),
                ),
                _ => (String::new(), String::new()),
            };
            let _ = write!(
                body,
                "<tr class=\"{}\"><td><a href=\"/machines/{name}\">{name}</a><a class=\"owner\" href=\"/people/{}\">{}</a>\
                 </td><td data-label=\"State\"><ul class=\"findings\"><li><span class=\"chip {class}\">{state}</span> \
                 {since} <span class=\"detail\">{detail}</span></li></ul></td></tr>",
                if *due { "attention" } else { "ok" },
                url_encode(&row.machine.owner),
                escape(&row.machine.owner),
                name = escape(&row.machine.name),
            );
        }
        body.push_str("</tbody></table></div>");
    }
    body.push_str("</section>");
    section(
        &mut body,
        "passing",
        "Passing",
        "The machines whose latest report passes it.",
    );
    match passing.is_empty() {
        true => body.push_str("<p class=\"empty\">None.</p>"),
        false => {
            let pills: Vec<String> = passing.iter().map(|row| machine_pill(row, "")).collect();
            let _ = write!(body, "<p class=\"pills\">{}</p>", pills.join(" "));
        }
    }
    body.push_str("</section>");
    Ok(Some(page(
        name,
        "/checks",
        &[("not-passing", "Not passing"), ("passing", "Passing")],
        Some(viewer),
        &body,
    )))
}

pub(super) fn render_machine(web: &Web, viewer: &Viewer, name: &str) -> Result<Option<String>, String> {
    let machines = machines::read(&web.machines)?;
    // someone else's machine is as missing as one not on the list: its name tells nothing
    let Some(machine) = machines
        .iter()
        .find(|machine| machine.name == name && (viewer.admin || machine.owner.eq_ignore_ascii_case(&viewer.email)))
    else {
        return Ok(None);
    };
    let now = Timestamp::now();
    let review::Reviewed {
        reports,
        mut findings,
        within_grace,
    } = review::reviewed(&web.reports, machine, now);
    // what only the admins can deal with, as in the reminders
    if !viewer.admin {
        findings.retain(Finding::for_owner);
    }
    let kind = Kind::of(reports.first());

    let mut body = String::new();
    // the types are for the admins
    let kind_link = match viewer.admin {
        true => format!("<a href=\"/types/{kind}\">{kind}</a>", kind = kind.slug()),
        false => kind.slug().to_string(),
    };
    let _ = write!(
        body,
        "<p class=\"lead\"><a href=\"/people/{}\">{}</a> · {kind_link}</p>",
        url_encode(&machine.owner),
        escape(&machine.owner),
    );
    if findings.is_empty() {
        body.push_str("<p class=\"verdict pass\">Nothing needs attention.</p>");
    } else {
        body.push_str("<div class=\"verdict fail\">Needs attention<ul class=\"findings\">");
        for finding in &findings {
            let _ = write!(
                body,
                "<li>{}{}</li>",
                finding_html(finding, now, viewer.admin, true),
                remedy_html(finding.remedy())
            );
        }
        body.push_str("</ul></div>");
    }

    section(
        &mut body,
        "latest",
        "Latest report",
        "Every check of the latest report, those not passing first, with what the agent found and what to do.",
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
                "<div class=\"table\"><table><thead><tr><th>Check</th><th>Outcome</th><th>Since</th><th>Detail</th>\
                 </tr></thead><tbody>",
            );
            let mut checks: Vec<_> = latest.checks.iter().collect();
            checks.sort_by_key(|check| check.status == Status::Pass);
            for check in checks {
                let not_passing = not_passing(&findings, &within_grace, &check.name);
                let (outcome, since, remedy) = match (check.status, not_passing) {
                    (Status::Pass, _) => ("pass", String::new(), String::new()),
                    (status, Some((finding, due))) => {
                        let outcome = match (due, status) {
                            (false, _) => "within grace",
                            (true, Status::Unknown) => "could not run",
                            (true, _) => "fail",
                        };
                        let since = match finding {
                            Finding::Check { since, .. } => format!(
                                "<span title=\"since {} UTC\">for {}</span>",
                                minutes(*since),
                                for_how_long(*since, now)
                            ),
                            _ => String::new(),
                        };
                        (outcome, since, remedy_html(finding.remedy()))
                    }
                    (Status::Unknown, None) => ("could not run", String::new(), String::new()),
                    (_, None) => ("fail", String::new(), String::new()),
                };
                let class = match outcome {
                    "pass" => "pass",
                    "within grace" => "grace",
                    "could not run" => "unknown",
                    _ => "fail",
                };
                let _ = write!(
                    body,
                    "<tr class=\"{}\"><td>{}</td><td data-label=\"Outcome\"><span class=\"chip {class}\">{outcome}</span>\
                     </td><td class=\"time\" data-label=\"Since\">{since}</td>\
                     <td class=\"detail\" data-label=\"Detail\">{}{remedy}</td></tr>",
                    if check.status == Status::Pass {
                        "ok passed"
                    } else {
                        "attention"
                    },
                    match viewer.admin {
                        true => format!(
                            "<a class=\"check\" href=\"/checks/{}\">{}</a>",
                            url_encode(&check.name),
                            escape(&check.name)
                        ),
                        false => escape(&check.name),
                    },
                    escape(&check.detail),
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
        let state = |report: &Report| not_passing_chips(report.checks.iter().map(|check| (&check.name, check.status)));
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
                not_passing_chips(summary.checks.iter().map(|(name, status)| (name, *status)))
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
        Some(viewer),
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

fn not_passing_chips<'a>(checks: impl Iterator<Item = (&'a String, Status)>) -> String {
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

fn for_how_long(since: Timestamp, now: Timestamp) -> String {
    let minutes = now.duration_since(since).as_secs().max(0) / 60;
    match minutes {
        ..1 => "less than a minute".to_string(),
        1..60 => format!("{minutes} min"),
        60..2880 => format!("{} h", minutes / 60),
        _ => format!("{} days", minutes / 1440),
    }
}

fn ago(then: Timestamp, now: Timestamp) -> String {
    match now.duration_since(then).as_secs() < 60 {
        true => "just now".to_string(),
        false => format!("{} ago", for_how_long(then, now)),
    }
}

/// How long ago, with the time itself on hover.
fn when(at: Timestamp, now: Timestamp) -> String {
    format!(
        "<time datetime=\"{at}\" title=\"{} UTC\">{}</time>",
        minutes(at),
        ago(at, now)
    )
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
/// Without a viewer, the page of a message before the login.
pub(super) fn page(title: &str, view: &str, sections: &[(&str, &str)], viewer: Option<&Viewer>, body: &str) -> String {
    let title = escape(title);
    let mut html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{title} · Posture</title>\
         <link rel=\"icon\" href=\"/favicon.ico\"><link rel=\"stylesheet\" href=\"/posture.css\"></head><body><header>\
         <h1><a href=\"/\"><img src=\"/favicon.ico\" alt=\"\">Posture</a><span class=\"page\">/ {title}</span></h1>"
    );
    if let Some(viewer) = viewer {
        html.push_str("<nav class=\"views\">");
        let views: &[(&str, &str)] = match viewer.admin {
            true => &[
                ("/", "Machines"),
                ("/people", "People"),
                ("/types", "Types"),
                ("/checks", "Checks"),
            ],
            false => &[("/", "Machines")],
        };
        for &(href, label) in views {
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
            escape(&viewer.email)
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

    fn admin() -> Viewer {
        Viewer {
            email: "admin@optionfactory.net".to_string(),
            admin: true,
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
    fn a_pending_hostname_is_never_markup_even_from_an_older_collector() {
        let dir = std::env::temp_dir().join(format!("optionfactory-posture-web-pending-{}", std::process::id()));
        let web = web(&dir, "");
        // as an older collector wrote it, before hostnames were cleaned
        let pending = machines::pending_dir(&web.reports);
        std::fs::create_dir_all(&pending).unwrap();
        std::fs::write(
            pending.join(format!("{}.json", "0".repeat(64))),
            r#"{"hostname":"<script>alert(1)</script>","machine_id":"id","first_seen":"2026-11-20T10:00:00Z"}"#,
        )
        .unwrap();

        let page = render_overview(&web, &admin(), None).unwrap().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!page.contains("<script>") && !page.contains("alert(1)"));
        assert!(page.contains("<td>invalid</td>"));
    }

    #[test]
    fn a_person_sees_their_machines_and_a_type_its_machines() {
        let dir = std::env::temp_dir().join(format!("optionfactory-posture-web-views-{}", std::process::id()));
        let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let web = web(
            &dir,
            &format!(
                "kup mario.rossi@optionfactory.net {a}\nbox mario.rossi@optionfactory.net {b}\n\
                 lap luigi.verdi@optionfactory.net {c}\n"
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

        let mario = render_person(&web, &admin(), "Mario.Rossi@optionfactory.net", None).unwrap();
        let laptops = render_kind(&web, &admin(), "laptop", None).unwrap();
        let workstations = render_kind(&web, &admin(), "workstation", None).unwrap();
        let nobody = render_person(&web, &admin(), "nobody@optionfactory.net", None).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(machines_on(mario), ["kup", "box"]);
        assert_eq!(machines_on(laptops), ["kup", "lap"]);
        assert_eq!(machines_on(workstations), ["box"]);
        assert!(nobody.is_none());
    }

    #[test]
    fn a_check_page_lists_the_machines_not_passing_it_then_those_passing() {
        let dir = std::env::temp_dir().join(format!("optionfactory-posture-web-check-{}", std::process::id()));
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        let web = web(
            &dir,
            &format!("kup mario.rossi@optionfactory.net {a}\nlap luigi.verdi@optionfactory.net {b}\n"),
        );
        write_report(&web, "kup", Some(10), Status::Fail);
        write_report(&web, "lap", Some(9), Status::Pass);

        let page = render_check(&web, &admin(), "firewall").unwrap().unwrap();
        let unknown = render_check(&web, &admin(), "<b>nope</b>").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let (not_passing, passing) = page.split_once("id=\"passing\"").unwrap();
        // failing for a moment only: shown, but within its grace
        assert!(not_passing.contains("href=\"/machines/kup\"") && not_passing.contains("within grace"));
        assert!(passing.contains("href=\"/machines/lap\"") && !passing.contains("kup"));
        assert!(unknown.is_none());
    }

    #[test]
    fn an_owner_sees_only_their_own_machines() {
        let dir = std::env::temp_dir().join(format!("optionfactory-posture-web-owner-{}", std::process::id()));
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        let web = web(
            &dir,
            &format!("kup mario.rossi@optionfactory.net {a}\nlap luigi.verdi@optionfactory.net {b}\n"),
        );
        write_report(&web, "kup", Some(10), Status::Pass);
        write_report(&web, "lap", Some(9), Status::Pass);
        let mario = Viewer {
            email: "mario.rossi@optionfactory.net".to_string(),
            admin: false,
        };

        let overview = render_overview(&web, &mario, None).unwrap().unwrap();
        let own = render_machine(&web, &mario, "kup").unwrap();
        let others = [
            render_machine(&web, &mario, "lap").unwrap(),
            render_person(&web, &mario, "luigi.verdi@optionfactory.net", None).unwrap(),
            render_people(&web, &mario).unwrap(),
            render_types(&web, &mario).unwrap(),
            render_kind(&web, &mario, "laptop", None).unwrap(),
            render_checks(&web, &mario).unwrap(),
            render_check(&web, &mario, "firewall").unwrap(),
        ];
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(overview.contains("href=\"/machines/kup\""));
        assert!(!overview.contains("href=\"/machines/lap\""));
        assert!(!overview.contains("href=\"/people\"") && !overview.contains("href=\"/checks"));
        assert!(own.is_some_and(|page| !page.contains("href=\"/types/")));
        assert!(others.iter().all(Option::is_none));
    }
}
