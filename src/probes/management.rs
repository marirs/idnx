//! A bounded, read-only audit of a management surface that has already answered.
//!
//! The narrow case this exists for: a device whose forwarding behaviour is confirmed, whose
//! HTTP port answers, and whose prefix nothing has disclosed. Such a device usually knows
//! its own addressing and often publishes it on a status page. Reading that page is the
//! last credential-free way to learn a prefix from it.
//!
//! It is an audit and not a crawler, and the difference is enforced here rather than left
//! to good behaviour:
//!
//! * Exact same origin -- scheme, host and port. A link to anywhere else is not this
//!   device's statement about itself.
//! * Twelve requests per device, depth one. Links found on the first page may be read;
//!   links found on those pages may not.
//! * `GET` only, no query strings, no cookies, no credentials, no forms, and none of
//!   `POST`, `PUT`, `PATCH` or `DELETE`.
//! * A short universal path list, and no `/cgi-bin/...` guessing: CGI handlers commonly
//!   carry mutating actions behind names that look inert.
//! * Any link whose text carries action semantics -- apply, save, reboot, reset, upgrade,
//!   delete, enable, disable, connect, logout, restore -- is refused, whatever it claims to
//!   be. Following one could change the device's configuration, and no discovery is worth
//!   that.
//!
//! Nothing it reads is trusted more for having been read here. Every response goes through
//! the same prefix gate as anything else: only an explicit interface address with a mask,
//! or a routing destination with a mask, creates topology. A bare address, a JavaScript
//! variable, a firewall rule or a documentation example creates nothing.

use crate::net::endpoint::Endpoint;
use crate::net::socket::SocketBinding;
use crate::probes::http::{HttpIdentity, PrefixCandidate, probe_http_path};
use std::time::Duration;

/// The whole guessed surface. Short, conventional, and read-only by convention on every
/// device that implements them at all.
pub const UNIVERSAL_PATHS: [&str; 8] = [
    "/status",
    "/status.html",
    "/info",
    "/device.xml",
    "/status.json",
    "/api/status",
    "/api/routes",
    "/api/routing",
];

/// Hard cap on requests per device, the root page included.
pub const REQUEST_BUDGET: usize = 12;

/// Words that make a link an action rather than a document.
///
/// Matched on the whole URL, because the dangerous part is as often in a path segment as in
/// a parameter. A false refusal costs one unread page; a false acceptance can reboot a
/// router.
const ACTION_WORDS: [&str; 11] = [
    "apply", "save", "reboot", "reset", "upgrade", "delete", "enable", "disable", "connect",
    "logout", "restore",
];

/// Why a path was not fetched, or what came back when it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathOutcome {
    /// Fetched, with the status the device returned.
    Answered {
        status: u16,
        prefixes: usize,
        /// The normalised body, so one representation served under many paths is
        /// recognisable as one.
        fingerprint: Option<u64>,
    },
    /// Fetched and the device demanded credentials, which are never supplied.
    AuthenticationRequired { status: u16 },
    /// Asked and nothing came back.
    NoResponse,
    /// Refused before being asked, with the rule that refused it.
    Refused(&'static str),
}

impl PathOutcome {
    pub fn label(&self) -> String {
        match self {
            PathOutcome::Answered {
                status, prefixes, ..
            } => format!("{status}, {prefixes} prefix candidate(s)"),
            PathOutcome::AuthenticationRequired { status } => {
                format!("{status}, credentials demanded and not supplied")
            }
            PathOutcome::NoResponse => "no response".to_string(),
            PathOutcome::Refused(rule) => format!("not fetched: {rule}"),
        }
    }
}

/// What one device's audit asked and what it produced.
#[derive(Debug, Clone, Default)]
pub struct ManagementAudit {
    /// Every path considered, with its outcome. All of it enters coverage: a path refused
    /// by a rule is as much a part of what was attempted as one that answered.
    pub attempted: Vec<(String, PathOutcome)>,
    /// Prefix candidates from every response, with the semantics the page gave them.
    pub candidates: Vec<PrefixCandidate>,
    /// Whether the request budget stopped the audit before the paths ran out.
    pub budget_exhausted: bool,
}

impl ManagementAudit {
    pub fn answered(&self) -> usize {
        self.attempted
            .iter()
            .filter(|(_, outcome)| matches!(outcome, PathOutcome::Answered { .. }))
            .count()
    }

    /// Paths that returned the same representation, most numerous first.
    ///
    /// Reported because eight paths answering 200 with one body is a catch-all handler or a
    /// single-page shell, not eight endpoints, and calling it eight successful reads
    /// overstates what was found. Grouped on status and body together: a 404 page and a
    /// 200 page are different answers even if their bodies match.
    pub fn identical_responses(&self) -> Vec<(u16, usize, usize)> {
        let mut groups: Vec<(u16, u64, usize, usize)> = Vec::new();
        for (_, outcome) in &self.attempted {
            let PathOutcome::Answered {
                status,
                prefixes,
                fingerprint: Some(fingerprint),
            } = outcome
            else {
                continue;
            };
            match groups
                .iter_mut()
                .find(|(seen, hash, _, _)| seen == status && hash == fingerprint)
            {
                Some((_, _, count, _)) => *count += 1,
                None => groups.push((*status, *fingerprint, 1, *prefixes)),
            }
        }
        groups.retain(|(_, _, count, _)| *count > 1);
        // Most numerous first: the largest group is the one that most overstates coverage.
        groups.sort_by_key(|group| std::cmp::Reverse(group.2));
        groups
            .into_iter()
            .map(|(status, _, count, prefixes)| (status, count, prefixes))
            .collect()
    }

    /// Candidates the page labelled as its own addressing or as a route, which are the only
    /// ones that may become topology.
    pub fn establishing(&self) -> impl Iterator<Item = &PrefixCandidate> {
        self.candidates
            .iter()
            .filter(|candidate| candidate.semantics.establishes_network())
    }
}

/// File extensions that are page furniture rather than a statement about the device.
const ASSET_SUFFIXES: [&str; 12] = [
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".map",
];

/// Words that mark a link as a descriptor or a status or routing document.
const DOCUMENT_WORDS: [&str; 10] = [
    "status",
    "info",
    "device",
    "route",
    "routing",
    "system",
    "network",
    "lan",
    "wan",
    "interface",
];

/// Whether a published link is the kind of document this audit exists to read.
///
/// The rule is "descriptor links and clearly read-only status or routing links", not "every
/// link on the page". A stylesheet, a font and a script bundle are page furniture: fetching
/// them spends the budget on things that cannot contain the device's own addressing, and it
/// is the difference between reading what a device publishes about itself and crawling it.
pub fn is_document_link(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if ASSET_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix)) {
        return false;
    }
    // A descriptor, by extension.
    if lower.ends_with(".xml") || lower.ends_with(".json") {
        return true;
    }
    DOCUMENT_WORDS.iter().any(|word| lower.contains(word))
}

/// Whether a link may be fetched, and the rule that decides it.
///
/// `Ok` carries the same-origin path. Everything else names why it was refused, so the
/// coverage report can say what was not read as well as what was.
pub fn admissible(link: &str, target: &Endpoint, port: u16) -> Result<String, &'static str> {
    let trimmed = link.trim();
    if trimmed.is_empty() {
        return Err("empty link");
    }
    // Fragments and non-HTTP schemes are not documents on this origin.
    if trimmed.starts_with('#') {
        return Err("fragment, not a document");
    }
    let lower = trimmed.to_ascii_lowercase();
    for scheme in ["javascript:", "mailto:", "tel:", "data:", "ftp:"] {
        if lower.starts_with(scheme) {
            return Err("not an HTTP URL");
        }
    }
    // A query string is a parameterised request, which is where actions hide.
    if trimmed.contains('?') {
        return Err("query string, which parameterises a request");
    }
    // CGI handlers commonly carry mutating actions behind inert-looking names.
    if lower.contains("/cgi-bin/") {
        return Err("CGI handler, which commonly performs actions");
    }
    for word in ACTION_WORDS {
        if lower.contains(word) {
            return Err("action semantics in the URL");
        }
    }

    // Exact same origin: scheme, host and port. `same_origin_path` already refuses
    // protocol-relative URLs, credentials in the authority, another host and another port.
    let path = crate::probes::http::same_origin_path(trimmed, target, port)?;
    if !is_document_link(&path) {
        return Err("not a descriptor or status document");
    }
    Ok(path)
}

/// Reads a bounded set of read-only endpoints on one management surface.
///
/// `root` is the response already obtained from `/`, whose published links are the only
/// ones considered: this is depth one, so nothing found on a fetched page is followed.
pub async fn audit(
    target: &Endpoint,
    port: u16,
    root: &HttpIdentity,
    binding: &SocketBinding,
    timeout: Duration,
) -> ManagementAudit {
    let mut audit = ManagementAudit::default();
    let mut asked: Vec<String> = Vec::new();

    // The device's own published links first: what it offers is better evidence than what
    // convention suggests it might.
    let mut queue: Vec<String> = Vec::new();
    for link in &root.links {
        match admissible(link, target, port) {
            Ok(path) => {
                if !queue.contains(&path) {
                    queue.push(path);
                }
            }
            Err(rule) => {
                // Recorded, because a refusal is part of what was attempted.
                if audit.attempted.len() < 64 {
                    audit
                        .attempted
                        .push((link.trim().to_string(), PathOutcome::Refused(rule)));
                }
            }
        }
    }
    for path in UNIVERSAL_PATHS {
        if !queue.contains(&path.to_string()) {
            queue.push(path.to_string());
        }
    }

    for path in queue {
        if asked.len() >= REQUEST_BUDGET {
            audit.budget_exhausted = true;
            break;
        }
        asked.push(path.clone());

        let outcome = match probe_http_path(target, port, &path, binding, timeout).await {
            Some(response) => {
                let prefixes = response.prefixes.len();
                audit.candidates.extend(response.prefixes);
                if response.authenticate.is_some() || response.status == 401 {
                    PathOutcome::AuthenticationRequired {
                        status: response.status,
                    }
                } else {
                    PathOutcome::Answered {
                        status: response.status,
                        prefixes,
                        fingerprint: response.body_fingerprint,
                    }
                }
            }
            None => PathOutcome::NoResponse,
        };
        audit.attempted.push((path, outcome));
    }

    audit
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn device() -> Endpoint {
        Endpoint::global("192.168.70.1".parse::<IpAddr>().unwrap())
    }

    #[test]
    fn the_guessed_surface_is_short_and_carries_no_cgi() {
        assert_eq!(UNIVERSAL_PATHS.len(), 8);
        assert_eq!(REQUEST_BUDGET, 12);
        for path in UNIVERSAL_PATHS {
            assert!(path.starts_with('/'), "{path}");
            assert!(!path.contains("cgi-bin"), "{path}");
            assert!(!path.contains('?'), "{path}");
        }
    }

    #[test]
    fn a_link_that_could_act_on_the_device_is_never_fetched() {
        // A false refusal costs one unread page. A false acceptance can reboot a router.
        for dangerous in [
            "/apply.html",
            "/status?action=save",
            "/reboot",
            "/factory_reset",
            "/firmware_upgrade",
            "/delete_rule",
            "/wan_enable",
            "/wifi_disable",
            "/connect_now",
            "/logout",
            "/restore_defaults",
            "/cgi-bin/status",
        ] {
            assert!(
                admissible(dangerous, &device(), 80).is_err(),
                "{dangerous} must not be fetched"
            );
        }

        // A query string parameterises a request, which is where actions hide.
        assert_eq!(
            admissible("/status?page=2", &device(), 80),
            Err("query string, which parameterises a request")
        );
    }

    #[test]
    fn only_this_origin_is_read() {
        // Another host, another port and another scheme are not this device's statement
        // about itself.
        assert!(admissible("http://example.com/status", &device(), 80).is_err());
        assert!(admissible("//example.com/status", &device(), 80).is_err());
        assert!(admissible("https://192.168.70.1/status", &device(), 80).is_err());
        assert!(admissible("javascript:void(0)", &device(), 80).is_err());
        assert!(admissible("#section", &device(), 80).is_err());
        assert!(admissible("mailto:admin@example.com", &device(), 80).is_err());

        // A relative path on this origin is admissible.
        assert_eq!(
            admissible("/device.xml", &device(), 80),
            Ok("/device.xml".to_string())
        );
        assert_eq!(
            admissible("http://192.168.70.1/info", &device(), 80),
            Ok("/info".to_string())
        );
    }

    #[test]
    fn page_furniture_is_not_a_statement_about_the_device() {
        // The live run spent budget on jQuery and a JSON polyfill. A script bundle cannot
        // contain the device's own addressing, and fetching it is crawling rather than
        // reading what the device publishes about itself.
        for asset in [
            "/static/js/lib/jquery.js",
            "/ui/static/cache/js/browser.js",
            "/style.css",
            "/logo.png",
            "/fonts/icons.woff2",
            "/app.js.map",
        ] {
            assert!(!is_document_link(asset), "{asset}");
            assert_eq!(
                admissible(asset, &device(), 80),
                Err("not a descriptor or status document")
            );
        }

        // Descriptors and status or routing documents are what this reads.
        for document in [
            "/device.xml",
            "/status.json",
            "/api/routes",
            "/system_info",
            "/lan_status",
            "/interface",
        ] {
            assert!(is_document_link(document), "{document}");
            assert!(admissible(document, &device(), 80).is_ok(), "{document}");
        }
    }

    #[test]
    fn published_links_are_extracted_but_decide_nothing_themselves() {
        let body = r#"
            <a href="/status.html">Status</a>
            <a href="/reboot.html">Reboot</a>
            <link rel="alternate" href="/device.xml">
            <script src="/js/app.js"></script>
            <a href='http://vendor.example.com/support'>Support</a>
        "#;
        let links = crate::probes::http::document_links(body);
        assert!(links.contains(&"/status.html".to_string()));
        assert!(links.contains(&"/reboot.html".to_string()));
        assert!(links.contains(&"/device.xml".to_string()));

        // The extractor keeps everything; the rules decide.
        let admitted: Vec<String> = links
            .iter()
            .filter_map(|link| admissible(link, &device(), 80).ok())
            .collect();
        assert!(admitted.contains(&"/status.html".to_string()));
        assert!(admitted.contains(&"/device.xml".to_string()));
        assert!(
            !admitted.iter().any(|path| path.ends_with(".js")),
            "a script bundle is page furniture: {admitted:?}"
        );
        assert!(
            !admitted.iter().any(|path| path.contains("reboot")),
            "{admitted:?}"
        );
        assert!(
            !admitted
                .iter()
                .any(|path| path.contains("vendor.example.com")),
            "{admitted:?}"
        );
    }

    #[test]
    fn a_prefix_still_has_to_be_labelled_to_establish_anything() {
        // The audit reads more pages; it does not lower the bar for what a page must say.
        // A bare address, a script variable, a firewall rule and an example create nothing.
        let mut audit = ManagementAudit {
            candidates: crate::probes::http::prefix_candidates(
                "<script>var lan='192.168.70.1';</script>\
                 <p>For example, 10.0.0.0/8 may be used.</p>\
                 <tr><td>Destination</td><td>172.16.0.0/12</td><td>Deny</td></tr>",
            ),
            ..Default::default()
        };
        assert_eq!(
            audit.establishing().count(),
            0,
            "none of these is the device stating its own addressing"
        );

        // An interface row with an address and a mask is.
        audit.candidates = crate::probes::http::prefix_candidates(
            "<tr><td>Interface</td><td>br-lan</td><td>IP Address</td><td>192.168.51.1</td>\
             <td>Subnet Mask</td><td>255.255.255.0</td></tr>",
        );
        assert!(
            audit.establishing().count() > 0,
            "an interface address with a mask is the device stating its own network"
        );
    }

    #[test]
    fn one_representation_under_many_paths_is_reported_as_one() {
        // 192.168.70.1 answered 200 to all eight guesses with one body. That is a
        // catch-all handler or a single-page shell, not eight endpoints, and calling it
        // eight successful reads overstates what was found by a factor of eight.
        let catch_all = ManagementAudit {
            attempted: UNIVERSAL_PATHS
                .iter()
                .map(|path| {
                    (
                        path.to_string(),
                        PathOutcome::Answered {
                            status: 200,
                            prefixes: 0,
                            fingerprint: Some(0xdead_beef),
                        },
                    )
                })
                .collect(),
            ..Default::default()
        };

        let groups = catch_all.identical_responses();
        assert_eq!(groups, vec![(200, 8, 0)]);
        assert_eq!(catch_all.answered(), 8, "the reads did happen");

        // Bodies that genuinely differ must not collapse: a status page carrying an
        // address and one carrying none are two answers, and that is the failure that
        // would matter.
        let distinct = ManagementAudit {
            attempted: vec![
                (
                    "/status".to_string(),
                    PathOutcome::Answered {
                        status: 200,
                        prefixes: 1,
                        fingerprint: Some(1),
                    },
                ),
                (
                    "/info".to_string(),
                    PathOutcome::Answered {
                        status: 200,
                        prefixes: 0,
                        fingerprint: Some(2),
                    },
                ),
            ],
            ..Default::default()
        };
        assert!(distinct.identical_responses().is_empty());

        // Normalisation covers reformatting and case, and nothing else.
        use crate::probes::http::normalised_body_fingerprint as fingerprint;
        assert_eq!(
            fingerprint("<html>\n  <body>Status</body>\n</html>"),
            fingerprint("<HTML> <body>status</body> </html>")
        );
        assert_ne!(
            fingerprint("<td>192.168.51.1</td>"),
            fingerprint("<td>192.168.70.1</td>")
        );
    }

    #[test]
    fn every_attempt_and_refusal_is_recorded() {
        let audit = ManagementAudit {
            attempted: vec![
                (
                    "/status".to_string(),
                    PathOutcome::Answered {
                        status: 200,
                        prefixes: 2,
                        fingerprint: Some(7),
                    },
                ),
                ("/info".to_string(), PathOutcome::NoResponse),
                (
                    "/api/status".to_string(),
                    PathOutcome::AuthenticationRequired { status: 401 },
                ),
                (
                    "/reboot".to_string(),
                    PathOutcome::Refused("action semantics in the URL"),
                ),
            ],
            candidates: Vec::new(),
            budget_exhausted: true,
        };

        assert_eq!(audit.answered(), 1);
        assert!(audit.attempted[3].1.label().contains("not fetched"));
        assert!(
            audit.attempted[2]
                .1
                .label()
                .contains("credentials demanded")
        );
        assert!(audit.budget_exhausted);
    }
}
