//! The router's log subscriber.
//!
//! `RUST_LOG` chooses what is logged, within an allow list it cannot lift:
//! the router's own targets (`signer_router`, `signer_router::*`) may log
//! at every level; every other target is capped at INFO, unless the closed
//! table [`ABOVE_INFO`] names it, with the most it may log and why.
//!
//! Why: a dependency's DEBUG or TRACE output is not reviewed, and one of
//! them is known to leak. ureq's protocol crate (`ureq_proto`) at TRACE
//! hex-dumps every byte sent and received (`ureq_proto::util::log_data`,
//! with an ASCII column): the `X-Vault-Token` header, a cert-auth login
//! reply with its client token, and every Vault record, keystore and all.
//! TLS does not help: the dump is of the plaintext above it. A crate that
//! is not in the table (a new dependency, a new version that moves the
//! dump to another target) stays at INFO.
//!
//! Each row names the package and version it was written against; a test
//! fails when Cargo.lock holds another version of any of them.

use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::filter::{filter_fn, EnvFilter, FilterExt as _};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer as _;

/// The router's own crate: every level (it never logs a secret).
const ROUTER: &str = "signer_router";

/// One row of [`ABOVE_INFO`]: a target outside the router, the package
/// that logs under it and the version its log calls were read in, the most
/// it may log, and why.
#[derive(Debug, Clone, Copy)]
pub struct Allowed {
    /// The log target (a crate name, `_` not `-`), with its modules.
    pub target: &'static str,
    /// The Cargo package behind `target` (its name in Cargo.lock).
    pub package: &'static str,
    /// The package version whose log calls were reviewed for this row; a
    /// test fails when Cargo.lock holds any other.
    pub version: &'static str,
    pub level: Level,
    pub reason: &'static str,
}

/// The closed table, the ONE source for both [`max_level`] and the
/// Cargo.lock pin: targets outside the router whose cap is not plain INFO,
/// each with the package and version it was reviewed against, the most it
/// may log and the reason. Anything else: INFO.
pub const ABOVE_INFO: &[Allowed] = &[
    Allowed {
        target: "ureq",
        package: "ureq",
        version: "3.5.2",
        level: Level::DEBUG,
        reason: "ureq's DEBUG lines are the method and URI, the request and the response \
                 status line, with headers printed through ureq's own DebugHeaders allowlist \
                 (X-Vault-Token is not on it: redacted); its TRACE lines are dropped",
    },
    Allowed {
        target: "ureq_proto",
        package: "ureq-proto",
        version: "0.7.1",
        level: Level::INFO,
        reason: "its TRACE is the wire dump (log_data: every byte, token and records); its \
                 DEBUG lines are state names, dropped so a version that moves the dump up one \
                 level stays out of the log",
    },
];

/// `target` is `krate` or one of its modules (`krate::…`).
fn in_crate(target: &str, krate: &str) -> bool {
    target
        .strip_prefix(krate)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
}

/// The most `target` may log, whatever the filter allows: TRACE for the
/// router, its [`ABOVE_INFO`] entry, or INFO.
pub fn max_level(target: &str) -> Level {
    if in_crate(target, ROUTER) {
        return Level::TRACE;
    }
    ABOVE_INFO
        .iter()
        .find(|row| in_crate(target, row.target))
        .map_or(Level::INFO, |row| row.level)
}

/// Whether `meta` is an event the router never logs (more verbose than
/// [`max_level`] allows its target; see the module doc).
pub fn never_logged(meta: &Metadata<'_>) -> bool {
    *meta.level() > max_level(meta.target())
}

/// The router's subscriber: `filter` (from `RUST_LOG`, or the default),
/// minus what [`never_logged`] drops, formatted to `writer`. Install with
/// `SubscriberInitExt::init`, which also bridges `log` records (ureq's
/// and rustls's) into it.
pub fn subscriber<W>(filter: EnvFilter, writer: W) -> impl Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_filter(filter.and(filter_fn(|meta| !never_logged(meta)))),
    )
}

/// Test-only: run `f` on this thread under the router's subscriber with
/// the filter `spec` (as `RUST_LOG`), and return what it logged. The one
/// capture harness of the router's unit tests.
#[cfg(test)]
pub(crate) fn capture_spec(spec: &str, f: impl FnOnce()) -> String {
    #[derive(Clone, Default)]
    struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let w = buf.clone();
    let sub = subscriber(EnvFilter::new(spec), move || w.clone());
    tracing::subscriber::with_default(sub, f);
    let out = buf.0.lock().unwrap().clone();
    String::from_utf8(out).unwrap()
}

/// [`capture_spec`] at `RUST_LOG=trace`.
#[cfg(test)]
pub(crate) fn capture(f: impl FnOnce()) -> String {
    capture_spec("trace", f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logged(spec: &str) -> String {
        capture_spec(spec, || {
            tracing::trace!(target: "ureq_proto::util", "wire-dump-trace");
            tracing::debug!(target: "ureq_proto::client", "wire-state-debug");
            tracing::trace!(target: "ureq_proto", "crate-root-trace");
            tracing::info!(target: "ureq_proto::client", "proto-info-kept");
            // F2: ureq is capped at DEBUG, any other crate at INFO.
            tracing::debug!(target: "ureq::run", "ureq-debug-kept");
            tracing::info!(target: "ureq_protox", "other-crate-info-kept");
            tracing::trace!(target: "signer_router::vault", "router-trace-kept");
        })
    }

    fn logged_events(spec: &str, events: &[(&'static str, Level, &'static str)]) -> String {
        capture_spec(spec, || {
            for &(target, level, text) in events {
                // `event!` needs constant targets and levels: one per case.
                macro_rules! ev {
                    ($t:literal) => {
                        match level {
                            Level::TRACE => tracing::trace!(target: $t, "{text}"),
                            Level::DEBUG => tracing::debug!(target: $t, "{text}"),
                            Level::INFO => tracing::info!(target: $t, "{text}"),
                            Level::WARN => tracing::warn!(target: $t, "{text}"),
                            Level::ERROR => tracing::error!(target: $t, "{text}"),
                        }
                    };
                }
                match target {
                    "some_other_crate" => ev!("some_other_crate"),
                    "some_other_crate::m" => ev!("some_other_crate::m"),
                    "rustls::client" => ev!("rustls::client"),
                    "signer_device" => ev!("signer_device"),
                    "ureq::run" => ev!("ureq::run"),
                    "ureq_proto::util" => ev!("ureq_proto::util"),
                    "signer_router::vault" => ev!("signer_router::vault"),
                    "signer_routerx" => ev!("signer_routerx"),
                    other => unreachable!("{other}"),
                }
            }
        })
    }

    /// N3: whether the `RUST_LOG` spec asks for `target`'s events at all:
    /// a bare level (every target), or a directive naming its crate.
    fn asks_for(spec: &str, target: &str) -> bool {
        let krate = target.split("::").next().unwrap_or(target);
        spec.split(',').any(|d| match d.split_once('=') {
            None => d.parse::<Level>().is_ok(),
            Some((t, _)) => t == krate,
        })
    }

    /// N3: the f2 test's "asked" is parsed from the spec, not a substring.
    #[test]
    fn asks_for_reads_directives() {
        assert!(asks_for("trace", "x::m"));
        assert!(asks_for("info", "x"));
        assert!(asks_for("a=trace,x=debug", "x::m"));
        assert!(!asks_for("ax=trace", "x"));
        assert!(!asks_for("x::m=trace", "x"));
        assert!(!asks_for("signer_routerx=trace", "signer_router::vault"));
    }

    /// F2: an allow list. Every target outside `signer_router` is capped
    /// at INFO, whatever RUST_LOG asks for, unless the closed table lets
    /// it log more: `ureq` up to DEBUG, `ureq_proto` INFO only.
    #[test]
    fn f2_targets_outside_the_router_are_capped_at_info() {
        use Level as L;
        let cases: &[(&str, Level, &str, bool)] = &[
            ("some_other_crate", L::TRACE, "f2-other-trace", false),
            ("some_other_crate", L::DEBUG, "f2-other-debug", false),
            ("some_other_crate", L::INFO, "f2-other-info", true),
            ("some_other_crate::m", L::TRACE, "f2-other-mod-trace", false),
            ("some_other_crate::m", L::WARN, "f2-other-mod-warn", true),
            ("rustls::client", L::DEBUG, "f2-rustls-debug", false),
            ("signer_device", L::DEBUG, "f2-device-debug", false),
            ("signer_device", L::INFO, "f2-device-info", true),
            ("ureq::run", L::TRACE, "f2-ureq-trace", false),
            ("ureq::run", L::DEBUG, "f2-ureq-debug", true),
            ("ureq_proto::util", L::DEBUG, "f2-proto-debug", false),
            ("ureq_proto::util", L::INFO, "f2-proto-info", true),
            ("signer_routerx", L::DEBUG, "f2-routerx-debug", false),
            ("signer_router::vault", L::TRACE, "f2-router-trace", true),
        ];
        let events: Vec<_> = cases.iter().map(|&(t, l, m, _)| (t, l, m)).collect();
        let mut wrong = Vec::new();
        for spec in [
            "trace",
            "some_other_crate=trace",
            "some_other_crate=trace,rustls=trace,signer_device=trace,ureq=trace,\
             ureq_proto=trace,signer_routerx=trace,signer_router=trace",
        ] {
            let out = logged_events(spec, &events);
            for &(target, level, text, kept) in cases {
                let asked = asks_for(spec, target);
                if out.contains(text) != (kept && asked) {
                    wrong.push(format!(
                        "RED RUST_LOG={spec}: {target} at {level}: logged={}",
                        out.contains(text)
                    ));
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// F2, G1: every row of the closed table was written for one locked
    /// package version; a Cargo.lock that holds another (or none: a row
    /// whose package or version is wrong or empty) fails here, pointing at
    /// this file. Derived from [`ABOVE_INFO`] itself, so a new row is
    /// pinned with no second list to update.
    #[test]
    fn f2_reviewed_versions_match_cargo_lock() {
        let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.lock"));
        let lines: Vec<&str> = lock.lines().collect();
        let mut wrong = Vec::new();
        for row in ABOVE_INFO {
            let locked: Vec<&str> = lines
                .windows(2)
                .filter(|w| w[0] == format!("name = \"{}\"", row.package))
                .filter_map(|w| w[1].strip_prefix("version = \"")?.strip_suffix('"'))
                .collect();
            if row.version.is_empty() || locked != [row.version] {
                wrong.push(format!(
                    "RED target {} (package {:?}): Cargo.lock has {locked:?}, the row was \
                     reviewed against {:?}",
                    row.target, row.package, row.version
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "{}\nre-read that version's log calls (what each level prints), then update the \
             row in router/src/logging.rs's ABOVE_INFO",
            wrong.join("\n")
        );
    }

    /// D2: whatever RUST_LOG asks for (everything at trace, or the dump's
    /// own target by name), ureq_proto's DEBUG/TRACE never reach the log;
    /// its INFO and every other target still do.
    #[test]
    fn wire_dumps_are_never_logged() {
        for spec in [
            "trace",
            "ureq_proto::util=trace",
            "ureq_proto=trace,ureq=trace,ureq_protox=trace,signer_router=trace",
        ] {
            let out = logged(spec);
            for dropped in ["wire-dump-trace", "wire-state-debug", "crate-root-trace"] {
                assert!(!out.contains(dropped), "{spec}: {dropped} logged:\n{out}");
            }
            if spec != "ureq_proto::util=trace" {
                for kept in [
                    "proto-info-kept",
                    "ureq-debug-kept",
                    "other-crate-info-kept",
                    "router-trace-kept",
                ] {
                    assert!(out.contains(kept), "{spec}: {kept} missing:\n{out}");
                }
            }
        }
    }
}
