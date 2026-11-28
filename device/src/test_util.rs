//! Test helpers shared by this crate's tests and the router's (compiled
//! only for tests, or with the `test-util` feature).

/// G3: no silent skips. A test that cannot run here fails, unless
/// `SIGNER_ALLOW_SKIP=1` allows the skip; then a loud line says why
/// (written to the real stderr, so the test harness does not swallow it on
/// a pass). Return from the test right after calling it.
#[track_caller]
pub fn skip_or_fail(why: &str) {
    skip_or_fail_with(skip_allowed(), why, &mut std::io::stderr());
}

/// Whether this process may skip (`SIGNER_ALLOW_SKIP=1` in its
/// environment). A run where it may is a partial run: see vault_real's
/// e3 test, which then fails.
pub fn skip_allowed() -> bool {
    allows_skip(std::env::var_os("SIGNER_ALLOW_SKIP").as_deref())
}

/// F7: only the literal `1` allows a skip (not `true`, `yes`, `0`, or a
/// `1` with spaces).
fn allows_skip(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| v == "1")
}

/// G5: whether a libtest run with this process's arguments runs the test
/// `name` (see [`runs_test`]).
pub fn this_run_includes(name: &str) -> bool {
    runs_test(&std::env::args().skip(1).collect::<Vec<_>>(), name)
}

/// G5: whether libtest, given `args` (its command line without the
/// program), runs the (not `#[ignore]`d) test `name`: no `--ignored` and
/// no `--list`; with filters (positional arguments), one matches; no
/// `--skip` matches. A filter or skip matches by substring, or whole
/// under `--exact`. Options known to take a value have it skipped, inline
/// (`--skip=x`) or as the next argument; an unknown option is taken as a
/// flag, so a value it takes counts as a filter: the answer errs to "not
/// run".
pub fn runs_test(args: &[String], name: &str) -> bool {
    const WITH_VALUE: &[&str] = &[
        "--test-threads",
        "--format",
        "--color",
        "--logfile",
        "-Z",
        "--shuffle-seed",
    ];
    let (mut filters, mut skips, mut exact): (Vec<&str>, Vec<&str>, bool) =
        (Vec::new(), Vec::new(), false);
    let mut args = args.iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--exact" => exact = true,
            "--ignored" | "--list" => return false,
            "--skip" => skips.extend(args.next().map(String::as_str)),
            "--" => filters.extend(args.by_ref().map(String::as_str)),
            o if o.starts_with("--skip=") => skips.push(&o["--skip=".len()..]),
            o if WITH_VALUE.contains(&o) => {
                args.next();
            }
            o if o.starts_with('-') => {}
            f => filters.push(f),
        }
    }
    let matches = |p: &str| if exact { name == p } else { name.contains(p) };
    (filters.is_empty() || filters.iter().any(|f| matches(f))) && !skips.iter().any(|s| matches(s))
}

#[track_caller]
fn skip_or_fail_with(allow_skip: bool, why: &str, out: &mut dyn std::io::Write) {
    if allow_skip {
        let _ = writeln!(out, "\n#### SKIPPED (SIGNER_ALLOW_SKIP=1): {why} ####\n");
    } else {
        panic!(
            "{why}: refusing to pass without running (set SIGNER_ALLOW_SKIP=1 to allow the skip)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "the reason: refusing to pass without running")]
    fn a_skip_fails_unless_allowed() {
        skip_or_fail_with(false, "the reason", &mut Vec::new());
    }

    /// F7: the opt-out is the literal `1` only.
    #[test]
    fn f7_only_the_literal_1_allows_a_skip() {
        assert!(allows_skip(Some("1".as_ref())));
        for v in ["true", "yes", "0", "", " 1", "1 ", "01", "TRUE", "on"] {
            assert!(!allows_skip(Some(v.as_ref())), "{v:?}");
        }
        assert!(!allows_skip(None));
    }

    /// G5: which libtest command lines run a test (here `e3_x`).
    #[test]
    fn g5_runs_test_reads_libtest_args() {
        let runs = |line: &str| {
            runs_test(
                &line
                    .split_whitespace()
                    .map(String::from)
                    .collect::<Vec<_>>(),
                "e3_x",
            )
        };
        for yes in [
            "",
            "--nocapture --test-threads=1",
            "--test-threads 1 e3",
            "e3_x --exact",
            "other e3_",
            "--skip other",
            "--skip=other --include-ignored",
            "--format terse",
            "--color never e3",
            "-- e3",
        ] {
            assert!(runs(yes), "{yes:?} runs e3_x");
        }
        for no in [
            "--skip e3",
            "--skip=e3_",
            "--skip x --skip e3",
            "other",
            "e3 --exact",
            "--exact --skip e3_x",
            "--ignored",
            "--list",
            "--format e3_x other",
            "--unknown-with-value other",
        ] {
            assert!(!runs(no), "{no:?} does not run e3_x");
        }
    }

    /// Captured, so this test prints no SKIPPED line of its own.
    #[test]
    fn an_allowed_skip_returns_and_says_why() {
        let mut out = Vec::new();
        skip_or_fail_with(true, "the reason", &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\n#### SKIPPED (SIGNER_ALLOW_SKIP=1): the reason ####\n\n"
        );
    }
}
