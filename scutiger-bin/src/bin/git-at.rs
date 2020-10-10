extern crate clap;
extern crate git2;
extern crate libc;
extern crate pcre2;
extern crate scutiger_core;

#[cfg(test)]
extern crate tempfile;

pub mod libgit2;

#[cfg(test)]
pub mod fixtures;

use clap::{App, AppSettings, Arg, ArgMatches};
use git2::{Oid, Repository};
use pcre2::bytes::Regex;
use scutiger_core::errors::{Error, ErrorKind, ExitStatus};
use std::io;
use std::process;

/// The main program.
struct Program<'a> {
    repo: &'a Repository,
    summary: bool,
    show: bool,
    quiet: bool,
    fixup: bool,
    head: &'a str,
    text: &'a str,
}

impl<'a> Program<'a> {
    // TODO: Drop when we drop support for Rust 1.24.
    const SORT_TIME: u32 = 1 << 1;

    /// Creates a new main program.
    ///
    /// The arguments correspond to the command line options. If `head` is `None`, it defaults to
    /// `HEAD`. `text` is a PCRE-compatible regular expression.
    fn new(
        repo: &'a Repository,
        summary: bool,
        show: bool,
        quiet: bool,
        fixup: bool,
        head: Option<&'a str>,
        text: &'a str,
    ) -> Self {
        Program {
            repo,
            summary,
            show,
            quiet,
            fixup,
            head: head.unwrap_or("HEAD"),
            text,
        }
    }

    /// Run this main program and generate a programmatically testable result.
    ///
    /// Returns the first object ID which matches the specified regular expression, or an error if
    /// one occurred. If the Error is due to no revision matching, the kind of the error will be
    /// `ErrorKind::NoSuchRevision`.
    fn run(&self) -> Result<Oid, Error> {
        let regex = self.pattern(self.text)?;
        let fixup_regex = self.pattern("\\A\\s*(?:fixup|squash)!")?;
        let head = self.repo.revparse_single(self.head)?;
        let mut walker = self.repo.revwalk()?;
        walker.set_sorting(git2::Sort::from_bits(Self::SORT_TIME).unwrap())?;
        walker.push(head.id())?;
        for rev in walker {
            let commit = self.repo.find_commit(rev?)?;
            let message = commit.message_bytes();
            if !self.fixup && fixup_regex.is_match(message)? {
                continue;
            }
            if regex.is_match(message)? {
                return Ok(commit.id());
            }
        }
        Err(Error::new::<git2::Error>(ErrorKind::NoSuchRevision, None))
    }

    /// Run this main program and generate output and error codes.
    ///
    /// The program is run (as per `run`) with the specified output and error streams
    /// (corresponding logically to standard output and standard error) and returns an exit code.
    /// For programmatic execution, see `run`.
    fn main<O: io::Write, E: io::Write>(&self, output: &mut O, error: &mut E) -> i32 {
        match self.run() {
            Ok(oid) => {
                if self.show {
                    process::Command::new("git")
                        .arg("show")
                        .arg(format!("{}", oid))
                        .spawn()
                        .unwrap()
                        .wait()
                        .unwrap()
                        .code()
                        .unwrap_or(ExitStatus::ExternalProgramFailed as i32)
                } else {
                    writeln!(output, "{}", oid).unwrap();
                    ExitStatus::Success as i32
                }
            }
            Err(e) => {
                match (e.fatal(), self.quiet) {
                    (true, _) | (false, false) => writeln!(error, "{}", e),
                    (false, true) => Ok(()),
                }
                .unwrap();
                e.exit_status() as i32
            }
        }
    }

    fn pattern(&self, pattern: &str) -> Result<Regex, Error> {
        if self.summary {
            return Ok(Regex::new(&format!("\\A[^\n]*{}", pattern))?);
        }
        Ok(Regex::new(pattern)?)
    }
}

fn parse_options<'a>() -> App<'a, 'a> {
    App::new("git-at")
        .setting(AppSettings::AllowMissingPositional)
        .about("Find a commit based on commit message")
        .arg(
            Arg::with_name("summary")
                .long("summary")
                .short("s")
                .help("Search only the commit summary"),
        )
        .arg(
            Arg::with_name("show")
                .long("show")
                .help("Invoke git show to show the commit"),
        )
        .arg(
            Arg::with_name("quiet")
                .long("quiet")
                .short("q")
                .help("Exit 1 silently if no commit is found"),
        )
        .arg(
            Arg::with_name("no-fixup")
                .long("no-fixup")
                .help("Ignore fixup and squash commits"),
        )
        .arg(Arg::with_name("revision"))
        .arg(Arg::with_name("pattern").required(true))
}

fn program<'a>(repo: &'a git2::Repository, matches: &'a ArgMatches) -> Program<'a> {
    Program::new(
        repo,
        matches.is_present("summary"),
        matches.is_present("show"),
        matches.is_present("quiet"),
        !matches.is_present("no-fixup"),
        matches.value_of("revision"),
        matches.value_of("pattern").unwrap(),
    )
}

fn repo() -> Repository {
    let repo = git2::Repository::discover(".");
    match repo {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(4);
        }
    }
}

fn main() {
    libgit2::init();
    let repo = repo();
    let app = parse_options();
    let matches = app.get_matches();
    let prog = program(&repo, &matches);
    process::exit(prog.main(&mut io::stdout(), &mut io::stderr()));
}

#[cfg(test)]
mod tests {
    use super::fixtures::TestRepository;
    use super::{Error, ErrorKind, Program};

    use git2;
    use git2::Oid;

    fn run(
        fixtures: &TestRepository,
        summary: bool,
        revision: Option<&str>,
        pattern: &str,
    ) -> Result<Oid, Error> {
        Program::new(
            &fixtures.repo,
            summary,
            false,
            false,
            true,
            revision,
            pattern,
        )
        .run()
    }

    fn run_fixup(
        fixtures: &TestRepository,
        summary: bool,
        fixup: bool,
        revision: Option<&str>,
        pattern: &str,
    ) -> Result<Oid, Error> {
        Program::new(
            &fixtures.repo,
            summary,
            false,
            false,
            fixup,
            revision,
            pattern,
        )
        .run()
    }

    fn oid(hex: &str) -> Oid {
        Oid::from_str(hex).unwrap()
    }

    fn error(kind: ErrorKind) -> Error {
        Error::new::<git2::Error>(kind, None)
    }

    #[test]
    fn simple_results() {
        let fixtures = TestRepository::new();

        assert_eq!(
            run(&fixtures, false, None, "maximum fooness").unwrap(),
            oid("cade2f7cc336453e30007fe76a57732f5e635cd0")
        );
        assert_eq!(
            run(&fixtures, false, None, "maximum barness").unwrap(),
            oid("f232e1550851a748b26f06e648ee10d210e05dea")
        );
        assert_eq!(
            run(&fixtures, false, None, "max.+\\s+bar.*content").unwrap(),
            oid("f232e1550851a748b26f06e648ee10d210e05dea")
        );
    }

    #[test]
    fn rev_results() {
        let fixtures = TestRepository::new();

        assert_eq!(
            run(&fixtures, false, Some("master~1"), "maximum fooness").unwrap(),
            oid("cade2f7cc336453e30007fe76a57732f5e635cd0")
        );
        assert_eq!(
            run(&fixtures, false, Some("master~1~1"), "maximum barness").unwrap_err(),
            error(ErrorKind::NoSuchRevision)
        );
        assert_eq!(
            run(&fixtures, false, Some("branch"), "maximum").unwrap(),
            oid("f232e1550851a748b26f06e648ee10d210e05dea")
        );
    }

    #[test]
    fn youngest_results() {
        let fixtures = TestRepository::new();

        assert_eq!(
            run(&fixtures, true, None, "Update").unwrap(),
            oid("f232e1550851a748b26f06e648ee10d210e05dea")
        );
        assert_eq!(
            run(&fixtures, false, None, "content").unwrap(),
            oid("f232e1550851a748b26f06e648ee10d210e05dea")
        );
        assert_eq!(
            run(&fixtures, false, None, "bar").unwrap(),
            oid("f232e1550851a748b26f06e648ee10d210e05dea")
        );
        assert_eq!(
            run(&fixtures, true, None, "Add").unwrap(),
            oid("eb31d2fb9733a85ddcd9ec63712caa0dfe79cccc")
        );
    }

    #[test]
    fn fixup_results() {
        let fixtures = TestRepository::new();

        for summary in vec![true, false] {
            assert_eq!(
                run_fixup(&fixtures, summary, true, None, "Add baz").unwrap(),
                oid("eb31d2fb9733a85ddcd9ec63712caa0dfe79cccc")
            );
            assert_eq!(
                run_fixup(&fixtures, summary, false, None, "Add baz").unwrap(),
                oid("4cf979cf194179a3b9dc1d65cc4dc29cfed32614")
            );
        }
        assert_eq!(
            run_fixup(&fixtures, false, true, None, "\\binitial\\b").unwrap(),
            oid("eb31d2fb9733a85ddcd9ec63712caa0dfe79cccc")
        );
        assert_eq!(
            run_fixup(&fixtures, false, false, None, "(?i)\\binitial\\b").unwrap(),
            oid("84f17cd225de12eeaea57e0bdb32fd6a7b940254")
        );
        assert_eq!(
            run_fixup(&fixtures, true, true, None, "\\binitial\\b").unwrap_err(),
            error(ErrorKind::NoSuchRevision)
        );
    }
}
