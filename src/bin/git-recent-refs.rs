#![allow(unknown_lints)]
#![allow(bare_trait_objects)]

extern crate clap;
extern crate git2;
extern crate libc;
extern crate pcre2;

#[cfg(test)]
extern crate tempfile;

pub mod errors;
pub mod libgit2;

#[cfg(test)]
pub mod fixtures;

use clap::{App, AppSettings, Arg, ArgMatches};
use errors::{Error, ExitStatus};
use git2::{Object, Reference, Repository, Time};
use std::io;
use std::process;

/// The types of sorting that can be provided.
enum SortKind {
    Visited,
    Committed,
    Authored,
}

/// The main program.
struct Program<'p> {
    repo: &'p Repository,
    kind: SortKind,
}

impl<'p> Program<'p> {
    /// Creates a new main program.
    ///
    /// The arguments correspond to the command line options.
    fn new(repo: &'p Repository, kind: SortKind) -> Self {
        Program { repo, kind }
    }

    ///
    fn stringify<'b>(obj: Option<(Object<'b>, Option<Reference<'b>>)>) -> Option<String> {
        match obj {
            Some((_, Some(r2))) => Some(r2.name()?.into()),
            Some((r1, None)) => Some(format!("{}", r1.id())),
            None => None,
        }
    }

    fn commit_date_for(r: &Reference) -> Option<Time> {
        let commit = r.peel_to_commit().ok()?;
        let time = commit.committer().when();
        Some(time)
    }

    fn author_date_for(r: &Reference) -> Option<Time> {
        let commit = r.peel_to_commit().ok()?;
        let time = commit.author().when();
        Some(time)
    }

    /// Runs this main program and generate a programmatically testable result.
    ///
    /// Returns the first object ID which matches the specified regular expression, or an error if
    /// one occurred. If the Error is due to no revision matching, the kind of the error will be
    /// `ErrorKind::NoSuchRevision`.
    fn run<'a>(&self, repo: &'a Repository) -> Result<Box<Iterator<Item = String> + 'a>, Error> {
        match self.kind {
            SortKind::Visited => {
                let chain: Vec<String> = vec!["HEAD".to_string()];
                let range = 1..;
                let iter = chain
                    .into_iter()
                    .chain(range.map(|i| format!("@{{-{}}}", i)));
                Ok(Box::new(
                    iter.map(move |rev| Self::stringify(repo.revparse_ext(&rev).ok()))
                        .take_while(Option::is_some)
                        .map(Option::unwrap),
                ))
            }
            SortKind::Committed => {
                let mut refs: Vec<_> = repo
                    .references()?
                    .filter_map(Result::ok)
                    .map(|r| (r.target(), Self::commit_date_for(&r), r))
                    .filter(|&(oid, time, _)| oid.is_some() && time.is_some())
                    .collect();
                refs.sort_by(|ref a, ref b| b.1.cmp(&a.1));
                Ok(Box::new(
                    refs.into_iter()
                        .filter_map(|(_, _, r)| Some(r.name()?.to_string())),
                ))
            }
            SortKind::Authored => {
                let mut refs: Vec<_> = repo
                    .references()?
                    .filter_map(Result::ok)
                    .map(|r| (r.target(), Self::author_date_for(&r), r))
                    .filter(|&(oid, time, _)| oid.is_some() && time.is_some())
                    .collect();
                refs.sort_by(|ref a, ref b| b.1.cmp(&a.1));
                Ok(Box::new(
                    refs.into_iter()
                        .filter_map(|(_, _, r)| Some(r.name()?.to_string())),
                ))
            }
        }
    }

    /// Runs this main program and generate output and error codes.
    ///
    /// The program is run (as per `run`) with the specified output and error streams
    /// (corresponding logically to standard output and standard error) and returns an exit code.
    /// For programmatic execution, see `run`.
    fn main<O: io::Write, E: io::Write>(&self, output: &mut O, error: &mut E) -> i32 {
        match self.run(&self.repo) {
            Ok(iter) => {
                for s in iter {
                    writeln!(output, "{}", s).unwrap();
                }
                ExitStatus::Success as i32
            }
            Err(e) => {
                writeln!(error, "{}", e).unwrap();
                e.exit_status() as i32
            }
        }
    }
}

fn parse_options<'a>() -> App<'a, 'a> {
    App::new("git-recent-refs")
        .setting(AppSettings::AllowMissingPositional)
        .about("Find a commit based on commit message")
        .arg(
            Arg::with_name("sort")
                .long("sort")
                .takes_value(true)
                .required(true)
                .possible_values(&["visitdate", "committerdate", "authordate"])
                .help("Sort refs by the given type"),
        )
}

fn sort_type(kind: &str) -> Result<SortKind, Error> {
    match kind {
        "visitdate" => Ok(SortKind::Visited),
        "authordate" => Ok(SortKind::Authored),
        "committerdate" => Ok(SortKind::Committed),
        _ => unimplemented!(),
    }
}

fn program<'a>(repo: &'a Repository, matches: &'a ArgMatches) -> Program<'a> {
    Program::new(repo, sort_type(matches.value_of("sort").unwrap()).unwrap())
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

fn setup() {
    libgit2::init();
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() {
    setup();
    let app = parse_options();
    let matches = app.get_matches();
    let repo = repo();
    let prog = program(&repo, &matches);
    process::exit(prog.main(&mut io::stdout(), &mut io::stderr()));
}

#[cfg(test)]
mod tests {
    use super::fixtures::TestRepository;
    use super::{Error, Program, SortKind};

    use git2::build::CheckoutBuilder;
    use git2::Oid;

    fn run<'a>(
        fixtures: &'a TestRepository,
        sorttype: SortKind,
    ) -> Result<Box<Iterator<Item = String> + 'a>, Error> {
        Program::new(&fixtures.repo, sorttype).run(&fixtures.repo)
    }

    fn oid(hex: &str) -> Oid {
        Oid::from_str(hex).unwrap()
    }

    fn checkout_branch(fixtures: &TestRepository, branch: &str) {
        if branch.len() == 40 {
            fixtures.repo.set_head_detached(oid(branch)).unwrap();
        } else {
            let full_branch = format!("refs/heads/{}", branch);
            fixtures.repo.set_head(&full_branch).unwrap();
        };
        let mut cb = CheckoutBuilder::new();
        fixtures.repo.checkout_head(Some(cb.force())).unwrap();
    }

    #[test]
    fn visited_results() {
        let fixtures = TestRepository::new();
        let rev = "4cf979cf194179a3b9dc1d65cc4dc29cfed32614";

        checkout_branch(&fixtures, "fixup");
        checkout_branch(&fixtures, rev);
        checkout_branch(&fixtures, "branch");
        checkout_branch(&fixtures, "master");

        assert_eq!(
            run(&fixtures, SortKind::Visited)
                .unwrap()
                .collect::<Vec<_>>(),
            vec![
                "refs/heads/master",
                "refs/heads/branch",
                rev,
                "refs/heads/fixup",
                "refs/heads/master"
            ],
        );
    }

    #[test]
    fn committer_results() {
        let fixtures = TestRepository::new();

        assert_eq!(
            run(&fixtures, SortKind::Committed)
                .unwrap()
                .collect::<Vec<_>>(),
            vec!["refs/heads/master", "refs/heads/fixup", "refs/heads/branch"],
        );
    }
}
