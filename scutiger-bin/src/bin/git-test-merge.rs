#![allow(unknown_lints)]
#![allow(bare_trait_objects)]

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
use git2::{MergeOptions, Oid, Repository};
use scutiger_core::errors::{Error, ErrorKind, ExitStatus};
use std::io;
use std::process;

/// The main program.
struct Program<'p> {
    repo: &'p Repository,
    heads: Vec<String>,
    write: bool,
}

impl<'p> Program<'p> {
    /// Creates a new main program.
    ///
    /// The arguments correspond to the command line options.
    fn new(repo: &'p Repository, heads: Vec<String>, write_tree: bool) -> Self {
        Program {
            repo,
            heads,
            write: write_tree,
        }
    }

    /// Runs this main program and generate a programmatically testable result.
    ///
    /// Returns the object ID of the written tree or `None` if the merge succeeded, or an error if
    /// one occurred.  The merge will return an object ID on success if it was requested to write
    /// the tree. If the Error is due to a conflict, the kind of the error will be
    /// `ErrorKind::Conflict`.
    fn run(&self) -> Result<Option<Oid>, Error> {
        let objects = self
            .heads
            .iter()
            .map(|x| self.repo.revparse_single(&x))
            .collect::<Result<Vec<_>, git2::Error>>()?;
        let parsed: Result<Vec<_>, git2::Error> =
            objects.iter().map(|x| x.peel_to_commit()).collect();
        let heads = parsed?;
        let mut index =
            self.repo
                .merge_commits(&heads[0], &heads[1], Some(&MergeOptions::new()))?;
        if index.has_conflicts() {
            return Err(Error::new::<git2::Error>(ErrorKind::Conflict, None));
        }

        // If we've gotten here, the merge has succeeded.
        if !self.write {
            return Ok(None);
        }
        let tree = index.write_tree_to(self.repo)?;
        Ok(Some(tree))
    }

    /// Runs this main program and generate output and error codes.
    ///
    /// The program is run (as per `run`) with the specified output and error streams
    /// (corresponding logically to standard output and standard error) and returns an exit code.
    /// For programmatic execution, see `run`.
    fn main<O: io::Write, E: io::Write>(&self, output: &mut O, error: &mut E) -> i32 {
        match self.run() {
            Ok(object) => {
                if let Some(oid) = object {
                    writeln!(output, "{}", oid).unwrap();
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
    App::new("git-test-merge")
        .setting(AppSettings::AllowMissingPositional)
        .about("Attempt to perform a merge without touching the working tree")
        .arg(
            Arg::with_name("write-tree")
                .long("write-tree")
                .help("Write and print the tree if merge is successful"),
        )
        .arg(Arg::with_name("head").min_values(2).required(true))
}

fn program<'a>(repo: &'a Repository, matches: &'a ArgMatches) -> Program<'a> {
    Program::new(
        repo,
        matches
            .values_of("head")
            .unwrap()
            .map(|x| x.to_string())
            .collect(),
        matches.is_present("write-tree"),
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
    use super::{Error, ErrorKind, Program};

    use git2;
    use git2::Oid;

    fn run(
        fixtures: &TestRepository,
        head: Vec<String>,
        write_tree: bool,
    ) -> Result<Option<Oid>, Error> {
        Program::new(&fixtures.repo, head, write_tree).run()
    }

    fn oid(hex: &str) -> Oid {
        Oid::from_str(hex).unwrap()
    }

    fn error(kind: ErrorKind) -> Error {
        Error::new::<git2::Error>(kind, None)
    }

    #[test]
    fn results_no_write_tree() {
        let fixtures = TestRepository::new();

        assert_eq!(
            run(
                &fixtures,
                vec!["merge1".to_string(), "merge2".to_string()],
                false
            )
            .unwrap_err(),
            error(ErrorKind::Conflict),
        );
        assert_eq!(
            run(
                &fixtures,
                vec!["merge1".to_string(), "merge3".to_string()],
                false
            )
            .unwrap(),
            None,
        );
        assert_eq!(
            run(
                &fixtures,
                vec!["merge2".to_string(), "merge3".to_string()],
                false
            )
            .unwrap(),
            None,
        );
    }

    #[test]
    fn results_write_tree() {
        let fixtures = TestRepository::new();

        assert_eq!(
            run(
                &fixtures,
                vec!["merge1".to_string(), "merge2".to_string()],
                true
            )
            .unwrap_err(),
            error(ErrorKind::Conflict),
        );
        assert_eq!(
            run(
                &fixtures,
                vec!["merge1".to_string(), "merge3".to_string()],
                true
            )
            .unwrap(),
            Some(oid("ff2a880a0f65b9291dae1958f772a7b819e023c9")),
        );
        assert_eq!(
            run(
                &fixtures,
                vec!["merge2".to_string(), "merge3".to_string()],
                true
            )
            .unwrap(),
            Some(oid("0fff45312f2530feb88948e85a3a022b52af9026")),
        );
    }
}
