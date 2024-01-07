#![allow(unknown_lints)]
#![allow(bare_trait_objects)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::mutable_key_type)]

extern crate bytes;
extern crate chrono;
extern crate clap;
extern crate digest;
extern crate git2;
extern crate hex;
extern crate libc;
#[cfg(unix)]
extern crate passwd;
extern crate scutiger_core;
extern crate scutiger_lfs;
extern crate sha2;
extern crate tempfile;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

use clap::{App, Arg, ArgMatches};
use git2::Repository;
use scutiger_core::errors::{Error, ErrorKind, ExitStatus};
use scutiger_lfs::backend::local::LocalBackend;
use scutiger_lfs::processor::{Mode, PktLineHandler, Processor};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

/// The main program.
struct Program<'p> {
    repo: &'p Repository,
    operation: String,
    lfs_path: PathBuf,
    umask: u32,
}

impl<'p> Program<'p> {
    /// Creates a new main program.
    ///
    /// The arguments correspond to the command line options.
    fn new(repo: &'p Repository, operation: String) -> Self {
        let mut lfs_path = repo.path().to_path_buf();
        lfs_path.push("lfs");
        Program {
            repo,
            operation,
            lfs_path,
            umask: 0o077,
        }
    }

    /// Runs this main program and generate a programmatically testable result.
    fn run<R: io::Read, O: io::Write, E: io::Write>(
        &self,
        input: &mut R,
        output: &mut O,
        _error: &mut E,
        timestamp: Option<i64>,
    ) -> Result<(), Error> {
        self.create_directories()?;
        let mut handler = PktLineHandler::new(input, output);
        self.send_capabilities(&mut handler)?;
        let backend = Box::new(LocalBackend::new(&self.lfs_path, self.umask, timestamp));
        let mut processor = Processor::new(handler, backend);
        match self.operation.as_str() {
            "upload" => processor.process_commands(Mode::Upload),
            "download" => processor.process_commands(Mode::Download),
            _ => Err(Error::new_simple(ErrorKind::UnknownCommand)),
        }
    }

    fn send_capabilities<R: io::Read, W: io::Write>(
        &self,
        handler: &mut PktLineHandler<R, W>,
    ) -> Result<(), Error> {
        handler.send(b"version=1\n")?;
        handler.flush()?;
        Ok(())
    }

    fn create_directories(&self) -> Result<(), Error> {
        for dir in &["objects", "incomplete", "tmp", "locks"] {
            let mut path = self.lfs_path.clone();
            path.push(dir);
            fs::create_dir_all(path)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn set_permissions(&self) -> Result<u32, Error> {
        let config = self.repo.config()?;
        let sval = config.get_string("core.sharedrepository");
        let tval = sval.as_ref().map(|s| s.as_str());
        let perms = match (config.get_bool("core.sharedrepository"), tval) {
            (Ok(true), _) | (_, Ok("group")) => Some(0o660),
            (Ok(false), _) | (_, Ok("umask")) => None,
            (_, Ok("all")) | (_, Ok("world")) | (_, Ok("everybody")) => Some(0o664),
            (_, Ok(x)) if u16::from_str_radix(x, 8).is_ok() => {
                Some(u16::from_str_radix(x, 8).unwrap())
            }
            (_, Err(e)) if e.code() == git2::ErrorCode::NotFound => None,
            (_, Err(e)) => return Err(git2::Error::new(e.code(), e.class(), e.message()).into()),
            _ => None,
        };
        let res = match perms {
            Some(value) => {
                // If the user has read permissions, also set executable permissions.
                let value = value | (value & 0o444) >> 2;
                let new = 0o777 & !value as libc::mode_t;
                unsafe { libc::umask(new) };
                new
            }
            None => unsafe {
                let value = libc::umask(0o777);
                libc::umask(value);
                value
            },
        };
        Ok(res as u32)
    }

    #[cfg(not(unix))]
    fn set_permissions(&self) -> Result<u32, Error> {
        Ok(0o077)
    }

    fn main_internal<R: io::Read, O: io::Write, E: io::Write>(
        &mut self,
        input: &mut R,
        output: &mut O,
        error: &mut E,
    ) -> Result<(), Error> {
        self.umask = self.set_permissions()?;
        self.run(input, output, error, None)
    }

    /// Runs this main program and generate output and error codes.
    ///
    /// The program is run (as per `run`) with the specified output and error streams
    /// (corresponding logically to standard output and standard error) and returns an exit code.
    /// For programmatic execution, see `run`.
    fn main<R: io::Read, O: io::Write, E: io::Write>(
        &mut self,
        input: &mut R,
        output: &mut O,
        error: &mut E,
    ) -> i32 {
        match self.main_internal(input, output, error) {
            Ok(()) => ExitStatus::Success as i32,
            Err(e) => {
                writeln!(error, "{}", e).unwrap();
                e.exit_status() as i32
            }
        }
    }
}

fn parse_options<'a>() -> App<'a, 'a> {
    App::new("git-lfs-transfer")
        .about("Implement the remote side of a Git LFS SSH transfer")
        .arg(Arg::with_name("path").required(true))
        .arg(Arg::with_name("operation").required(true))
}

fn program<'a>(r: &'a Repository, matches: &'a ArgMatches) -> Program<'a> {
    Program::new(r, matches.value_of("operation").unwrap().into())
}

fn repo<P: AsRef<Path>>(path: P) -> Repository {
    let repo = git2::Repository::open(path);
    match repo {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(4);
        }
    }
}

#[cfg(unix)]
fn setup() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn setup() {}

fn main() {
    setup();
    let app = parse_options();
    let matches = app.get_matches();
    let path = matches.value_of_os("path").unwrap();
    let r = repo(path);
    let mut prog = program(&r, &matches);
    process::exit(prog.main(&mut io::stdin(), &mut io::stdout(), &mut io::stderr()));
}

#[cfg(test)]
mod tests {
    use super::{Error, Program};
    use git2::Repository;
    use std::fs;
    use std::io;
    use std::io::Read;
    use std::path::PathBuf;

    pub struct TestRepository {
        pub repo: Repository,
        pub tempdir: tempfile::TempDir,
    }

    impl TestRepository {
        pub fn new() -> TestRepository {
            let dir = tempfile::tempdir().unwrap();
            let repo = Repository::init(dir.path()).unwrap();
            TestRepository { repo, tempdir: dir }
        }
    }

    fn run(
        fixtures: &TestRepository,
        operation: &str,
        transcript: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut input = io::Cursor::new(transcript);
        let mut output = io::Cursor::new(Vec::new());
        let mut error = io::Cursor::new(Vec::new());
        Program::new(&fixtures.repo, operation.into()).run(
            &mut input,
            &mut output,
            &mut error,
            Some(1000684800),
        )?;
        Ok(output.into_inner())
    }

    fn assert_file(fixtures: &TestRepository, name: &str, contents: &[u8]) {
        let mut path: PathBuf = fixtures.repo.path().into();
        path.push("lfs");
        path.push("objects");
        path.push(name);
        let file = fs::File::open(&path).unwrap();
        let bytes = file
            .bytes()
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
        assert_eq!(bytes, contents);
    }

    fn refute_file(fixtures: &TestRepository, name: &str) {
        let mut path: PathBuf = fixtures.repo.path().into();
        path.push("lfs");
        path.push("objects");
        path.push(name);
        fs::metadata(&path).unwrap_err();
    }

    #[cfg(windows)]
    fn username() -> String {
        "unknown".into()
    }

    #[cfg(unix)]
    fn username() -> String {
        let uid = unsafe { libc::getuid() } as u32;
        match passwd::Passwd::from_uid(uid) {
            Some(pwd) => pwd.name,
            None => format!("uid {}", uid),
        }
    }

    fn replace_user_id(transcript: &str) -> String {
        let name = username();
        transcript.replace(
            "0018ownername=test user\n",
            &format!(
                "{:04x}ownername={}\n",
                4 + "ownername=\n".len() + name.len(),
                name
            ),
        ).replace(
            "0059ownername d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 test user\n",
            &format!(
                "{:04x}ownername d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 {}\n",
                4 + "ownername d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 \n".len() + name.len(),
                name
            ),
        )
    }

    #[test]
    fn failed_verify() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000053verify-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=5
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 200
0000000fstatus 409
0001002emismatched size or cryptographic collision0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn missing_object() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000053verify-object 0000000000000000000000000000000000000000000000000000000000000000
000bsize=5
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 200
0000000fstatus 404
0001000dnot found0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn simple_upload() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
0000000abatch
0011transfer=ssh
0015hash-algo=sha256
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000053verify-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
00000053verify-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        assert_file(
            &fixtures,
            "6c/a1/6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
            b"abc123",
        );
        assert_file(
            &fixtures,
            "ce/08/ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626",
            b"This is\x00a complicated\xc2\xa9message.\n",
        );
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 200
0000000fstatus 200
0000000fstatus 200
0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn invalid_hash_algo() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
0000000abatch
0011transfer=ssh
0015hash-algo=sha512
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 400
00010040error: not allowed: sha512 is not a permitted hash algorithm0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn simple_download() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000053verify-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 200
0000";
        assert_eq!(result, expected);

        let message = b"000eversion 1
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050get-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
0000";
        let result = run(&fixtures, "download", message).unwrap();
        assert_file(
            &fixtures,
            "ce/08/ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626",
            b"This is\x00a complicated\xc2\xa9message.\n",
        );
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 200
0001004c6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 noop
0051ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 download
0000000fstatus 200
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn invalid_upload() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x01a complicated\xc2\xa9message.
00000053verify-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
00000053verify-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        // This file was correct.
        assert_file(
            &fixtures,
            "6c/a1/6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
            b"abc123",
        );
        // We didn't write this file because it was corrupt.
        refute_file(
            &fixtures,
            "ce/08/ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626",
        );
        // We didn't write this one, either, because nobody asked us to.
        refute_file(
            &fixtures,
            "36/79/367988c7cb91e13beda0a15fb271afcbf02fa7a0e75d9e25ac50b2b4b38af5f5",
        );

        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 400
000100acerror: corrupt data: expected oid ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626, got 367988c7cb91e13beda0a15fb271afcbf02fa7a0e75d9e25ac50b2b4b38af5f50000000fstatus 200
0000000fstatus 404
0001000dnot found0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn simple_locking() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
00000009lock
000dpath=foo
001crefname=refs/heads/main
00000009lock
000dpath=foo
001crefname=refs/heads/main
0000000elist-lock
000elimit=100
0000004cunlock d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &str = "000eversion=1
0000000fstatus 200
00010000000fstatus 201
0048id=d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
000dpath=foo
0028locked-at=2001-09-17T00:00:00+00:00
0018ownername=test user
0000000fstatus 409
0048id=d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
000dpath=foo
0028locked-at=2001-09-17T00:00:00+00:00
0018ownername=test user
0001000cconflict0000000fstatus 200
0001004alock d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
004epath d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 foo
0069locked-at d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 2001-09-17T00:00:00+00:00
0059ownername d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 test user
0050owner d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 ours
0000000fstatus 200
0048id=d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
000dpath=foo
0028locked-at=2001-09-17T00:00:00+00:00
0018ownername=test user
0000";
        let expected = replace_user_id(expected);
        assert_eq!(result, expected.as_bytes());
    }
}
